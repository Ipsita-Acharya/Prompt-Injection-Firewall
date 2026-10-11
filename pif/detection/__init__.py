"""Detection Engine (Phase 4): coordinates the detection mechanisms —
rule (Layer A), semantic (Layer B), fuzzy phrase similarity, context
(Layer C), the encoded-instruction and indirect-injection detectors, and
the nine-category summary."""

import logging
import re
from abc import ABC, abstractmethod
from pif.detection.context import ContextDetector, sequence_findings
from pif.detection.encoded import EncodedDetector
from pif.detection.fuzzy import FUZZY_PHRASES, FuzzyDetector, fuzzy_matches
from pif.detection.indirect import IndirectDetector
from pif.detection.rules import (
    RULES,
    RULES_REGISTRY,
    RULE_REASONS,
    RuleDetector,
    WORD_VOCAB,
    get_custom_rules,
    get_rule_overrides,
    log_categories,
    quoted_example,
    set_custom_rules,
    set_rule_overrides,
    validate_custom_rule,
)
from pif.detection.semantic import LABELS, LocalClassifier, SemanticDetector
from pif.normalization import normalize
from pif.observability import content_preview, logger, source_context
from pif.schemas import Finding, Segment

__all__ = [
    "Detector",
    "DetectionEngine",
    "detect",
    "RULES",
    "RULES_REGISTRY",
    "RULE_REASONS",
    "RULE_DETECTOR",
    "WORD_VOCAB",
    "log_categories",
    "quoted_example",
    "set_rule_overrides",
    "get_rule_overrides",
    "set_custom_rules",
    "get_custom_rules",
    "validate_custom_rule",
    "FUZZY_PHRASES",
    "fuzzy_matches",
    "sequence_findings",
    "LABELS",
    "LocalClassifier",
    "SemanticDetector",
    "EncodedDetector",
    "IndirectDetector",
]


class Detector(ABC):
    """Common interface for every detection mechanism (spec §9-§12).

    Each detector declares a stable `name` (its layer id) and returns findings
    for the inputs it owns; the DetectionEngine coordinates them."""

    name: str = "detector"

    @abstractmethod
    def scan(self, *args, **kwargs) -> list[Finding]:
        raise NotImplementedError


class DetectionEngine:
    """Coordinates all detection mechanisms for one segment (and the
    conversation-level context pass), then applies the encoded/indirect
    modifiers and the nine-category summary."""

    # Views the semantic layer may score. Rule matching benefits from every
    # view, but the MODEL reads rot13/reversed views of BENIGN text as
    # high-entropy gibberish and flags it (measured: benign FPR 0.08 purely
    # from rot13 views). Transformation names chain ("canonical/rot13"), so
    # the permutation markers are excluded at any depth; decoded and repair
    # views carry real language and stay model-visible.
    _SEMANTIC_EXCLUDED_MARKERS = ("rot13", "reversed")

    # Raw-encoding shape (long hex or base64 runs): the model reads these as
    # attack (hex-attack training examples dominate), but the decoded views
    # already carry the meaning and the rule layer scans every view — so raw
    # encodings are not model evidence (view-differential principle). 32
    # chars: any typical encoded payload is caught; real prose cannot form a
    # 32-char alnum run without separators.
    _RAW_ENCODING_SHAPE = re.compile(r"(?:[0-9a-fA-F]{40,}|[A-Za-z0-9+/]{32,}={0,2})")

    def __init__(self, classifier: LocalClassifier | None = None):
        self.rules = RuleDetector()
        self.semantic = SemanticDetector(classifier) if classifier is not None else None
        self.fuzzy = FuzzyDetector()
        self.context = ContextDetector()
        self.encoded = EncodedDetector()
        self.indirect = IndirectDetector()

    def scan_segment(self, segment: Segment) -> list[Finding]:
        logger.debug("detection.segment_started", extra={"event_fields": dict(source=segment.source, input_chars=len(segment.text), semantic_enabled=self.semantic is not None, input_text=content_preview(segment.text))})
        findings: list[Finding] = []
        for transformation, text in normalize(segment.text, WORD_VOCAB):
            logger.info("story.step_started", extra={"event_fields": dict(step=4, title="Rule-Based Detection", transformation=transformation)})
            rule_categories = set()
            findings.extend(self.rules.scan_view(segment, transformation, text, rule_categories))
            remaining_categories = [category for category in RULES if category not in rule_categories]
            logger.info("detection.rules_completed", extra={"event_fields": dict(actionable_categories=sorted(rule_categories), remaining_categories=remaining_categories, matched=bool(rule_categories), next_step="semantic classification"
                if remaining_categories
                else "category/context analysis")})
            logger.info("story.step_completed", extra={"event_fields": dict(step=4, title="Rule-Based Detection")})
            logger.info("story.step_started", extra={"event_fields": dict(step=5, title="Semantic Classifier")})
            if (
                self.semantic is not None
                and remaining_categories
                and not any(marker in transformation for marker in self._SEMANTIC_EXCLUDED_MARKERS)
                and not self._RAW_ENCODING_SHAPE.search(text)
            ):
                findings.extend(
                    self.semantic.evaluate_view(
                        segment,
                        transformation,
                        text,
                        remaining_categories,
                        no_rule_match=not rule_categories,
                    )
                )
            else:
                logger.info("detection.semantic_skipped", extra={"event_fields": dict(reason="classifier_unavailable_or_explicit_rules_only"
                    if self.semantic is None
                    else "all_rule_categories_already_detected", categories=remaining_categories)})
            logger.info("story.step_completed", extra={"event_fields": dict(step=5, title="Semantic Classifier", next_step="encoded/indirect modifiers and context analysis")})
        findings.extend(self.fuzzy.scan(segment, get_rule_overrides()))
        # First-class indirect-injection detection: AI-directed directives in
        # external or hidden-channel content (user text never matches).
        findings.extend(self.indirect.scan(segment))
        # Encoded-instruction promotion (differential rule): evidence that only
        # exists in a decoded/obfuscated view becomes encoded_instruction.
        modifiers = self.encoded.scan(findings, segment)
        for finding in findings:
            if segment.source != "user" and finding.severity >= 0.5:
                logger.info("detection.modifier_selected", extra={"event_fields": dict(category="indirect_injection", layer="context", rule_id="modifiers-v0.1/external-malicious-instruction", triggered_by_category=finding.category, transformation=finding.transformation, reason="external source")})
                modifiers.append(
                    finding.model_copy(
                        update={
                            "category": "indirect_injection",
                            "layer": "context",
                            "rule_id": "modifiers-v0.1/external-malicious-instruction",
                        }
                    )
                )
        unique = {}
        for finding in findings + modifiers:
            key = (finding.category, finding.source_id, finding.locator)
            if key not in unique or finding.severity > unique[key].severity:
                unique[key] = finding
        result = list(unique.values())
        log_categories(result)
        logger.debug("detection.segment_completed", extra={"event_fields": dict(source=segment.source, finding_count=len(result), layer_counts={
                layer: sum(finding.layer == layer for finding in result)
                for layer in ("rule", "semantic", "context")
            }, attacks=sorted({finding.category for finding in result if finding.severity >= 0.5}))})
        return result

    def scan_context(self, previous: list[str], current: str) -> list[Finding]:
        return self.context.scan(previous, current)


def detect(segment: Segment, classifier: LocalClassifier | None = None) -> list[Finding]:
    token = source_context.set(
        {
            **(source_context.get() or {}),
            "source_id": segment.source_id,
            "source": segment.source,
            "locator": content_preview(segment.locator),
        }
    )
    try:
        return DetectionEngine(classifier).scan_segment(segment)
    finally:
        source_context.reset(token)
