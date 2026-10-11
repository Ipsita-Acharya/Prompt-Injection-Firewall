"""Risk Correlation / Decision Fusion Engine — the fourth detection layer.

Combines evidence from the rule, semantic and context layers with obfuscation
and source-trust signals into a single fused risk score instead of a naive
max-severity decision. Every contribution is reported so the final risk is
explainable (spec: rule/semantic/context/obfuscation evidence, category,
source trust, confidence).
"""

import logging
from dataclasses import dataclass, field

from pif.observability import logger
from pif.schemas import Finding

# Categories with irreversible side effects always force the hard-block path.
HARD_BLOCK_CATEGORIES = frozenset({"credential_theft", "tool_abuse"})

# Hidden-content channels (locator provenance from the parser forensics):
# a payload the attacker deliberately hid from human readers — CSS-hidden
# HTML, white/tiny/off-page PDF text, DOCX vanish runs, faint OCR — is
# stronger evidence than one typed in the open, so it scales the fused score.
HIDDEN_LOCATOR_PREFIXES = (
    "hidden_css:",
    "comment:",
    "pdf_white:",
    "pdf_tiny:",
    "pdf_offpage:",
    "pdf_render_diff:",
    "docx_hidden:",
    "ocr_faint:",
)

DEFAULT_WEIGHTS = {
    "layer_agreement": 1.08,
    "obfuscation": 1.06,
    "external_source": 1.10,
    "multi_category": 1.04,
    "hidden_content": 1.10,
}

_EXTERNAL_PREFIXES = ("file:", "content:", "web:", "rag:", "tool:", "api:", "ocr:")


@dataclass
class RiskAssessment:
    risk: float
    hard_block: bool
    contributions: list[dict] = field(default_factory=list)
    factors: dict = field(default_factory=dict)


def correlate(
    findings: list[Finding],
    hard_threshold: float = 0.95,
    weights: dict | None = None,
) -> RiskAssessment:
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    actionable = [finding for finding in findings if finding.severity >= 0.5]
    if not actionable:
        return RiskAssessment(risk=0.0, hard_block=False, contributions=[], factors=dict(weights))

    by_category: dict[str, list[Finding]] = {}
    for finding in actionable:
        by_category.setdefault(finding.category, []).append(finding)

    contributions = []
    fused = 0.0
    for category, group in sorted(by_category.items()):
        base = max(finding.severity for finding in group)
        layers = sorted({item.layer for item in group})
        factor = 1.0
        signals = []
        if "rule" in layers and "semantic" in layers:
            factor *= weights["layer_agreement"]
            signals.append("layer_agreement")
        if any(
            finding.transformation != "canonical" or finding.category == "encoded_instruction"
            for finding in group
        ):
            factor *= weights["obfuscation"]
            signals.append("obfuscation")
        if any(finding.source_id.startswith(_EXTERNAL_PREFIXES) for finding in group):
            factor *= weights["external_source"]
            signals.append("external_source")
        if any(
            finding.locator.startswith(HIDDEN_LOCATOR_PREFIXES) for finding in group
        ):
            factor *= weights["hidden_content"]
            signals.append("hidden_content")
        score = min(1.0, base * factor)
        contributions.append(
            {
                "category": category,
                "category_id": group[0].category_id,
                "detection_ids": sorted({finding.rule_id for finding in group if finding.rule_id}),
                "base": base,
                "factor": round(factor, 3),
                "fused": round(score, 4),
                "signals": signals,
                "layers": layers,
            }
        )
        fused = max(fused, score)

    if len(by_category) > 1:
        fused = min(1.0, fused * weights["multi_category"] ** (len(by_category) - 1))

    hard_block = fused >= hard_threshold or any(
        category in HARD_BLOCK_CATEGORIES for category in by_category
    )
    assessment = RiskAssessment(
        risk=round(fused, 4),
        hard_block=hard_block,
        contributions=contributions,
        factors=dict(weights),
    )
    logger.debug("risk.correlated", extra={"event_fields": dict(fused_risk=assessment.risk, hard_block=hard_block, category_count=len(contributions), contributions=contributions)})
    return assessment
