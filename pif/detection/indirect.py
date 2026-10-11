"""Indirect-injection detector (spec §9 category 9): first-class detection of
AI-directed directives arriving through content the user did not author —
web pages, documents, email bodies, tool results — and through hidden-content
channels (CSS-hidden payloads, white/tiny PDF text, DOCX vanish runs, faint
OCR, comments). Directives typed by the user are the user's own intent and
are handled by the rule layer instead."""

import re

from pif.observability import content_preview, logger
from pif.risk import HIDDEN_LOCATOR_PREFIXES
from pif.schemas import Finding, Segment

# Educational-quoted matches drop to the same 0.2 severity the rule layer
# uses, so documentation quoting the pattern is not actioned on.
_QUOTED_SUPPRESSION = 0.2
_MAX_SPANS = 16

# (rule id, severity, pattern, reason) — evaluated with re.I over the raw
# segment text so spans map back onto the original for span redaction.
PATTERNS: list[tuple[str, float, str, str]] = [
    (
        "IIND-001",
        0.85,
        r"\b(?:hey\s+)?(?:AI|A\.I\.|assistant|chatbot|agent|LLM|GPT|Copilot)\s*[,.:!?\-\u2014]+\s*(?:you\s+(?:are|must|should|need\s+to)|please\s+)?(?:now\s+)?(?:ignore|disregard|forget|override|reveal|expose|send|upload|visit|open|execute|download|delete|disable|follow)\b",
        "AI-addressed override directive in external content",
    ),
    (
        "IIND-002",
        0.8,
        r"\b(?:when|after|before)\s+(?:summarizing|summarising|reading|processing|analy[sz]ing|reviewing|translating|rendering|consuming)\s+(?:this|the)\s+(?:page|document|article|text|content|email|post)\b.{0,200}\b(?:state|say|mention|recommend|claim|tell|include|assert|insert|add|visit|link|provide|output)\b",
        "conditional directive to the reading model",
    ),
    (
        "IIND-003",
        0.8,
        r"\b(?:pass|forward|relay|convey|read\s+out)\s+(?:this\s+)?(?:message|note|text|instruction)s?\s+to\s+(?:the\s+)?(?:AI|assistant|model|agent|chatbot|user)\b",
        "content instructs relay of a hidden message",
    ),
    (
        "IIND-004",
        0.75,
        r"\b(?:admin|administrator|system|security|support|IT)\s+(?:note|message|directive|memo|announcement|update)\s*:",
        "forged authority note inside content",
    ),
]


def _quoted_educational(text: str, start: int, end: int) -> bool:
    from pif.detection.rules import quoted_example

    return quoted_example(text, start, end)


class IndirectDetector:
    """Detects directives addressed to the AI inside untrusted content. A
    finding requires untrusted provenance: the segment source is external
    (file/web/rag/tool/api/ocr) or the payload arrived over a hidden-content
    channel. User-authored text never matches here."""

    name = "indirect"

    def _untrusted(self, segment: Segment) -> bool:
        return segment.source != "user" or segment.locator.startswith(HIDDEN_LOCATOR_PREFIXES)

    def scan(self, segment: Segment) -> list[Finding]:
        if not self._untrusted(segment) or not segment.text:
            return []
        findings: list[Finding] = []
        for rule_id, severity, pattern, reason in PATTERNS:
            matches = list(re.finditer(pattern, segment.text, re.I))
            if not matches:
                continue
            educational = all(
                _quoted_educational(segment.text, match.start(), match.end())
                for match in matches
            )
            effective = _QUOTED_SUPPRESSION if educational else severity
            spans = (
                []
                if educational
                else [
                    [match.start(), match.end()]
                    for match in re.finditer(pattern, segment.text, re.I | re.S)
                ][:_MAX_SPANS]
            )
            logger.info("detection.indirect_matched", extra={"event_fields": dict(rule_id=rule_id, severity=effective, match_count=len(matches), quoted_educational=educational, source=segment.source, locator=content_preview(segment.locator), reason=reason)})
            findings.append(
                Finding(
                    category="indirect_injection",
                    rule_id=rule_id,
                    source_id=segment.source_id,
                    # A per-rule locator suffix keeps this finding visible
                    # next to the source-relabel copy under the dedup key
                    # (category, source_id, locator) instead of being hidden
                    # behind it.
                    locator=f"{segment.locator}/iind:{rule_id}",
                    layer="rule",
                    transformation="canonical",
                    severity=effective,
                    spans=spans,
                )
            )
        return findings
