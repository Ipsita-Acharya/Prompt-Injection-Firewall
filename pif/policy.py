import logging
import re

from pif.detection import detect
from pif.observability import content_preview, logger
from pif.schemas import Finding, Segment

DEFAULT_THRESHOLDS = {"sanitize": 0.5, "block": 0.85, "hard_block": 0.95}
DEFAULT_ACTIONS = {"allow": True, "sanitize": True, "block": True, "partial_block": True, "spotlight": True}
# SANITIZE→BLOCK escalation (v6.1): when span redaction removes more than
# this share of the user content, nothing meaningful survives — forwarding
# the residue as "sanitized" would be theater, so the decision escalates.
ESCALATION_REMOVE_RATIO = 0.8
SPOTLIGHT_OPEN = "[PIF-SANITIZED]"
SPOTLIGHT_CLOSE = "[/PIF-SANITIZED]"


def _merge_spans(spans: list[list[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Expand a match span to full sentence boundaries so removal never leaves
    a mid-sentence attack residue like 'obey this document' behind."""
    lead = max([match.end() for match in re.finditer(r"[.!?\n]", text[:start])] or [0])
    trail = re.search(r"[.!?\n]", text[end:])
    end = end + trail.end() if trail else len(text)
    return lead, end


def _redact_user_content(segments: list[Segment], findings: list[Finding]):
    """Spec SANITIZE: remove the malicious instruction from user content while
    preserving legitimate text ("Hi, how are you? Ignore all previous
    instructions." -> "Hi, how are you?"). Returns the redacted segment list, or
    None when span redaction is not applicable (external evidence, non-span
    evidence, or no legitimate residual)."""
    if any(finding.source_id != "user" for finding in findings):
        return None
    by_segment: dict[str, list[list[int]]] = {}
    for finding in findings:
        if not finding.spans:
            return None
        by_segment.setdefault(finding.source_id, []).extend(finding.spans)
    if not by_segment:
        return None
    redacted, removed = [], 0
    original_chars = 0
    for segment in segments:
        if segment.source_id in by_segment:
            text = segment.text
            before = text
            original_chars += len(text)
            bounds = [
                _sentence_bounds(text, start, end)
                for start, end in _merge_spans(by_segment[segment.source_id])
            ]
            for start, end in reversed(bounds):
                text = text[:start] + text[end:]
            text = re.sub(r"\s+", " ", text).strip()
            removed += len(bounds)
            logger.debug("policy.span_redaction", extra={"event_fields": dict(removed_spans=len(bounds), residual_chars=len(text), before_text=content_preview(before), after_text=content_preview(text))})
            if text:
                redacted.append(
                    segment.model_copy(update={"text": text, "locator": f"{segment.locator}/sanitized"})
                )
        else:
            redacted.append(segment)
    residual = " ".join(s.text for s in redacted if s.source_id == "user").strip()
    if not residual or len(residual) < 4:
        return None
    # Escalation: when redaction gutted the content (>80% removed), the
    # honest decision is BLOCK, not a "sanitized" shell.
    if original_chars and 1 - len(residual) / max(original_chars, 1) > ESCALATION_REMOVE_RATIO:
        logger.info("policy.sanitize_escalated", extra={"event_fields": dict(reason="residual_too_small", original_chars=original_chars, residual_chars=len(residual))})
        return None
    return redacted


def neutralize(
    segments: list[Segment],
    findings: list[Finding],
    warnings: list[str],
    classifier=None,
    assessment=None,
    thresholds: dict | None = None,
    actions: dict | None = None,
):
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    actions = {**DEFAULT_ACTIONS, **(actions or {})}
    if assessment is not None:
        risk, hard_block = assessment.risk, assessment.hard_block
    else:
        risk = max((finding.severity for finding in findings), default=0.0)
        hard_block = False
    logger.info("policy.risk_evaluated", extra={"event_fields": dict(risk=risk, high_threshold=thresholds["block"], medium_threshold=thresholds["sanitize"], hard_block=hard_block, inspection_complete=not warnings, finding_count=len(findings))})
    block_decision = "block" if actions.get("block", True) else "isolate"
    if warnings:
        logger.info("policy.block_selected", extra={"event_fields": dict(reason="incomplete_inspection" if actions.get("block", True) else "incomplete_inspection_isolated", forwarded_segments=0)})
        return block_decision, []
    if hard_block or risk >= thresholds["block"]:
        if (
            actions.get("sanitize")
            and actions.get("partial_block", True)
            and not hard_block
        ):
            suspicious = [f for f in findings if f.severity >= thresholds["sanitize"]]
            redacted = _redact_user_content(segments, suspicious)
            if redacted is not None:
                logger.info("policy.rescan_started", extra={"event_fields": dict(remaining_segments=len(redacted))})
                if any(
                    finding.severity >= thresholds["sanitize"]
                    for segment in redacted
                    for finding in detect(segment, classifier)
                ):
                    logger.warning("policy.rescan_failed", extra={"event_fields": dict(reason="suspicious_content_remains_after_redaction")})
                    return block_decision, []
                logger.info("policy.sanitize_selected", extra={"event_fields": dict(reason="user_span_redaction", removed_segments=0, forwarded_segments=len(redacted))})
                if actions.get("spotlight", True):
                    # Survivor spotlighting (v6.1): the downstream agent can
                    # see exactly which content passed the firewall, so a
                    # smuggled residual cannot pose as operator text.
                    redacted = [
                        segment.model_copy(
                            update={"text": f"{SPOTLIGHT_OPEN} {segment.text} {SPOTLIGHT_CLOSE}"}
                        )
                        if segment.locator.endswith("/sanitized")
                        else segment
                        for segment in redacted
                    ]
                return "sanitize", redacted
        logger.info("policy.block_selected", extra={"event_fields": dict(reason="hard_block_category" if hard_block and risk < thresholds["block"] else "high_risk", forwarded_segments=0)})
        return block_decision, []
    suspicious = [finding for finding in findings if finding.severity >= thresholds["sanitize"]]
    if not suspicious:
        logger.info("policy.allow_selected", extra={"event_fields": dict(reason="no_medium_or_high_risk_findings", forwarded_segments=len(segments))})
        return "allow", segments
    source_ids = {finding.source_id for finding in suspicious}
    if "user" in source_ids:
        logger.info("policy.isolate_selected", extra={"event_fields": dict(reason="suspicious_user_intent", forwarded_segments=0)})
        return "isolate", []
    locators = {(finding.source_id, finding.locator) for finding in suspicious}
    known = {(segment.source_id, segment.locator) for segment in segments}
    exact = locators.issubset(known) and all(
        finding.transformation == "canonical" for finding in suspicious
    )
    if exact and actions.get("partial_block", True):
        safe = [
            segment for segment in segments if (segment.source_id, segment.locator) not in locators
        ]
        decision = "sanitize"
        logger.info("policy.sanitize_selected", extra={"event_fields": dict(reason="exact_segment_mapping", removed_segments=len(segments) - len(safe))})
    else:
        safe = [segment for segment in segments if segment.source_id not in source_ids]
        decision = "isolate"
        logger.info("policy.isolate_selected", extra={"event_fields": dict(reason="ambiguous_mapping_quarantines_source"
            if not actions.get("partial_block", True)
            else "ambiguous_mapping_quarantines_source", removed_segments=len(segments) - len(safe))})
    logger.info("policy.rescan_started", extra={"event_fields": dict(remaining_segments=len(safe))})
    if any(finding.severity >= thresholds["sanitize"] for segment in safe for finding in detect(segment, classifier)):
        logger.warning("policy.rescan_failed", extra={"event_fields": dict(reason="suspicious_content_remains")})
        return block_decision, []
    logger.info("policy.rescan_completed", extra={"event_fields": dict(forwarded_segments=len(safe))})
    return decision, safe
