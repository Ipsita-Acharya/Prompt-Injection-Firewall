"""Context detector (Layer C, spec §11): multi-turn conversation sequence
analysis — alias-then-extract and bypass-then-extract composition patterns,
cross-turn fragment assembly (split payloads), variable-assignment payload
splitting (SS-SPLIT), short-window re-scan (SS-CONCAT), trigger-word setup
and crescendo escalation (v6.0)."""

import re

from pif.observability import content_preview, logger
from pif.schemas import Finding, Segment


def _fragment_assembly_findings(previous: list[str], current: str) -> list[Finding]:
    """Split payloads distribute an attack phrase across turns as quoted
    fragments ("'IGN'", "'ORE PRE'", "'VIOUS'"); no single turn matches any
    rule. The fragments are joined in conversation order and the assembled
    text is scanned through the rule layer — the assembly itself is the
    signal."""
    fragments: list[str] = []
    turns_with_fragments = 0
    for turn in [*previous, current]:
        found = [
            a or b
            for a, b in re.findall(r'"([^"\n]{2,40})"|\x27([^\x27\n]{2,40})\x27', turn)
        ]
        if found:
            turns_with_fragments += 1
        fragments.extend(found)
        if len(fragments) >= 16:
            break
    # Assembly is only meaningful across turns: a single turn with quoted
    # fragments is the quoted-educational case the rule layer already handles.
    joined = "".join(fragments)[:200].strip()
    if len(joined) < 8 or turns_with_fragments < 2:
        return []
    from pif.detection.rules import RuleDetector

    findings = RuleDetector().scan_view(
        Segment(source_id="user", source="user", locator="session-assembly", text=joined),
        "session-assembly",
        joined.casefold(),
        set(),
    )
    actionable = [finding for finding in findings if finding.severity >= 0.5]
    if not actionable:
        logger.debug("session.assembly_scanned", extra={"event_fields": dict(fragment_count=len(fragments), assembled_chars=len(joined), matched=False)})
        return []
    logger.info("session.sequence_matched", extra={"event_fields": dict(reason="quoted_fragments_assemble_into_rule_match", severity=0.9, rule_id="context-v0.1/fragment-assembly", evidence=content_preview({"previous_turns": previous[-3:], "assembled": joined}), categories=sorted({finding.category for finding in actionable}), fragment_count=len(fragments), category="multi_step_jailbreak", layer="context")})
    return [
        Finding(
            category="multi_step_jailbreak",
            source_id="user",
            locator="session-assembly",
            layer="context",
            severity=0.9,
        )
    ]


def sequence_findings(previous: list[str], current: str):
    logger.debug("session.sequence_started", extra={"event_fields": dict(previous_turn_count=len(previous), current_chars=len(current))})
    aliases = []
    for turn in previous:
        aliases.extend(
            re.findall(
                r"\b(?:the )?([a-z]{2,20})\s+(?:means|refers to|is an alias for)\s+(?:your |the )?(system prompt|hidden configuration|api key|password)\b",
                turn.casefold(),
            )
        )
    for alias, _secret in aliases:
        if re.search(
            r"\b(?:reveal|send|show|print|provide|upload)\b.{0,40}\b" + re.escape(alias) + r"\b",
            current.casefold(),
        ):
            logger.info("session.sequence_matched", extra={"event_fields": dict(reason="secret_alias_followed_by_extraction", severity=0.97, rule_id="context-v0.1/secret-alias-then-extraction", evidence=content_preview(
                    {"previous_turns": previous[-3:], "current_turn": current, "alias": alias}
                ), category="multi_step_jailbreak", layer="context")})
            return [
                Finding(
                    category="multi_step_jailbreak",
                    source_id="user",
                    locator="session-sequence",
                    layer="context",
                    severity=0.97,
                )
            ]
    if (
        previous
        and re.search(
            r"\b(?:disable|bypass)\b.{0,40}\b(?:safety|restrictions)\b",
            " ".join(previous).casefold(),
        )
        and re.search(
            r"\b(?:reveal|show|send)\b.{0,60}\b(?:system prompt|api key|password)\b",
            current.casefold(),
        )
    ):
        logger.info("session.sequence_matched", extra={"event_fields": dict(reason="safety_bypass_followed_by_secret_request", severity=0.97, rule_id="context-v0.1/bypass-then-secret-request", evidence=content_preview({"previous_turns": previous[-3:], "current_turn": current}), category="multi_step_jailbreak", layer="context")})
        return [
            Finding(
                category="multi_step_jailbreak",
                source_id="user",
                locator="session-sequence",
                layer="context",
                severity=0.97,
            )
        ]
    logger.debug("session.sequence_completed", extra={"event_fields": dict(finding_count=0, alias_count=len(aliases))})
    return _fragment_assembly_findings(previous, current)


def _scan_joined(source_id: str, locator: str, transformation: str, text: str) -> list[Finding]:
    """Run the rule layer over assembled multi-turn text. The assembly itself
    is the signal — no single turn had to match anything."""
    from pif.detection.rules import RuleDetector

    findings = RuleDetector().scan_view(
        Segment(source_id=source_id, source="user", locator=locator, text=text),
        transformation,
        text.casefold(),
        set(),
    )
    return [finding for finding in findings if finding.severity >= 0.5]


# var=value / var: value assignments ("x1 = Ignore", "code2: all previous")
# collected across turns: the payload arrives in fragments disguised as data.
# The value runs to end-of-line so multi-word fragments survive intact.
_ASSIGNMENT = re.compile(r"\b([A-Za-z][\w-]{0,30})\s*[:=]\s*([^\n:]{2,120})")
_MAX_ASSIGNMENTS = 24


# URL schemes must never read as assignment names ("https://..." is an
# address, not "the variable https holds the value //...").
_SCHEME_NAMES = frozenset({"http", "https", "ftp", "mailto", "file", "ws", "wss"})


def _assignment_values(turns: list[str]) -> list[str]:
    values: list[str] = []
    for turn in turns:
        for name, value in _ASSIGNMENT.findall(turn):
            if name.casefold() in _SCHEME_NAMES:
                continue
            # Nested-assignment-looking values are kept on purpose: the join
            # is only evidence when the rule layer matches inside it, so junk
            # fragments ride along harmlessly while payload fragments count.
            value = value.strip().strip("\"'")
            if value and not value.isdecimal():
                values.append(value)
            if len(values) >= _MAX_ASSIGNMENTS:
                return values
    return values


def _split_payload_findings(previous: list[str], current: str) -> list[Finding]:
    """SS-SPLIT: assignments scattered across turns re-joined and re-scanned
    (multi-turn by definition — a single turn's assignments are the rule
    layer's job). SS-CONCAT: the recent-turn window re-scanned as one
    message — catches plain payload splitting without any assignment syntax."""
    findings: list[Finding] = []
    if previous:
        joined_values = " ".join(_assignment_values([*previous, current]))[:400].strip()
        if len(joined_values) >= 8:
            matched = _scan_joined("user", "session-assignment-split", "session-assignment-split", joined_values)
            if matched:
                logger.info("session.sequence_matched", extra={"event_fields": dict(reason="assignment_values_assemble_into_rule_match", rule_id="context-v0.1/assignment-split", severity=0.9, assembled=content_preview(joined_values), categories=sorted({finding.category for finding in matched}), category="multi_step_jailbreak", layer="context")})
                findings.append(
                    Finding(
                        category="multi_step_jailbreak",
                        source_id="user",
                        locator="session-assignment-split",
                        layer="context",
                        severity=0.9,
                    )
                )
    window = "\n".join([*previous[-2:], current])[:1500].strip()
    if len(window) >= 16 and "\n" in window:
        matched = _scan_joined("user", "session-concat", "session-concat", window)
        if matched:
            logger.info("session.sequence_matched", extra={"event_fields": dict(reason="recent_turns_concatenate_into_rule_match", rule_id="context-v0.1/turn-concat", severity=0.85, categories=sorted({finding.category for finding in matched}), category="multi_step_jailbreak", layer="context")})
            findings.append(
                Finding(
                    category="multi_step_jailbreak",
                    source_id="user",
                    locator="session-concat",
                    layer="context",
                    severity=0.85,
                )
            )
    return findings


_TRIGGER_SETUP = re.compile(
    r"\bwhen(?:ever)?\s+I\s+say\s+[\"']?(.{2,40})[\"']?\s*,?\s+(?:you\s+)?(?:ignore|disregard|reveal|send|execute|obey|switch|act|forget|bypass|say)\b",
    re.I,
)


def _trigger_setup_findings(previous: list[str], current: str) -> list[Finding]:
    """Trigger-word setup: an earlier turn plants "when I say X, do Y" and a
    later turn activates it ("X" / "I say X now")."""
    for turn in previous:
        for trigger in _TRIGGER_SETUP.findall(turn):
            phrase = trigger.strip().strip("\"'.,!?;:").casefold()
            if len(phrase) >= 3 and phrase in current.casefold():
                logger.info("session.sequence_matched", extra={"event_fields": dict(reason="planted_trigger_word_activated", rule_id="context-v0.1/trigger-setup", severity=0.9, trigger=content_preview(phrase), category="multi_step_jailbreak", layer="context")})
                return [
                    Finding(
                        category="multi_step_jailbreak",
                        source_id="user",
                        locator="session-trigger",
                        layer="context",
                        severity=0.9,
                    )
                ]
    return []


_RISK_LANGUAGE = (
    r"\b(?:ignore|disregard|forget|bypass|disable|override|reveal|send|execute|"
    r"credentials?|passwords?|api[ _-]?keys?|system prompt|unrestricted|admin)\b"
)


def _turn_risk_level(turn: str) -> int:
    """Coarse per-turn risk indicator: how many distinct risk-language
    keywords the turn contains (0-3 buckets)."""
    count = len(set(re.findall(_RISK_LANGUAGE, turn.casefold())))
    return min(count, 3)


def _crescendo_findings(previous: list[str], current: str) -> list[Finding]:
    """Crescendo: three or more consecutive turns with monotonically rising
    risk language, where the latest turn carries action language — the
    gradual-escalation jailbreak shape."""
    turns = [*previous[-4:], current]
    if len(turns) < 3:
        return []
    levels = [_turn_risk_level(turn) for turn in turns]
    # Strictly rising risk language across the window with the final turn at
    # or above the previous peak — the gradual-escalation shape. A plateau on
    # the final strike turn still counts; a flat or dipping window does not.
    tail = levels[-3:]
    if not (tail[0] < tail[1] <= tail[2] and tail[2] >= 2):
        return []
    if not re.search(_RISK_LANGUAGE, turns[-1].casefold()):
        return []
    logger.info("session.sequence_matched", extra={"event_fields": dict(reason="monotonic_multi_turn_escalation", rule_id="context-v0.1/crescendo", severity=0.85, levels=levels, category="multi_step_jailbreak", layer="context")})
    return [
        Finding(
            category="multi_step_jailbreak",
            source_id="user",
            locator="session-crescendo",
            layer="context",
            severity=0.85,
        )
    ]


class ContextDetector:
    """Layer C: evaluates the current prompt against conversation history and
    external content composition rather than isolated sentences."""

    name = "context"

    def scan(self, previous: list[str], current: str) -> list[Finding]:
        findings = sequence_findings(previous, current)
        seen = {(finding.category, finding.locator) for finding in findings}
        for candidate in [
            *_split_payload_findings(previous, current),
            *_trigger_setup_findings(previous, current),
            *_crescendo_findings(previous, current),
        ]:
            key = (candidate.category, candidate.locator)
            if key not in seen:
                seen.add(key)
                findings.append(candidate)
        return findings
