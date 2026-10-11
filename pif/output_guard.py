"""Output-side leak guard (v6.1): the third checkpoint.

Input scanning and the taint gate protect what goes INTO the agent; this
module inspects what comes OUT. Outbound agent text is checked for
credential-shaped secrets (API keys, bearer tokens, private-key blocks,
password assignments) and for detonation canaries — a canary in outbound
text is proof the content drove a real leak, regardless of what any
classifier concluded about it.

The guard only reports; the caller decides (withhold, redact, or deny).
"""

import re

from pif.observability import content_preview, logger

LEAK_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        "api_key",
        re.compile(
            r"\b(?:sk[-_][A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{12,}|xox[bp]-[A-Za-z0-9-]{16,})\b"
        ),
    ),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "credential_assignment",
        re.compile(
            # Optional closing quote between key and separator: matches JSON
            # ("password": "value"), YAML (password: value) and env
            # (password=value) shapes alike.
            r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b[\"']?\s*[:=]\s*"
            r"[\"']?[^\s'\"]{8,}",
            re.I,
        ),
    ),
)


def scan_output_leaks(text: str, canaries: dict | None = None) -> list[dict]:
    """Return the leak records found in outbound text. Evidence is withheld
    (kind only) so the guard's own report cannot become the exfil channel."""
    leaks: list[dict] = []
    for kind, pattern in LEAK_PATTERNS:
        match = pattern.search(text or "")
        if match:
            leaks.append({"kind": kind, "matched_chars": len(match.group())})
    for slot, canary in (canaries or {}).items():
        if canary and canary.casefold() in (text or "").casefold():
            leaks.append({"kind": f"canary_leak:{slot}"})
    if leaks:
        logger.info("output_guard.leak_detected", extra={"event_fields": dict(kinds=[leak["kind"] for leak in leaks], preview=content_preview(text))})
    return leaks
