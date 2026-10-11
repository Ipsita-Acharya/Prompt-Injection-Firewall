"""Encoded-instruction detector (spec §9 category 8): owns the promotion of
rule/semantic evidence that exists only in a decoded or obfuscated view to
the encoded_instruction category. The differential rule lives here — evidence
the canonical view already produced is NOT hidden content, so it is never
re-labeled: a payload someone bothered to hide is the attack channel, plain
text that happens to match is not."""

import unicodedata

from pif.normalization import CONFUSABLES
from pif.observability import logger
from pif.schemas import Finding, Segment

# Transformations that mean the finding was produced by a decoded view
# (normalization.py candidate encodings), not by the canonical text.
_ENCODED_TRANSFORMATIONS = (
    "base64",
    "base32",
    "hex",
    "percent",
    "unicode-escape",
    "spaced",
    "rot13",
    "leet",
    "ascii-decimal",
    "reversed",
    "unicode-tags",
    "separators",
    "html-entity",
)

RULE_ID = "modifiers-v0.1/encoded-malicious-instruction"


class EncodedDetector:
    """Post-scan promotion pass: rule/semantic findings that ONLY appear in a
    derived view (or inside an obfuscated-text segment) are re-labeled
    encoded_instruction so the fused risk and the nine-category summary treat
    hidden encodings as their own attack type."""

    name = "encoded"

    def scan(self, findings: list[Finding], segment: Segment) -> list[Finding]:
        # Categories the canonical (unobfuscated) view already matched: a rule
        # matching there and again in a derived view is not evidence of hidden
        # content, so such findings must not earn the encoded-instruction label.
        base_categories = {
            finding.category for finding in findings if finding.transformation == "canonical"
        }
        # Homoglyph/invisible-character smuggling is inherently MIXED-script:
        # an attack spelled with a Cyrillic о inside Latin text. Pure
        # non-Latin text (e.g. an all-Russian sentence) normalizes too, but
        # that is translation, not obfuscation — requiring Latin presence
        # keeps multilingual benign content out of the encoded label
        # (measured: the top benign-FP class on NotInject/jackhhao).
        has_latin = any("a" <= char.casefold() <= "z" for char in segment.text)
        obfuscated_unicode = (
            has_latin
            and (
                unicodedata.normalize("NFKC", segment.text) != segment.text
                or segment.text.translate(CONFUSABLES) != segment.text
                or any(unicodedata.category(char) == "Cf" for char in segment.text)
            )
        )
        modifiers: list[Finding] = []
        for finding in findings:
            if finding.severity < 0.5:
                continue
            if (
                (
                    any(
                        encoding in finding.transformation
                        for encoding in _ENCODED_TRANSFORMATIONS
                    )
                    and finding.category not in base_categories
                )
                or "&#" in segment.text
                or obfuscated_unicode
            ):
                logger.info("detection.modifier_selected", extra={"event_fields": dict(category="encoded_instruction", layer="normalization+evidence", rule_id=RULE_ID, triggered_by_category=finding.category, transformation=finding.transformation, reason="encoded/obfuscated view")})
                modifiers.append(
                    finding.model_copy(
                        update={"category": "encoded_instruction", "rule_id": RULE_ID}
                    )
                )
        return modifiers
