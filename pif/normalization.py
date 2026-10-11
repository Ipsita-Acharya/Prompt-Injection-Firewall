import base64
import binascii
import codecs
from difflib import SequenceMatcher
import html
import logging
import re
import unicodedata
from urllib.parse import unquote

from pif.input import InspectionError
from pif.observability import content_preview, logger

CONFUSABLES = str.maketrans(
    {
        # Cyrillic homoglyphs
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
        "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0458": "j",
        "\u04bb": "h", "\u0443": "y", "\u0501": "d", "\u043d": "h",
        "\u043a": "k", "\u043c": "m", "\u0442": "t", "\u0432": "b",
        # Greek homoglyphs
        "\u03bf": "o", "\u03b9": "i", "\u03c5": "u", "\u03b1": "a",
        "\u03b5": "e", "\u03c1": "p", "\u03c4": "t", "\u03c7": "x",
        "\u03ba": "k", "\u03bd": "v", "\u03c3": "s", "\u03c2": "s",
        "\u03c9": "w", "\u03b3": "g",
        # Latin phonetic / small-cap lookalikes
        "\u0261": "g", "\u0131": "i", "\u0299": "b", "\u1d04": "c",
        "\u1d05": "d", "\u1d07": "e", "\ua730": "f", "\u0262": "g",
        "\u029c": "h", "\u026a": "i", "\u1d0a": "j", "\u1d0b": "k",
        "\u029f": "l", "\u1d0d": "m", "\u0274": "n", "\u1d0f": "o",
        "\u1d18": "p", "\u0280": "r", "\u017f": "s", "\u1d1b": "t",
        "\u1d1c": "u", "\u1d20": "v", "\u1d21": "w", "\u028f": "y",
        "\u1d22": "z", "\u1d00": "a",
        # Additional lookalikes
        "\u2113": "l", "\u2c60": "l",
        # Stroke / hooked letters that Unicode does NOT decompose into the base
        # letter (accented forms like e or i are handled by the combining-mark
        # strip; these need explicit mapping): Ign|o|re, previ|o|us ...
        "\u00f8": "o", "\u0275": "o", "\u01a1": "o",
        "\u0268": "i",
        "\u0455": "s", "\u0282": "s", "\u023f": "s", "\u0292": "s",
        "\u0111": "d", "\u00f0": "d", "\u0257": "d",
        "\u0142": "l", "\u019a": "l",
        "\u0127": "h",
        "\u0167": "t", "\u01ab": "t",
        "\u0259": "e", "\u01dd": "e", "\u024b": "e",
        "\u0180": "b", "\u0183": "b",
        "\u0192": "f",
        "\u0260": "g", "\u01e5": "g",
        "\u0272": "n", "\u014b": "n", "\u0273": "n", "\u019e": "n",
        "\u01a5": "p",
        "\u024d": "r",
        "\u0289": "u", "\u028a": "u",
        "\u028b": "v", "\u0475": "v",
        "\u01b3": "y",
        "\u01b6": "z",
        "\u0249": "j",
        "\u0188": "c",
        "\u0138": "k",
    }
)

# OCR/leetspeak substitutions applied in a dedicated "leet" view so legitimate
# text containing digits is never silently rewritten by the canonical form.
LEET = str.maketrans(
    {
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
        "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
        "!": "i", "+": "t", "|": "l", "\u00a3": "l", "\u20ac": "e",
    }
)

# Combining marks and format characters are stripped from every canonical view:
# this neutralizes combining overlays (I̷g̷n̷o̷r̷e̷), zero-width/invisible
# characters, bidirectional overrides and accents in one pass while the original
# text is preserved untouched.
_STRIP_CATEGORIES = {"Mn", "Cf"}

# Word-level fuzzy vocabulary (spec section 9: word fragments, obfuscated
# variants). The "fuzzy-words" view maps unknown tokens to their closest
# vocabulary word (SequenceMatcher ratio >= 0.75, length-aware) so a transposed,
# inserted or deleted letter inside an attack word -- Ignroe, Requset, Tlel,
# Beocme, SYTSEM -- still lets the rule engine match in that view. The original
# text is never modified; only the additional view is scanned.
WORD_VOCAB = frozenset({
    "ignore", "disregard", "forget", "override", "previous", "prior", "above",
    "instructions", "prompts", "rules", "task", "reveal", "show", "print",
    "tell", "provide", "expose", "leak", "return", "give", "share", "hand",
    "password", "passwords", "keys", "tokens", "credentials", "bearer",
    "secrets", "steal", "extract", "upload", "exfiltrate", "send", "delete",
    "wipe", "remove", "files", "filesystem", "database", "backups", "execute",
    "shell", "command", "email", "higher", "system", "prompt", "hidden",
    "configuration", "private", "confidential", "first", "then", "next",
    "step", "disable", "bypass", "safety", "unrestricted", "unfiltered",
    "uncensored", "restrictions", "administrator", "admin", "message",
    "notice", "update", "obey", "priority", "supersedes", "document",
    "become", "switch", "pretend", "hacker", "request", "demand",
})
WORD_FUZZY_THRESHOLD = 0.75
_PUNCT_STRIP = ".,!?;:()\"'"


def _fuzzy_words(value: str, vocab: frozenset) -> str:
    out = []
    for token in value.split(" "):
        core = token.strip(_PUNCT_STRIP)
        # Tokens that are already vocabulary words are correct as they stand;
        # rewriting them to longer inflections would break literal rule matches.
        if len(core) >= 4 and core.isalpha() and core not in vocab:
            best, best_ratio = core, 0.0
            for word in vocab:
                if abs(len(word) - len(core)) > 2:
                    continue
                ratio = SequenceMatcher(None, core, word).ratio()
                if ratio > best_ratio:
                    best, best_ratio = word, ratio
            if best_ratio >= WORD_FUZZY_THRESHOLD and best != core:
                out.append(token.replace(core, best))
                continue
        out.append(token)
    return " ".join(out)


def canonical(text: str) -> str:
    # NFKC first (fullwidth, math alphabets), casefold, then decompose so
    # combining marks (accents, overlays) can be stripped, and only then map
    # stroke/hook homoglyphs -- the ordering lets decomposed-then-stripped
    # forms (e.g. U+01FF -> U+00F8) hit the confusables table as well.
    text = unicodedata.normalize("NFKC", html.unescape(text)).casefold()
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(
        char for char in decomposed if unicodedata.category(char) not in _STRIP_CATEGORIES
    )
    return stripped.translate(CONFUSABLES)


def readable(text: str) -> bool:
    return (
        bool(text.strip())
        and sum(char.isprintable() or char.isspace() for char in text) / len(text) > 0.95
    )


def normalize(text: str, word_vocab: frozenset | None = None) -> list[tuple[str, str]]:
    logger.info("story.step_started", extra={"event_fields": dict(step=3, title="Text Normalization")})
    logger.info("normalization.original", extra={"event_fields": dict(text=content_preview(text))})
    logger.debug("normalization.started", extra={"event_fields": dict(input_chars=len(text))})
    views, queue, seen = [], [("canonical", text, 0)], set()
    work = 0
    while queue:
        transformation, raw, depth = queue.pop(0)
        value = canonical(raw)
        collapsed = re.sub(r"\s+", " ", value).strip()
        if collapsed in seen:
            continue
        seen.add(collapsed)
        views.append((transformation, collapsed))
        logger.debug("normalization.view_created", extra={"event_fields": dict(transformation=transformation, decode_depth=depth, output_chars=len(collapsed), steps=[
                "HTML entity decoding",
                "Unicode NFKC",
                "case folding",
                "selected confusable mapping",
                "invisible character removal",
                "whitespace collapse",
                transformation,
            ])})
        logger.debug("normalization.result", extra={"event_fields": dict(transformation=transformation, text=content_preview(collapsed), changed_from_original=collapsed != text)})
        work += len(collapsed)
        if len(views) > 32 or work > 1_000_000:
            logger.warning("normalization.budget_rejected", extra={"event_fields": dict(view_count=len(views), processed_chars=work)})
            raise InspectionError("normalization_budget_exceeded")
        spaced = re.sub(
            r"\b(?:[a-z][ \t]){2,}[a-z]\b", lambda match: re.sub(r"[ \t]", "", match.group()), value
        )
        if spaced != value:
            queue.append((transformation + "/spaced", spaced, depth))
        if depth >= 2 or transformation.endswith("/reversed"):
            # Reversed views are scanned but terminal: expanding decoder
            # candidates from them re-decodes already-decoded fragments and
            # can exhaust the view budget (fail-closed) on letter-spaced text.
            continue
        candidates = []
        if html.unescape(raw) != raw:
            candidates.append(("html-entity", html.unescape(raw)))
        if re.search(r"%[0-9a-fA-F]{2}", raw):
            try:
                candidates.append(("percent", unquote(raw, errors="strict")))
            except (UnicodeError, ValueError):
                pass
        if re.search(r"\\u[0-9a-fA-F]{4}", raw):
            candidates.append(
                (
                    "unicode-escape",
                    re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), raw),
                )
            )
        for match in re.finditer(
            r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])", raw
        ):
            try:
                token = match.group()
                decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode(
                    "utf-8"
                )
                candidates.append(("base64", decoded))
            except (UnicodeError, binascii.Error):
                pass
        for match in re.finditer(r"\b(?:[0-9a-fA-F]{2}){12,}\b", raw):
            try:
                candidates.append(("hex", bytes.fromhex(match.group()).decode("utf-8")))
            except (ValueError, UnicodeError):
                pass
        for match in re.finditer(r"\b[A-Za-z2-7]{16,}={0,6}\b", raw):
            try:
                token = match.group()
                decoded = base64.b32decode(token + "=" * (-len(token) % 8), casefold=True).decode("utf-8")
                candidates.append(("base32", decoded))
            except (UnicodeError, ValueError, binascii.Error):
                pass
        codes = [int(code) for code in re.findall(r"(?<!\S)(\d{2,3})(?!\S)", raw)]
        if len(codes) >= 5 and all(32 <= code <= 126 for code in codes):
            candidates.append(("ascii-decimal", "".join(chr(code) for code in codes)))
        # Transliteration candidates: leetspeak/OCR substitutions, separator
        # splitting (i.g.n.o.r.e) and ROT13-style rotations. ROT13 is only
        # worthwhile when the rotated text reads like natural language (vowel
        # ratio ~35-45%); rotating plain text yields vowel-starved gibberish
        # (~25%) that would only waste scan budget.
        leeted = collapsed.translate(LEET)
        if leeted != collapsed and re.search(r"[a-z]", leeted):
            candidates.append(("leet", leeted))
        if re.search(r"[a-z][._\-~*]{1,3}[a-z]", collapsed):
            candidates.append(("separators", re.sub(r"[._\-~*]+", "", collapsed)))
        if sum(char.isalpha() for char in raw) >= 6:
            rotated = codecs.encode(raw, "rot13")
            letters = sum(char.isalpha() for char in rotated)
            folded = rotated.casefold()
            vowels = sum(char in "aeiou" for char in folded)
            if 0.24 <= vowels / letters <= 0.62:
                candidates.append(("rot13", rotated))
        # Letter counts are order-invariant, so the vowel band gates the
        # reversed view: natural-language text reversed by an attacker keeps
        # its vowel ratio, while reversing benign text only wastes a view the
        # rules will not match. Generated from the canonical view only — like
        # fuzzy-words, per-view candidates multiply into budget exhaustion.
        if transformation == "canonical" and sum(char.isalpha() for char in raw) >= 6:
            alpha = sum(char.isalpha() for char in raw)
            raw_vowels = sum(char in "aeiou" for char in raw.casefold())
            if 0.24 <= raw_vowels / alpha <= 0.62:
                candidates.append(("reversed", raw[::-1]))
        # Fuzzy-word repair runs on the canonical view only: deriving it from
        # every decoded view multiplies views (budget fail-closed) while the
        # decoded attack text already matches the rules directly.
        if transformation == "canonical":
            fuzzy = _fuzzy_words(collapsed, word_vocab or WORD_VOCAB)
            if fuzzy != collapsed:
                candidates.append(("fuzzy-words", fuzzy))
            # Unicode tag characters (U+E0000-U+E007F) smuggle ASCII past the
            # canonical view, which strips format characters entirely: decode
            # the tag range back to its letters so the rules can match it.
            tag_codes = [
                ord(char) - 0xE0000
                for char in raw
                if 0xE0000 <= ord(char) < 0xE007F and 32 <= ord(char) - 0xE0000 <= 126
            ]
            if len(tag_codes) >= 4:
                candidates.append(("unicode-tags", "".join(chr(code) for code in tag_codes)))
        if len(candidates) > 32:
            logger.warning("normalization.candidates_rejected", extra={"event_fields": dict(candidate_count=len(candidates))})
            raise InspectionError("decoding_candidate_limit")
        for encoding, decoded in candidates:
            if readable(decoded):
                queue.append((transformation + "/" + encoding, decoded, depth + 1))
    logger.debug("normalization.completed", extra={"event_fields": dict(view_count=len(views), transformations=[transformation for transformation, _text in views])})
    logger.info("story.step_completed", extra={"event_fields": dict(step=3, title="Text Normalization", view_count=len(views), next_step="rule-based detection")})
    return views
