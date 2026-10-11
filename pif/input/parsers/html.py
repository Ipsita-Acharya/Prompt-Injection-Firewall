"""HTML parser (Phase 2): raw source, rendered visible text, and hidden-content
forensics. Payloads hidden from rendering (display:none, visibility:hidden,
font-size:0, opacity:0, white/transparent color, off-screen positioning) and
HTML comments are extracted as their OWN segments so detection and policy see
their provenance instead of the payload silently riding inside the rendered
text."""

import re

from bs4 import BeautifulSoup, Comment, Tag

from pif.input.base import TextFormatParser
from pif.observability import content_preview, logger

# Bounded forensics: a page with thousands of hidden nodes must not explode
# the segment count or the extraction budget.
_MAX_HIDDEN_SEGMENTS = 48
_MAX_COMMENT_SEGMENTS = 24
_MAX_PAYLOAD_CHARS = 20_000

# Inline declarations that remove content from the rendered page. The payload
# behind any of these is exactly the indirect-injection channel RULE-021's
# hidden-text branch targets.
_HIDDEN_DECLARATIONS = (
    ("display", re.compile(r"display\s*:\s*none", re.I)),
    ("visibility", re.compile(r"visibility\s*:\s*hidden", re.I)),
    ("zero_size", re.compile(r"font(?:-size)?\s*:\s*0(?:\.0+)?(?:px|pt|em|%)?(?![\d.])", re.I)),
    ("transparent", re.compile(r"opacity\s*:\s*0(?:\.0+)?(?![\d.])", re.I)),
    ("invisible_ink", re.compile(r"color\s*:\s*(?:#fff(?:fff)?\b|white\b|transparent\b)", re.I)),
    ("off_screen", re.compile(r"(?:left|text-indent)\s*:\s*-\d{3,}px", re.I)),
)

# Selectors inside <style> blocks whose declarations hide content: the parser
# maps simple `.class` / `#id` selectors back onto matching elements.
_STYLE_RULE = re.compile(r"([^{}]{1,200})\{([^}]{1,500})\}", re.S)
_SELECTOR_TOKEN = re.compile(r"[.#][A-Za-z_][\w-]*")


def _hiding_reason(declarations: str) -> str | None:
    for reason, pattern in _HIDDEN_DECLARATIONS:
        if pattern.search(declarations):
            return reason
    return None


def _element_matches_tokens(element: Tag, tokens: list[str]) -> bool:
    classes = set(element.get("class") or [])
    element_id = element.get("id") or ""
    for token in tokens:
        if token.startswith(".") and token[1:] in classes:
            return True
        if token.startswith("#") and token[1:] == element_id:
            return True
    return False


def _hidden_from_style_blocks(soup: BeautifulSoup, captured: set[int]) -> list[tuple[str, str]]:
    """Class/id-hidden payloads: declarations inside <style> blocks cannot be
    seen on the element's own style attribute, so hiding rules are matched
    back onto elements by their class/id tokens. Elements already captured by
    an inline style (or nested inside one) are skipped: their payload is
    already extracted and they must not appear twice."""
    hidden: list[tuple[str, str]] = []
    for style_tag in soup.find_all("style"):
        declarations_source = style_tag.string or style_tag.get_text() or ""
        for selector_text, declarations in _STYLE_RULE.findall(declarations_source):
            reason = _hiding_reason(declarations)
            if reason is None:
                continue
            tokens = _SELECTOR_TOKEN.findall(selector_text)
            if not tokens:
                continue
            for element in soup.find_all(True):
                if len(hidden) >= _MAX_HIDDEN_SEGMENTS:
                    return hidden
                if element.name == "style":
                    continue
                if any(ancestor_id in captured for ancestor_id in (id(element), *[id(node) for node in element.parents])):
                    continue
                if _element_matches_tokens(element, tokens):
                    payload = element.get_text(" ").strip()
                    if payload:
                        hidden.append((f"hidden_css:{reason}:{len(hidden) + 1}", payload[:_MAX_PAYLOAD_CHARS]))
                        captured.add(id(element))
                        element.decompose()
    return hidden


class HtmlParser(TextFormatParser):
    format_name = "html"

    def parsed_segments(self, text: str) -> list[tuple[str, str]]:
        soup = BeautifulSoup(text, "html.parser")
        hidden: list[tuple[str, str]] = []
        # Inline style hiding first (the direct forensic pass), then class/id
        # selectors hidden from <style> blocks. Elements already captured by
        # their style attribute are not captured twice.
        inline_hidden = []
        for element in soup.find_all(True):
            if len(inline_hidden) >= _MAX_HIDDEN_SEGMENTS:
                break
            reason = _hiding_reason(element.get("style") or "")
            if reason is None:
                continue
            payload = element.get_text(" ").strip()
            if payload:
                inline_hidden.append((element, f"hidden_css:{reason}:{len(inline_hidden) + 1}", payload[:_MAX_PAYLOAD_CHARS]))
        hidden.extend((locator, payload) for _element, locator, payload in inline_hidden)
        captured = {id(element) for element, _locator, _payload in inline_hidden}
        inline_hidden_elements = [element for element, _locator, _payload in inline_hidden]
        for element in inline_hidden_elements:
            element.decompose()
        hidden.extend(_hidden_from_style_blocks(soup, captured))
        # Hidden payloads leave the rendered view: get_text() on the full soup
        # includes display:none text, which misrepresents what a reader sees
        # and lets the payload ride into benign content unseen.
        visible = soup.get_text(" ")
        result = [("visible", visible)]
        result.extend(hidden)
        comment_count = 0
        for comment_node in soup.find_all(string=lambda value: isinstance(value, Comment)):
            if comment_count >= _MAX_COMMENT_SEGMENTS:
                break
            payload = str(comment_node).strip()
            if not payload:
                continue
            comment_count += 1
            result.append((f"comment:{comment_count}", payload[:_MAX_PAYLOAD_CHARS]))
        if hidden or comment_count:
            logger.info("html.hidden_forensics", extra={"event_fields": dict(hidden_segment_count=len(hidden), comment_segment_count=comment_count, hidden_locators=[locator for locator, _payload in hidden[:8]], hidden_previews=[content_preview(payload) for _locator, payload in hidden[:4]])})
        return result
