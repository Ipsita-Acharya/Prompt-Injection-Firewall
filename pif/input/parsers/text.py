"""Text and source-code parser (Phase 2): raw segments for .txt/.py/.js/... .
Code files are inspected as text; no source-specific extraction applies."""

from pif.input.base import TextFormatParser


class TextParser(TextFormatParser):
    format_name = "text"

    def parsed_segments(self, text: str) -> list[tuple[str, str]]:
        return []
