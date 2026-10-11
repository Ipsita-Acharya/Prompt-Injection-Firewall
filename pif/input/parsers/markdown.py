"""Markdown parser (Phase 2): block-token extraction via markdown-it."""

from markdown_it import MarkdownIt

from pif.input.base import TextFormatParser


class MarkdownParser(TextFormatParser):
    format_name = "markdown"

    def parsed_segments(self, text: str) -> list[tuple[str, str]]:
        return [
            (f"block:{index}", token.content)
            for index, token in enumerate(MarkdownIt().parse(text))
            if token.content
        ]
