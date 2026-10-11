"""JSON parser (Phase 2): recursive key/value walk with depth limiting."""

import json

from pif.input.base import InspectionError, TextFormatParser


class JsonParser(TextFormatParser):
    format_name = "json"

    def parsed_segments(self, text: str) -> list[tuple[str, str]]:
        document = json.loads(text)
        result: list[tuple[str, str]] = []

        def visit(value, path, depth=0):
            if depth > 32:
                raise InspectionError("json_depth_limit")
            if isinstance(value, dict):
                for index, (key, child) in enumerate(value.items()):
                    result.append((f"{path}/key:{index}", key))
                    visit(child, f"{path}/{index}", depth + 1)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{path}/{index}", depth + 1)
            elif isinstance(value, str):
                result.append((path, value))

        visit(document, "json")
        return result
