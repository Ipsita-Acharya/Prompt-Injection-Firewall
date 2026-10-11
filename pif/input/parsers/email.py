"""Email parser (Phase 2): RFC822 multipart recursion with nested-attachment
dispatch back into the extraction pipeline."""

from email import policy
from email.parser import BytesParser

from pif.input.base import InspectionError, Parser, decode_text
from pif.observability import content_preview, logger


class EmailParser(Parser):
    format_name = "email"

    def parse(self, data: bytes, name: str, declared: str, settings, budget: dict, dispatcher, depth: int = 0):
        message = BytesParser(policy=policy.default).parsebytes(data)
        if message.defects:
            raise InspectionError("malformed_email")
        result = []

        def visit_email(part, part_depth=0):
            budget["parts"] += 1
            index = budget["parts"]
            headers = "\n".join(f"{key}: {value}" for key, value in part.items())
            logger.debug("email.part_started", extra={"event_fields": dict(part_index=index, depth=depth + part_depth, multipart=part.is_multipart(), attachment=bool(part.get_filename()), headers=content_preview(headers))})
            if index > 30 or depth + part_depth > 2 or part.defects:
                raise InspectionError("email_part_limit_or_defect")
            result.append(
                (
                    f"part:{index}/headers",
                    headers,
                )
            )
            if part.is_multipart():
                for child in part.get_payload():
                    visit_email(child, part_depth + 1)
                return
            payload = part.get_payload(decode=True)
            if payload is None:
                raise InspectionError("email_part_unreadable")
            mime = part.get_content_type()
            filename = part.get_filename()
            if filename:
                nested = dispatcher(
                    payload, filename, mime, settings, depth + part_depth + 1, budget
                )
            elif mime in {"text/plain", "text/html"}:
                from pif.input.parsers.html import HtmlParser
                from pif.input.parsers.text import TextParser

                nested = (HtmlParser() if mime == "text/html" else TextParser()).parse_text(
                    decode_text(payload)
                )
            else:
                raise InspectionError("email_part_unsupported")
            result.extend((f"part:{index}/{locator}", text) for locator, text in nested)

        visit_email(message)
        return result
