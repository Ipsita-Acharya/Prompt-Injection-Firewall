"""File-type identification (Phase 2): extension vs magic bytes vs declared MIME."""

import json
import re
from pathlib import PurePath

from pif.input.base import InspectionError, check_zip, decode_text
from pif.observability import content_preview, logger

EXTENSIONS = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".eml": "email",
    ".md": "markdown",
    ".markdown": "markdown",
    ".txt": "text",
    ".py": "text",
    ".js": "text",
    ".ts": "text",
    ".java": "text",
    ".c": "text",
    ".cpp": "text",
    ".cs": "text",
    ".xml": "text",
    ".csv": "text",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
}
MIMES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "text/html": "html",
    "application/json": "json",
    "message/rfc822": "email",
    "text/markdown": "markdown",
    "text/plain": "text",
    "text/csv": "text",
    "text/xml": "text",
    "application/xml": "text",
    "image/png": "image",
    "image/jpeg": "image",
    "image/gif": "image",
    "image/webp": "image",
}


def identify(data: bytes, name: str, declared: str) -> str:
    extension = PurePath(name).suffix.lower()
    logger.debug("file.type_check_started", extra={"event_fields": dict(file_name=content_preview(name), byte_count=len(data), extension=extension or None, attachment_bytes_received=True, non_empty_attachment=bool(data))})
    expected = EXTENSIONS.get(extension)
    mime = declared.split(";", 1)[0].strip().lower()
    signature, method = None, "magic_bytes"
    if data.startswith(b"%PDF-"):
        actual = "pdf"
        signature = data[:5].hex(" ").upper()
    elif data.startswith(b"PK"):
        with check_zip(data):
            actual = "docx"
        signature = data[:4].hex(" ").upper()
    elif data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")) or (
        data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    ):
        actual = "image"
        signature = data[:12].hex(" ").upper()
    else:
        text = decode_text(data)
        method = "text_structure"
        stripped = text.lstrip()
        if re.match(
            r"(?:<!doctype\s+html\b|<(?:html|head|body|p|div|h[1-6]|table|span|script)\b)",
            stripped,
            re.I,
        ):
            actual = "html"
            signature = stripped[:9].encode("utf-8").hex(" ").upper()
        elif stripped.startswith(("{", "[")):
            try:
                json.loads(text)
            except (ValueError, RecursionError) as error:
                raise InspectionError("invalid_json_structure") from error
            actual = "json"
        elif re.match(r"(?:from|to|subject|mime-version|content-type):", stripped, re.I):
            actual = "email"
        else:
            actual = "markdown" if expected == "markdown" or mime == "text/markdown" else "text"
            method = "text_encoding_and_format_hint" if actual == "markdown" else "text_encoding"
    declared_kind = MIMES.get(mime)
    logger.info("file.type_identified", extra={"event_fields": dict(extension=extension or None, expected=expected, detected=actual, signature_hex=signature, identification_method=method, signature_is_universal=method == "magic_bytes", next_step="compare detected type with extension and declared MIME")})
    if (extension and expected is None) or (
        mime not in MIMES and mime != "application/octet-stream"
    ):
        raise InspectionError("unsupported_file_type")
    if (expected is not None and expected != actual) or (
        declared_kind is not None and declared_kind != actual
    ):
        logger.warning("file.type_mismatch", extra={"event_fields": dict(expected=expected, detected=actual, declared=declared_kind, signature_hex=signature, validation_result="mismatch")})
        raise InspectionError(f"file_type_mismatch:expected={expected},detected={actual}")
    if actual == "image":
        image_type = (
            "image/png"
            if data.startswith(b"\x89PNG")
            else "image/jpeg"
            if data.startswith(b"\xff\xd8")
            else "image/gif"
            if data.startswith(b"GIF")
            else "image/webp"
        )
        extension_mime = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".webp": "image/webp",
        }.get(extension)
        if (extension_mime is not None and image_type != extension_mime) or (
            mime != "application/octet-stream" and mime != image_type
        ):
            raise InspectionError("file_type_mismatch:image_signature")
    logger.info("file.type_check_completed", extra={"event_fields": dict(expected=expected, detected=actual, declared=declared_kind or "unspecified", extension=extension or None, signature_hex=signature, validation_result="type_verified; parser validation still required", next_step=f"{actual} parser")})
    return actual
