"""Shared parser-layer primitives: errors, decoding, archive validation and the
common parser interface (spec §7: file processing with a shared contract)."""

import io
import logging
import zipfile
from abc import ABC

from pif.observability import content_preview, logger


class InspectionError(ValueError):
    """Raised for any input-processing failure; every failure is fail-closed."""


def decode_text(data: bytes) -> str:
    logger.debug("text.decoding_started", extra={"event_fields": dict(byte_count=len(data))})
    try:
        text = (
            data.decode("utf-16")
            if data.startswith((b"\xff\xfe", b"\xfe\xff"))
            else data.decode("utf-8-sig")
        )
    except UnicodeError as error:
        raise InspectionError("unsupported_text_encoding") from error
    if "\x00" in text or any(ord(char) < 32 and char not in "\n\r\t\f" for char in text):
        raise InspectionError("ambiguous_binary_content")
    logger.debug("text.decoding_completed", extra={"event_fields": dict(encoding="utf-16-bom" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig", output_chars=len(text))})
    return text


def check_zip(data: bytes, settings=None):
    entry_limit = getattr(settings, "zip_entry_limit", None) or 100
    uncompressed_limit = getattr(settings, "docx_max_uncompressed_bytes", None) or 50 * 1024 * 1024
    expansion_limit = getattr(settings, "zip_expansion_limit", None) or 100
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
        logger.debug("archive.checked", extra={"event_fields": dict(entry_count=len(entries), uncompressed_bytes=sum(entry.file_size for entry in entries))})
        if len(entries) > entry_limit or sum(entry.file_size for entry in entries) > uncompressed_limit:
            raise InspectionError("archive_budget_exceeded")
        for entry in entries:
            if entry.flag_bits & 1 or entry.file_size / max(entry.compress_size, 1) > expansion_limit:
                raise InspectionError("archive_encrypted_or_expansion_limit")
        names = {entry.filename for entry in entries}
        if not {"[Content_Types].xml", "word/document.xml"}.issubset(names):
            raise InspectionError("unsupported_archive")
        if any("vbaProject" in name or name.startswith("word/embeddings/") for name in names):
            raise InspectionError("docx_embedded_content_unsupported")
        return archive
    except zipfile.BadZipFile as error:
        raise InspectionError("invalid_archive") from error


class Parser(ABC):
    """Common parser interface: every file format parser implements parse()."""

    format_name: str = ""

    def parse(self, data: bytes, name: str, declared: str, settings, budget: dict, dispatcher, depth: int = 0):
        """Return (locator, text) segments extracted from raw file bytes."""
        raise NotImplementedError


class TextFormatParser(Parser):
    """Parsers operating on decoded text (html, json, markdown, text/code).

    Subclasses implement parsed_segments(); the template wraps the parsed
    output with the raw segment and enforces the segment-count limit exactly
    as the original text_segments() helper did."""

    def parse_text(self, text: str, settings=None) -> list[tuple[str, str]]:
        segment_limit = getattr(settings, "max_extracted_segments", None) or 2000
        logger.debug("text.parser_started", extra={"event_fields": dict(format=self.format_name, input_chars=len(text), input_text=content_preview(text))})
        result = [("raw", text)]
        result.extend(self.parsed_segments(text))
        if len(result) > segment_limit:
            raise InspectionError("segment_count_limit")
        logger.debug("text.parser_completed", extra={"event_fields": dict(format=self.format_name, segment_count=len(result), extracted_chars=sum(len(value) for _locator, value in result))})
        return result

    def parsed_segments(self, text: str) -> list[tuple[str, str]]:
        return []

    def parse(self, data: bytes, name: str, declared: str, settings, budget: dict, dispatcher, depth: int = 0):
        return self.parse_text(decode_text(data))
