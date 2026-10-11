"""Input Processing Layer (Phase 2).

Owns everything between the request schema and the normalization engine:
file-type identification, the sandboxed parser-worker pool, the format parser
registry and segment assembly with fail-closed budgets."""

import base64
import binascii
import logging
import multiprocessing
import threading
import time

from pif.input.base import InspectionError, decode_text
from pif.input.identify import EXTENSIONS, MIMES, identify
from pif.input.ocr import ocr_image
from pif.input.parsers import PARSERS
from pif.observability import (
    capture_fields,
    content_preview,
    logger,
    relay_worker_event,
    request_context,
    scan_context,
    set_diagnostics,
    source_context,
)
from pif.schemas import ScanRequest, Segment
from pif.settings import Settings

__all__ = [
    "InspectionError",
    "Processor",
    "extract_file",
    "identify",
    "decode_text",
    "ocr_image",
    "EXTENSIONS",
    "MIMES",
    "PARSERS",
]


def _log_segment_capture(segment: Segment):
    """Full-content capture of one extracted segment (log_content opt-in):
    the BEFORE snapshot of what normalization and detection will receive."""
    logger.info("input.segment_captured", extra={"event_fields": dict(source_id=segment.source_id, source=segment.source, locator=segment.locator, text=content_preview(segment.text))})


def extract_file(data: bytes, name: str, declared: str, settings: Settings, depth=0, budget=None):
    budget = budget if budget is not None else {"bytes": 0, "parts": 0}
    budget["bytes"] += len(data)
    budget["parts"] += 1
    if depth > getattr(settings, "attachment_max_depth", 2) or budget["bytes"] > settings.max_bytes or budget["parts"] > 30:
        raise InspectionError("attachment_budget_exceeded")
    kind = identify(data, name, declared)
    logger.info("file.parser_selected", extra={"event_fields": dict(parser=kind, attachment_depth=depth, cumulative_bytes=budget["bytes"])})
    result = PARSERS[kind].parse(
        data, name, declared, settings, budget, dispatcher=extract_file, depth=depth
    )
    if len(result) > getattr(settings, "max_extracted_segments", 2000) or sum(len(text) for _, text in result) > settings.max_chars:
        raise InspectionError("extracted_text_limit")
    logger.info("file.parser_completed", extra={"event_fields": dict(parser=kind, segment_count=len(result), extracted_chars=sum(len(text) for _locator, text in result))})
    return result


class _PipeHandler(logging.Handler):
    """Child-process handler: forwards every record to the parent over the
    parser pipe, with the child-side attribution captured at emit time."""

    def __init__(self, connection):
        super().__init__(level=logging.DEBUG)
        self.connection = connection

    def emit(self, record):
        try:
            fields = capture_fields(record)
            self.connection.send(
                ("event", record.levelno, record.getMessage(), dict(fields), record.created)
            )
        except Exception:
            self.handleError(record)


def _worker(connection, data, name, declared, settings, scan_id, request_id, source_details):
    scan_context.set(scan_id)
    request_context.set(request_id)
    source_context.set(source_details)
    set_diagnostics(settings)
    logger.addHandler(_PipeHandler(connection))
    logger.setLevel(getattr(logging, settings.log_level))
    try:
        logger.info("parser.worker_started", extra={"event_fields": dict(byte_count=len(data))})
        result = extract_file(data, name, declared, settings)
        logger.info("parser.worker_completed", extra={"event_fields": dict(segment_count=len(result))})
        connection.send(("result", True, result))
    except InspectionError as error:
        logger.warning("parser.worker_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        connection.send(("result", False, str(error)))
    except Exception:
        logger.error("parser.worker_failed", extra={"event_fields": dict(reason="parser_failed")})
        connection.send(("result", False, "parser_failed"))
    finally:
        connection.close()


class Processor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.slots = threading.BoundedSemaphore(settings.parser_concurrency)

    def parse(self, data: bytes, name: str, declared: str):
        if not self.slots.acquire(blocking=False):
            raise InspectionError("parser_capacity_exceeded")
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(
            target=_worker,
            args=(
                child,
                data,
                name,
                declared,
                self.settings,
                scan_context.get(),
                request_context.get(),
                source_context.get(),
            ),
            daemon=True,
        )
        try:
            process.start()
            logger.info("parser.worker_dispatched", extra={"event_fields": dict(worker_process_id=process.pid, timeout_seconds=self.settings.parser_timeout)})
            child.close()
            deadline = time.monotonic() + self.settings.parser_timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not parent.poll(remaining):
                    logger.warning("parser.worker_timeout", extra={"event_fields": dict()})
                    raise InspectionError("parser_timeout")
                try:
                    message = parent.recv()
                except EOFError as error:
                    raise InspectionError("parser_worker_failed") from error
                if message[0] == "event":
                    relay_worker_event(*message[1:])
                    continue
                _kind, success, result = message
                if not success:
                    raise InspectionError(result)
                return result
        finally:
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join()
                process.close()
            parent.close()
            child.close()
            self.slots.release()

    def process(self, request: ScanRequest):
        logger.info("input.received", extra={"event_fields": dict(prompt_chars=len(request.user_prompt), file_count=len(request.files), content_count=len(request.content))})
        segments = [
            Segment(source_id="user", source="user", locator="prompt", text=request.user_prompt)
        ]
        _log_segment_capture(segments[0])
        warnings, total_bytes = [], 0
        deadline = time.monotonic() + 60
        for index, item in enumerate(request.files):
            source_id = f"file:{index}"
            started = time.perf_counter()
            source_token = source_context.set(
                {
                    "source_id": source_id,
                    "source": "file",
                    "file_index": index,
                    "file_name": content_preview(item.name),
                }
            )
            logger.info("file.extraction_started", extra={"event_fields": dict(file_index=index, declared_mime=content_preview(item.type), byte_payload_supplied=True)})
            try:
                if time.monotonic() >= deadline:
                    raise InspectionError("request_extraction_deadline")
                data = base64.b64decode(item.data_base64, validate=True)
                total_bytes += len(data)
                if total_bytes > self.settings.max_bytes:
                    raise InspectionError("file_bytes_limit")
                parts = self.parse(data, item.name, item.type)
                segments.extend(
                    Segment(source_id=source_id, source="file", locator=locator, text=text)
                    for locator, text in parts
                )
                for segment in segments[len(segments) - len(parts):]:
                    _log_segment_capture(segment)
                logger.info("file.extraction_completed", extra={"event_fields": dict(file_index=index, decoded_bytes=len(data), segment_count=len(parts), extracted_chars=sum(len(text) for _locator, text in parts), attachment_validation="file bytes parsed successfully", genuine_attachment=bool(data), next_step="normalized text inspection", duration_ms=round((time.perf_counter() - started) * 1000, 3))})
            except (InspectionError, binascii.Error, ValueError) as error:
                code = str(error) if isinstance(error, InspectionError) else "invalid_file_base64"
                warnings.append(f"{source_id}:{code}")
                reason = code.split(":", 1)[0]
                safe_reasons = {
                    "file_type_mismatch",
                    "unsupported_file_type",
                    "unsupported_archive",
                    "archive_budget_exceeded",
                    "archive_encrypted_or_expansion_limit",
                    "parser_timeout",
                    "parser_failed",
                    "parser_worker_failed",
                    "parser_capacity_exceeded",
                    "ocr_not_enabled",
                    "ocr_unavailable",
                    "image_size_or_frame_limit",
                    "invalid_file_base64",
                    "file_bytes_limit",
                    "extracted_text_limit",
                    "request_extraction_deadline",
                    "scanned_empty_or_image_pdf_requires_ocr",
                    "docx_images_require_ocr",
                }
                logger.warning("file.extraction_failed", extra={"event_fields": dict(file_index=index, reason=reason if reason in safe_reasons else "inspection_failed", duration_ms=round((time.perf_counter() - started) * 1000, 3))})
            finally:
                source_context.reset(source_token)
        for index, item in enumerate(request.content):
            try:
                source = item.source if item.source != "user" else "rag"
                logger.info("content.received", extra={"event_fields": dict(content_index=index, source=source, format=item.format, input_chars=len(item.text))})
                parts = PARSERS[item.format].parse_text(item.text, self.settings)
                segments.extend(
                    Segment(source_id=f"content:{index}", source=source, locator=locator, text=text)
                    for locator, text in parts
                )
                for segment in segments[len(segments) - len(parts):]:
                    _log_segment_capture(segment)
            except (ValueError, RecursionError):
                warnings.append(f"content:{index}:invalid_structured_content")
                logger.warning("content.extraction_failed", extra={"event_fields": dict(content_index=index, reason="invalid_structured_content")})
        if (
            len(segments) > 2000
            or sum(len(segment.text) for segment in segments) > self.settings.max_chars
        ):
            raise InspectionError("total_extracted_text_limit")
        try:
            for segment in segments:
                segment.text.encode("utf-8")
        except UnicodeError as error:
            raise InspectionError("invalid_extracted_unicode") from error
        logger.info("input.processing_completed", extra={"event_fields": dict(segment_count=len(segments), warning_count=len(warnings), next_stage="normalization")})
        return segments, warnings
