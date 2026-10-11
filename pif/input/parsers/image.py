"""Image parser (Phase 2): metadata-forensics text extraction + OCR.

Hidden injection channels that need no OCR are always extracted: PNG tEXt/
iTXt/zTXt text chunks, JPEG COM/app-segment comments and GIF comment blocks.
When Tesseract is available (and OCR is enabled) the pixel text is extracted
on top; when it is not, the parser degrades to metadata-only with an explicit
warning instead of failing every image scan fail-closed — the same no-key
degraded-mode posture the gray-band LLM judge uses.
"""

import io
import struct

from pif.input.base import InspectionError, Parser
from pif.observability import logger


_MAX_METADATA_CHARS = 100_000


def _png_text_chunks(data: bytes) -> list[tuple[str, str]]:
    """tEXt/iTXt/zTXt chunks straight from the byte stream (no image decode)."""
    out = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return out
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        if chunk_type == b"tEXt" and b"\x00" in payload:
            key, _, text = payload.partition(b"\x00")
            out.append((f"png_text:{key.decode('latin-1', 'replace')[:40]}", text.decode("latin-1", "replace")))
        elif chunk_type == b"iTXt" and b"\x00" in payload:
            key, _, rest = payload.partition(b"\x00")
            # keyword\0 compression-flag\0 compression-method\0 language\0 translated\0 text
            parts = rest.split(b"\x00", 3)
            text = parts[3] if len(parts) == 4 else b""
            out.append((f"png_text:{key.decode('latin-1', 'replace')[:40]}", text.decode("latin-1", "replace")))
        elif chunk_type == b"zTXt" and b"\x00" in payload:
            import zlib
            key, _, rest = payload.partition(b"\x00")
            try:
                out.append((f"png_text:{key.decode('latin-1', 'replace')[:40]}", zlib.decompress(rest[1:]).decode("latin-1", "replace")))
            except (ValueError, zlib.error):
                pass
        if chunk_type == b"IEND":
            break
        offset += 12 + length
    return out


def _jpeg_comments(data: bytes) -> list[tuple[str, str]]:
    out = []
    if not data.startswith(b"\xff\xd8"):
        return out
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        segment = data[offset + 4:offset + 2 + length]
        if marker == 0xFE:  # COM
            out.append(("jpeg_comment", segment.decode("latin-1", "replace")))
        elif marker == 0xDA:  # start of scan: entropy-coded data follows
            break
        offset += 2 + length
    return out


def _gif_comments(data: bytes) -> list[tuple[str, str]]:
    out = []
    if not data.startswith((b"GIF87a", b"GIF89a")):
        return out
    offset, block = 13, b""
    while offset < len(data):
        intro = data[offset]
        if intro == 0x21 and offset + 2 < len(data) and data[offset + 1] == 0xFE:  # comment extension
            offset += 2
            while offset < len(data):
                size = data[offset]
                if size == 0:
                    offset += 1
                    break
                block += data[offset + 1:offset + 1 + size]
                offset += 1 + size
        elif intro == 0x3B:
            break
        else:
            # not a section we walk; stop — forensic value is in comments only
            break
    if block:
        out.append(("gif_comment", block.decode("latin-1", "replace")))
    return out


def _ocr_available() -> bool:
    import shutil

    return shutil.which("tesseract") is not None


class ImageParser(Parser):
    format_name = "image"

    def parse(self, data: bytes, name: str, declared: str, settings, budget: dict, dispatcher, depth: int = 0):
        import warnings

        from PIL import Image

        segments = _png_text_chunks(data) + _jpeg_comments(data) + _gif_comments(data)
        extracted = sum(len(text) for _loc, text in segments)
        if extracted > _MAX_METADATA_CHARS:
            raise InspectionError("extracted_text_limit")
        if not settings.ocr_enabled:
            logger.info("image.metadata_only", extra={"event_fields": dict(reason="ocr_disabled", metadata_chars=extracted, segment_count=len(segments))})
            return segments
        if not _ocr_available():
            # Degraded mode: pixel text cannot be extracted without Tesseract,
            # but metadata channels are still inspected (the same no-key
            # degraded-mode posture the gray-band LLM judge uses).
            logger.info("image.metadata_only", extra={"event_fields": dict(reason="ocr_unavailable", metadata_chars=extracted, segment_count=len(segments))})
            return segments
        Image.MAX_IMAGE_PIXELS = settings.image_pixel_limit
        from pif.input.ocr import ocr_image

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                if probe.width * probe.height > settings.image_pixel_limit or getattr(probe, "n_frames", 1) != 1:
                    raise InspectionError("image_size_or_frame_limit")
        segments.append(("ocr", ocr_image(data, settings)))
        return segments
