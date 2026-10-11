"""PDF parser (Phase 2): pypdf extraction with per-page OCR fallback and
active-content rejection, plus hidden-content forensics — white text (char
fill color), sub-2pt text, off-page text and render-vs-text-layer differences
are extracted as their own segments so detection sees the provenance. Every
piece of captured content is logged (page text, annotation text, metadata,
catalog state) so a missed detection can be analyzed from the logs alone;
content fields go through content_preview() and honor the PIF_LOG_CONTENT
opt-in."""

import io
import re

from pif.input.base import InspectionError, Parser
from pif.input.ocr import faint_text_ocr, ocr_image
from pif.observability import content_preview, logger

# Forensics budgets: a hostile PDF must not explode extraction time.
_MAX_TRIAGE_CHARS = 200_000
_MAX_HIDDEN_CHARS = 20_000
# Off-page margin: text placed just outside the visible box is a classic
# injection channel; 36pt tolerates ordinary layout overshoot.
_OFF_PAGE_MARGIN = 36.0


def _resolve(value):
    return value.get_object() if hasattr(value, "get_object") else value


def _is_destination(action) -> bool:
    """True for benign view destinations (page position), False for actions
    that execute behavior when the document opens (JavaScript, Launch, ...)."""
    if isinstance(action, (list, tuple)):
        return True
    if isinstance(action, str):
        return True  # named destination
    if isinstance(action, dict):
        subtype = action.get("/S")
        if subtype == "/GoTo":
            return True
        return subtype is None and "/D" in action
    return False


def _check_annotation(annotation, page_number: int, annotation_index: int) -> str | None:
    """Return safe visible text (URI / contents) from a benign annotation;
    raise InspectionError for executable or unknown action types."""
    annotation = _resolve(annotation)
    if not isinstance(annotation, dict):
        logger.info("pdf.annotation_rejected", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype="unknown", reason="annotation_not_a_dictionary")})
        raise InspectionError("pdf_annotations_unsupported")
    subtype = str(annotation.get("/Subtype", "unknown"))
    if "/AA" in annotation or "/JS" in annotation:
        logger.info("pdf.annotation_rejected", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype=subtype, reason="additional_action_or_javascript")})
        raise InspectionError("pdf_active_or_embedded_content")
    action = _resolve(annotation.get("/A")) if "/A" in annotation else None
    if action is not None:
        if not isinstance(action, dict) or "/JS" in action:
            logger.info("pdf.annotation_rejected", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype=subtype, reason="executable_action")})
            raise InspectionError("pdf_active_or_embedded_content")
        action_subtype = str(action.get("/S", "unknown"))
        if action_subtype not in ("/URI", "/GoTo") and action_subtype != "None":
            logger.info("pdf.annotation_rejected", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype=subtype, reason=f"action_{action_subtype.strip('/').lower()}")})
            raise InspectionError("pdf_active_or_embedded_content")
    text = annotation.get("/Contents") or ""
    uri = action.get("/URI") if isinstance(action, dict) else None
    visible = " ".join(part for part in (str(text), str(uri)) if part) or None
    if visible:
        logger.info("pdf.annotation_captured", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype=subtype, annotation_chars=len(visible), text=content_preview(visible))})
    else:
        logger.debug("pdf.annotation_empty", extra={"event_fields": dict(page_number=page_number, annotation_index=annotation_index, subtype=subtype)})
    return visible


def _device_position(cm, tm) -> tuple[float, float]:
    """Device-space position of the text-showing operation: cm x tm applied
    to the text-space origin (0, 0)."""
    x = cm[0] * tm[4] + cm[2] * tm[5] + cm[4]
    y = cm[1] * tm[4] + cm[3] * tm[5] + cm[5]
    return x, y


def _char_triage(page, page_number: int) -> tuple[str, list[tuple[str, str]]]:
    """pypdf visitor triage: collect text drawn at a sub-2pt font size or
    positioned outside the visible page box (± margin). Both channels hide a
    payload from the reader while leaving it in the text layer for the model
    to read. Returns (page text, hidden segments) from ONE extract pass."""
    box = page.mediabox
    left, right = float(box.left) - _OFF_PAGE_MARGIN, float(box.right) + _OFF_PAGE_MARGIN
    bottom, top = float(box.bottom) - _OFF_PAGE_MARGIN, float(box.top) + _OFF_PAGE_MARGIN
    tiny: list[str] = []
    off_page: list[str] = []

    def visitor(text, cm, tm, font_dict, font_size):
        if not text or not text.strip() or len(tiny) + len(off_page) > 512:
            return
        size = None
        try:
            size = float(font_size) if font_size is not None else None
        except (TypeError, ValueError):
            size = None
        try:
            x, y = _device_position(cm, tm)
        except (TypeError, ValueError, IndexError):
            return
        if size is not None and 0 < size < 2.0:
            tiny.append(text)
        elif not (left <= x <= right and bottom <= y <= top):
            off_page.append(text)

    try:
        text = page.extract_text(visitor_text=visitor) or ""
    except (ValueError, TypeError):
        return "", []
    result = []
    for label, fragments in (("tiny", tiny), ("offpage", off_page)):
        joined = " ".join(fragment.strip() for fragment in fragments if fragment.strip())
        if joined.strip():
            logger.info("pdf.hidden_text_captured", extra={"event_fields": dict(page_number=page_number, channel=label, fragment_count=len(fragments), text=content_preview(joined))})
            result.append((f"pdf_{label}:{page_number}", joined[:_MAX_HIDDEN_CHARS]))
    return text, result


def _is_white_fill(color) -> bool:
    """pdfplumber non_stroking_color forms: scalar, (g,), (r,g,b), (c,m,y,k).
    White/transparent on a white page = every gray/RGB component at the top of
    the range, or a CMYK key with no ink."""
    if color is None:
        return False
    if isinstance(color, (int, float)):
        return color >= 0.95
    if not isinstance(color, (tuple, list)) or not color:
        return False
    values = [float(value) for value in color if isinstance(value, (int, float))]
    if not values:
        return False
    if len(values) == 4:  # CMYK: no ink at all = white
        return all(value <= 0.05 for value in values)
    return all(value >= 0.95 for value in values)


def _white_text_pass(data: bytes, page_number: int) -> str:
    """pdfplumber pass: characters whose fill color matches the page
    background (white-on-white, the most common invisible-ink channel) are
    rejoined into their own payload string. Skipped silently when the optional
    forensics dependency is absent."""
    try:
        import pdfplumber
    except ImportError:
        logger.debug("pdf.forensics_dependency_missing", extra={"event_fields": dict(dependency="pdfplumber", channel="white_text")})
        return ""
    chars = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            if page_number - 1 >= len(pdf.pages):
                return ""
            page_chars = pdf.pages[page_number - 1].chars or []
            for char in page_chars[:_MAX_TRIAGE_CHARS]:
                if _is_white_fill(char.get("non_stroking_color")) and (char.get("text") or "").strip():
                    chars.append(char)
    except Exception as error:  # noqa: BLE001 - forensics must never fail a scan
        logger.debug("pdf.white_text_pass_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        return ""
    if not chars:
        return ""
    # Rejoin the invisible characters in reading order: line by line (top),
    # left to right, with a space on inter-word gaps.
    chars.sort(key=lambda char: (round(char["top"] / 3.0), char["x0"]))
    pieces: list[str] = []
    previous = None
    for char in chars:
        if previous is not None:
            same_line = abs(char["top"] - previous["top"]) <= 3
            gap = char["x0"] - previous["x1"]
            if not same_line:
                pieces.append("\n")
            elif gap > 3:
                pieces.append(" ")
        pieces.append(char["text"])
        previous = char
    joined = "".join(pieces).strip()
    if joined:
        logger.info("pdf.hidden_text_captured", extra={"event_fields": dict(page_number=page_number, channel="white", char_count=len(chars), text=content_preview(joined))})
    return joined[:_MAX_HIDDEN_CHARS]


def _render_diff_words(text_layer: str, ocr_text: str) -> str:
    """Words the render-only OCR sees that the text layer does not: the
    signature of content deliberately kept out of extraction (covered layers,
    tiny/white runs the triage missed)."""
    def words(value: str) -> set[str]:
        return {
            word.casefold()
            for word in re.findall(r"[A-Za-z][A-Za-z0-9']{3,}", value)
        }
    new_words = words(ocr_text) - words(text_layer)
    return " ".join(sorted(new_words))[:_MAX_HIDDEN_CHARS]


class PdfParser(Parser):
    format_name = "pdf"

    def parse(self, data: bytes, name: str, declared: str, settings, budget: dict, dispatcher, depth: int = 0):
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data), strict=True)
        logger.debug("pdf.opened", extra={"event_fields": dict(encrypted=reader.is_encrypted, page_count=None if reader.is_encrypted else len(reader.pages))})
        if reader.is_encrypted or len(reader.pages) > settings.pdf_max_pages:
            raise InspectionError("pdf_encrypted_or_page_limit")
        root = _resolve(reader.trailer["/Root"])
        # /OpenAction is only dangerous when it is an executable action; a plain
        # destination (the common case in real-world documents) is benign.
        open_action = _resolve(root["/OpenAction"]) if "/OpenAction" in root else None
        if open_action is not None and not _is_destination(open_action):
            logger.info("pdf.active_content_rejected", extra={"event_fields": dict(location="OpenAction", reason="executable_open_action")})
            raise InspectionError("pdf_active_or_embedded_content")
        if "/AA" in root or any(
            key in _resolve(root.get("/Names", {})) for key in ("/JavaScript", "/EmbeddedFiles")
        ):
            logger.info("pdf.active_content_rejected", extra={"event_fields": dict(location="catalog", reason="additional_actions_or_javascript_names")})
            raise InspectionError("pdf_active_or_embedded_content")
        logger.info("pdf.catalog_checked", extra={"event_fields": dict(open_action="none" if open_action is None else "destination", catalog_keys=sorted(str(key) for key in root.keys()))})
        result = []
        for index, page in enumerate(reader.pages):
            page = _resolve(page)
            if "/AA" in page:
                raise InspectionError("pdf_annotations_unsupported")
            text, hidden_segments = _char_triage(page, index + 1)
            result.extend(hidden_segments)
            white = _white_text_pass(data, index + 1)
            if white:
                result.append((f"pdf_white:{index + 1}", white))
            # Annotations are scanned individually: link/destination annotations
            # are common in real documents, so only executable ones fail closed,
            # and their visible text joins the page text for detection.
            for annotation_index, annotation in enumerate(page.get("/Annots") or []):
                annotation_text = _check_annotation(annotation, index + 1, annotation_index)
                if annotation_text:
                    text += "\n" + annotation_text
            image_count = len(page.images)
            if not text.strip() or image_count > 0:
                if not settings.ocr_enabled:
                    if not text.strip():
                        # No text layer and no way to inspect image pixels.
                        raise InspectionError("scanned_empty_or_image_pdf_requires_ocr")
                    # A text layer exists but embedded images cannot be
                    # inspected without OCR; refusing the whole page would
                    # suppress detection of its text, so scan the text.
                else:
                    import pypdfium2

                    with pypdfium2.PdfDocument(data) as document:
                        pdf_page = document[index]
                        width, height = pdf_page.get_size()
                        if width * height * 4 > settings.image_pixel_limit:
                            raise InspectionError("pdf_raster_pixel_limit")
                        bitmap = pdf_page.render(scale=2)
                        image = bitmap.to_pil()
                        buffer = io.BytesIO()
                        image.save(buffer, format="PNG")
                        ocr_text = ocr_image(buffer.getvalue(), settings)
                        render_diff = _render_diff_words(text, ocr_text)
                        if render_diff:
                            logger.info("pdf.hidden_text_captured", extra={"event_fields": dict(page_number=index + 1, channel="render_diff", text=content_preview(render_diff))})
                            result.append((f"pdf_render_diff:{index + 1}", render_diff))
                        try:
                            faint = faint_text_ocr(buffer.getvalue(), exclude=set(ocr_text.split()), settings=settings)
                        except InspectionError:
                            faint = ""
                        if faint:
                            logger.info("pdf.hidden_text_captured", extra={"event_fields": dict(page_number=index + 1, channel="faint_ocr", text=content_preview(faint))})
                            result.append((f"ocr_faint:{index + 1}", faint[:_MAX_HIDDEN_CHARS]))
                        text += "\n" + ocr_text
                        bitmap.close()
                        pdf_page.close()
            result.append((f"page:{index + 1}", text))
            logger.info("pdf.page_extracted", extra={"event_fields": dict(page_number=index + 1, locator=f"page:{index + 1}", extracted_chars=len(text), image_count=image_count, ocr_applied=bool(settings.ocr_enabled and (image_count > 0 or not text.strip())), text=content_preview(text))})
        if reader.metadata:
            metadata_text = str(reader.metadata)
            result.append(("metadata", metadata_text))
            logger.info("pdf.metadata_captured", extra={"event_fields": dict(locator="metadata", metadata_chars=len(metadata_text), text=content_preview(metadata_text))})
        return result
