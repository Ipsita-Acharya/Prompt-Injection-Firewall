"""OCR extraction (Phase 2): image text via Tesseract, with hard limits."""

import io

from pif.input.base import InspectionError
from pif.observability import content_preview, logger


def ocr_image(data: bytes, settings=None) -> str:
    pixel_limit = getattr(settings, "image_pixel_limit", None) or 20_000_000
    logger.info("ocr.started", extra={"event_fields": dict(byte_count=len(data))})
    import warnings

    import pytesseract
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = 20_000_000
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as image:
            logger.debug("ocr.image_checked", extra={"event_fields": dict(width=image.width, height=image.height, frame_count=getattr(image, "n_frames", 1))})
            if image.width * image.height > pixel_limit or getattr(image, "n_frames", 1) != 1:
                raise InspectionError("image_size_or_frame_limit")
            output = pytesseract.image_to_data(
                image, output_type=pytesseract.Output.DICT, timeout=10
            )
    words = [
        (word, float(confidence))
        for word, confidence in zip(output["text"], output["conf"], strict=True)
        if word.strip()
    ]
    if not words or min(confidence for _, confidence in words) < 60:
        raise InspectionError("ocr_empty_or_low_confidence")
    text = " ".join(word for word, _ in words)
    logger.info("ocr.completed", extra={"event_fields": dict(word_count=len(words), extracted_chars=len(text))})
    logger.info("ocr.text_captured", extra={"event_fields": dict(word_count=len(words), text=content_preview(text))})
    return text


def faint_text_ocr(data: bytes, exclude: set[str] | None = None, settings=None) -> str:
    """Second OCR pass over a background-binarized image (hidden-forensics
    layer): text rendered near the background color (white-on-white, light
    gray, watermark payloads) often escapes the normal pass. Every pixel that
    differs from the dominant background becomes ink, and only words the
    normal pass did NOT already report come back. Raises the same limits as
    ocr_image; callers treat failure as "no faint text", never as a scan
    failure — the normal pass already succeeded by the time this runs."""
    logger.info("ocr.faint_started", extra={"event_fields": dict(byte_count=len(data))})
    import warnings

    import pytesseract
    from PIL import Image

    exclude = {word.casefold() for word in (exclude or set())}
    pixel_limit = getattr(settings, "image_pixel_limit", None) or 20_000_000
    Image.MAX_IMAGE_PIXELS = pixel_limit
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > pixel_limit or getattr(image, "n_frames", 1) != 1:
                raise InspectionError("image_size_or_frame_limit")
            gray = image.convert("L")
    histogram = gray.histogram()
    background = max(range(256), key=lambda level: histogram[level])
    binary = gray.point(lambda level: 0 if abs(level - background) > 2 else 255)
    output = pytesseract.image_to_data(binary, output_type=pytesseract.Output.DICT, timeout=10)
    words = [
        word.strip()
        for word, confidence in zip(output["text"], output["conf"], strict=True)
        if word.strip() and float(confidence) >= 60
    ]
    faint = [
        word
        for word in words
        if word.casefold() not in exclude and sum(char.isalnum() for char in word) >= 3
    ]
    logger.info("ocr.faint_completed", extra={"event_fields": dict(word_count=len(words), faint_word_count=len(faint), background_level=background, faint_text=content_preview(" ".join(faint)))})
    return " ".join(faint)
