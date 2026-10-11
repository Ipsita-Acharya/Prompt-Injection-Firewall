# PIF — Prompt Injection Firewall (v6.0)
FROM python:3.11-slim

# Tesseract for the OCR path (image/scanned-PDF text extraction)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY pif ./pif
COPY scripts ./scripts
COPY conf ./conf
COPY models ./models
COPY data/training ./data/training
COPY data/processed ./data/processed

RUN pip install --no-cache-dir -e ".[ocr,forensics]"

# Non-root runtime user; logs/report dirs are writable volumes.
RUN useradd --create-home pif \
    && mkdir -p logs data quarantine \
    && chown -R pif:pif /app
USER pif

ENV PIF_HOST=0.0.0.0 \
    PIF_PORT=8080 \
    PIF_OCR=1

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

CMD ["python", "scripts/main.py"]
