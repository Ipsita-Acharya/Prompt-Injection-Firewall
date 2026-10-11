import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import base64
import json
import logging
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from pif.observability import configure_logging, logger, request_context
from pif.settings import Settings


def pack_request(path: Path):
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("Request configuration exceeds 1 MiB")
    request = json.loads(path.read_text(encoding="utf-8"))
    logger.info("client.config_loaded", extra={"event_fields": dict(file_count=len(request.get("files", [])), content_count=len(request.get("content", [])))})
    total_bytes = 0
    if len(request.get("files", [])) > 10:
        raise ValueError("Too many files")
    for index, item in enumerate(request.get("files", [])):
        if "path" not in item:
            continue
        file_path = Path(item.pop("path"))
        if not file_path.is_absolute():
            file_path = path.parent / file_path
        if not file_path.is_file() or file_path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("File unavailable or too large")
        with file_path.open("rb") as handle:
            data = handle.read(10 * 1024 * 1024 + 1)
        total_bytes += len(data)
        if total_bytes > 10 * 1024 * 1024:
            raise ValueError("Total file size exceeds 10 MiB")
        item.setdefault("name", file_path.name)
        item.setdefault(
            "type", mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        )
        item["data_base64"] = base64.b64encode(data).decode("ascii")
        logger.info("client.file_read", extra={"event_fields": dict(file_index=index, decoded_bytes=len(data), base64_chars=len(item["data_base64"]))})
    logger.info("client.request_prepared", extra={"event_fields": dict(file_count=len(request.get("files", [])), decoded_bytes=total_bytes)})
    return request


def main():
    parser = argparse.ArgumentParser(description="Submit a local JSON prompt/file request to PIF")
    parser.add_argument("request", type=Path)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--session-id")
    parser.add_argument("--show-safe-content", action="store_true")
    args = parser.parse_args()
    context_token = request_context.set(str(uuid4()))
    try:
        configure_logging(Settings.load(), component="client")
        return _submit(args, parser)
    finally:
        request_context.reset(context_token)


def _submit(args, parser):
    logger.info("client.started", extra={"event_fields": dict()})
    parsed = urlparse(args.url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
    ):
        parser.error("Only loopback HTTP endpoints are supported")
    token = os.getenv("PIF_API_TOKEN", "")
    if not token and Path(".pif-token").is_file():
        token = Path(".pif-token").read_text(encoding="utf-8").strip()
    if not token:
        parser.error("Set PIF_API_TOKEN or run main.py --init-token")
    try:
        request = pack_request(args.request)
        if args.session_id:
            request["session_id"] = args.session_id
        logger.info("client.http_started", extra={"event_fields": dict()})
        response = httpx.post(
            args.url.rstrip("/") + "/v1/scan",
            json=request,
            headers={"Authorization": f"Bearer {token}", "X-PIF-Trace-ID": request_context.get()},
            timeout=90,
            trust_env=False,
            follow_redirects=False,
        )
        logger.info("client.http_completed", extra={"event_fields": dict(http_status=response.status_code)})
        response.raise_for_status()
        result = response.json()
        logger.info("client.completed", extra={"event_fields": dict(scan_id=result["scan_id"], decision=result["decision"], status=result["status"], attacks=result["attacks"])})
        if not args.show_safe_content:
            result.pop("safe_content", None)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 2 if result["decision"] == "block" else 0
    except (OSError, ValueError, httpx.HTTPError) as error:
        logger.error("client.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        print(
            json.dumps(
                {"error": "Request failed; verify configuration, file paths, and API availability."}
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
