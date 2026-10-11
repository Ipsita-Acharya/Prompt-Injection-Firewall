"""Quarantine system (spec: blocked attachments move to a configured quarantine
directory, with the reason and attack categories recorded in a sidecar file).
Storage never raises into the scan pipeline; failures are telemetry only."""

import base64
import binascii
import json
import logging
import re
import time
from pathlib import Path, PurePath

from pif.observability import logger
from pif.schemas import ScanRequest, ScanResult
from pif.settings import Settings


def store(request: ScanRequest, result: ScanResult, settings: Settings) -> list[str]:
    stored: list[str] = []
    if not request.files:
        return stored
    try:
        target = Path(settings.quarantine_dir)
        target.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        logger.warning("quarantine.unavailable", extra={"event_fields": dict(error_type=type(error).__name__)})
        return stored
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for index, item in enumerate(request.files):
        try:
            data = base64.b64decode(item.data_base64, validate=True)
        except (binascii.Error, ValueError):
            continue
        safe_name = PurePath(item.name or f"attachment-{index}").name
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name) or f"attachment-{index}"
        filename = f"{stamp}_{result.scan_id[:8]}_{index}_{safe_name}"
        try:
            (target / filename).write_bytes(data)
            (target / f"{filename}.json").write_text(
                json.dumps(
                    {
                        "scan_id": result.scan_id,
                        "decision": result.decision,
                        "risk": result.risk,
                        "risk_correlation": result.risk_correlation,
                        "attacks": result.attacks,
                        "attack_ids": result.attack_ids,
                        "warnings": result.warnings,
                        "original_name": safe_name,
                        "declared_type": item.type,
                        "bytes": len(data),
                        "timestamp": stamp,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as error:
            logger.warning("quarantine.write_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            continue
        stored.append(filename)
        logger.info("quarantine.stored", extra={"event_fields": dict(file_index=index, quarantine_file=filename)})
    return stored
