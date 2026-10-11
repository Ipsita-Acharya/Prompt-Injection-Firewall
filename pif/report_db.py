"""SQLite persistence for every scan: the request, the policy decision and every
finding land in data/report.db so nothing about a scan is lost when the log files
rotate, and so the admin portal (UI_PIF/pif_portal.py) can replay live telemetry.

Storage never raises into the scan pipeline (same contract as pif/quarantine.py).
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from pif.observability import logger, request_context

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    scan_id TEXT NOT NULL UNIQUE,
    request_id TEXT,
    owner TEXT,
    session_id TEXT,
    decision TEXT NOT NULL,
    status TEXT,
    malicious INTEGER,
    risk REAL,
    risk_level TEXT,
    attacks TEXT,
    attack_ids TEXT,
    warnings TEXT,
    quarantined TEXT,
    file_count INTEGER,
    file_names TEXT,
    content_count INTEGER,
    prompt_chars INTEGER,
    user_prompt TEXT,
    duration_ms REAL,
    detector_version TEXT,
    coverage TEXT,
    request_json TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans (ts);
CREATE INDEX IF NOT EXISTS idx_scans_decision ON scans (decision);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    category TEXT,
    category_id INTEGER,
    rule_id TEXT,
    source_id TEXT,
    source TEXT,
    locator TEXT,
    layer TEXT,
    severity REAL,
    evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _request_summary(request) -> dict:
    """Request shape without file bytes: data_base64 is replaced by its length."""
    try:
        document = request.model_dump()
        for file_input in document.get("files", []):
            file_input["data_base64_bytes"] = len(file_input.pop("data_base64", "") or "")
        return document
    except Exception:
        return {"unserializable_request": True}


class ReportDB:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
        logger.info("report_db.initialized", extra={"event_fields": dict(path=str(self.path))})

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def record(self, request, result, owner: str = "", duration_ms: float | None = None):
        """Persist one completed scan: its request, decision and every finding."""
        try:
            now = _now()
            summary = _request_summary(request)
            result_document = result.model_dump()
            with self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO scans (ts, scan_id, request_id, owner, session_id,"
                    " decision, status, malicious, risk, risk_level, attacks, attack_ids,"
                    " warnings, quarantined, file_count, file_names, content_count, prompt_chars,"
                    " user_prompt, duration_ms, detector_version, coverage, request_json,"
                    " result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        now,
                        result.scan_id,
                        request_context.get(None),
                        owner,
                        result.session_id,
                        result.decision,
                        result.status,
                        None if result.malicious is None else int(result.malicious),
                        result.risk,
                        result.risk_level,
                        json.dumps(result.attacks),
                        json.dumps(result.attack_ids),
                        json.dumps(result.warnings),
                        json.dumps(result.quarantined),
                        len(request.files),
                        json.dumps([file_input.name for file_input in request.files]),
                        len(request.content),
                        len(request.user_prompt),
                        request.user_prompt,
                        duration_ms,
                        result.detector_version,
                        result.coverage,
                        json.dumps(summary),
                        json.dumps(result_document),
                    ),
                )
                for finding in result.findings:
                    connection.execute(
                        "INSERT INTO findings (ts, scan_id, category, category_id, rule_id,"
                        " source_id, source, locator, layer, severity, evidence)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            now,
                            result.scan_id,
                            finding.category,
                            finding.category_id,
                            finding.rule_id,
                            finding.source_id,
                            finding.source_id.split(":", 1)[0] if finding.source_id else "",
                            finding.locator,
                            finding.layer,
                            finding.severity,
                            finding.evidence,
                        ),
                    )
            logger.info(
                "report_db.recorded",
                extra={"event_fields": dict(scan_id=result.scan_id, decision=result.decision, finding_count=len(result.findings))},
            )
        except Exception as error:
            logger.warning(
                "report_db.record_failed",
                extra={"event_fields": dict(error_type=type(error).__name__)},
            )

    def record_error(self, request, scan_id: str, owner: str = "", error: Exception | None = None):
        """Persist a scan that raised before a result existed (decision='error')."""
        try:
            now = _now()
            summary = _request_summary(request)
            with self._connect() as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO scans (ts, scan_id, request_id, owner, decision,"
                    " status, warnings, file_count, file_names, content_count, prompt_chars,"
                    " user_prompt, request_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        now,
                        scan_id,
                        request_context.get(None),
                        owner,
                        "error",
                        "error",
                        json.dumps([type(error).__name__] if error else []),
                        len(request.files),
                        json.dumps([file_input.name for file_input in request.files]),
                        len(request.content),
                        len(request.user_prompt),
                        request.user_prompt,
                        json.dumps(summary),
                    ),
                )
        except Exception as error_type:
            logger.warning(
                "report_db.record_failed",
                extra={"event_fields": dict(error_type=type(error_type).__name__)},
            )


_instances: dict[str, ReportDB] = {}
_instance_lock = threading.Lock()


def get_report_db(settings) -> ReportDB | None:
    """Process-wide ReportDB per database path, or None when disabled/unavailable."""
    if not settings.report_db_enabled:
        return None
    key = str(settings.report_db_path)
    with _instance_lock:
        if key not in _instances:
            try:
                _instances[key] = ReportDB(settings.report_db_path)
            except (OSError, sqlite3.Error) as error:
                logger.warning(
                    "report_db.init_failed",
                    extra={"event_fields": dict(error_type=type(error).__name__, path=key)},
                )
                return None
        return _instances[key]
