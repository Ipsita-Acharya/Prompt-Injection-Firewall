import json
import logging
import re
import sys
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pif.settings import Settings

scan_context = ContextVar("pif_scan_id", default=None)
request_context = ContextVar("pif_request_id", default=None)
source_context = ContextVar("pif_source", default=None)
content_options = ContextVar("pif_content_options", default=(False, 4096, ""))
logger = logging.getLogger("pif")
logger.propagate = False
configuration_lock = threading.Lock()
project_root = Path(__file__).resolve().parent.parent


class EventFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
            **getattr(record, "event_fields", {}),
        }
        return json.dumps(event, ensure_ascii=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# SMOD narrative rendering (PIL_SMOD.log)
#
# One human-readable line per event, phase-tagged to mirror FLOW_DIAGRAM.md,
# rendered by SmodFormatter as aligned columns:
#   timestamp [LEVEL] [file.py:line - function()] #scan-id | PHASE message | details
#   P1 security boundary -> P2 input processing -> P3 normalization ->
#   P4 detection layers A/B/C -> P5 nine categories -> P6 policy ->
#   P7 guards -> P8 final result.
# Content appears only through content_preview(), which honors the opt-in
# PIF_LOG_CONTENT setting and applies best-effort redaction.
# ---------------------------------------------------------------------------

SMOD_MESSAGES: dict[str, str] = {
    # ----- pre-stage / startup -----
    "main.started": "PIF entry point: mode={mode}",
    "main.token_created": "API token file created (.pif-token); protect its permissions",
    "main.token_already_exists": "API token file already present; not overwritten",
    "main.server_starting": "API server starting on {host}:{port} (loopback only)",
    "main.completed": "API server stopped",
    "service.started": "API READY (ready={ready}, coverage={coverage})",
    "service.stopped": "API stopped; sessions cleared",
    # ----- phase 1: security boundary -----
    "http.auth_completed": "Bearer token accepted (constant-time compare)",
    "http.auth_rejected": "AUTHENTICATION REJECTED: {reason}",
    "http.validation_rejected": "Schema validation rejected: {error_count} error(s) -> 422",
    "http.body_rejected": "Request body rejected: {reason} -> 413",
    "schema.prompt_validated": "user_prompt schema-valid ({input_chars} chars)",
    "schema.external_text_validated": "external content schema-valid ({input_chars} chars)",
    "api.scan_dispatched": "Request accepted: {file_count} file(s), {content_count} content item(s) -> engine core",
    "request.raw_received": "Request received: {attachment_count} attachment(s); preview: {request}",
    "api.health_checked": "Health check",
    "api.readiness_checked": "Readiness check: ready={ready}",
    # ----- sessions (context memory) -----
    "session.created": "New session created ({active_sessions} active)",
    "session.acquired": "Session acquired: {history_turns} history turn(s) for context analysis",
    "session.released": "Session released ({retained_turns} turn(s) retained)",
    "session.rejected": "Session request rejected: {reason}",
    "session.reset_completed": "Session reset",
    "session.turn_recorded": "Session updated: {history_turns} turn(s) now in memory ({context_bytes} bytes recorded)",
    "session.expiry_checked": "Session expiry sweep: {active_sessions} active",
    # ----- phase 2: input processing -----
    "scan.started": "SCAN START: {file_count} file(s), {content_count} content item(s), {prompt_chars} prompt char(s)",
    "scan.capacity_rejected": "SCAN REJECTED: concurrent scan capacity exceeded -> block",
    "extraction.started": "Input processing started",
    "extraction.completed": "Input processing completed: {segment_count} segment(s), {extracted_chars} char(s) extracted",
    "extraction.failed": "Input processing FAILED ({error_type}) -> fail-closed",
    "input.received": "Inputs: {prompt_chars} prompt char(s), {file_count} file(s), {content_count} content item(s)",
    "input.processing_completed": "All inputs processed: {segment_count} segment(s) -> normalization",
    "file.extraction_started": "File {file_index}: extraction started (declared {declared_mime})",
    "file.extraction_completed": "File {file_index}: {decoded_bytes} byte(s) -> {segment_count} segment(s), {extracted_chars} char(s)",
    "file.extraction_failed": "File {file_index}: extraction FAILED ({reason}) -> warning, fail-closed",
    "file.type_check_started": "File type check: {file_name} ({byte_count} byte(s))",
    "file.type_identified": "Type identified: extension={extension} detected={detected} signature={signature_hex} via {identification_method}",
    "file.type_check_completed": "Type verified: detected={detected}, declared={declared} -> {next_step}",
    "file.type_mismatch": "TYPE MISMATCH FLAG: expected={expected} but magic bytes say {detected} (declared={declared}, signature={signature_hex})",
    "file.parser_selected": "Parser selected: {parser} (attachment depth {attachment_depth})",
    "file.parser_completed": "Parser finished: {segment_count} segment(s), {extracted_chars} char(s)",
    "text.decoding_started": "Decoding text ({byte_count} byte(s))",
    "text.decoding_completed": "Decoded as {encoding}: {output_chars} char(s)",
    "text.parser_started": "Parsing {format} ({input_chars} char(s))",
    "text.parser_completed": "Parsed {format}: {segment_count} segment(s), {extracted_chars} char(s)",
    "archive.checked": "Archive checked: {entry_count} entr(y/ies), {uncompressed_bytes} uncompressed byte(s)",
    "pdf.opened": "PDF opened: {page_count} page(s), encrypted={encrypted}",
    "pdf.catalog_checked": "PDF catalog checked: open_action={open_action}",
    "pdf.page_extracted": "PDF page {page_number} captured: {extracted_chars} char(s), {image_count} image(s)",
    "pdf.annotation_captured": "PDF page {page_number} annotation {annotation_index} ({subtype}) captured: {annotation_chars} char(s)",
    "pdf.annotation_empty": "PDF page {page_number} annotation {annotation_index}: no visible text ({subtype})",
    "pdf.annotation_rejected": "PDF page {page_number} annotation {annotation_index} REJECTED ({subtype}): {reason} -> fail-closed",
    "pdf.active_content_rejected": "PDF active content REJECTED at {location}: {reason} -> fail-closed",
    "pdf.metadata_captured": "PDF metadata captured: {metadata_chars} char(s)",
    "docx.opened": "DOCX opened: {paragraph_count} paragraph(s), {table_count} table(s)",
    "email.part_started": "Email part {part_index}: multipart={multipart}, attachment={attachment}",
    "ocr.started": "OCR started ({byte_count} byte(s))",
    "ocr.image_checked": "Image checked: {width}x{height}, {frame_count} frame(s)",
    "ocr.completed": "OCR completed: {word_count} word(s)",
    "content.received": "External content {content_index}: source={source}, format={format}, {input_chars} char(s)",
    "content.extraction_failed": "Content {content_index} invalid ({reason})",
    "parser.worker_dispatched": "Isolated parser worker dispatched (pid {worker_process_id}, timeout {timeout_seconds}s)",
    "parser.worker_started": "Parser worker running on {byte_count} byte(s)",
    "parser.worker_completed": "Parser worker done: {segment_count} segment(s)",
    "parser.worker_failed": "Parser worker failed ({error_type}{reason})",
    "parser.worker_timeout": "Parser worker TIMEOUT -> fail-closed",
    # Full content capture (log_content opt-in): what each stage actually saw
    "input.segment_captured": "CONTENT BEFORE NORMALIZATION ({source_id}/{locator}): {text}",
    "docx.paragraph_captured": "DOCX paragraph {paragraph_index}: {text}",
    "docx.table_captured": "DOCX table {table_index}: {text}",
    "docx.xml_captured": "DOCX XML part {entry}: {text}",
    "ocr.text_captured": "OCR text extracted from image: {text}",
    "policy.input_segments": "Policy input: {segment_count} segment(s) before decision",
    # ----- phase 3: normalization -----
    "normalization.original": "Original text: {text}",
    "normalization.started": "Normalization started ({input_chars} char(s))",
    "normalization.view_created": "View '{transformation}' created (decode depth {decode_depth}): {output_chars} char(s)",
    "normalization.result": "Normalized view '{transformation}': {text}",
    "normalization.completed": "Normalization completed: {view_count} view(s) -> every view is scanned",
    "normalization.budget_rejected": "Normalization budget exceeded ({view_count} view(s), {processed_chars} char(s)) -> fail-closed",
    "normalization.candidates_rejected": "Decoding candidate limit reached ({candidate_count}) -> fail-closed",
    # ----- phase 4A: rule-based detection -----
    "inspection.started": "Detection engine started (layers: {layers})",
    "inspection.segment_dispatched": "Segment {segment_index} ({source}) dispatched to detection",
    "inspection.completed": "Detection engine completed: {finding_count} finding(s); attacks={attacks}",
    "inspection.failed": "Detection engine FAILED ({error_type}) -> fail-closed",
    "inspection.finding_limit": "Finding count limit (256) reached; further segments skipped",
    "detection.segment_started": "Scanning segment source={source}: {input_chars} char(s), semantic={semantic_enabled}",
    "detection.segment_completed": "Segment done: {finding_count} finding(s); attacks={attacks}",
    "detection.rule_evaluated": "Rule '{category}': matched={matched}, actionable={actionable} — {reason}",
    "detection.fuzzy_matched": "FUZZY MATCH: '{category}' severity={severity} via {rule_id}",
    "detection.rule_matched": "RULE MATCH: '{category}' severity={severity} in view '{transformation}'",
    "detection.rules_completed": "Rules done: actionable={actionable_categories}; remaining={remaining_categories}",
    "detection.semantic_skipped": "Semantic classifier skipped ({reason}); categories={categories}",
    # ----- phase 4B: semantic classifier -----
    "classifier.load_started": "Loading local classifier",
    "classifier.manifest_verified": "Classifier manifest verified: version {model_version}, {label_count} label(s)",
    "classifier.vectorizer_loaded": "Classifier TF-IDF {analyzer} features loaded ({feature_count})",
    "classifier.load_completed": "Classifier READY: {feature_count} feature(s), {label_count} label(s)",
    "classifier.load_failed": "Classifier load failed -> rules-only degraded mode",
    "classifier.unavailable": "Classifier unavailable -> rules-only degraded mode",
    "classifier.prediction_started": "Classifying window ({input_chars} char(s))",
    "classifier.prediction_completed": "Classifier scores: {scores}",
    "classifier.feature_evidence": "Feature evidence ({category}): {explanation}",
    "detection.semantic_invoked": "Semantic classifier invoked ({reason}); evaluating categories={categories}",
    "detection.semantic_threshold_checked": "Window {window_start}: attack={attack_score} (threshold 0.85: {attack_threshold_met})",
    "detection.semantic_matched": "SEMANTIC MATCH: '{category}' category_score={score} -> severity {assigned_severity}",
    "detection.semantic_category_evaluated": "Category '{category}': score={category_score}, attack={attack_score}, detected={detected} — {reason}",
    # ----- phase 4C: context analysis -----
    "context.started": "Context analysis: {history_turns} history turn(s) + {external_segment_count} external segment(s)",
    "context.completed": "Context analysis completed: {context_finding_count} finding(s)",
    "session.sequence_started": "Session sequence check ({previous_turn_count} prior turn(s))",
    "session.sequence_matched": "MULTI-STEP PATTERN MATCHED: {reason} (severity {severity})",
    "session.sequence_completed": "Session sequence check done ({alias_count} alias(es))",
    # ----- phase 5: nine attack categories -----
    "detection.category_evaluated": "Category '{category}': detected={detected} via {methods} — {reason}",
    "detection.modifier_selected": "Modifier '{category}' added: triggered by {triggered_by_category} — {reason}",
    # ----- phase 6: policy + neutralization -----
    "policy.started": "Policy evaluation started: risk={risk}, warning_count={warning_count}",
    "policy.risk_evaluated": "Risk={risk} (block at >= {high_threshold}, medium at >= {medium_threshold})",
    "policy.block_selected": "DECISION: BLOCK ({reason}) — zero segments forwarded",
    "policy.allow_selected": "DECISION: ALLOW — {forwarded_segments} segment(s) forwarded",
    "policy.sanitize_selected": "DECISION: SANITIZE — {removed_segments} segment(s) removed, rest kept",
    "policy.isolate_selected": "DECISION: ISOLATE ({reason}) — {removed_segments} segment(s) quarantined",
    "policy.rescan_started": "Re-scanning {remaining_segments} surviving segment(s) before forwarding",
    "policy.rescan_completed": "Re-scan clean: {forwarded_segments} segment(s) safe to forward",
    "policy.rescan_failed": "Re-scan found residual suspicious content -> upgraded to BLOCK",
    "policy.failed": "Policy FAILED ({error_type}) -> BLOCK",
    # ----- phase 7: guards for web/RAG/tool data -----
    "web.guard_received": "Web guard: page received ({input_chars} char(s)) -> scan before LLM reads it",
    "rag.guard_received": "RAG guard: {chunk_count} chunk(s) received -> scan before grounding",
    "tool.authorization_started": "Tool guard: authorization check (registered={registered}, approved={approval_present})",
    "tool.authorization_completed": "Tool guard: authorized (side_effect={side_effect})",
    "tool.authorization_rejected": "TOOL GUARD REJECTED: tool_not_authorized",
    "tool.arguments_validated": "Tool arguments schema-validated ({field_count} field(s))",
    "tool.arguments_rejected": "Tool arguments rejected ({reason})",
    "tool.result_received": "Tool result received ({result_chars} char(s)) -> outbound scan",
    # ----- final result / transport -----
    "scan.completed": "SCAN COMPLETE: decision={decision}, status={status}, risk={risk}, attacks={attacks}",
    "scan.failed": "SCAN FAILED ({error_type})",
    "api.scan_returned": "Response returned: {decision} ({status})",
    "http.response_started": "HTTP {http_status} responding ({duration_ms} ms)",
    "http.response_completed": "HTTP response completed ({duration_ms} ms)",
    # ----- client (call.py) -----
    "client.started": "Client started",
    "client.config_loaded": "Client: request config loaded ({file_count} file(s), {content_count} content item(s))",
    "client.file_read": "Client: file packed ({decoded_bytes} byte(s) -> {base64_chars} base64 char(s))",
    "client.request_prepared": "Client: request prepared ({file_count} file(s), {decoded_bytes} byte(s) total)",
    "client.http_started": "Client: submitting to POST /v1/scan (loopback)",
    "client.http_completed": "Client: HTTP {http_status} received",
    "client.completed": "Client: done — scan={scan_id} decision={decision} ({status}); attacks={attacks}",
    "client.failed": "Client: request failed ({error_type})",
    "firewall.initialized": "Engine core initialized (ready={ready}, coverage={coverage})",
    "policy.completed": "Policy decision finalized: {decision} ({safe_segment_count} safe segment(s) prepared)",
    "risk.correlated": "Fused risk={fused_risk} from {category_count} category(ies) (hard_block={hard_block})",
    "policy.span_redaction": "Span redaction: {removed_spans} span(s) removed, {residual_chars} legitimate char(s) preserved",
    "quarantine.stored": "Quarantined attachment {quarantine_file}",
    "quarantine.unavailable": "Quarantine directory unavailable ({error_type})",
    "quarantine.write_failed": "Quarantine write failed ({error_type})",
}

SMOD_PREVIEW_FIELDS = frozenset(
    {"request", "text", "input_text", "declared_mime", "file_name", "locator", "evidence", "explanation", "scores",
     "safe_text", "withheld_text", "segment_texts", "before_text", "after_text", "headers", "external_text", "turn_text"}
)
SMOD_AUTO_FIELDS = frozenset(
    {
        "category", "severity", "layer", "transformation", "matched", "actionable", "detected",
        "expected", "declared", "extension", "signature_hex", "identification_method", "parser",
        "view_count", "decode_depth", "segment_count", "extracted_chars", "input_chars", "output_chars",
        "finding_count", "context_finding_count", "history_turns", "risk", "decision", "status",
        "attacks", "warning_count", "reason", "next_step", "validation_result", "file_index",
        "content_index", "page_number", "word_count", "byte_count", "decoded_bytes", "entry_count",
        "uncompressed_bytes", "attack_score", "category_score", "score", "window_start",
        "assigned_severity", "coverage", "ready", "duration_ms", "removed_segments",
        "forwarded_segments", "remaining_segments", "title", "mode", "host", "port", "http_status",
        "active_sessions", "retained_turns", "model_version", "feature_count", "label_count",
        "analyzer", "chunk_count", "registered", "approval_present", "side_effect", "error_count",
        "error_type", "alias_count", "previous_turn_count", "processed_chars", "candidate_count",
        "timeout_seconds", "attachment_depth", "encrypted", "page_count", "paragraph_count",
        "table_count", "part_index", "multipart", "attachment", "encoding", "format", "sequence",
        "scope", "methods", "source_id", "source", "triggered_by_category", "actionable_categories",
        "remaining_categories", "layers", "categories", "prompt_chars", "file_count",
        "content_count", "attachment_count", "has_attachments", "context_bytes", "rule_id",
        "nonzero_features", "changed_from_original", "high_threshold", "medium_threshold",
        "request_reused", "session_reused", "safe_segment_count", "withheld_segment_count",
        "locator", "image_count", "ocr_applied", "subtype", "annotation_index",
        "annotation_chars", "metadata_chars", "open_action", "location", "catalog_keys",
        "paragraph_index", "table_index", "entry", "cumulative_bytes",
    }
)
SMOD_HIDDEN_FIELDS = frozenset(
    {
        "script", "function", "line", "process_id", "step", "timestamp", "levelname", "event",
        "pattern", "steps", "request_id", "scan_id", "owner",
    }
)

def _smod_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    text = str(value)
    return text if len(text) <= 90 else text[:87] + "..."


def _smod_field_value(value, depth: int = 0) -> str:
    """Render an event field for the SMOD/story logs without leaking raw secrets:
    content only appears through content_preview() output, which is already
    redacted or explicitly disabled."""
    if depth > 3:
        return "[...]"
    if isinstance(value, dict):
        if "text" in value and "enabled" in value:
            return f'"{value["text"]}"'
        return " ".join(f"{key}={_smod_field_value(child, depth + 1)}" for key, child in list(value.items())[:8])
    if isinstance(value, (list, tuple)):
        rendered = [_smod_field_value(item, depth + 1) for item in value[:8]]
        return "[" + ", ".join(rendered) + "]" if rendered else "[]"
    return _smod_scalar(value)


class _SmodTemplate(dict):
    def __missing__(self, key):
        return ""


def _smod_interpolate(description: str, fields: dict) -> str:
    if "{" not in description:
        return description
    values = _SmodTemplate()
    for key, value in fields.items():
        if isinstance(value, dict) and "text" in value:
            values[key] = str(value["text"])
        elif isinstance(value, bool):
            values[key] = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            values[key] = ", ".join(str(item) for item in value[:12])
        elif value is None:
            values[key] = ""
        else:
            values[key] = str(value)
    try:
        return description.format_map(values)
    except (ValueError, IndexError):
        return description


class SmodFilter(logging.Filter):
    def filter(self, record) -> bool:
        fields = getattr(record, "event_fields", None)
        if not isinstance(fields, dict):
            return False
        name = record.getMessage()
        return name.startswith("story.") or name in SMOD_MESSAGES


class SmodFormatter(logging.Formatter):
    """Human-readable narrative line (columns aligned like a pipeline log):

        timestamp [LEVEL  ] [script.py:line -         function()] #scan-id | PHASE message | details

    The [script] and #scan-id segments can be switched off via
    conf/pif.ini ([logging] script_details / scan_id)."""

    SEPARATOR = "-" * 78
    FUNCTION_WIDTH = 24

    def __init__(self, show_script_details: bool = True, show_scan_id: bool = True):
        super().__init__()
        self.show_script_details = show_script_details
        self.show_scan_id = show_scan_id
        self._scan_starts: dict[str, float] = {}
        self._timing_lock = threading.Lock()

    def format(self, record):
        fields = getattr(record, "event_fields", {})
        name = record.getMessage()
        stamp = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"{stamp} [{record.levelname:<7}]"
        if self.show_script_details:
            script = fields.get("script")
            if script:
                function = str(fields.get("function", "")).rjust(self.FUNCTION_WIDTH)
                prefix += f" [{Path(script).name}:{fields.get('line', '')} - {function}()]"
            else:
                prefix += f" [{record.name}]"
        scan_id = fields.get("scan_id")
        if self.show_scan_id and scan_id:
            prefix += f" #{str(scan_id)[:8]}"
        prefix += " | "
        step = fields.get("step")
        lead, tail = "", ""
        if name == "story.step_started":
            core = f"STEP {fields.get('step')} START | {fields.get('title', '')}"
            used = {"step", "title"}
            lead = f"\n{self.SEPARATOR}\n"
        elif name == "story.step_completed":
            core = f"STEP {fields.get('step')} END | {fields.get('title', '')}"
            used = {"step", "title"}
            tail = f"\n{self.SEPARATOR}"
        else:
            template = SMOD_MESSAGES.get(name, name)
            core = _smod_interpolate(template, fields)
            used = set(re.findall(r"\{(\w+)\}", template))
            if name == "scan.started":
                lead = f"\n{self.SEPARATOR}\n{self.SEPARATOR}\n"
            elif name == "scan.completed":
                tail = f"\n{self.SEPARATOR}\n{self.SEPARATOR}"
        # Templates already carry their phase tag (P1, P4A, P4B...); only prefix
        # the computed step for untagged messages.
        phase = f"P{step} " if isinstance(step, int) and step > 0 and not re.match(r"P\d", core) else ""
        details = []
        for key, value in fields.items():
            if key in SMOD_HIDDEN_FIELDS or key in used:
                continue
            if key in SMOD_AUTO_FIELDS or key in SMOD_PREVIEW_FIELDS:
                details.append(f"{key}={_smod_field_value(value)}")
        # Total wall-clock time per scan, mirroring the tool-output style
        # "Start Time / End Time / Total Time" of the example pipeline log.
        timing_key = str(scan_id)[:8] if scan_id else ""
        with self._timing_lock:
            if name == "scan.started":
                self._scan_starts[timing_key] = record.created
            elif name == "scan.completed":
                started = self._scan_starts.pop(timing_key, None)
                if timing_key and started is not None:
                    core += f" (elapsed {record.created - started:.2f}s)"
            elif name == "scan.failed":
                self._scan_starts.pop(timing_key, None)
        body = f"{phase}{core}"
        if details:
            body += " | " + " ".join(details[:10])
        if "\n" in body:
            body = body.replace("\n", "\n" + " " * len(prefix))
        return lead + prefix + body[:8000] + tail


def set_diagnostics(settings: Settings):
    return content_options.set(
        (settings.log_content, settings.log_content_max_chars, settings.api_token)
    )


def content_preview(value):
    enabled, limit, token = content_options.get()
    if not enabled:
        return {"enabled": False, "text": "[content logging disabled]"}

    def sanitize(item, depth=0):
        if depth > 32:
            return "[depth limit]"
        if isinstance(item, dict):
            return {
                key: f"[attachment payload omitted; {len(str(child))} encoded characters]"
                if str(key).casefold() == "data_base64"
                else "[REDACTED]"
                if re.sub(r"[\s_-]", "", str(key).casefold())
                in {
                    "authorization",
                    "password",
                    "passwords",
                    "apikey",
                    "apikeys",
                    "token",
                    "tokens",
                    "accesstoken",
                    "credentials",
                    "credential",
                    "secret",
                    "secrets",
                    "sessionid",
                    "bearertoken",
                }
                else sanitize(child, depth + 1)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [sanitize(child, depth + 1) for child in item]
        if isinstance(item, str):
            if item.lstrip().startswith(("{", "[")):
                try:
                    return json.dumps(sanitize(json.loads(item), depth + 1), ensure_ascii=True)
                except (ValueError, RecursionError):
                    pass
            if token:
                item = re.sub(re.escape(token), "[REDACTED]", item, flags=re.I)
            item = re.sub(
                r'(?i)\b(passwords?|api[ _-]?keys?|access[ _-]?tokens?|secrets?|tokens?|credentials?)\b(["\x27]?\s*[:=]\s*)(?:"[^"\n]*"|\x27[^\x27\n]*\x27|[^\s,;"\x27]+)',
                r"\1\2[REDACTED]",
                item,
            )
            return re.sub(r"(?i)\bbearer\s+[a-z0-9._-]{8,}", "Bearer [REDACTED]", item)
        return item

    sanitized = sanitize(value)
    text = sanitized if isinstance(sanitized, str) else json.dumps(sanitized, ensure_ascii=True)
    return {
        "enabled": True,
        "text": text if limit <= 0 else text[:limit],
        "total_chars": len(text),
        "truncated": limit > 0 and len(text) > limit,
        "redaction": "recognized credential fields, assignments and configured API token; not a DLP guarantee",
    }


def _step(name):
    if name.startswith("normalization."):
        return 3
    if name.startswith(("classifier.prediction", "classifier.feature", "detection.semantic")):
        return 5
    if name.startswith(("detection.rule", "detection.segment", "inspection.segment")):
        return 4
    if name.startswith(("detection.category", "context.", "session.sequence")):
        return 6
    if name.startswith("policy."):
        return 7
    if name.startswith(
        ("scan.completed", "api.scan_returned", "http.response", "client.completed")
    ):
        return 8
    if name.startswith(
        (
            "input.",
            "file.",
            "text.",
            "parser.",
            "archive.",
            "pdf.",
            "docx.",
            "email.",
            "ocr.",
            "extraction.",
            "content.",
        )
    ):
        return 2
    if name.startswith(
        ("http.", "request.", "schema.", "scan.started", "client.", "api.scan_dispatched")
    ):
        return 1
    return 0


def capture_fields(record: logging.LogRecord) -> dict:
    """Enrich a record's event_fields with correlation IDs, the pipeline step,
    caller attribution and process identity. Used by ContextFilter on every
    record and by the parser-worker pipe handler in child processes. Existing
    values (e.g. relayed from a worker) are never overwritten."""
    fields = getattr(record, "event_fields", None)
    if not isinstance(fields, dict):
        fields = {}
        record.event_fields = fields
    for key, value in (source_context.get() or {}).items():
        fields.setdefault(key, value)
    fields.setdefault("step", _step(record.getMessage()))
    script = Path(record.pathname).resolve()
    try:
        script = script.relative_to(project_root)
    except ValueError:
        script = Path(script.name)
    fields.setdefault("script", script.as_posix())
    fields.setdefault("function", record.funcName)
    fields.setdefault("line", record.lineno)
    fields.setdefault("process_id", record.process)
    scan_id = scan_context.get()
    if scan_id is not None:
        fields.setdefault("scan_id", scan_id)
    request_id = request_context.get()
    if request_id is not None:
        fields.setdefault("request_id", request_id)
    return fields


class ContextFilter(logging.Filter):
    """Standard logging filter carrying the enrichment the event() helper used
    to provide, so call sites can log directly with logger.info/warning/error."""

    def filter(self, record) -> bool:
        capture_fields(record)
        return True


def configure_logging(settings: Settings, component: str = "pif"):
    set_diagnostics(settings)

    if component not in {"pif", "client", "training", "evaluation", "demo", "redteam"}:
        raise ValueError("Unknown logging component")

    config = (
        settings.log_dir.resolve(),
        settings.log_level,
        settings.log_max_bytes,
        settings.log_backup_count,
        settings.log_console,
        component,
        settings.log_simple,
        settings.log_script_details,
        settings.log_scan_id,
    )

    with configuration_lock:
        if any(
            getattr(handler, "pif_config", None) == config
            for handler in logger.handlers
        ):
            return logger

        settings.log_dir.mkdir(parents=True, exist_ok=True)

        # Two streams, one logger (spec telemetry + readable narrative):
        #   <component>.log  - full JSON telemetry for machines/forensics
        #   PIL_SMOD.log     - human-readable phase-tagged narrative
        file_handler = RotatingFileHandler(
            settings.log_dir / f"{component}.log",
            maxBytes=settings.log_max_bytes,
            backupCount=settings.log_backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(EventFormatter())
        handlers = [file_handler]

        if settings.log_console:
            console_handler = logging.StreamHandler(sys.stderr)
            if settings.log_simple:
                console_handler.setFormatter(SmodFormatter(settings.log_script_details, settings.log_scan_id))
                console_handler.addFilter(SmodFilter())
            else:
                console_handler.setFormatter(EventFormatter())
            handlers.append(console_handler)

        if settings.log_simple:
            smod_handler = RotatingFileHandler(
                settings.log_dir / "PIL_SMOD.log",
                maxBytes=settings.log_max_bytes,
                backupCount=settings.log_backup_count,
                encoding="utf-8",
                delay=True,
            )
            smod_handler.setFormatter(SmodFormatter(settings.log_script_details, settings.log_scan_id))
            smod_handler.addFilter(SmodFilter())
            handlers.append(smod_handler)

        for handler in list(logger.handlers):
            if hasattr(handler, "pif_config"):
                logger.removeHandler(handler)
                handler.close()

        for handler in handlers:
            handler.pif_config = config
            logger.addHandler(handler)

        if not any(isinstance(item, ContextFilter) for item in logger.filters):
            logger.addFilter(ContextFilter())
        logger.setLevel(settings.log_level)
        logger.propagate = False

    logger.info("logging.configured", extra={"event_fields": dict(component=component, log_level=settings.log_level, max_bytes=settings.log_max_bytes, backup_count=settings.log_backup_count)})

    settings.log_configuration()

    return logger


def relay_worker_event(level, name, fields, created):
    if logger.isEnabledFor(level):
        record = logger.makeRecord(
            logger.name, level, "", 0, name, (), None, extra={"event_fields": dict(fields)}
        )
        record.created = created
        logger.handle(record)
