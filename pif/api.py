import asyncio
import logging
import secrets
import shutil
import time
from contextlib import asynccontextmanager, suppress
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from pif.detection import (
    FUZZY_PHRASES,
    RULES_REGISTRY,
    get_custom_rules,
    get_rule_overrides,
)
from pif.engncore import Firewall
from pif.observability import (
    configure_logging,
    content_options,
    content_preview,
    logger,
    request_context,
    set_diagnostics,
)
from pif.schemas import ATTACK_IDS, ScanRequest, ScanResult
from pif.settings import Settings
from pif.sessions import SessionError

# The detection pipeline as shown in the admin portal: WHAT runs, in WHICH
# stage, and what each stage consumes. Keys are stable identifiers the UI maps
# rules onto ("stage1_rules" etc).
POLICY_STAGES = {
    "stage1_rules": {
        "scope": "per_view",
        "order": 1,
        "label": "Stage 1 — Rule patterns",
        "alias": "Rule A",
        "what": "Every normalized view of the prompt and each attachment is matched against the enabled regex rules. A match flags its attack category with the rule's severity (× weight).",
        "inputs": "each normalization view (canonical, leet, base64-decoded, reversed ...) of every segment",
    },
    "stage2_semantic": {
        "scope": "per_view",
        "order": 2,
        "label": "Stage 2 — Semantic classifier",
        "alias": "Rule B / Semantic",
        "what": "Categories no rule caught in this view go to the local ML classifier, which scores the text per attack category; high scores become findings even without a regex match.",
        "inputs": "the same views, only for categories Stage 1 did not already decide",
    },
    "stage3_fuzzy": {
        "scope": "per_view",
        "order": 3,
        "label": "Stage 3 — Fuzzy matching",
        "alias": "Fuzzy Matching",
        "what": "Sliding word windows of the original text are similarity-compared (difflib ≥ 0.86) against canonical attack phrases, catching typos/transpositions no regex view matches.",
        "inputs": "the original segment text after canonicalization",
    },
    "stage4_context": {
        "scope": "per_scan",
        "order": 4,
        "label": "Stage 4 — Context analysis",
        "alias": "Rule C / Context",
        "what": "The whole scan is analyzed as ONE sequence: multi-turn jailbreak steps spread across messages, and injections arriving from external sources (indirect_injection), are detected here.",
        "inputs": "session history (previous turns, last 2048 bytes each) + external fragments (file/web/RAG/OCR segments)",
    },
}


class BodyLimit:
    def __init__(self, app, limit: int, settings: Settings):
        self.app, self.limit = app, limit
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        trace_header = dict(scope.get("headers", [])).get(b"x-pif-trace-id", b"")
        try:
            request_id = str(UUID(trace_header.decode("ascii")))
        except (ValueError, UnicodeError):
            request_id = str(uuid4())
        context_token = request_context.set(request_id)
        diagnostic_token = set_diagnostics(self.settings)
        started = time.perf_counter()
        endpoint = scope.get("path", "")
        endpoint = (
            endpoint
            if endpoint in {"/v1/scan", "/health", "/ready"}
            else "session_reset"
            if endpoint.startswith("/v1/sessions/")
            else "other"
        )

        async def traced_send(message):
            if message["type"] == "http.response.start":
                message = {
                    **message,
                    "headers": [
                        *message.get("headers", []),
                        (b"x-pif-request-id", request_id.encode("ascii")),
                    ],
                }
                logger.info("http.response_started", extra={"event_fields": dict(http_status=message["status"], duration_ms=round((time.perf_counter() - started) * 1000, 3))})
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                logger.info("http.response_completed", extra={"event_fields": dict(duration_ms=round((time.perf_counter() - started) * 1000, 3))})

        try:
            # event("http.request_received", endpoint=endpoint)
            await self._handle(scope, receive, traced_send)
        except Exception as error:
            logger.error("http.request_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            raise
        finally:
            request_context.reset(context_token)
            content_options.reset(diagnostic_token)

    async def _handle(self, scope, receive, send):
        messages, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.limit:
                logger.warning("http.body_rejected", extra={"event_fields": dict(reason="request_body_limit")})
                return await JSONResponse({"detail": "request_body_limit"}, status_code=413)(
                    scope, receive, send
                )
            messages.append(message)
            if not message.get("more_body", False):
                break
        # event("http.body_received", body_bytes=size)

        async def replay():
            return messages.pop(0) if messages else await receive()

        await self.app(scope, replay, send)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings)
    firewall = Firewall(settings)

    @asynccontextmanager
    async def lifespan(app):
        # Sync scan endpoints run on the AnyIO worker-thread pool; size it so
        # the pool never becomes the bottleneck below scan_concurrency.
        from anyio import to_thread

        to_thread.current_default_thread_limiter().total_tokens = max(
            40, settings.scan_concurrency + settings.parser_concurrency
        )
        logger.info("service.started", extra={"event_fields": dict(ready=firewall.ready, coverage=firewall.coverage)})

        async def cleanup():
            while True:
                await asyncio.sleep(30)
                firewall.sessions.prune()

        task = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            with firewall.sessions.lock:
                firewall.sessions.sessions.clear()
            logger.info("service.stopped", extra={"event_fields": dict()})

    app = FastAPI(title="Prompt Injection Firewall", version="0.1.0", lifespan=lifespan)
    app.state.firewall = firewall
    app.add_middleware(BodyLimit, limit=15 * 1024 * 1024, settings=settings)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        logger.warning("http.validation_rejected", extra={"event_fields": dict(error_count=len(error.errors()))})
        return JSONResponse(
            {"detail": "invalid_request", "errors": [item["type"] for item in error.errors()[:20]]},
            status_code=422,
        )

    def authenticate(authorization: str = Header(default="")):
        if not settings.api_token:
            logger.warning("http.auth_rejected", extra={"event_fields": dict(reason="token_not_configured")})
            raise HTTPException(503, "PIF_API_TOKEN is not configured")
        if not secrets.compare_digest(
            authorization.encode(), f"Bearer {settings.api_token}".encode()
        ):
            logger.warning("http.auth_rejected", extra={"event_fields": dict(reason="invalid_token")})
            raise HTTPException(401, "Invalid bearer token")
        logger.info("http.auth_completed", extra={"event_fields": dict()})
        return "local-client"

    @app.get("/health")
    def health():
        logger.debug("api.health_checked", extra={"event_fields": dict()})
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        operational = firewall.ready and bool(settings.api_token)
        logger.debug("api.readiness_checked", extra={"event_fields": dict(ready=operational)})
        return JSONResponse(
            {
                "ready": operational,
                "coverage": firewall.coverage,
                "ocr_enabled": settings.ocr_enabled,
                "ocr_executable_available": shutil.which("tesseract") is not None,
            },
            status_code=200 if operational else 503,
        )

    @app.get("/v1/policy")
    def get_policy(owner: str = Depends(authenticate)):
        """Everything the admin portal needs: engines, every detection with its
        stage, thresholds and the stage map. Read-only by design — rules are
        managed through scripts via conf/policy.ini, which the firewall
        hot-reloads, so this always reflects the LIVE runtime state (severity
        and weight exactly as a script last tuned them)."""

        def severity_of(base: float, entry: dict) -> float:
            """The severity a script last configured (INI override wins over
            the registry value); falls back to the base on a malformed entry."""
            try:
                return float(entry.get("severity", base))
            except (TypeError, ValueError):
                return float(base)

        firewall.maybe_reload()
        overrides = get_rule_overrides()
        rules = []
        for rule in RULES_REGISTRY:
            entry = overrides.get(rule["id"], {})
            rules.append(
                {
                    "id": rule["id"],
                    "category": rule["category"],
                    "severity": severity_of(rule["severity"], entry),
                    "reason": rule["reason"],
                    "pattern": rule["pattern"][:600],
                    "stage": "stage1_rules",
                    "built_in": True,
                    "deletable": False,
                    "enabled": entry.get("enabled", True) is not False,
                    "weight": float(entry.get("weight", 1.0)),
                }
            )
        for rule in get_custom_rules():
            entry = overrides.get(rule["id"], {})
            rules.append(
                {
                    "id": rule["id"],
                    "category": rule["category"],
                    "severity": severity_of(rule["severity"], entry),
                    "reason": rule["reason"],
                    "pattern": rule["pattern"],
                    "stage": "stage1_rules",
                    "built_in": False,
                    "deletable": True,
                    "enabled": entry.get("enabled", True) is not False,
                    "weight": float(entry.get("weight", rule.get("weight", 1.0))),
                }
            )
        for rule_id, category, severity, phrase in FUZZY_PHRASES:
            entry = overrides.get(rule_id, {})
            rules.append(
                {
                    "id": rule_id,
                    "category": category,
                    "severity": severity_of(severity, entry),
                    "reason": f'fuzzy phrase: "{phrase}"',
                    "pattern": phrase,
                    "stage": "stage3_fuzzy",
                    "built_in": True,
                    "deletable": False,
                    "enabled": entry.get("enabled", True) is not False,
                    "weight": float(entry.get("weight", 1.0)),
                }
            )
        logger.info("api.policy_read", extra={"event_fields": dict(rule_count=len(rules))})
        return JSONResponse(
            {
                "engines": {
                    "rule_engine": firewall.rule_engine_enabled,
                    "semantic_engine": firewall.semantic_engine_enabled,
                    "semantic_available": firewall.classifier is not None,
                    "context_engine": firewall.context_engine_enabled,
                    "risk_correlation": firewall.risk_correlation_enabled,
                },
                "stages": POLICY_STAGES,
                "rules": rules,
                "categories": dict(ATTACK_IDS),
            }
        )

    @app.post("/v1/scan", response_model=ScanResult)
    def scan(request: ScanRequest, owner: str = Depends(authenticate)):
        logger.info("story.step_started", extra={"event_fields": dict(step=1, title="Request Received and Validated")})
        logger.info("request.raw_received", extra={"event_fields": dict(request=content_preview(request.model_dump(exclude_unset=True)), has_attachments=bool(request.files), attachment_count=len(request.files), source_count=len(request.content), transport="JSON with base64 file bytes; not multipart upload", schema_validation="passed", authentication="passed")})
        logger.info("story.step_completed", extra={"event_fields": dict(step=1, title="Request Received and Validated")})
        logger.info("api.scan_dispatched", extra={"event_fields": dict(file_count=len(request.files), content_count=len(request.content), next_script="pif/engncore.py")})
        try:
            result = firewall.scan(request, owner)
            logger.info("api.scan_returned", extra={"event_fields": dict(scan_id=result.scan_id, decision=result.decision, status=result.status)})
            return result
        except SessionError as error:
            logger.warning("session.rejected", extra={"event_fields": dict()})
            raise HTTPException(409, str(error)) from error

    @app.delete("/v1/sessions/{session_id}")
    def reset(session_id: str, owner: str = Depends(authenticate)):
        try:
            firewall.sessions.reset(session_id, owner)
        except SessionError as error:
            logger.warning("session.reset_rejected", extra={"event_fields": dict()})
            raise HTTPException(409, str(error)) from error
        logger.info("session.reset_completed", extra={"event_fields": dict()})
        return {"reset": True}

    logger.info("api.routes_configured", extra={"event_fields": dict(custom_route_count=3)})
    return app
