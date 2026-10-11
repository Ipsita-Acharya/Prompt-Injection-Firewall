import json
import logging
import re
from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, ValidationError

from pif.engncore import Firewall
from pif.schemas import ContentInput, ScanRequest, ScanResult
from pif.observability import logger


class GuardDenied(RuntimeError):
    pass


# Taint extraction (v6.0): the tokens whose presence in a tool argument marks
# the argument as derived from untrusted content — destinations and long
# identifiers an attacker might plant in a retrieved page or tool result.
_TAINT_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_TAINT_HOST = re.compile(r"(?:https?://|www\.)[\w.-]+(?:/[\w./?%&=-]*)?")
_TAINT_TOKEN = re.compile(r"\b[\w][\w.-]{9,}\b")


def _taint_tokens(text: str) -> set[str]:
    tokens = set()
    for pattern in (_TAINT_EMAIL, _TAINT_HOST, _TAINT_TOKEN):
        for match in pattern.finditer(text or ""):
            value = match.group().strip(".").casefold()
            if len(value) >= 6:
                tokens.add(value)
    return tokens


def _argument_tokens(arguments: dict) -> set[str]:
    """Every string value inside the validated arguments, flattened."""
    tokens = set()
    for value in arguments.values():
        if isinstance(value, str):
            tokens.update(_taint_tokens(value))
        elif isinstance(value, dict):
            tokens.update(_argument_tokens(value))
        elif isinstance(value, (list, tuple)):
            tokens.update(_argument_tokens(dict(enumerate(value))))
    return tokens


def scan_page(firewall: Firewall, html: str, task: str = "Read retrieved page") -> ScanResult:
    logger.info("web.guard_received", extra={"event_fields": dict(input_chars=len(html), next_script="pif/engncore.py")})
    return firewall.scan(
        ScanRequest(
            user_prompt=task, content=[ContentInput(source="web", text=html, format="html")]
        )
    )


def scan_chunks(
    firewall: Firewall, chunks: list[str], task: str = "Read retrieved chunks"
) -> ScanResult:
    logger.info("rag.guard_received", extra={"event_fields": dict(chunk_count=len(chunks), next_script="pif/engncore.py")})
    return firewall.scan(
        ScanRequest(
            user_prompt=task,
            content=[
                ContentInput(source="rag", reference=f"chunk:{index}", text=text)
                for index, text in enumerate(chunks)
            ],
        )
    )


@dataclass(frozen=True)
class ToolSpec:
    function: Callable
    schema: type[BaseModel]
    scope: str
    side_effect: bool = False


class ToolGuard:
    def __init__(self, firewall: Firewall, tools: dict[str, ToolSpec]):
        self.firewall = firewall
        self.tools = dict(tools)

    def execute(
        self,
        name: str,
        arguments: dict,
        *,
        scopes: frozenset[str],
        approved: bool = False,
        task: str = "Use approved tool",
        untrusted_content: str = "",
        user_request: str = "",
    ) -> ScanResult:
        """Execute an approved tool.

        Taint gate (v6.0): when `untrusted_content` is supplied, any argument
        token (email, URL/host, long identifier) that appears in the
        untrusted content but NOT in the user's own request denies execution
        — a destination planted by retrieved content must never steer a tool
        call, even when the content itself scanned clean."""
        spec = self.tools.get(name)
        logger.info("tool.authorization_started", extra={"event_fields": dict(registered=spec is not None, approval_present=approved)})
        if spec is None or spec.scope not in scopes or (spec.side_effect and not approved):
            logger.warning("tool.authorization_rejected", extra={"event_fields": dict()})
            raise GuardDenied("tool_not_authorized")
        if untrusted_content:
            tainted = _argument_tokens(arguments) & _taint_tokens(untrusted_content)
            trusted = _taint_tokens(user_request)
            tainted -= trusted
            if tainted:
                logger.warning("tool.authorization_rejected", extra={"event_fields": dict(reason="tainted_argument_origin", tainted_tokens=sorted(tainted)[:4])})
                raise GuardDenied("tainted_tool_argument")
        logger.info("tool.authorization_completed", extra={"event_fields": dict(side_effect=spec.side_effect)})
        try:
            validated = spec.schema.model_validate(arguments)
            logger.info("tool.arguments_validated", extra={"event_fields": dict(field_count=len(validated.model_fields_set))})
            encoded = json.dumps(validated.model_dump(mode="json"), ensure_ascii=True)
            inbound = self.firewall.scan(
                ScanRequest(
                    user_prompt=task,
                    content=[ContentInput(source="api", text=encoded, format="json")],
                )
            )
        except (ValidationError, ValueError, TypeError) as error:
            logger.warning("tool.arguments_rejected", extra={"event_fields": dict(reason="invalid_arguments")})
            raise GuardDenied("invalid_tool_arguments") from error
        if inbound.decision != "allow" or inbound.status != "complete":
            logger.warning("tool.arguments_rejected", extra={"event_fields": dict(reason="unsafe_arguments", scan_id=inbound.scan_id)})
            raise GuardDenied("unsafe_tool_arguments")
        logger.info("tool.execution_started", extra={"event_fields": dict(scan_id=inbound.scan_id)})
        try:
            output = spec.function(**validated.model_dump())
            encoded = json.dumps(output, ensure_ascii=True)
            logger.info("tool.result_received", extra={"event_fields": dict(result_chars=len(encoded), next_script="pif/engncore.py")})
            result = self.firewall.scan(
                ScanRequest(
                    user_prompt=task,
                    content=[ContentInput(source="tool", text=encoded, format="json")],
                )
            )
        except Exception as error:
            logger.error("tool.execution_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            raise GuardDenied("tool_or_output_inspection_failed") from error
        # Output-side leak guard (v6.1): the third checkpoint — a tool result
        # that carries credential-shaped secrets or a detonation canary is
        # withheld even when the content scan passed it.
        from pif.output_guard import scan_output_leaks

        if scan_output_leaks(encoded, canaries=getattr(self, "canaries", None)):
            logger.warning("tool.output_withheld", extra={"event_fields": dict(reason="output_leak_detected", scan_id=result.scan_id)})
            raise GuardDenied("output_leak_detected")
        logger.info("tool.output_completed", extra={"event_fields": dict(scan_id=result.scan_id, decision=result.decision, status=result.status)})
        return result
