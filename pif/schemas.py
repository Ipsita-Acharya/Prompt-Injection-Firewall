import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pif.observability import logger

Attack = Literal[
    "instruction_override",
    "role_change",
    "secret_extraction",
    "tool_abuse",
    "credential_theft",
    "context_poisoning",
    "multi_step_jailbreak",
    "encoded_instruction",
    "indirect_injection",
]

# Spec: each of the 9 fixed attack categories carries a unique numeric ID.
ATTACK_IDS: dict[str, int] = {
    "instruction_override": 1,
    "role_change": 2,
    "secret_extraction": 3,
    "tool_abuse": 4,
    "credential_theft": 5,
    "context_poisoning": 6,
    "multi_step_jailbreak": 7,
    "encoded_instruction": 8,
    "indirect_injection": 9,
}
Source = Literal["user", "file", "web", "rag", "tool", "api", "ocr"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FileInput(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(default="application/octet-stream", max_length=100)
    data_base64: str = Field(max_length=14_000_000)


class ContentInput(StrictModel):
    source: Source = "rag"
    reference: str = Field(default="", max_length=255)
    text: str = Field(max_length=250_000)
    format: Literal["text", "html", "json", "markdown"] = "text"

    @field_validator("text")
    @classmethod
    def valid_unicode(cls, value):
        value.encode("utf-8")
        logger.debug("schema.external_text_validated", extra={"event_fields": dict(input_chars=len(value))})
        return value


class ScanRequest(StrictModel):
    user_prompt: str = Field(default="", max_length=250_000)
    files: list[FileInput] = Field(default_factory=list, max_length=10)
    content: list[ContentInput] = Field(default_factory=list, max_length=50)
    session_id: str | None = Field(default=None, max_length=100)

    @field_validator("user_prompt")
    @classmethod
    def valid_unicode(cls, value):
        value.encode("utf-8")
        logger.debug("schema.prompt_validated", extra={"event_fields": dict(input_chars=len(value))})
        return value


class Segment(StrictModel):
    source_id: str
    source: Source
    locator: str
    text: str


class Finding(StrictModel):
    category: Attack
    category_id: int = 0
    rule_id: str = ""
    source_id: str
    locator: str
    layer: Literal["rule", "semantic", "context"] = "rule"
    transformation: str = "canonical"
    severity: float = Field(ge=0, le=1)
    evidence: str = "[instruction evidence withheld]"
    spans: list[list[int]] = Field(default_factory=list)

    @model_validator(mode="after")
    def assign_category_id(self):
        if not self.category_id:
            self.category_id = ATTACK_IDS.get(self.category, 0)
        return self


class ScanResult(StrictModel):
    scan_id: str
    status: Literal["complete", "incomplete", "error"]
    malicious: bool | None
    risk: float | None
    risk_level: Literal["low", "medium", "high", "unknown"]
    decision: Literal["allow", "sanitize", "isolate", "block"]
    attacks: list[Attack] = Field(default_factory=list)
    attack_ids: list[int] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    safe_content: list[Segment] = Field(default_factory=list)
    risk_correlation: dict | None = None
    quarantined: list[str] = Field(default_factory=list)
    session_id: str | None = None
    detector_version: str = "6.1.0"
    coverage: str = "rules-only: degraded"
