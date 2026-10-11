import configparser
import json
import logging
import os
import threading
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from pif.detection.semantic import LocalClassifier
from pif.detection import (
    DetectionEngine,
    FUZZY_PHRASES,
    RULES_REGISTRY,
    log_categories,
    set_custom_rules,
    set_rule_overrides,
    validate_custom_rule,
)
from pif.detection.llm_judge import LLMJudge, judge_and_escalate
from pif.detonation import DetonationPolicy, detonate, signals_to_category
from pif.input import InspectionError, Processor
from pif.observability import (
    content_options,
    content_preview,
    logger,
    scan_context,
    set_diagnostics,
    source_context,
)
from pif.policy import neutralize
from pif.quarantine import store as quarantine_store
from pif.report_db import get_report_db
from pif.risk import correlate
from pif.schemas import ATTACK_IDS, Finding, ScanRequest, ScanResult
from pif.settings import Settings
from pif.sessions import SessionStore


class Firewall:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.classifier = None
        self.processor = Processor(settings)
        self.sessions = SessionStore(settings)
        self.scan_slots = threading.BoundedSemaphore(settings.scan_concurrency)
        self.report_db = get_report_db(settings)
        self.model_error = None
        self._policy_stamp = self._policy_fingerprint()
        self._pinned_thresholds = self._pinned_thresholds_from_sources()
        self._apply_policy_config(settings.policy_config)
        if not settings.rules_only:
            try:
                self.classifier = LocalClassifier(settings.model_path)
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.model_error = "classifier_unavailable_or_invalid"
                logger.warning("classifier.load_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        logger.info("firewall.initialized", extra={"event_fields": dict(ready=self.ready, coverage=self.coverage, ocr_enabled=settings.ocr_enabled)})

    def _apply_policy_config(self, policy_config: dict):
        """Push a policy document (from the policy INI + agent override JSON)
        into the live state: engine toggles, per-rule enable/severity/weight
        overrides, compiled CUSTOM- rules, thresholds and actions.
        conf/policy.ini is the single source of truth — the UI never mutates
        policy."""
        detection_config = policy_config.get("detection", {})
        rule_config = dict(policy_config.get("rules", {}))
        self.rule_engine_enabled = detection_config.get("rule_engine", True) is not False
        if not self.rule_engine_enabled:
            # rule_engine covers every pattern-based detection: Stage-1 rules,
            # Stage-3 fuzzy phrases and compiled CUSTOM- rules alike.
            forced_off = {rule["id"] for rule in RULES_REGISTRY}
            forced_off.update(fuzzy[0] for fuzzy in FUZZY_PHRASES)
            rule_config.update({rule_id: {"enabled": False} for rule_id in forced_off})
            for definition in rule_config.values():
                if definition.get("pattern"):
                    definition["enabled"] = False
        set_rule_overrides(rule_config)
        # [rules:CUSTOM-###] sections carry full definitions (pattern/category/
        # severity/reason) — compile them into the live registry; invalid ones
        # are skipped with a warning, never block startup.
        custom_rules = []
        for rule_id, definition in rule_config.items():
            if not definition.get("pattern"):
                continue
            try:
                custom_rules.append(validate_custom_rule(rule_id, definition))
            except ValueError as error:
                logger.warning("firewall.custom_rule_invalid", extra={"event_fields": dict(rule_id=rule_id, reason=str(error))})
        set_custom_rules(custom_rules)
        self.semantic_engine_enabled = detection_config.get("semantic_engine", True) is not False
        self.context_engine_enabled = detection_config.get("context_engine", True) is not False
        self.risk_correlation_enabled = detection_config.get("risk_correlation", True) is not False
        # Gray-band LLM judge (v6.0): disabled unless [llm_judge] enables it;
        # rebuilt here so policy hot-reloads reconfigure it too.
        self.llm_judge = LLMJudge(policy_config=policy_config, policy_file=self.settings.policy_file)
        # Detonation chamber (v6.0): wired into the live gray-band path below;
        # off by default, emulator decoy works fully offline.
        self.detonation = DetonationPolicy(policy_config=policy_config, policy_file=self.settings.policy_file)
        self._refresh_thresholds_and_actions(policy_config)

    def _pinned_thresholds_from_sources(self) -> dict:
        """Thresholds explicitly pinned OUTSIDE the policy INI (conf/pif.ini
        [pif] values, or PIF_* environment variables when no PIF_CONF ini
        exists). They keep precedence on every hot-reload, exactly as at
        startup, so a script edit of [thresholds] can never clobber them."""
        fields = {"block": "block_threshold", "hard_block": "hard_block_threshold", "sanitize": "sanitize_threshold"}
        ini_path = Path(os.getenv("PIF_CONF", "conf/pif.ini"))
        pinned: dict = {}
        if ini_path.is_file():
            parser = configparser.ConfigParser()
            parser.read(ini_path, encoding="utf-8")
            for key, field in fields.items():
                if parser.has_section("pif") and parser.has_option("pif", field):
                    try:
                        value = float(parser.get("pif", field))
                    except ValueError:
                        continue
                    if 0 <= value <= 1:
                        pinned[key] = value
            return pinned
        env_names = {"block": "PIF_BLOCK_THRESHOLD", "hard_block": "PIF_HARD_BLOCK_THRESHOLD", "sanitize": "PIF_SANITIZE_THRESHOLD"}
        for key, name in env_names.items():
            raw = os.getenv(name, "")
            if not raw:
                continue
            try:
                value = float(raw)
            except ValueError:
                continue
            if 0 <= value <= 1:
                pinned[key] = value
        return pinned

    def _refresh_thresholds_and_actions(self, policy_config: dict):
        """Make [thresholds]/[actions] script edits live too: rewrite the frozen
        Settings dataclass in place (the one sanctioned writer — policy comes
        from scripts, never from the UI). conf/pif.ini / env pins win, then the
        fresh policy INI values, then the built-in defaults."""
        thresholds = policy_config.get("thresholds", {})
        fields = {"block": "block_threshold", "hard_block": "hard_block_threshold", "sanitize": "sanitize_threshold"}
        defaults = {"block": 0.85, "hard_block": 0.95, "sanitize": 0.5}
        for key, field in fields.items():
            pinned = self._pinned_thresholds.get(key)
            value = pinned if pinned is not None else thresholds.get(key, defaults[key])
            if not 0 <= value <= 1:
                logger.warning("policy.threshold_ignored", extra={"event_fields": dict(threshold=key, value=value)})
                continue
            if getattr(self.settings, field) != value:
                object.__setattr__(self.settings, field, value)
                logger.info("policy.threshold_reloaded", extra={"event_fields": dict(threshold=key, value=value)})
        # actions (allow/sanitize/block/partial_block) are read from
        # settings.policy_config on every scan — publishing the fresh document
        # makes their script edits live from the next scan as well.
        object.__setattr__(self.settings, "policy_config", policy_config)

    def _policy_paths(self) -> list[Path]:
        paths = [Path(self.settings.policy_file)]
        override = Settings._resolve_policy_override_file()
        if override is not None:
            paths.append(override)
        return paths

    def _policy_fingerprint(self) -> tuple:
        """Content digests of every file policy is sourced from (the INI and
        the agent override JSON); compared on each scan / policy read to
        hot-reload. Content, not mtime: two writes landing inside one
        filesystem timestamp tick must never hide a script edit. A missing or
        unreadable file hashes as None so creating it later still reloads."""
        stamp = []
        for path in self._policy_paths():
            try:
                stamp.append(sha256(path.read_bytes()).hexdigest())
            except OSError:
                stamp.append(None)
        return tuple(stamp)

    def maybe_reload(self):
        """Live policy reload: when a script edits conf/policy.ini (rules,
        severity, weight, engine toggles, thresholds, actions) or an approved
        override JSON lands, re-apply the policy so the change is live from the
        next scan. A failed read keeps the last good state and retries on the
        next call."""
        stamp = self._policy_fingerprint()
        if stamp == self._policy_stamp:
            return
        try:
            self._apply_policy_config(self.settings.fresh_policy_config())
        except Exception as error:
            logger.error("policy.reload_failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            return
        self._policy_stamp = stamp
        logger.info("policy.reloaded", extra={"event_fields": dict(policy_file=str(self.settings.policy_file))})

    def _effective_classifier(self):
        return self.classifier if self.semantic_engine_enabled else None

    @property
    def coverage(self):
        return (
            "rules-only: degraded"
            if self.classifier is None
            else f"hybrid-demo:{self.classifier.version}"
        )

    @property
    def ready(self):
        return self.settings.rules_only or self.classifier is not None

    def scan(self, request: ScanRequest, owner: str = "local") -> ScanResult:
        self.maybe_reload()
        scan_id = str(uuid4())
        token = scan_context.set(scan_id)
        diagnostic_token = set_diagnostics(self.settings)
        started = time.perf_counter()
        try:
            logger.info("scan.started", extra={"event_fields": dict(file_count=len(request.files), content_count=len(request.content), prompt_chars=len(request.user_prompt), session_reused=request.session_id is not None, has_attachments=bool(request.files))})
            logger.info("story.step_started", extra={"event_fields": dict(step=1, title="Firewall Request Received")})
            logger.info("request.raw_received", extra={"event_fields": dict(request=content_preview(request.model_dump(exclude_unset=True)), has_attachments=bool(request.files), attachment_count=len(request.files), schema_validation="Pydantic ScanRequest constructed")})
            logger.info("story.step_completed", extra={"event_fields": dict(step=1, title="Firewall Request Received")})
            result = self._run_scan(request, owner, scan_id)
            if result.decision == "block" and self.settings.quarantine_enabled:
                result.quarantined = quarantine_store(request, result, self.settings)
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            if self.report_db is not None:
                self.report_db.record(request, result, owner, duration_ms=duration_ms)
            logger.info("scan.completed", extra={"event_fields": dict(decision=result.decision, status=result.status, risk=result.risk, attacks=result.attacks, safe_segment_count=len(result.safe_content), warning_count=len(result.warnings), duration_ms=duration_ms)})
            return result
        except Exception as error:
            if self.report_db is not None:
                self.report_db.record_error(request, scan_id, owner, error)
            logger.error("scan.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
            raise
        finally:
            scan_context.reset(token)
            content_options.reset(diagnostic_token)

    def _run_scan(self, request: ScanRequest, owner: str, scan_id: str) -> ScanResult:
        if not self.scan_slots.acquire(blocking=False):
            logger.warning("scan.capacity_rejected", extra={"event_fields": dict()})
            return ScanResult(
                scan_id=scan_id,
                status="incomplete",
                malicious=None,
                risk=None,
                risk_level="unknown",
                decision="block",
                warnings=["scan_capacity_exceeded"],
                coverage=self.coverage,
            )
        try:
            session_id, session = self.sessions.acquire(request.session_id, owner)
            try:
                logger.info("session.acquired", extra={"event_fields": dict(history_turns=len(session.turns), risk_memory=session.risk_memory)})
                result, context = self._scan(request, list(session.turns), scan_id, session_risk_memory=session.risk_memory)
                tail = context.encode("utf-8")[-2048:]
                session.turns.append(tail.decode("utf-8", errors="ignore"))           # saves the current content into session history. Stores up to the last 2048 bytes of context.
                # Decay-accumulate the session risk (v6.0): 75% memory + 25%
                # of this scan's fused risk, so repeated probing escalates.
                session.risk_memory = round(session.risk_memory * 0.75 + (result.risk or 0.0) * 0.25, 4)
                logger.info("session.turn_recorded", extra={"event_fields": dict(history_turns=len(session.turns), risk_memory=session.risk_memory, context_bytes=len(tail), turn_text=content_preview(tail.decode("utf-8", errors="ignore")))})
                return result.model_copy(update={"session_id": session_id})
            finally:
                self.sessions.release(session)
        finally:
            self.scan_slots.release()

    def _scan(self, request: ScanRequest, history: list[str], scan_id: str, session_risk_memory: float = 0.0):
        logger.info("story.step_started", extra={"event_fields": dict(step=2, title="Input Processing and File Validation")})
        logger.info("extraction.started", extra={"event_fields": dict()})
        started = time.perf_counter()
        try:
            segments, warnings = self.processor.process(request)
        except InspectionError as error:
            segments, warnings = [], [str(error)]
            logger.warning("extraction.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        logger.info("extraction.completed", extra={"event_fields": dict(segment_count=len(segments), extracted_chars=sum(len(segment.text) for segment in segments), warning_count=len(warnings), duration_ms=round((time.perf_counter() - started) * 1000, 3))})
        if not self.ready:
            warnings.append("classifier_unavailable")
            logger.warning("classifier.unavailable", extra={"event_fields": dict()})
        logger.info("story.step_completed", extra={"event_fields": dict(step=2, title="Input Processing and File Validation", warning_count=len(warnings))})
        logger.info("inspection.started", extra={"event_fields": dict(layers=[
                "normalization",
                "rules",
                "semantic" if self.classifier is not None else "rules-only",
            ])})
        started = time.perf_counter()
        engine = DetectionEngine(self._effective_classifier())
        try:
            findings = []
            for segment_index, segment in enumerate(segments):
                logger.debug("inspection.segment_dispatched", extra={"event_fields": dict(segment_index=segment_index, source=segment.source, input_chars=len(segment.text), next_script="pif/detection")})
                origin = {
                    "source_id": segment.source_id,
                    "source": segment.source,
                    "locator": content_preview(segment.locator),
                }
                if segment.source_id.startswith("file:"):
                    file_index = int(segment.source_id.split(":")[1])
                    origin.update(
                        file_index=file_index,
                        file_name=content_preview(request.files[file_index].name),
                    )
                source_token = source_context.set(origin)
                try:
                    findings.extend(engine.scan_segment(segment))
                finally:
                    source_context.reset(source_token)
                if len(findings) > 256:
                    warnings.append("finding_count_limit")
                    findings = findings[:256]
                    logger.warning("inspection.finding_limit", extra={"event_fields": dict()})
                    break
            external = [segment.text for segment in segments if segment.source != "user"]
            logger.info("story.step_started", extra={"event_fields": dict(step=6, title="Context and Nine Attack Category Results")})
            logger.info("context.started", extra={"event_fields": dict(history_turns=len(history), external_segment_count=len(external), external_text=[content_preview(text) for text in external[:5]])})
            if self.context_engine_enabled:
                findings.extend(engine.scan_context(history + external, request.user_prompt))
            # Decaying session-risk accumulator (v6.0): a session that kept
            # risky memory across turns escalates a mild repeat of probing —
            # accumulated risk >= 0.6 plus actionable evidence this turn.
            if (
                self.context_engine_enabled
                and session_risk_memory >= 0.6
                and any(finding.severity >= 0.5 for finding in findings)
            ):
                logger.info("context.accumulated_risk_escalated", extra={"event_fields": dict(risk_memory=session_risk_memory, rule_id="context-v0.1/risk-accumulator", severity=0.85)})
                findings.append(
                    Finding(
                        category="context_poisoning",
                        rule_id="context-v0.1/risk-accumulator",
                        source_id="user",
                        locator="session-risk-accumulator",
                        layer="context",
                        severity=0.85,
                    )
                )
            logger.info("context.completed", extra={"event_fields": dict(context_finding_count=sum(finding.layer == "context" for finding in findings))})
            log_categories(findings, scope="request_after_context")
            logger.info("story.step_completed", extra={"event_fields": dict(step=6, title="Context and Nine Attack Category Results")})
        except Exception as error:
            findings = []
            warnings.append("detection_incomplete")
            logger.error("inspection.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        logger.info("inspection.completed", extra={"event_fields": dict(finding_count=len(findings), attacks=sorted({finding.category for finding in findings if finding.severity >= 0.5}), duration_ms=round((time.perf_counter() - started) * 1000, 3))})
        risk = max((finding.severity for finding in findings), default=0.0)
        assessment = None
        if self.risk_correlation_enabled:
            assessment = correlate(findings, hard_threshold=self.settings.hard_block_threshold)
            risk = assessment.risk
        # Gray-band LLM judge (v6.0): escalation-only, fail-closed. It runs
        # after deterministic fusion and can only add a finding; any failure
        # lands in `warnings`, which the policy layer turns into a block.
        if self.llm_judge is not None and self.llm_judge.applies(
            risk, self.settings.block_threshold
        ):
            judge_token = source_context.set({"source_id": "user", "source": "user", "locator": "llm-judge"})
            try:
                findings = judge_and_escalate(
                    self.llm_judge,
                    "\n".join(segment.text for segment in segments),
                    findings,
                    warnings,
                )
            finally:
                source_context.reset(judge_token)
            if self.risk_correlation_enabled:
                assessment = correlate(findings, hard_threshold=self.settings.hard_block_threshold)
                risk = assessment.risk
        # Detonation chamber (v6.0): behavioral verdict for the gray band. The
        # decoy observes what the content DIRECTS (canary leaks, tool fires,
        # memory writes); a malicious verdict adds a hard finding and the risk
        # is re-fused. A clean or inconclusive detonation changes nothing —
        # the chamber can never lower a deterministic decision.
        # The chamber honors the rule layer's deliberate suppression: content
        # whose only findings are quoted-educational (0.2 severity) is not
        # behaviorally escalated — that would undo the FP guard. Content with
        # NO findings at all is still detonated: a rule-missed paraphrase that
        # directs the decoy to leak is exactly the case the chamber exists for.
        suppressed_only = bool(findings) and max(
            finding.severity for finding in findings
        ) <= 0.2
        if (
            self.detonation is not None
            and not suppressed_only
            and self.detonation.applies(risk, self.settings.block_threshold)
        ):
            detonation_text = "\n".join(segment.text for segment in segments)
            detonation = detonate(
                detonation_text,
                self.detonation.build_decoy(),
                self.detonation.server_secret,
                scan_id,
            )
            if detonation.verdict == "malicious":
                category = signals_to_category(detonation.signals)
                logger.info("detonation.escalated", extra={"event_fields": dict(signals=detonation.signals, category=category, decoy=self.detonation.decoy)})
                findings = [
                    *findings,
                    Finding(
                        category=category,
                        rule_id="DETONATION-001",
                        source_id="user",
                        locator="detonation",
                        layer="context",
                        transformation="canonical",
                        severity=0.95,
                        # Behavioral evidence summary: what the decoy agent was
                        # observed doing. Canary VALUES are never included —
                        # only the signal kinds and the decoy type.
                        evidence="decoy="
                        + self.detonation.decoy
                        + " signals="
                        + json.dumps(sorted(detonation.signals)),
                    ),
                ]
                if self.risk_correlation_enabled:
                    assessment = correlate(findings, hard_threshold=self.settings.hard_block_threshold)
                    risk = assessment.risk
        logger.info("story.step_started", extra={"event_fields": dict(step=7, title="Policy and Neutralization Decision")})
        logger.info("policy.started", extra={"event_fields": dict(risk=risk, warning_count=len(warnings))})
        logger.info("policy.input_segments", extra={"event_fields": dict(segment_count=len(segments), segment_texts=[content_preview(segment.text) for segment in segments[:10]])})
        try:
            decision, safe_content = neutralize(
                segments,
                findings,
                warnings,
                self._effective_classifier(),
                assessment=assessment,
                thresholds={
                    "block": self.settings.block_threshold,
                    "hard_block": self.settings.hard_block_threshold,
                    "sanitize": self.settings.sanitize_threshold,
                },
                actions=self.settings.policy_config.get("actions", {}),
            )
        except Exception as error:
            warnings.append("neutralization_failed")
            decision, safe_content = "block", []
            logger.error("policy.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        safe_ids = {id(segment) for segment in safe_content}
        withheld = [segment for segment in segments if id(segment) not in safe_ids]
        logger.info("policy.completed", extra={"event_fields": dict(decision=decision, safe_segment_count=len(safe_content), withheld_segment_count=len(segments) - len(safe_content), safe_text=[content_preview(segment.text) for segment in safe_content[:5]], withheld_text=[content_preview(segment.text) for segment in withheld[:5]])})
        logger.info("story.step_completed", extra={"event_fields": dict(step=7, title="Policy and Neutralization Decision", decision=decision)})
        logger.info("story.step_started", extra={"event_fields": dict(step=8, title="Final Result")})
        blocked = decision == "block"
        suspicious = risk >= 0.5
        attack_list = sorted({finding.category for finding in findings if finding.severity >= 0.5})
        result = ScanResult(
            scan_id=scan_id,
            status="incomplete" if warnings else "complete",
            malicious=True if suspicious else (None if warnings else False),
            risk=None if warnings else risk,
            risk_level="unknown"
            if warnings
            else ("high" if blocked else ("medium" if suspicious else "low")),
            decision=decision,
            findings=findings,
            attacks=attack_list,
            attack_ids=[ATTACK_IDS[attack] for attack in attack_list],
            warnings=warnings,
            safe_content=safe_content,
            risk_correlation={
                "risk": assessment.risk,
                "hard_block": assessment.hard_block,
                "contributions": assessment.contributions,
            }
            if assessment is not None
            else None,
            coverage=self.coverage,
        )
        logger.info("story.step_completed", extra={"event_fields": dict(step=8, title="Final Result", decision=decision, risk=result.risk, status=result.status, attacks=result.attacks)})
        return result, "\n".join(segment.text for segment in segments)
