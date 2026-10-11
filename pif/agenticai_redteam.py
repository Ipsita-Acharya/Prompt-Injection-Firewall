"""PIF red-team / self-tuning agent (spec evaluation parameter: agentic and
autonomous capability, supervised).

One loop, two drivers, one rule: the agent may only ever write candidate fixes
to ``reports/redteam/``; production policy is touched exclusively by an
explicit human ``--approve``.

Phase 1 (``--tune``, the self-tuning driver) closes the false-positive
feedback loop of spec §13/§14:

    PERCEIVE  scan a benign sample and an attack verification sample with the
              baseline firewall; read reports/rule_analytics.json,
              reports/evaluation.json and the agent's own memory
    PLAN      targets are rules that cause DECISION-level false positives
              (a benign record actually blocked/sanitized/isolated). A rule
              finding below the policy threshold is noise, not harm, and is
              deliberately not a target. Analytics fp_rate ranks targets.
    ACT       build a shadow firewall per candidate weight (least-invasive
              ladder 0.75 → 0.35); re-scan the affected records
    OBSERVE   which benign records lose their false positive, which attack
              records (must not) lose protection
    ADAPT     the first candidate that passes both gates becomes a pending fix
    VERIFY    gates: no benign record newly mishandled, no attack record
              newly allowed (monotonic: lowering one rule's weight can only
              loosen that rule, so failures are honest, not transient)
    RECOVER   global rule overrides are restored to the baseline configuration
              after every candidate; failed hypotheses are remembered and
              never retried; any unexpected error fails closed
    HUMAN     pending fixes wait in reports/redteam/pending_overrides.json
              until ``--approve`` merges them into the PIF_POLICY_FILE JSON
              (default conf/policy-overrides.json) and re-verifies; a failed
              post-approval verification rolls the file change back

Phase 2 (``--probe``, the FN-direction probe driver) reuses the same
ADAPT/VERIFY/GATE path from the attack side: missed attack records are
mutated into probe families (paraphrase wrappers, base64/hex encodings,
punctuation noise); below-threshold rule evidence on missed records drives
severity-override candidates through the identical human gate.

Usage:
    python -m pif.agenticai_redteam --tune [--benign-sample 200] [--attack-per-category 30]
    python -m pif.agenticai_redteam --status
    python -m pif.agenticai_redteam --approve CAND-0001
    python -m pif.agenticai_redteam --reject CAND-0001

Point the production server at the approved overrides with:
    PIF_POLICY_FILE=conf/policy-overrides.json  (scripts/main.py)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import time
from pathlib import Path

from pif.detection import set_rule_overrides
from pif.detection.rules import RULES_REGISTRY
from pif.engncore import Firewall
from pif.observability import configure_logging, logger
from pif.schemas import ContentInput, ScanRequest
from pif.settings import Settings

REPORTS_DIR = Path("reports")
REDTEAM_DIR = REPORTS_DIR / "redteam"
MEMORY_PATH = REDTEAM_DIR / "memory.json"
PENDING_PATH = REDTEAM_DIR / "pending_overrides.json"
FINDINGS_PATH = REPORTS_DIR / "redteam_findings.json"
ANALYTICS_PATH = REPORTS_DIR / "rule_analytics.json"
EVALUATION_PATH = REPORTS_DIR / "evaluation.json"
EVAL_CORPUS_PATH = Path("data/processed/eval_full.jsonl")
POLICY_OVERRIDE_PATH = Path("conf/policy-overrides.json")

# Weight ladder: least invasive first; the loop escalates only when the gates
# reject the milder candidate. Every step is verified against the same data.
WEIGHT_LADDER = [0.75, 0.6, 0.5, 0.45, 0.35]
# Severity ladder for the FN probe: raise a rule's below-threshold findings
# across the policy line, mildest candidate first.
PROBE_SEVERITY_LADDER = [0.6, 0.75, 0.85, 0.95]
DEFAULT_FP_THRESHOLD = 0.0  # optional analytics prior filter; 0 = decision-level victims only
DEFAULT_BENIGN_SAMPLE = 200
DEFAULT_ATTACK_PER_CATEGORY = 30
DEFAULT_SEED = 13


def _redteam_event(event: str, **fields):
    logger.info(event, extra={"event_fields": fields})


def _story(step: int, title: str, completed: bool = False, **fields):
    event = "story.step_completed" if completed else "story.step_started"
    logger.info(event, extra={"event_fields": dict(step=step, title=title, **fields)})


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_memory() -> dict:
    return _load_json(MEMORY_PATH, {"cycles": [], "failed_hypotheses": [], "next_candidate_id": 1})


def load_pending() -> dict:
    return _load_json(PENDING_PATH, {"pending": []})


def _settings_for(policy_config: dict, log_dir: Path | None = None) -> Settings:
    """Redteam runtime settings: no report DB, no quarantine, agent log stream.

    The agent observes firewall behavior without polluting the production
    audit trail (data/report.db) or the quarantine store. The behavioral
    layers (detonation, judge) are pinned OFF: the loop tunes the
    deterministic layers only — a chamber finding would be indistinguishable
    from the rule being tuned and would poison the VERIFY gates."""
    base = Settings.load()
    pinned = {"detonation": {"enabled": "false"}, "llm_judge": {"enabled": "false"}}
    merged = {**pinned, **(policy_config or {})}
    merged["detonation"] = {**pinned["detonation"], **merged.get("detonation", {})}
    merged["llm_judge"] = {**pinned["llm_judge"], **merged.get("llm_judge", {})}
    return dataclasses.replace(
        base,
        policy_config=merged,
        report_db_enabled=False,
        quarantine_enabled=False,
        log_dir=log_dir or base.log_dir,
    )


def _scan_record(firewall: Firewall, text: str, source: str) -> dict:
    """One corpus record through the firewall; the session turn is reset so
    records stay independent (mirrors scripts/evaluate.py)."""
    request = (
        ScanRequest(user_prompt=text)
        if source == "user"
        else ScanRequest(
            user_prompt="Summarize this source",
            content=[ContentInput(source=source, text=text)],
        )
    )
    result = firewall.scan(request)
    if result.session_id:
        firewall.sessions.reset(result.session_id, "local")
    return {
        "decision": result.decision,
        "status": result.status,
        "risk": result.risk,
        "attacks": list(result.attacks),
        "findings": list(result.findings),
    }


class RedTeamAgent:
    def __init__(
        self,
        corpus_path: Path = EVAL_CORPUS_PATH,
        benign_sample: int = DEFAULT_BENIGN_SAMPLE,
        attack_per_category: int = DEFAULT_ATTACK_PER_CATEGORY,
        fp_threshold: float = DEFAULT_FP_THRESHOLD,
        seed: int = DEFAULT_SEED,
        target_rule: str | None = None,
    ):
        self.corpus_path = Path(corpus_path)
        self.benign_sample_size = benign_sample
        self.attack_per_category = attack_per_category
        self.fp_threshold = fp_threshold
        self.rng = random.Random(seed)
        self.target_rule = target_rule
        self.settings = _settings_for(Settings.load().policy_config)

    # ------------------------------------------------------------------ data

    def _load_corpus(self) -> list[dict]:
        records = []
        with self.corpus_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("split") == "test":
                    records.append(record)
        if not records:
            raise ValueError(f"No held-out test records in {self.corpus_path}")
        return records

    def _samples(self, records: list[dict]) -> tuple[list[dict], list[dict]]:
        benign = [r for r in records if not r.get("labels")]
        attacks = [r for r in records if r.get("labels")]
        by_category: dict[str, list[dict]] = {}
        for record in attacks:
            for category in record["labels"]:
                by_category.setdefault(category, []).append(record)
        picked: dict[str, dict] = {}
        for _category, pool in sorted(by_category.items()):
            for record in self.rng.sample(pool, min(self.attack_per_category, len(pool))):
                picked.setdefault(record["id"], record)
        benign_pick = self.rng.sample(benign, min(self.benign_sample_size, len(benign)))
        return benign_pick, sorted(picked.values(), key=lambda r: r["id"])

    # ------------------------------------------------------- observe (plan 1)

    def _baseline_pass(self, firewall: Firewall, benign: list[dict], attacks: list[dict]):
        """Scan both samples once with the unmodified configuration."""
        _story(21, "RedTeam: Baseline Observation")
        baseline_benign, baseline_attacks = {}, {}
        started = time.perf_counter()
        for record in benign:
            baseline_benign[record["id"]] = _scan_record(firewall, record["text"], record.get("source", "user"))
        for record in attacks:
            baseline_attacks[record["id"]] = _scan_record(firewall, record["text"], record.get("source", "user"))
        victims: dict[str, set] = {}  # rule_id -> benign record ids it falsely flags
        for record_id, result in baseline_benign.items():
            if result["decision"] == "allow":
                continue
            for finding in result["findings"]:
                if finding.rule_id and finding.severity >= self.settings.sanitize_threshold:
                    victims.setdefault(finding.rule_id, set()).add(record_id)
        _redteam_event(
            "redteam.baseline_completed",
            benign=len(baseline_benign),
            attacks=len(baseline_attacks),
            false_positive_records=sum(1 for r in baseline_benign.values() if r["decision"] != "allow"),
            seconds=round(time.perf_counter() - started, 1),
        )
        _story(21, "RedTeam: Baseline Observation", completed=True)
        return baseline_benign, baseline_attacks, victims

    # ----------------------------------------------------------------- cycle

    def run_tune_cycle(self) -> dict:
        configure_logging(self.settings, component="redteam")
        memory = load_memory()
        analytics = _load_json(ANALYTICS_PATH, {})

        records = self._load_corpus()
        benign, attacks = self._samples(records)
        base_policy = self.settings.policy_config or {}
        base_rules = dict(base_policy.get("rules", {}))
        base_settings = _settings_for(base_policy)
        firewall = Firewall(base_settings)

        # PERCEIVE: decision-level ground truth from the baseline firewall.
        baseline_benign, baseline_attacks, victims = self._baseline_pass(firewall, benign, attacks)

        # PLAN: only rules that actually harm a benign record's decision.
        _story(20, "RedTeam: Perceive and Plan")
        targets = self._plan_targets(victims, analytics, memory)
        _redteam_event("redteam.plan_ready", targets=targets, victim_rules=len(victims))
        _story(20, "RedTeam: Perceive and Plan", completed=True, targets=len(targets))
        if not targets:
            summary = {
                "cycle": len(memory["cycles"]) + 1,
                "targets": [],
                "candidates": [],
                "note": (
                    "no decision-level false positives in the benign sample: "
                    "the configuration is clean where it matters (finding-level "
                    "noise below the policy threshold is not harm)"
                ),
            }
            self._finish_cycle(memory, summary)
            return summary

        cycle_summary = {"cycle": len(memory["cycles"]) + 1, "targets": targets, "candidates": []}
        try:
            for rule_id in targets:
                candidate = self._verify_rule(rule_id, victims, benign, attacks, baseline_benign, baseline_attacks, base_rules, base_settings, memory)
                cycle_summary["candidates"].append(candidate)
        finally:
            # RECOVER: the override registry is global; leave it exactly as the
            # baseline configuration had it, whatever happened above.
            set_rule_overrides(base_rules)
            _redteam_event("redteam.overrides_restored", rule_count=len(base_rules))

        self._finish_cycle(memory, cycle_summary)
        return cycle_summary

    def _plan_targets(self, victims: dict, analytics: dict, memory: dict) -> list[str]:
        """PLAN: rules with at least one decision-level victim in the sample,
        ranked by victim count then by the analytics finding-level FP rate.
        Skips rules whose exact (rule, weight) candidate pairs all failed in
        earlier cycles, and honors the optional --fp-threshold prior filter."""
        failed_pairs = {(entry["rule_id"], entry["weight"]) for entry in memory["failed_hypotheses"]}
        ranked = []
        for rule_id, record_ids in victims.items():
            if self.target_rule and rule_id != self.target_rule:
                continue
            fp_rate = (analytics.get("rules", {}).get(rule_id) or {}).get("fp_rate") or 0.0
            if self.fp_threshold and fp_rate < self.fp_threshold:
                continue
            if all((rule_id, weight) in failed_pairs for weight in WEIGHT_LADDER):
                continue
            ranked.append((len(record_ids), fp_rate, rule_id))
        ranked.sort(reverse=True)
        return [rule_id for _count, _fp, rule_id in ranked]

    def _verify_rule(self, rule_id, victims, benign_records, attack_records, baseline_benign, baseline_attacks, base_rules, base_settings, memory) -> dict:
        """ADAPT+VERIFY for one target rule: climb the weight ladder until both
        gates pass, or record the failed hypothesis."""
        _story(22, f"RedTeam: Verify Candidate for {rule_id}")
        rule_victims = victims.get(rule_id, set())
        if not rule_victims:
            # The analytics flagged this rule, but none of its false-positive
            # records landed in the sampled benign set: nothing to verify, and
            # no honest hypothesis either. Skip without polluting memory.
            _redteam_event("redteam.target_skipped", rule_id=rule_id, reason="no_victims_in_sample")
            return {"rule_id": rule_id, "victims": 0, "note": "victim records not in benign sample; raise --benign-sample", "attempts": []}
        candidate_record = {"rule_id": rule_id, "victims": len(rule_victims), "attempts": []}
        for weight in WEIGHT_LADDER:
            attempt = self._attempt_weight(weight, rule_id, rule_victims, benign_records, attack_records, baseline_benign, baseline_attacks, base_rules, base_settings)
            candidate_record["attempts"].append(attempt)
            if attempt["verdict"] == "accepted":
                pending = self._register_pending(rule_id, weight, attempt, memory)
                candidate_record["pending_id"] = pending["id"]
                break
            memory["failed_hypotheses"].append(
                {"rule_id": rule_id, "weight": weight, "reason": attempt["verdict"], "cycle": len(memory["cycles"]) + 1}
            )
        _story(22, f"RedTeam: Verify Candidate for {rule_id}", completed=True, verdict=candidate_record["attempts"][-1]["verdict"] if candidate_record["attempts"] else "none")
        return candidate_record

    def _attempt_weight(self, weight, rule_id, rule_victims, benign_records, attack_records, baseline_benign, baseline_attacks, base_rules, base_settings) -> dict:
        """One candidate: shadow firewall under {rule: {weight}}, both gates
        evaluated. The shadow Firewall constructor installs its overrides
        globally; they are restored before returning.

        Only records whose baseline findings include the target rule are
        re-scanned: every other detection layer sees identical inputs, so
        their findings — and therefore decisions — are provably unchanged."""
        affected = {
            record_id
            for record_id, result in {**baseline_benign, **baseline_attacks}.items()
            if any(finding.rule_id == rule_id for finding in result["findings"])
        }
        shadow_rules = {**base_rules, rule_id: {**base_rules.get(rule_id, {}), "weight": weight}}
        shadow = Firewall(_settings_for({**base_settings.policy_config, "rules": shadow_rules}))
        started = time.perf_counter()
        try:
            shadow_benign = {
                record["id"]: _scan_record(shadow, record["text"], record.get("source", "user"))
                for record in benign_records
                if record["id"] in affected
            }
            shadow_attacks = {
                record["id"]: _scan_record(shadow, record["text"], record.get("source", "user"))
                for record in attack_records
                if record["id"] in affected
            }
        finally:
            set_rule_overrides(base_rules)

        # Gate A: benign handling may only improve (loosen). No record that the
        # baseline allowed may become blocked/sanitized/isolated.
        new_victims = [
            record_id for record_id, result in shadow_benign.items()
            if result["decision"] != "allow" and baseline_benign[record_id]["decision"] == "allow"
        ]
        fixed_victims = [record_id for record_id in rule_victims if shadow_benign.get(record_id, {}).get("decision") == "allow"]
        # Gate B: attack protection may only improve (tighten or equal). A
        # record the baseline stopped must never pass in the shadow.
        lost_protection = [
            record_id for record_id, result in shadow_attacks.items()
            if baseline_attacks[record_id]["decision"] != "allow" and result["decision"] == "allow"
        ]
        verdict = "accepted" if not new_victims and not lost_protection and fixed_victims else "rejected"
        attempt = {
            "weight": weight,
            "verdict": verdict,
            "false_positives_before": len(rule_victims),
            "false_positives_after": len(rule_victims) - len(fixed_victims),
            "new_benign_victims": new_victims[:10],
            "lost_protection": lost_protection[:10],
            "seconds": round(time.perf_counter() - started, 1),
        }
        _redteam_event(
            "redteam.candidate_verified",
            rule_id=rule_id,
            weight=weight,
            verdict=verdict,
            fixed_victims=len(fixed_victims),
            new_victims=len(new_victims),
            lost_protection=len(lost_protection),
        )
        return attempt

    # ------------------------------------------------------- human gate I/O

    def _register_pending(self, rule_id: str, weight: float, attempt: dict, memory: dict) -> dict:
        pending = load_pending()
        existing = next(
            (
                item
                for item in pending["pending"]
                if item["rule_id"] == rule_id and item["status"] == "pending"
            ),
            None,
        )
        if existing is not None:
            return existing  # one open candidate per rule; do not queue duplicates
        candidate_id = f"CAND-{memory['next_candidate_id']:04d}"
        memory["next_candidate_id"] += 1
        entry = {
            "id": candidate_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": "rule_weight",
            "rule_id": rule_id,
            "override": {"weight": weight},
            "corpus": str(self.corpus_path),
            "evidence": {
                "false_positives_before": attempt["false_positives_before"],
                "false_positives_after": attempt["false_positives_after"],
                "lost_protection": attempt["lost_protection"],
                "new_benign_victims": attempt["new_benign_victims"],
            },
            "status": "pending",
        }
        pending["pending"].append(entry)
        # Persist both stores from the same source of truth so a crash cannot
        # desynchronize the id counter from the pending queue.
        _write_json(PENDING_PATH, pending)
        _write_json(MEMORY_PATH, memory)
        _redteam_event("redteam.candidate_pending", candidate_id=candidate_id, rule_id=rule_id, weight=weight)
        return entry

    def _finish_cycle(self, memory: dict, summary: dict):
        memory["cycles"].append({key: summary[key] for key in ("cycle", "targets", "candidates") if key in summary})
        _write_json(MEMORY_PATH, memory)
        _write_json(FINDINGS_PATH, summary)
        _redteam_event("redteam.cycle_completed", cycle=summary.get("cycle"), candidates=len(summary.get("candidates", [])))

    # ------------------------------------------------- phase 2: FN probing

    def run_probe_cycle(self) -> dict:
        """Phase 2 (``--probe``): the false-NEGATIVE direction.

        PERCEIVE  scan the held-out attack sample; records whose decision is
                  ``allow`` despite attack labels are misses. Below-threshold
                  rule findings on missed records are the leading evidence.
        PLAN      mutate every missed record into probe families (paraphrase
                  wrappers, base64/hex encodings, punctuation noise); a family
                  is SYSTEMATIC when most mutants stay missed too.
        ACT       for the rule with the strongest below-threshold evidence,
                  walk a severity-override ladder (raise the finding above the
                  policy threshold) and re-scan everything.
        VERIFY    gates mirror the tune loop inverted: at least one miss newly
                  caught, zero benign records newly mishandled, zero attack
                  records newly allowed. A severity raise is monotonic for its
                  own rule, so failures are honest, not transient.
        ADAPT     the first passing candidate becomes a pending severity fix
        HUMAN     ``--approve`` merges it exactly like a tune candidate.
        """
        import base64

        configure_logging(self.settings, component="redteam")
        memory = load_memory()

        records = self._load_corpus()
        _benign, attacks = self._samples(records)
        base_policy = self.settings.policy_config or {}
        base_rules = dict(base_policy.get("rules", {}))
        base_settings = _settings_for(base_policy)
        firewall = Firewall(base_settings)

        _story(30, "RedTeam Probe: Baseline Observation")
        baseline_attacks = {
            record["id"]: _scan_record(firewall, record["text"], record.get("source", "user"))
            for record in attacks
        }
        misses = {
            record_id: result
            for record_id, result in baseline_attacks.items()
            if result["decision"] == "allow"
        }
        _redteam_event("redteam_probe.baseline_completed", attacks=len(attacks), misses=len(misses))
        _story(30, "RedTeam Probe: Baseline Observation", completed=True)

        if not misses:
            summary = {
                "cycle": len(memory["cycles"]) + 1,
                "kind": "probe",
                "misses": 0,
                "note": "no missed attack records in the sample: nothing to probe",
            }
            self._finish_cycle(memory, summary)
            return summary

        corpus_rows = {record["id"]: record for record in attacks}

        # PLAN: below-threshold rule evidence per missed record + mutation
        # families. Evidence rules are the only rules a severity override can
        # help — a rule that never fired cannot be raised into firing.
        evidence_rules: dict[str, set] = {}
        unexplained: list[dict] = []
        probes: dict[str, dict] = {}
        for record_id, result in misses.items():
            text = corpus_rows[record_id]["text"]
            sub_threshold = [
                finding.rule_id
                for finding in result["findings"]
                if finding.severity > 0 and finding.severity < self.settings.sanitize_threshold
            ]
            for rule_id in sub_threshold:
                evidence_rules.setdefault(rule_id, set()).add(record_id)
            families = {
                "paraphrase-wrapper": [f"Hey, {text}", f"Please {text} right now."],
                "encoded-base64": [base64.b64encode(text.encode()).decode()],
                "encoded-hex": [text.encode().hex()],
                "punctuation-noise": [f"{text}!!", text.replace(" ", "  ", 1)],
            }
            still_missed = {}
            for family, mutants in families.items():
                missed_mutants = 0
                for mutant in mutants:
                    mutant_result = _scan_record(firewall, mutant, corpus_rows[record_id].get("source", "user"))
                    missed_mutants += mutant_result["decision"] == "allow"
                still_missed[family] = [missed_mutants, len(mutants)]
            systematic = [family for family, (missed, total) in still_missed.items() if missed >= total * 0.6]
            probes[record_id] = {"families": still_missed, "systematic": systematic}
            if not sub_threshold:
                unexplained.append({"id": record_id, "systematic_families": systematic})

        _redteam_event(
            "redteam_probe.planned",
            evidence_rules={rule: len(ids) for rule, ids in evidence_rules.items()},
            systematic_probes=sum(1 for probe in probes.values() if probe["systematic"]),
        )

        targets = self._plan_probe_targets(evidence_rules, memory)
        cycle_summary = {
            "cycle": len(memory["cycles"]) + 1,
            "kind": "probe",
            "misses": len(misses),
            "evidence_rules": {rule: len(ids) for rule, ids in evidence_rules.items()},
            "systematic_probe_records": sum(1 for probe in probes.values() if probe["systematic"]),
            "targets": targets,
            "candidates": [],
            "unexplained_misses": unexplained[:8],
        }
        try:
            for rule_id in targets:
                candidate = self._verify_probe_rule(
                    rule_id,
                    misses,
                    corpus_rows,
                    _benign,
                    attacks,
                    base_rules,
                    base_settings,
                    memory,
                )
                cycle_summary["candidates"].append(candidate)
        finally:
            set_rule_overrides(base_rules)
            _redteam_event("redteam_probe.overrides_restored", rule_count=len(base_rules))

        self._finish_cycle(memory, cycle_summary)
        return cycle_summary

    def _plan_probe_targets(self, evidence_rules: dict, memory: dict) -> list[str]:
        """Rules with below-threshold evidence on missed records, ranked by
        record count; pairs already failed in earlier probe cycles are skipped."""
        failed = {(entry["rule_id"], entry.get("severity")) for entry in memory["failed_hypotheses"]}
        ranked = []
        for rule_id, record_ids in evidence_rules.items():
            if self.target_rule and rule_id != self.target_rule:
                continue
            if all((rule_id, severity) in failed for severity in PROBE_SEVERITY_LADDER):
                continue
            ranked.append((len(record_ids), rule_id))
        ranked.sort(reverse=True)
        return [rule_id for _count, rule_id in ranked[:3]]

    def _verify_probe_rule(
        self,
        rule_id: str,
        misses: dict,
        corpus_rows: dict,
        benign: list[dict],
        attacks: list[dict],
        base_rules: dict,
        base_settings,
        memory: dict,
    ) -> dict:
        """Severity ladder for one evidence rule: raise the rule's severity so
        its below-threshold findings cross the policy line, verify both gates
        (new catches without new benign victims or lost protection), and
        register the first passing candidate."""
        import base64 as _b64
        import codecs as _codecs

        _ = _b64, _codecs  # mutation encoding kept local to the probe helpers
        current_severity = next(
            (
                rule["severity"]
                for rule in RULES_REGISTRY
                if rule["id"] == rule_id
            ),
            None,
        )
        if current_severity is None:
            current_severity = 0.8
        miss_ids = sorted(misses)
        benign_records = benign
        attack_records = attacks

        # Baseline benign/attack outcomes with the unmodified configuration.
        base_firewall = Firewall(base_settings)
        baseline_benign = {
            record["id"]: _scan_record(base_firewall, record["text"], record.get("source", "user"))
            for record in benign_records
        }
        baseline_attacks = {
            record["id"]: _scan_record(base_firewall, record["text"], record.get("source", "user"))
            for record in attack_records
        }

        attempt = {
            "rule_id": rule_id,
            "current_severity": current_severity,
            "tried": [],
            "misses_before": len(miss_ids),
            "false_positives_before": sum(1 for r in baseline_benign.values() if r["decision"] != "allow"),
        }
        for severity in PROBE_SEVERITY_LADDER:
            if severity <= current_severity:
                continue
            attempt["tried"].append(severity)
            set_rule_overrides({**base_rules, rule_id: {"severity": severity}})
            probe_firewall = Firewall(base_settings)
            newly_caught = 0
            for record_id in miss_ids:
                result = _scan_record(probe_firewall, corpus_rows[record_id]["text"], corpus_rows[record_id].get("source", "user"))
                newly_caught += result["decision"] != "allow"
            new_benign_victims = 0
            for record in benign_records:
                result = _scan_record(probe_firewall, record["text"], record.get("source", "user"))
                new_benign_victims += (
                    result["decision"] != "allow"
                    and baseline_benign[record["id"]]["decision"] == "allow"
                )
            lost_protection = 0
            for record in attack_records:
                result = _scan_record(probe_firewall, record["text"], record.get("source", "user"))
                lost_protection += (
                    result["decision"] == "allow"
                    and baseline_attacks[record["id"]]["decision"] != "allow"
                )
            passed = newly_caught >= 1 and new_benign_victims == 0 and lost_protection == 0
            _redteam_event(
                "redteam_probe.candidate_evaluated",
                rule_id=rule_id,
                severity=severity,
                newly_caught=newly_caught,
                new_benign_victims=new_benign_victims,
                lost_protection=lost_protection,
                passed=passed,
            )
            if passed:
                set_rule_overrides(base_rules)
                return self._register_probe_pending(rule_id, severity, attempt, newly_caught, memory)
        set_rule_overrides(base_rules)
        memory["failed_hypotheses"].extend(
            {"rule_id": rule_id, "severity": severity, "kind": "probe"} for severity in attempt["tried"]
        )
        _write_json(MEMORY_PATH, memory)
        return {**attempt, "outcome": "no severity met both gates"}

    def _register_probe_pending(self, rule_id: str, severity: float, attempt: dict, newly_caught: int, memory: dict) -> dict:
        pending = load_pending()
        existing = next(
            (
                item
                for item in pending["pending"]
                if item["rule_id"] == rule_id and item["status"] == "pending"
            ),
            None,
        )
        if existing is not None:
            return existing
        candidate_id = f"CAND-{memory['next_candidate_id']:04d}"
        memory["next_candidate_id"] += 1
        entry = {
            "id": candidate_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": "rule_severity_probe",
            "rule_id": rule_id,
            "override": {"severity": severity},
            "corpus": str(self.corpus_path),
            "evidence": {
                "misses_before": attempt["misses_before"],
                "newly_caught": newly_caught,
                "current_severity": attempt["current_severity"],
            },
            "status": "pending",
        }
        pending["pending"].append(entry)
        _write_json(PENDING_PATH, pending)
        _write_json(MEMORY_PATH, memory)
        _redteam_event("redteam_probe.candidate_pending", candidate_id=candidate_id, rule_id=rule_id, severity=severity)
        return entry


    # ------------------------------------------------------------- approval

    def approve(self, candidate_id: str, corpus: Path | None = None, reason: str = "") -> dict:
        """HUMAN GATE: merge the pending override into the policy JSON file and
        re-verify with a fresh firewall; any gate failure rolls the file back.
        The human's ``reason`` is stored in the pending entry (audit record).

        Verification corpus, strictest first: the explicit ``corpus`` argument,
        else the corpus the candidate was derived from (recorded provenance),
        else the default full held-out corpus. The default is deliberately the
        largest scope: a candidate that survives its own demo corpus can still
        regress a real attack record, and only the full-corpus check sees it."""
        pending = load_pending()
        entry = next((item for item in pending["pending"] if item["id"] == candidate_id and item["status"] == "pending"), None)
        if entry is None:
            raise ValueError(f"No pending candidate {candidate_id}")
        verify_corpus = corpus or (Path(entry["corpus"]) if entry.get("corpus") else None) or self.corpus_path
        policy_path = Path(os.getenv("PIF_POLICY_FILE", POLICY_OVERRIDE_PATH))
        original_bytes = policy_path.read_bytes() if policy_path.is_file() else None
        document = _load_json(policy_path, {}) if policy_path.is_file() else {}
        document.setdefault("rules", {})[entry["rule_id"]] = {**document.get("rules", {}).get(entry["rule_id"], {}), **entry["override"]}
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(policy_path, document)
        _redteam_event("redteam.approve_applied", candidate_id=candidate_id, policy_file=str(policy_path))

        # Post-approval verification: fresh firewalls, old vs new configuration.
        verifier = RedTeamAgent(
            corpus_path=verify_corpus,
            benign_sample=self.benign_sample_size,
            attack_per_category=self.attack_per_category,
            fp_threshold=self.fp_threshold,
            seed=DEFAULT_SEED,
            target_rule=self.target_rule,
        )
        try:
            records = verifier._load_corpus()
            benign, attacks = verifier._samples(records)
            base_settings = _settings_for(Settings.load().policy_config)
            baseline = Firewall(base_settings)
            baseline_benign = {record["id"]: _scan_record(baseline, record["text"], record.get("source", "user")) for record in benign}
            baseline_attacks = {record["id"]: _scan_record(baseline, record["text"], record.get("source", "user")) for record in attacks}
            approved_settings = _settings_for(document)
            approved = Firewall(approved_settings)
            for record in benign:
                before = baseline_benign[record["id"]]["decision"]
                after = _scan_record(approved, record["text"], record.get("source", "user"))["decision"]
                if before == "allow" and after != "allow":
                    raise AssertionError(f"benign regression on {record['id']}")
            for record in attacks:
                before = baseline_attacks[record["id"]]["decision"]
                after = _scan_record(approved, record["text"], record.get("source", "user"))["decision"]
                if before != "allow" and after == "allow":
                    raise AssertionError(f"protection regression on {record['id']}")
        except Exception as error:
            if original_bytes is None:
                policy_path.unlink(missing_ok=True)
            else:
                policy_path.write_bytes(original_bytes)
            entry["status"] = "rollback"
            entry["rollback_reason"] = str(error)
            if reason:
                entry["decision_reason"] = reason[:300]
            self._save_pending_entry(entry)
            # A rolled-back candidate is a failed hypothesis: the same
            # (rule, weight) pair must not be re-proposed or re-approved.
            memory = load_memory()
            memory["failed_hypotheses"].append(
                {
                    "rule_id": entry["rule_id"],
                    "weight": entry.get("override", {}).get("weight"),
                    "reason": f"approval_rollback: {error}",
                    "cycle": None,
                }
            )
            _write_json(MEMORY_PATH, memory)
            _redteam_event("redteam.approve_rolled_back", candidate_id=candidate_id, reason=str(error))
            return entry

        entry["status"] = "approved"
        entry["policy_file"] = str(policy_path)
        if reason:
            entry["decision_reason"] = reason[:300]
        self._save_pending_entry(entry)
        _redteam_event("redteam.approve_verified", candidate_id=candidate_id)
        return entry

    def reject(self, candidate_id: str, reason: str = "") -> dict:
        pending = load_pending()
        entry = next((item for item in pending["pending"] if item["id"] == candidate_id), None)
        if entry is None:
            raise ValueError(f"No pending candidate {candidate_id}")
        entry["status"] = "rejected"
        if reason:
            entry["decision_reason"] = reason[:300]
        self._save_pending_entry(entry)
        return entry

    @staticmethod
    def _save_pending_entry(entry: dict):
        pending = load_pending()
        pending["pending"] = [item if item["id"] != entry["id"] else entry for item in pending["pending"]]
        _write_json(PENDING_PATH, pending)


def status() -> dict:
    return {"memory": load_memory(), "pending": load_pending()}


def main():
    parser = argparse.ArgumentParser(description="PIF red-team / self-tuning agent (dry-run by default)")
    parser.add_argument("--tune", action="store_true", help="run one self-tuning cycle (FP direction)")
    parser.add_argument("--probe", action="store_true", help="run one FN-probe cycle: mutation-based attack generation against the weakest-recall families (Phase 2)")
    parser.add_argument("--status", action="store_true", help="show memory and pending candidates")
    parser.add_argument("--approve", metavar="CAND-ID", help="merge a pending override into the policy file (human gate)")
    parser.add_argument("--reject", metavar="CAND-ID", help="reject a pending override")
    parser.add_argument("--reason", default="", help="human decision reason stored with --approve/--reject")
    parser.add_argument("--corpus", type=Path, default=None, help="evaluator-format JSONL corpus (tune: corpus to probe; approve: verification scope; default: data/processed/eval_full.jsonl)")
    parser.add_argument("--benign-sample", type=int, default=DEFAULT_BENIGN_SAMPLE)
    parser.add_argument("--attack-per-category", type=int, default=DEFAULT_ATTACK_PER_CATEGORY)
    parser.add_argument("--fp-threshold", type=float, default=DEFAULT_FP_THRESHOLD, help="prior filter: only target rules whose analytics finding-level FP rate is at or above this value (0 disables)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--target-rule", default=None, help="restrict the cycle to one rule id")
    args = parser.parse_args()

    if args.approve:
        agent = RedTeamAgent(corpus_path=args.corpus or EVAL_CORPUS_PATH)
        print(json.dumps(agent.approve(args.approve, corpus=args.corpus, reason=args.reason), indent=2))
        return
    if args.reject:
        print(json.dumps(RedTeamAgent().reject(args.reject, reason=args.reason), indent=2))
        return
    if args.status or not (args.tune or args.probe):
        print(json.dumps(status(), indent=2))
        if not args.status:
            print("\nNothing done. Use --tune (FP direction) or --probe (FN direction) to run one cycle.")
        return

    agent = RedTeamAgent(
        corpus_path=args.corpus or EVAL_CORPUS_PATH,
        benign_sample=args.benign_sample,
        attack_per_category=args.attack_per_category,
        fp_threshold=args.fp_threshold,
        seed=args.seed,
        target_rule=args.target_rule,
    )
    if args.probe:
        print(json.dumps(agent.run_probe_cycle(), indent=2))
        return
    print(json.dumps(agent.run_tune_cycle(), indent=2))


if __name__ == "__main__":
    main()
