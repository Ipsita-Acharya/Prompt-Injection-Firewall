import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import json
import logging
import math
import platform
import statistics
import time
from pathlib import Path

from pif.detection.semantic import LABELS
from pif.engncore import Firewall
from scripts.dataset import read_dataset
from pif.schemas import ContentInput, ScanRequest
from pif.reporting import evaluation_report_options, write_report
from pif.settings import Settings
from pif.observability import configure_logging, logger


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def wilson(successes, total):
    if not total:
        return None
    probability, squared = successes / total, 1.96**2
    center = (probability + squared / (2 * total)) / (1 + squared / total)
    radius = (
        1.96
        * math.sqrt(probability * (1 - probability) / total + squared / (4 * total**2))
        / (1 + squared / total)
    )
    return [max(0, center - radius), min(1, center + radius)]


def evaluate(data: Path, settings: Settings):
    logger.info("evaluation.started", extra={"event_fields": dict()})
    records = [record for record in read_dataset(data) if record["split"] == "test"]
    if not records:
        raise ValueError("No held-out test records")
    firewall = Firewall(settings)
    if not firewall.ready:
        raise ValueError("Classifier unavailable")
    categories = [*LABELS[1:], "encoded_instruction", "indirect_injection"]
    counts = {category: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for category in categories}
    outcomes, latencies = [], []
    attack_count = benign_count = detected = false_positives = incomplete = 0
    for index, record in enumerate(records):
        source = record.get("source", "user")
        request = (
            ScanRequest(user_prompt=record["text"])
            if source == "user"
            else ScanRequest(
                user_prompt="Summarize this source",
                content=[ContentInput(source=source, text=record["text"])],
            )
        )
        start = time.perf_counter()
        result = firewall.scan(request)
        logger.debug("evaluation.case_completed", extra={"event_fields": dict(case_index=index, scan_id=result.scan_id, expected_attack=bool(record["labels"]), decision=result.decision, status=result.status)})
        latencies.append((time.perf_counter() - start) * 1000)
        expected, predicted = set(record["labels"]), set(result.attacks)
        incomplete += result.status != "complete"
        if expected:
            attack_count += 1
            detected += result.malicious is True
        else:
            benign_count += 1
            false_positives += result.decision != "allow"
        for category, values in counts.items():
            key = (
                "tp"
                if category in expected and category in predicted
                else "fn"
                if category in expected
                else "fp"
                if category in predicted
                else "tn"
            )
            values[key] += 1
        outcomes.append(
            {
                "id": record["id"],
                "family": record["family"],
                "source": source,
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "decision": result.decision,
                "status": result.status,
            }
        )
        firewall.sessions.reset(result.session_id, "local")
    # Provenance breakdown (v6.1): the corpus mixes self-generated records
    # (templates written by the same codebase as the rules — circular by
    # construction), matched twins (same), and the public deepset rows
    # relabeled from dataset ground truth (RULE-023 was authored from that
    # set's misses, so its rows are development-adjacent, not fully blind).
    # Publishing the split keeps the headline number honest about what it
    # does and does not demonstrate.
    provenance_groups = {
        "generated": "generated-",
        "twin": "twin-",
        "public-deepset": "hf-",
        "authored-demo": "",
    }

    def _group_of(family: str) -> str:
        for group, prefix in provenance_groups.items():
            if prefix and family.startswith(prefix):
                return group
        return "authored-demo"

    provenance_breakdown: dict[str, dict] = {}
    for record, outcome in zip(records, outcomes, strict=True):
        group = _group_of(record["family"])
        entry = provenance_breakdown.setdefault(
            group, {"samples": 0, "attack_samples": 0, "caught": 0, "benign_samples": 0, "false_positives": 0}
        )
        entry["samples"] += 1
        if outcome["expected"]:
            entry["attack_samples"] += 1
            entry["caught"] += outcome["decision"] != "allow"
        else:
            entry["benign_samples"] += 1
            entry["false_positives"] += outcome["decision"] != "allow"
    for group, entry in provenance_breakdown.items():
        entry["attack_recall"] = ratio(entry["caught"], entry["attack_samples"])
        entry["attack_recall_95ci"] = wilson(entry["caught"], entry["attack_samples"])
        entry["benign_fpr"] = ratio(entry["false_positives"], entry["benign_samples"])
    metrics = {}
    for category, values in counts.items():
        metrics[category] = {
            **values,
            "precision": ratio(values["tp"], values["tp"] + values["fp"]),
            "recall": ratio(values["tp"], values["tp"] + values["fn"]),
            "recall_95ci": wilson(values["tp"], values["tp"] + values["fn"]),
        }
    # Matched-twin per-channel FPR (v6.0): benign twins hidden the same way as
    # attack twins — a detector that reacts to "content was hidden" rather
    # than "the hidden content is an attack" shows up here, per channel.
    twin_channels: dict[str, dict] = {}
    for record, outcome in zip(records, outcomes, strict=True):
        family = record["family"]
        if not family.startswith("twin-") or record["labels"]:
            continue
        channel = family.removeprefix("twin-").rsplit("-", 1)[0]
        entry = twin_channels.setdefault(channel, {"benign": 0, "false_positives": 0})
        entry["benign"] += 1
        entry["false_positives"] += outcome["decision"] != "allow"
    for channel, entry in twin_channels.items():
        entry["fpr"] = ratio(entry["false_positives"], entry["benign"])
        entry["fpr_95ci"] = wilson(entry["false_positives"], entry["benign"])
    adequately_sampled = [
        values for values in metrics.values() if values["tp"] + values["fn"] >= 100
    ]
    adequate = len(adequately_sampled) >= 7 and benign_count >= 500
    passed = (
        adequate
        and ratio(detected, attack_count) >= 0.95
        and ratio(false_positives, benign_count) <= 0.02
        and sum(values["recall"] >= 0.9 for values in adequately_sampled) >= 7
        and incomplete == 0
    )
    logger.info("evaluation.completed", extra={"event_fields": dict(test_samples=len(records), attack_samples=attack_count, benign_samples=benign_count, dataset_size_gate=adequate, numerical_release_gate=passed)})
    return {
        "release_status": "candidate: independent provenance review required"
        if passed
        else "prototype: D2 reliability not established",
        "coverage": firewall.coverage,
        "test_samples": len(records),
        "test_families": len({record["family"] for record in records}),
        "attack_samples": attack_count,
        "benign_samples": benign_count,
        "attack_recall": ratio(detected, attack_count),
        "attack_recall_95ci": wilson(detected, attack_count),
        "benign_false_positive_rate": ratio(false_positives, benign_count),
        "benign_fpr_95ci": wilson(false_positives, benign_count),
        "incomplete_inspections": incomplete,
        "dataset_size_gate": adequate,
        "numerical_release_gate": passed,
        "provenance_breakdown": provenance_breakdown,
        "provenance_note": (
            "generated/twin groups are self-authored (circular by construction; "
            "regression value only). public-deepset rows carry dataset ground "
            "truth but RULE-023 was authored from their misses — "
            "development-adjacent, not fully blind. Only scripts/build_public_eval.py "
            "against datasets the rules never saw is fully independent evidence."
        ),
        "twin_channel_fpr": twin_channels,
        "per_category": metrics,
        "outcomes": outcomes,
        "timing": {
            "median_ms": statistics.median(latencies),
            "max_ms": max(latencies),
            "model_startup_excluded": True,
            "platform": platform.platform(),
            "cpu": platform.processor(),
            "python": platform.python_version(),
        },
        "limitations": [
            "Authored demo cases are smoke tests, not independent reliability evidence.",
            "English-first text evaluation; OCR and arbitrary novel attacks are not certified.",
            "Numerical gates do not substitute for provenance review or integration authorization tests.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate frozen held-out families without adjusting thresholds"
    )
    parser.add_argument("--data", type=Path, default=Path("data/processed/eval_full.jsonl"))
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings, component="evaluation")
    try:
        report = evaluate(args.data, settings)
    except Exception as error:
        logger.error("evaluation.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        raise
    options = evaluation_report_options()
    payload = dict(report)
    if not options["include_outcomes"]:
        payload.pop("outcomes", None)
    written = write_report(
        "evaluation",
        payload,
        csv_rows=[
            {
                "category": category,
                "tp": values["tp"],
                "fp": values["fp"],
                "fn": values["fn"],
                "tn": values["tn"],
                "precision": values["precision"],
                "recall": values["recall"],
            }
            for category, values in report["per_category"].items()
        ],
    )
    # Versioned negative results (v6.0): the false positives and false
    # negatives of THIS build against THIS corpus, shipped beside the report.
    negatives = write_report(
        "evaluation_negatives",
        {"false_positives": [o for o in report["outcomes"] if o["expected"] == [] and o["decision"] != "allow"],
         "false_negatives": [o for o in report["outcomes"] if o["expected"] and o["decision"] == "allow"]},
        csv_rows=[o | {"kind": "false_positive"} for o in report["outcomes"] if o["expected"] == [] and o["decision"] != "allow"]
        + [o | {"kind": "false_negative"} for o in report["outcomes"] if o["expected"] and o["decision"] == "allow"],
        csv_name="evaluation_negatives",
    )
    logger.info("evaluation.report_written", extra={"event_fields": dict(case_count=len(report["outcomes"]), outputs={key: str(path) for key, path in {**written, **negatives}.items()})})
    print(
        json.dumps(
            {
                key: report[key]
                for key in [
                    "release_status",
                    "test_samples",
                    "attack_recall",
                    "benign_false_positive_rate",
                    "dataset_size_gate",
                ]
            },
            indent=2,
        )
    )
    print("Full report:", ", ".join(str(path) for path in written.values()))


if __name__ == "__main__":
    main()
