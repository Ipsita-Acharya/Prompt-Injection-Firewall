import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""Per-rule false-positive analytics (spec §13/§14).

Runs the held-out corpus through the firewall and aggregates, per RULE-### /
FUZZY-### detection id: matches on attack records, matches on benign records
(false positives) and the benign FP rate. Produces reports/rule_analytics.json
plus a console table in the spec's format. The report may carry a conservative
suggestion (monitor / consider weight reduction) for rules above the FP
threshold; it never changes runtime behavior by itself.
"""

import argparse
import json
import statistics
import time
from pathlib import Path

from pif.engncore import Firewall
from scripts.dataset import read_dataset
from pif.observability import configure_logging, logger
from pif.schemas import ContentInput, ScanRequest
from pif.reporting import rule_analytics_report_options, write_report
from pif.settings import Settings

FP_SUGGESTION_THRESHOLD = 0.10


def analyze(data: Path, settings: Settings) -> dict:
    records = [record for record in read_dataset(data) if record["split"] == "test"]
    if not records:
        raise ValueError("No held-out test records")
    firewall = Firewall(settings)
    if not firewall.ready:
        raise ValueError("Classifier unavailable")

    stats: dict[str, dict] = {}
    latencies = []
    for record in records:
        source = record.get("source", "user")
        request = (
            ScanRequest(user_prompt=record["text"])
            if source == "user"
            else ScanRequest(
                user_prompt="Summarize this source",
                content=[ContentInput(source=source, text=record["text"])],
            )
        )
        started = time.perf_counter()
        result = firewall.scan(request)
        latencies.append((time.perf_counter() - started) * 1000)
        if result.session_id:
            firewall.sessions.reset(result.session_id, "local")
        is_attack = bool(record["labels"])
        seen_rules = {finding.rule_id for finding in result.findings if finding.rule_id}
        for rule_id in seen_rules:
            values = stats.setdefault(
                rule_id, {"attack_matches": 0, "benign_matches": 0, "records": 0}
            )
            values["records"] += 1
            values["attack_matches" if is_attack else "benign_matches"] += 1
    firewall.sessions.prune()

    benign_records = sum(1 for record in records if not record["labels"])
    attack_records = len(records) - benign_records
    report = {
        "dataset": str(data),
        "records": len(records),
        "attack_records": attack_records,
        "benign_records": benign_records,
        "median_latency_ms": round(statistics.median(latencies), 2) if latencies else None,
        "rules": {},
    }
    for rule_id, values in sorted(stats.items()):
        benign_matches = values["benign_matches"]
        fp_rate = benign_matches / benign_records if benign_records else None
        suggestion = None
        if fp_rate is not None and fp_rate > FP_SUGGESTION_THRESHOLD:
            suggestion = (
                "monitoring-only candidate: benign false-positive rate above "
                f"{FP_SUGGESTION_THRESHOLD:.0%}; consider a weight reduction via "
                "PIF_POLICY_FILE rules overrides after review"
            )
        report["rules"][rule_id] = {
            **values,
            "fp_rate": round(fp_rate, 4) if fp_rate is not None else None,
            "suggestion": suggestion,
        }
    return report


def print_table(report: dict):
    print(f"{'Rule':<10} {'Matches':>8} {'Attack':>7} {'Benign':>7} {'FP rate':>8}")
    for rule_id, values in report["rules"].items():
        fp_rate = values["fp_rate"]
        fp_text = f"{fp_rate:>8.2%}" if fp_rate is not None else f"{'n/a':>8}"
        print(
            f"{rule_id:<10} {values['records']:>8} {values['attack_matches']:>7} "
            f"{values['benign_matches']:>7} {fp_text}"
        )


def main():
    parser = argparse.ArgumentParser(description="Per-rule match/FP analytics report")
    parser.add_argument("--data", type=Path, default=Path("data/processed/eval_full.jsonl"))
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings, component="evaluation")
    report = analyze(args.data, settings)
    options = rule_analytics_report_options()
    payload = dict(report)
    if not options["include_suggestions"]:
        for values in payload.get("rules", {}).values():
            values.pop("suggestion", None)
    written = write_report(
        "rule_analytics",
        payload,
        csv_rows=[
            {
                "rule": rule_id,
                "matches": values["records"],
                "attack_matches": values["attack_matches"],
                "benign_matches": values["benign_matches"],
                "fp_rate": values["fp_rate"],
            }
            for rule_id, values in report["rules"].items()
        ],
    )
    print_table(report)
    flagged = [rule for rule, values in report["rules"].items() if values["suggestion"]]
    logger.info(
        "analytics.completed",
        extra={"event_fields": dict(rules=len(report["rules"]), flagged=len(flagged))},
    )
    print("Full report:", ", ".join(str(path) for path in written.values()))


if __name__ == "__main__":
    main()
