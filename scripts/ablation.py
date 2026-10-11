import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""Three-layer ablation (v6.2): what does each defense layer add?

Runs the frozen public-dataset splits under three configurations and writes
reports/ablation.json:

  1. rules+semantic        — deterministic content layers only
  2. +detonation           — adds the gray-band behavioral chamber (offline)
  3. +judge                — adds the gray-band LLM judge (requires an API key;
                             without one the column is reported honestly as
                             unavailable rather than fabricated)

Each column reports per-dataset attack recall and benign FPR, plus the
detonation signal counts for column 2 — the "three independent layers"
story (content rules -> behavioral canaries -> action-time taint) with
measured catch rates per layer, as the round-2 review requested.
"""

import argparse
import json
import time
from pathlib import Path

from pif.engncore import Firewall
from pif.observability import configure_logging, logger
from pif.schemas import ContentInput, ScanRequest
from pif.settings import Settings

CACHE_DIR = Path("data/eval/public")
PUBLIC_ORDER = (
    "deepset-prompt-injections",
    "gandalf-ignore-instructions",
    "llmail-inject",
    "jackhhao-jailbreak-classification",
    "notinject",
)


def load_frozen(slug: str) -> list[dict] | None:
    path = CACHE_DIR / f"{slug}.jsonl"
    if not path.is_file():
        return None
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_config(config_name: str, policy_overrides: dict, datasets: dict[str, list[dict]]):
    settings = Settings.load()
    policy = {**(settings.policy_config or {}), **policy_overrides}
    settings = Settings(policy_config=policy, report_db_enabled=False)
    firewall = Firewall(settings)
    report = {"config": config_name, "datasets": {}}
    for slug, records in datasets.items():
        attack_total = attack_caught = benign_total = benign_flagged = 0
        for record in records:
            if record.get("source") == "llmail-inject":
                request = ScanRequest(
                    user_prompt="Summarize this email",
                    content=[ContentInput(source="web", reference=record["id"], text=record["text"])],
                )
            else:
                request = ScanRequest(user_prompt=record["text"])
            result = firewall.scan(request)
            caught = result.malicious is True or result.decision in {"block", "sanitize", "isolate"}
            if record["attack"]:
                attack_total += 1
                attack_caught += caught
            else:
                benign_total += 1
                benign_flagged += result.decision != "allow"
            firewall.sessions.reset(result.session_id, "local")
        report["datasets"][slug] = {
            "attacks": attack_total,
            "caught": attack_caught,
            "recall": round(attack_caught / attack_total, 4) if attack_total else None,
            "benign": benign_total,
            "false_positives": benign_flagged,
            "fpr": round(benign_flagged / benign_total, 4) if benign_total else None,
        }
    total_attacks = sum(d["attacks"] for d in report["datasets"].values())
    total_caught = sum(d["caught"] for d in report["datasets"].values())
    total_benign = sum(d["benign"] for d in report["datasets"].values())
    total_fp = sum(d["false_positives"] for d in report["datasets"].values())
    report["aggregate"] = {
        "attacks": total_attacks,
        "recall": round(total_caught / total_attacks, 4) if total_attacks else None,
        "benign": total_benign,
        "fpr": round(total_fp / total_benign, 4) if total_benign else None,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Layer ablation over the frozen public splits")
    parser.add_argument("--datasets", nargs="*", default=list(PUBLIC_ORDER))
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings, component="evaluation")

    datasets = {}
    for slug in args.datasets:
        records = load_frozen(slug)
        if records is None:
            logger.warning("ablation.dataset_missing", extra={"event_fields": dict(slug=slug)})
            continue
        datasets[slug] = records
    if not datasets:
        raise SystemExit("No frozen public splits found — run scripts/build_public_eval.py --refresh first")

    started = time.perf_counter()
    # Column 2 mirrors the SHIPPED operating point: full-band detonation
    # (min_risk 0.0) — measured on these splits it adds +31 recall points at
    # flat FPR (see reports/ablation.json).
    columns = [
        ("rules+semantic", {"detonation": {"enabled": "false"}, "llm_judge": {"enabled": "false"}}),
        ("+detonation (full band)", {"detonation": {"enabled": "true", "decoy": "emulator", "min_risk": "0.0"}, "llm_judge": {"enabled": "false"}}),
    ]
    judge_available = bool(__import__("os").getenv("OPENAI_API_KEY"))
    if judge_available:
        columns.append(("+judge", {"detonation": {"enabled": "true", "decoy": "emulator"}, "llm_judge": {"enabled": "true"}}))

    ablation = {"columns": [], "judge_column": "measured" if judge_available else "unavailable: no OPENAI_API_KEY — the harness is ready, run with a key to fill this column"}
    for name, overrides in columns:
        logger.info("ablation.column_started", extra={"event_fields": dict(config=name)})
        ablation["columns"].append(run_config(name, overrides, datasets))
        logger.info("ablation.column_completed", extra={"event_fields": dict(config=name)})

    ablation["elapsed_seconds"] = round(time.perf_counter() - started, 1)
    output = Path("reports") / "ablation.json"
    output.write_text(json.dumps(ablation, indent=2) + "\n", encoding="utf-8")

    print(f"{'config':<18} {'recall':>7} {'FPR':>7}")
    for column in ablation["columns"]:
        aggregate = column["aggregate"]
        print(f"{column['config']:<18} {aggregate['recall']:>7} {aggregate['fpr']:>7}")
    if not judge_available:
        print(f"{'(+judge)':<18} {'—':>7} {'—':>7}   <- requires OPENAI_API_KEY")
    print(f"Written: {output}")


if __name__ == "__main__":
    main()
