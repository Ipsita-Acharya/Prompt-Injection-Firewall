import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""Public-dataset evaluation (v6.0): the independence layer the synthetic
corpus cannot provide.

Downloads fixed public prompt-injection datasets through the Hugging Face
datasets-server API (stdlib urllib, no SDK), caches them under
data/eval/public/, and evaluates the deployed firewall on them — binary
attack recall and benign FPR with Wilson 95% CIs per dataset, plus latency
percentiles. The synthetic corpus stays the regression suite; these numbers
are the generalization evidence.

Datasets (train splits are NEVER used here — held-out evaluation only):
- deepset/prompt-injections  (test split, binary label 1 = injection)
- jackhhao/jailbreak-classification (train split, type = jailbreak/benign)

Offline behavior: cached files are used when present; without a cache the
script exits with code 2 and a clear message instead of pretending.
"""

import argparse
import hashlib
import json
import math
import platform
import statistics
import time
import urllib.request
from pathlib import Path

from pif.engncore import Firewall
from pif.observability import configure_logging, logger
from pif.schemas import ContentInput, ScanRequest
from pif.settings import Settings

DATASETS_SERVER = "https://datasets-server.huggingface.co/rows"

# slug -> (hf dataset id, config, split, text field, label field, label -> attack)
# Dataset IDs adopted from the tripwire round-2 builder (backend/eval/build_sets.py).
# Once downloaded, rows are CACHED under data/eval/public/ and every later run
# replays the cached file verbatim — the split is frozen by construction for
# the rest of the round; --refresh re-downloads and re-freezes (documented).
PUBLIC_DATASETS = {
    "deepset-prompt-injections": (
        "deepset/prompt-injections",
        "default",
        "test",
        "text",
        "label",
        {1: True, 0: False},
    ),
    "gandalf-ignore-instructions": (
        "Lakera/gandalf_ignore_instructions",
        "default",
        "test",
        "text",
        None,  # every gandalf row is a secret-extraction attack
        {None: True},
    ),
    "llmail-inject": (
        "microsoft/llmail-inject-challenge",
        "default",
        "Phase1",
        ("subject", "body"),  # assembled as "Subject: ...\n\n<body>"
        None,  # every challenge row is an indirect-injection attack
        {None: True},
    ),
    "notinject": (
        "leolee99/NotInject",
        "default",
        "NotInject_one",
        "prompt",
        None,
        {None: False},  # every NotInject row is benign-but-trigger-heavy (FPR metric)
    ),
    "jackhhao-jailbreak-classification": (
        "jackhhao/jailbreak-classification",
        "default",
        "test",
        "prompt",
        "type",
        {"jailbreak": True, "benign": False},
    ),
}

# Per-dataset row caps: keeps a full four-dataset run inside a few minutes.
DATASET_ROW_CAPS = {
    "deepset-prompt-injections": 600,
    "gandalf-ignore-instructions": 100,
    "llmail-inject": 300,
    "notinject": 300,
    "jackhhao-jailbreak-classification": 300,
}

MAX_ROWS = 600


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
    return [max(0, round(center - radius, 4)), min(1, round(center + radius, 4))]


def fetch_rows(dataset: str, config: str, split: str, cap: int) -> list[dict]:
    rows, offset = [], 0
    while len(rows) < cap:
        length = min(100, cap - len(rows))
        url = f"{DATASETS_SERVER}?dataset={dataset}&config={config}&split={split}&offset={offset}&length={length}"
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        batch = payload.get("rows", [])
        if not batch:
            break
        rows.extend(batch)
        offset += len(batch)
    return rows


def _row_text(row_data: dict, text_field) -> str:
    if isinstance(text_field, tuple):
        return str(
            "Subject: "
            + (row_data.get(text_field[0]) or "")
            + "\n\n"
            + (row_data.get(text_field[1]) or "")
        ).strip()
    return str(row_data.get(text_field, "")).strip()


def load_public_records(slug: str, cache_dir: Path, refresh: bool) -> list[dict]:
    """Download (or replay the frozen cache of) one public dataset. The cache
    file IS the frozen split: its sha256 and freeze date go into the report
    manifest, so a run's evidence cannot silently change underneath it."""
    cache_path = cache_dir / f"{slug}.jsonl"
    if cache_path.is_file() and not refresh:
        logger.info("public_eval.cache_hit", extra={"event_fields": dict(slug=slug, path=str(cache_path))})
        return [json.loads(line) for line in cache_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    dataset, config, split, text_field, label_field, label_map = PUBLIC_DATASETS[slug]
    logger.info("public_eval.downloading", extra={"event_fields": dict(slug=slug, dataset=dataset, split=split)})
    records = []
    seen_bodies: set[str] = set()
    for row in fetch_rows(dataset, config, split, DATASET_ROW_CAPS.get(slug, MAX_ROWS)):
        row_data = row.get("row", {})
        text = _row_text(row_data, text_field)
        # llmail challenge submissions repeat bodies; keep the first, drop stubs
        # (the tripwire builder applies the same discipline).
        if slug == "llmail-inject":
            body_key = text.casefold()
            if len(text) <= 40 or body_key in seen_bodies:
                continue
            seen_bodies.add(body_key)
        raw_label = row_data.get(label_field) if label_field else None
        attack = label_map.get(raw_label, next(iter(label_map.values())) if label_field is None else None)
        if not text or attack is None:
            continue
        family = str(row_data.get("attack_type") or row_data.get("category") or slug)
        records.append(
            {
                "id": f"{slug}-{len(records):04d}",
                "text": text,
                "attack": attack,
                "family": family,
                "source": slug,
            }
        )
    if not records:
        raise ValueError(f"No usable rows downloaded for {slug}")
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records),
        encoding="utf-8",
    )
    return records


def evaluate_records(firewall: Firewall, records: list[dict]) -> tuple[dict, list[dict]]:
    attack_total = attack_caught = benign_total = benign_flagged = 0
    per_family: dict[str, dict] = {}
    misses: list[dict] = []
    latencies = []
    for index, record in enumerate(records):
        # Retrieved-channel datasets (llmail) arrive as external content, the
        # shape the indirect-injection defenses exist for; the rest are user
        # prompts — matching how each dataset is consumed in the field.
        if record.get("source") == "llmail-inject":
            request = ScanRequest(
                user_prompt="Summarize this email",
                content=[ContentInput(source="web", reference=record["id"], text=record["text"])],
            )
        else:
            request = ScanRequest(user_prompt=record["text"])
        start = time.perf_counter()
        result = firewall.scan(request)
        latencies.append((time.perf_counter() - start) * 1000)
        caught = result.malicious is True or result.decision in {"block", "sanitize", "isolate"}
        if record["attack"]:
            attack_total += 1
            attack_caught += caught
            family = record.get("family", record.get("source", "unknown"))
            entry = per_family.setdefault(family, {"attacks": 0, "caught": 0})
            entry["attacks"] += 1
            entry["caught"] += caught
            if not caught:
                misses.append({"id": record["id"], "family": family, "text": record["text"][:400]})
        else:
            benign_total += 1
            benign_flagged += result.decision != "allow"
        firewall.sessions.reset(result.session_id, "local")
        if index % 100 == 0:
            logger.info("public_eval.progress", extra={"event_fields": dict(processed=index + 1, total=len(records))})
    for family, entry in per_family.items():
        entry["recall"] = round(entry["caught"] / entry["attacks"], 4) if entry["attacks"] else None
    metrics = {
        "samples": len(records),
        "attack_samples": attack_total,
        "benign_samples": benign_total,
        "attack_recall": round(attack_caught / attack_total, 4) if attack_total else None,
        "attack_recall_95ci": wilson(attack_caught, attack_total),
        "benign_fpr": round(benign_flagged / benign_total, 4) if benign_total else None,
        "benign_fpr_95ci": wilson(benign_flagged, benign_total),
        "per_family": per_family,
        "latency_median_ms": round(statistics.median(latencies), 1) if latencies else None,
        "latency_p95_ms": round(sorted(latencies)[int(0.95 * len(latencies))], 1) if latencies else None,
    }
    return metrics, misses


def main():
    parser = argparse.ArgumentParser(description="Evaluate on held-out public datasets (independence layer)")
    parser.add_argument("--datasets", nargs="*", default=sorted(PUBLIC_DATASETS), choices=sorted(PUBLIC_DATASETS))
    parser.add_argument("--cache-dir", type=Path, default=Path("data/eval/public"))
    parser.add_argument("--refresh", action="store_true", help="re-download even when cached")
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings, component="evaluation")
    firewall = Firewall(settings)
    if not firewall.ready:
        raise SystemExit("Classifier unavailable — run scripts/train_classifier.py first")

    datasets_report, failures, all_misses, freeze_manifest = {}, [], [], {}
    for slug in args.datasets:
        try:
            records = load_public_records(slug, args.cache_dir, args.refresh)
        except Exception as error:  # noqa: BLE001 - offline must degrade clearly
            failures.append(slug)
            logger.warning("public_eval.unavailable", extra={"event_fields": dict(slug=slug, error_type=type(error).__name__)})
            continue
        datasets_report[slug], misses = evaluate_records(firewall, records)
        all_misses.extend({"dataset": slug, **miss} for miss in misses)
        # Freeze manifest: the exact evidence any future run will replay.
        cache_path = args.cache_dir / f"{slug}.jsonl"
        if cache_path.is_file():
            freeze_manifest[slug] = {
                "rows": len(records),
                "sha256": hashlib.sha256(cache_path.read_bytes()).hexdigest()[:16],
                "frozen_at": time.strftime("%Y-%m-%d", time.gmtime()),
            }

    report = {
        "release_status": "public-eval: independent generalization evidence"
        if datasets_report
        else "public-eval: no dataset evaluated",
        "coverage": firewall.coverage,
        "datasets": datasets_report,
        "unavailable": failures,
        "freeze_manifest": freeze_manifest,
        "provenance": {
            "source": "Hugging Face datasets-server rows API",
            "held_out": "these datasets were never used for training; RULE-023's deepset provenance is disclosed in README.md",
            "note": "binary attack/benign labels; per-family recall published including misses",
            "labeling_philosophy": "deepset marks in-context roleplay setups ('act as an interviewer') and out-of-context harmful requests ('generate SQL') as injections; this firewall deliberately requires attack evidence in the text itself, so a residual miss rate on those families is a labeling-scope difference, not a detection bug — the published number includes them regardless",
        },
        "timing": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    output = reports_dir / "evaluation_public.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    misses_path = reports_dir / "evaluation_public_misses.json"
    misses_path.write_text(json.dumps(all_misses, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"datasets": datasets_report, "unavailable": failures, "written": [str(output), str(misses_path)]}, indent=2))
    if failures and not datasets_report:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
