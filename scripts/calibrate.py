import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""Semantic threshold calibration (v6.0).

Replaces the hardcoded semantic decision thresholds (attack 0.85, category
0.65, severity 0.86) with values swept on labeled corpus records and written
to conf/thresholds.json, so the operating point is measured, versioned and
hot-reloadable without retraining or code edits.

Method (record level, documented approximation): every labeled record's text
is scored by the deployed classifier; the record's attack score is the max
over its 2000-char windows. A grid sweep picks the attack threshold with the
best F1 on attack-vs-benign, then the lowest category threshold whose
per-category precision stays at or above --min-precision. The chosen severity
keeps the semantic layer's assigned finding severity equal to the attack
threshold's operating band (severity = attack threshold, clamped to the
policy block threshold's neighborhood) — recorded transparently in the output
document.

Limitation: record-level labels approximate window-level intent; the sweep is
evidence for the operating point, not a substitute for the public-dataset
evaluation (scripts/build_public_eval.py).
"""

import argparse
import json
from pathlib import Path

from pif.detection.semantic import LABELS, LocalClassifier, load_semantic_thresholds
from pif.observability import configure_logging, logger
from pif.settings import Settings
from scripts.dataset import read_dataset

CATEGORY_LABELS = LABELS[1:]


def best_f1(scores: list[float], labels: list[bool], grid, max_fpr: float = 0.02) -> tuple[float, dict]:
    """Highest-recall threshold whose record-level false-positive rate stays
    within max_fpr (mirroring the release gate); falls back to best F1 when
    no threshold meets the ceiling. Pure best-F1 selection lets a freshly
    retrained model trade FPR for recall — the gate is the binding
    constraint, so it binds here too."""
    evaluated = []
    for threshold in grid:
        predicted = [score >= threshold for score in scores]
        tp = sum(1 for flag, truth in zip(predicted, labels, strict=True) if flag and truth)
        fp = sum(1 for flag, truth in zip(predicted, labels, strict=True) if flag and not truth)
        fn = sum(1 for flag, truth in zip(predicted, labels, strict=True) if not flag and truth)
        tn = len(labels) - tp - fp - fn
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        evaluated.append(
            (threshold, {"threshold": round(threshold, 3), "precision": round(precision, 4), "recall": round(recall, 4), "fpr": round(fpr, 4), "f1": round(f1, 4)})
        )
    within = [entry for entry in evaluated if entry[1]["fpr"] <= max_fpr]
    if within:
        _threshold, best = max(within, key=lambda entry: (entry[1]["recall"], entry[1]["f1"]))
        best["selection"] = "max-recall within FPR ceiling"
        return best["f1"], best
    _threshold, best = max(evaluated, key=lambda entry: entry[1]["f1"])
    best["selection"] = "best-F1 fallback: no threshold met the FPR ceiling"
    return best["f1"], best


def calibrate(data: Path, model_path: Path, min_precision: float, split: str = "train") -> dict:
    settings = Settings(model_path=model_path, report_db_enabled=False, quarantine_enabled=False)
    classifier = LocalClassifier(settings.model_path)
    all_records = read_dataset(data)
    # Calibration on TRAIN records only: the test split stays untouched so the
    # evaluation remains held-out evidence.
    records = [record for record in all_records if record["split"] == split]
    if not records:
        raise ValueError(f"No records in split {split!r}")
    attack_scores, attack_labels = [], []
    category_scores: dict[str, list[tuple[float, bool]]] = {label: [] for label in CATEGORY_LABELS}
    for index, record in enumerate(records):
        text = record["text"]
        max_attack = 0.0
        for start in range(0, max(len(text), 1), 1500):
            scores = classifier.predict(text[start : start + 2000])
            max_attack = max(max_attack, scores["attack"])
            for label in CATEGORY_LABELS:
                category_scores[label].append((scores[label], label in record["labels"]))
        attack_scores.append(max_attack)
        attack_labels.append(bool(record["labels"]))
        if index % 500 == 0:
            logger.info("calibration.progress", extra={"event_fields": dict(records_processed=index + 1, record_total=len(records))})

    grid = [round(0.30 + step * 0.05, 3) for step in range(13)]  # 0.30 .. 0.90
    attack_f1, attack_best = best_f1(attack_scores, attack_labels, grid)

    category_best = {}
    for label, pairs in category_scores.items():
        positives = [pair for pair in pairs if pair[1]]
        if len(positives) < 20:
            category_best[label] = {"threshold": None, "reason": "insufficient positive samples", "positives": len(positives)}
            continue
        chosen = None
        for threshold in grid:
            tp = sum(1 for score, truth in pairs if score >= threshold and truth)
            fp = sum(1 for score, truth in pairs if score >= threshold and not truth)
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fp) if tp + fp else None
            recall_value = tp / sum(1 for _score, truth in pairs if truth)
            if precision >= min_precision and recall_value >= 0.5:
                chosen = {"threshold": round(threshold, 3), "precision": round(precision, 4), "recall": round(recall_value, 4)}
                break
        category_best[label] = chosen or {"threshold": None, "reason": "no threshold met precision/recall floor", "positives": len(positives)}

    valid_category = [
        entry["threshold"] for entry in category_best.values() if entry.get("threshold")
    ]
    category_threshold = min(valid_category) if valid_category else load_semantic_thresholds()["category"]
    # The semantic layer must not out-vote the policy's sanitize floor: keep
    # the assigned severity below the block threshold so semantic-only
    # evidence lands in the review band, not straight to block.
    severity = round(min(0.84, max(0.5, attack_best["threshold"])), 3)
    return {
        "semantic": {
            "attack": attack_best["threshold"],
            "category": round(float(category_threshold), 3),
            "severity": severity,
        },
        "calibration_metadata": {
            "records": len(records),
            "attack": attack_best,
            "per_category": category_best,
            "min_precision": min_precision,
            "grid_start": grid[0],
            "grid_end": grid[-1],
            "method_note": "record-level sweep on the labeled corpus; public-dataset evaluation (scripts/build_public_eval.py) is the generalization evidence",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Calibrate semantic thresholds into conf/thresholds.json")
    parser.add_argument("--data", type=Path, default=Path("data/processed/eval_full.jsonl"))
    parser.add_argument("--split", default="train", choices=["train", "validation", "test"])
    parser.add_argument("--model", type=Path, default=Path("models/classifier.json"))
    parser.add_argument("--min-precision", type=float, default=0.95)
    parser.add_argument("--output", type=Path, default=Path("conf/thresholds.json"))
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings, component="training")
    document = calibrate(args.data, args.model, args.min_precision, args.split)
    if not args.dry_run:
        args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(document, indent=2))
    if not args.dry_run:
        print(f"Written: {args.output}")


if __name__ == "__main__":
    main()
