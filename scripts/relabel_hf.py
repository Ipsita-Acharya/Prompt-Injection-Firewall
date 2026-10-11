import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

"""Relabel the HF-held-out rows in eval_full.jsonl from the DATASET's ground
truth instead of the legacy auto-labels.

The legacy corpus builder wrote deepset rows into families by what the
detector itself found ("auto-labeling"), so ground-truth ATTACK rows the
detector missed were recorded with labels [] and counted as benign in every
evaluation since — silently deflating both recall AND FPR. This script
relabels hf-deepset rows from the ground-truth cache produced by
scripts/build_public_eval.py (data/eval/public/*.jsonl) and reports the
correction. Binary ground truth maps to the generic instruction_override
label; the family name keeps its provenance so the distinction stays
visible in every report.
"""

import json
from pathlib import Path

GROUND_TRUTH = {
    "deepset-prompt-injections": Path("data/eval/public/deepset-prompt-injections.jsonl"),
}

GENERIC_ATTACK_LABEL = ["instruction_override"]


def _norm(text: str) -> str:
    """Whitespace-normalized key: the legacy corpus rows differ from the
    dataset rows in line-wrap whitespace only."""
    return " ".join(text.split())


def main():
    corpus_path = Path("data/processed/eval_full.jsonl")
    records = [json.loads(line) for line in corpus_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    corrected, checked = 0, 0
    for slug, truth_path in GROUND_TRUTH.items():
        if not truth_path.is_file():
            print(f"Ground-truth cache missing for {slug} — run scripts/build_public_eval.py first")
            continue
        truth = {
            _norm(record["text"]): record["attack"]
            for record in (
                json.loads(line)
                for line in truth_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        }
        for record in records:
            if not record.get("family", "").startswith("hf-"):
                continue
            attack = truth.get(_norm(record["text"]))
            if attack is None:
                continue
            checked += 1
            labels = GENERIC_ATTACK_LABEL if attack else []
            if record["labels"] != labels:
                corrected += 1
            record["labels"] = labels
            record["family"] = record["family"].replace(
                "injection-test", "ground-truth" if attack else "ground-truth-benign"
            )
    corpus_path.write_text(
        "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records),
        encoding="utf-8",
    )
    print(json.dumps({"records_checked": checked, "labels_corrected": corrected}, indent=2))


if __name__ == "__main__":
    main()
