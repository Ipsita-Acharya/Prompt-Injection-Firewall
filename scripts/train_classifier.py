import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import hashlib
import json
import logging
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from pif.detection.semantic import LABELS
from scripts.dataset import read_dataset
from pif.observability import configure_logging, logger
from pif.settings import Settings


def read_extra(path: Path) -> list[dict]:
    """Binary extra rows for the attack head: {"text": str, "label": 0|1}.
    Rows without an integer label are rejected — a silent mislabel would
    poison the attack head."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row.get("text"), str) or not isinstance(row.get("label"), int):
            raise ValueError(f"Extra row missing text or integer label: {row!r}"[:120])
        rows.append({"text": row["text"], "label": row["label"]})
    return rows


def train(data: Path, output: Path, extra: Path | None = None):
    logger.info("training.started", extra={"event_fields": dict()})
    records = read_dataset(data)
    training = [record for record in records if record["split"] == "train"]
    extra_rows = read_extra(extra) if extra is not None else []
    texts = [record["text"] for record in training] + [row["text"] for row in extra_rows]
    vectorizers = [
        TfidfVectorizer(ngram_range=(1, 2), max_features=4000, sublinear_tf=True),
        TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), max_features=6000, sublinear_tf=True
        ),
    ]
    features = hstack([vectorizer.fit_transform(texts) for vectorizer in vectorizers])
    logger.info("training.features_created", extra={"event_fields": dict(training_samples=len(training), feature_count=features.shape[1])})
    document = {"version": 1, "labels": LABELS, "weights": [], "intercepts": []}
    for label in LABELS:
        if label == "attack":
            targets = np.array(
                [bool(record["labels"]) for record in training]
                + [int(row["label"]) for row in extra_rows],
                dtype=int,
            )
            head_features = features
        else:
            targets = np.array(
                [label in record["labels"] for record in training], dtype=int
            )
            head_features = features[: len(training)]
        if len(set(targets)) < 2:
            raise ValueError(f"Missing positive/negative training examples for {label}")
        logger.info("training.label_started", extra={"event_fields": dict(label=label, positive_samples=int(targets.sum()), negative_samples=int(len(targets) - targets.sum()))})
        model = LogisticRegression(
            C=8, class_weight="balanced", max_iter=1000, random_state=42
        ).fit(head_features, targets)
        document["weights"].append(model.coef_[0].tolist())
        document["intercepts"].append(float(model.intercept_[0]))
        logger.info("training.label_completed", extra={"event_fields": dict(label=label, iterations=int(model.n_iter_[0]))})
    for vectorizer in vectorizers:
        document[vectorizer.analyzer] = {
            "vocabulary": {token: int(index) for token, index in vectorizer.vocabulary_.items()},
            "idf": vectorizer.idf_.tolist(),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    output.write_bytes(raw)
    output.with_suffix(".manifest.json").write_text(
        json.dumps(
            {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "dataset_sha256": hashlib.sha256(data.read_bytes()).hexdigest(),
                "extra_dataset_sha256": hashlib.sha256(extra.read_bytes()).hexdigest()
                if extra is not None
                else None,
                "extra_samples": len(extra_rows),
                "training_samples": len(training),
                "seed": 42,
                "kind": "tfidf-logistic-regression",
                "warning": "Trained on the corpus train split with dataset ground-truth labels; test split held out. Independent provenance review still required before any production claim.",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    logger.info("training.completed", extra={"event_fields": dict(training_samples=len(training), artifact_bytes=len(raw), artifact_format="numeric-json")})
    return len(training)


def main():
    parser = argparse.ArgumentParser(
        description="Train a discriminative local classifier, not a generative LLM"
    )
    parser.add_argument("--data", type=Path, default=Path("data/training/demo.jsonl"))
    parser.add_argument("--extra-data", type=Path, default=None, help="optional binary extra rows JSONL merged into the attack head")
    parser.add_argument("--output", type=Path, default=Path("models/classifier.json"))
    args = parser.parse_args()
    configure_logging(Settings.load(), component="training")
    try:
        count = train(args.data, args.output, args.extra_data)
    except Exception as error:
        logger.error("training.failed", extra={"event_fields": dict(error_type=type(error).__name__)})
        raise
    print(f"Trained on {count} examples; saved {args.output}")


if __name__ == "__main__":
    main()
