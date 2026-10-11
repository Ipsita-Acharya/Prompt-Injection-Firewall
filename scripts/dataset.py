"""Corpus JSONL reading and validation, shared by the training, evaluation
and analytics scripts. Corpus records: {"id", "family", "split", "text",
"labels"} with family-level split isolation and the 9 attack labels."""

import json
import logging
from pathlib import Path

from pif.detection.semantic import LABELS
from pif.observability import logger


def read_dataset(path: Path):
    logger.info("dataset.read_started", extra={"event_fields": dict()})
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    ids, families = set(), {}
    for record in records:
        if record["id"] in ids or record["split"] not in {"train", "validation", "test"}:
            raise ValueError("Duplicate ID or invalid split")
        ids.add(record["id"])
        if families.setdefault(record["family"], record["split"]) != record["split"]:
            raise ValueError("Family leakage across splits")
        if not set(record["labels"]).issubset(
            set(LABELS) - {"attack"} | {"encoded_instruction", "indirect_injection"}
        ):
            raise ValueError("Unknown attack label")
    logger.info("dataset.validated", extra={"event_fields": dict(record_count=len(records), family_count=len(families), split_counts={
            split: sum(record["split"] == split for record in records)
            for split in ("train", "validation", "test")
        })})
    return records
