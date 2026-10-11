"""Semantic detector (Layer B, spec §10): local TF-IDF + logistic-regression
model over the categories the rule layer did not already cover. This is the
inference/runtime model code for the ML area."""

import hashlib
import json
import logging
import time
from pathlib import Path

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer

from pif.detection.rules import RULES
from pif.observability import content_preview, logger
from pif.schemas import Finding, Segment

LABELS = ["attack", *RULES]

# Decision thresholds for the semantic layer. Defaults are the values the
# model artifact was tuned with; scripts/calibrate.py can pin PR-validated
# values in conf/thresholds.json ({"semantic": {...}}) and they take
# precedence so threshold changes never require retraining or code edits.
DEFAULT_SEMANTIC_THRESHOLDS = {"attack": 0.85, "category": 0.65, "severity": 0.86}


def load_semantic_thresholds(path: Path | None = None) -> dict:
    path = path or Path("conf/thresholds.json")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        semantic = document.get("semantic", {})
        thresholds = {
            key: float(semantic[key])
            for key in ("attack", "category", "severity")
            if key in semantic
        }
    except (OSError, ValueError, TypeError, AttributeError):
        thresholds = {}
    merged = {**DEFAULT_SEMANTIC_THRESHOLDS, **thresholds}
    if not all(0 < value <= 1 for value in merged.values()):
        logger.warning("semantic.threshold_config_invalid", extra={"event_fields": dict()})
        return dict(DEFAULT_SEMANTIC_THRESHOLDS)
    return merged


class LocalClassifier:
    """The trained model artifact: loading, prediction and TF-IDF feature
    explanations. Inference/runtime model code for the semantic detector."""

    def __init__(self, path: Path):
        logger.info("classifier.load_started", extra={"event_fields": dict()})
        if path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("Model artifact too large")
        raw = path.read_bytes()
        manifest = json.loads(path.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        if manifest["sha256"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("Model checksum mismatch")
        document = json.loads(raw)
        if document["version"] != 1 or document["labels"] != LABELS:
            raise ValueError("Unsupported model schema")
        self.version = manifest["sha256"][:12]
        logger.info("classifier.manifest_verified", extra={"event_fields": dict(model_version=self.version, label_count=len(LABELS))})
        self.vectorizers = []
        for analyzer, ngrams in [("word", (1, 2)), ("char_wb", (3, 5))]:
            state = document[analyzer]
            vocabulary = state["vocabulary"]
            if not 0 < len(vocabulary) <= 10_000 or sorted(vocabulary.values()) != list(
                range(len(vocabulary))
            ):
                raise ValueError("Invalid model vocabulary")
            vectorizer = TfidfVectorizer(
                analyzer=analyzer, ngram_range=ngrams, vocabulary=vocabulary, sublinear_tf=True
            )
            vectorizer.idf_ = np.asarray(state["idf"], dtype=float)
            if len(vectorizer.idf_) != len(vocabulary) or not np.isfinite(vectorizer.idf_).all():
                raise ValueError("Invalid IDF values")
            self.vectorizers.append(vectorizer)
            logger.debug("classifier.vectorizer_loaded", extra={"event_fields": dict(analyzer=analyzer, feature_count=len(vocabulary))})
        self.weights = np.asarray(document["weights"], dtype=float)
        self.intercepts = np.asarray(document["intercepts"], dtype=float)
        feature_count = sum(len(vectorizer.vocabulary) for vectorizer in self.vectorizers)
        if (
            self.weights.shape != (len(LABELS), feature_count)
            or self.intercepts.shape != (len(LABELS),)
            or not np.isfinite(self.weights).all()
            or not np.isfinite(self.intercepts).all()
        ):
            raise ValueError("Invalid classifier weights")
        logger.info("classifier.load_completed", extra={"event_fields": dict(feature_count=feature_count, label_count=len(LABELS))})
        self.feature_names = np.concatenate(
            [vectorizer.get_feature_names_out() for vectorizer in self.vectorizers]
        )

    def explain(self, text: str, category: str):
        index = LABELS.index(category)
        features = hstack([vectorizer.transform([text]) for vectorizer in self.vectorizers]).tocsr()
        contributions = features.data * self.weights[index, features.indices]
        selected = np.argsort(np.abs(contributions))[::-1][:6]
        return {
            "method": "largest absolute linear TF-IDF contributions; positive raises and negative lowers the score; not causal proof or LLM reasoning",
            "intercept": round(float(self.intercepts[index]), 4),
            "feature_contribution_sum": round(float(contributions.sum()), 4),
            "linear_score": round(float(self.intercepts[index] + contributions.sum()), 4),
            "top_features": [
                {
                    "feature": content_preview(str(self.feature_names[features.indices[position]])),
                    "contribution": round(float(contributions[position]), 4),
                }
                for position in selected
            ],
        }

    def predict(self, text: str) -> dict[str, float]:
        started = time.perf_counter()
        logger.debug("classifier.prediction_started", extra={"event_fields": dict(input_chars=len(text), input_text=content_preview(text))})
        features = hstack([vectorizer.transform([text]) for vectorizer in self.vectorizers])
        logits = np.asarray(features @ self.weights.T).ravel() + self.intercepts
        probabilities = 1 / (1 + np.exp(-np.clip(logits, -50, 50)))
        scores = dict(zip(LABELS, probabilities.tolist(), strict=True))
        logger.debug("classifier.prediction_completed", extra={"event_fields": dict(nonzero_features=features.nnz, scores={label: round(score, 4) for label, score in scores.items()}, duration_ms=round((time.perf_counter() - started) * 1000, 3))})
        return scores


class SemanticDetector:
    """Layer B: intent-level classification over sliding windows, restricted to
    the categories the rule layer did not already cover."""

    name = "semantic"

    def __init__(self, classifier: LocalClassifier):
        self.classifier = classifier
        self.thresholds = load_semantic_thresholds()

    def evaluate_view(
        self,
        segment: Segment,
        transformation: str,
        text: str,
        remaining_categories: list[str],
        no_rule_match: bool,
    ) -> list[Finding]:
        classifier = self.classifier
        attack_threshold = self.thresholds["attack"]
        category_threshold = self.thresholds["category"]
        severity = self.thresholds["severity"]
        findings: list[Finding] = []
        logger.info("detection.semantic_invoked", extra={"event_fields": dict(reason="no_actionable_rule_match"
            if no_rule_match
            else "remaining_categories_not_covered_by_rules", categories=remaining_categories, model="local-tfidf-logistic-regression", model_version=getattr(classifier, "version", "injected-classifier"), attack_threshold=attack_threshold, category_threshold=category_threshold)})
        for start in range(0, max(len(text), 1), 1500):
            window = text[start : start + 2000]
            scores = classifier.predict(window)
            if hasattr(classifier, "explain"):
                logger.debug("classifier.feature_evidence", extra={"event_fields": dict(category="attack", explanation=classifier.explain(window, "attack"))})
            logger.debug("detection.semantic_threshold_checked", extra={"event_fields": dict(window_start=start, attack_score=round(scores["attack"], 4), attack_threshold=attack_threshold, category_threshold=category_threshold, attack_threshold_met=scores["attack"] >= attack_threshold)})
            if scores["attack"] >= attack_threshold:
                for category in remaining_categories:
                    if scores[category] >= category_threshold:
                        logger.debug("detection.semantic_matched", extra={"event_fields": dict(category=category, score=round(scores[category], 4), assigned_severity=severity, transformation=transformation)})
                        findings.append(
                            Finding(
                                category=category,
                                source_id=segment.source_id,
                                locator=f"{segment.locator}/window:{start}",
                                layer="semantic",
                                transformation=transformation,
                                severity=severity,
                            )
                        )
            for category in remaining_categories:
                selected = scores["attack"] >= attack_threshold and scores[category] >= category_threshold

                logger.debug("detection.semantic_category_evaluated", extra={"event_fields": dict(category=category, model="local-tfidf-logistic-regression", category_score=round(scores[category], 4), attack_score=round(scores["attack"], 4), attack_threshold=attack_threshold, category_threshold=category_threshold, detected=selected, attack_threshold_met=scores["attack"] >= attack_threshold, category_threshold_met=scores[category] >= category_threshold, input_text=content_preview(window), window_start=start, reason="thresholds met"
                    if selected
                    else f"attack score below {attack_threshold}"
                    if scores["attack"] < attack_threshold
                    else f"category score below {category_threshold}")})
                if selected and hasattr(classifier, "explain"):
                    logger.debug("classifier.feature_evidence", extra={"event_fields": dict(category=category, explanation=classifier.explain(window, category))})
        return findings
