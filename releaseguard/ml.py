from __future__ import annotations

import csv
import json
import math
import random
import statistics
from pathlib import Path
from typing import Any

from .features import FEATURE_NAMES, extract_features
from .models import MLPrediction
from .scanner import discover_java_files


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-min(value, 700.0))
        return 1.0 / (1.0 + z)
    z = math.exp(max(value, -700.0))
    return z / (1.0 + z)


def _fit_scaler(rows: list[list[float]]) -> tuple[list[float], list[float]]:
    columns = list(zip(*rows))
    means = [statistics.fmean(column) for column in columns]
    standard_deviations = [statistics.pstdev(column) or 1.0 for column in columns]
    return means, standard_deviations


def _scale(rows: list[list[float]], means: list[float], deviations: list[float]) -> list[list[float]]:
    return [
        [(value - mean) / deviation for value, mean, deviation in zip(row, means, deviations)]
        for row in rows
    ]


def _train_logistic(rows: list[list[float]], labels: list[int]) -> dict[str, Any]:
    means, deviations = _fit_scaler(rows)
    scaled = _scale(rows, means, deviations)
    weights = [0.0] * len(FEATURE_NAMES)
    bias = 0.0
    positives = max(1, sum(labels))
    negatives = max(1, len(labels) - positives)
    positive_weight = negatives / positives
    learning_rate = 0.06
    regularization = 0.002

    for _ in range(800):
        weight_gradient = [0.0] * len(weights)
        bias_gradient = 0.0
        total_weight = 0.0
        for row, label in zip(scaled, labels):
            sample_weight = positive_weight if label else 1.0
            prediction = _sigmoid(sum(w * x for w, x in zip(weights, row)) + bias)
            error = (prediction - label) * sample_weight
            for index, value in enumerate(row):
                weight_gradient[index] += error * value
            bias_gradient += error
            total_weight += sample_weight
        for index in range(len(weights)):
            gradient = weight_gradient[index] / total_weight + regularization * weights[index]
            weights[index] -= learning_rate * gradient
        bias -= learning_rate * bias_gradient / total_weight
    return {
        "model_type": "logistic_regression",
        "feature_names": FEATURE_NAMES,
        "scaler": {"means": means, "standard_deviations": deviations},
        "parameters": {"weights": weights, "bias": bias},
        "threshold": 0.5,
    }


def _train_gaussian_nb(rows: list[list[float]], labels: list[int]) -> dict[str, Any]:
    classes: dict[str, Any] = {}
    for label in (0, 1):
        selected = [row for row, value in zip(rows, labels) if value == label]
        columns = list(zip(*selected))
        classes[str(label)] = {
            "prior": len(selected) / len(rows),
            "means": [statistics.fmean(column) for column in columns],
            "variances": [max(statistics.pvariance(column), 1e-6) for column in columns],
        }
    return {
        "model_type": "gaussian_naive_bayes",
        "feature_names": FEATURE_NAMES,
        "classes": classes,
        "threshold": 0.5,
    }


def _predict_probability(model: dict[str, Any], row: list[float]) -> float:
    if model["model_type"] == "logistic_regression":
        scaler = model["scaler"]
        scaled = [
            (value - mean) / deviation
            for value, mean, deviation in zip(
                row, scaler["means"], scaler["standard_deviations"]
            )
        ]
        params = model["parameters"]
        return _sigmoid(sum(w * x for w, x in zip(params["weights"], scaled)) + params["bias"])
    if model["model_type"] == "gaussian_naive_bayes":
        log_probabilities: dict[int, float] = {}
        for label in (0, 1):
            params = model["classes"][str(label)]
            total = math.log(max(params["prior"], 1e-12))
            for value, mean, variance in zip(row, params["means"], params["variances"]):
                total += -0.5 * math.log(2.0 * math.pi * variance)
                total -= ((value - mean) ** 2) / (2.0 * variance)
            log_probabilities[label] = total
        maximum = max(log_probabilities.values())
        p0 = math.exp(log_probabilities[0] - maximum)
        p1 = math.exp(log_probabilities[1] - maximum)
        return p1 / (p0 + p1)
    raise ValueError(f"Unsupported model type: {model.get('model_type')}")


def _metrics(labels: list[int], probabilities: list[float], threshold: float = 0.5) -> dict[str, Any]:
    predictions = [int(value >= threshold) for value in probabilities]
    tp = sum(predicted == 1 and actual == 1 for predicted, actual in zip(predictions, labels))
    tn = sum(predicted == 0 and actual == 0 for predicted, actual in zip(predictions, labels))
    fp = sum(predicted == 1 and actual == 0 for predicted, actual in zip(predictions, labels))
    fn = sum(predicted == 0 and actual == 1 for predicted, actual in zip(predictions, labels))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": round((tp + tn) / len(labels), 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "balanced_accuracy": round((recall + specificity) / 2.0, 6),
        "f1": round(f1, 6),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
    }


def _load_dataset(path: Path) -> tuple[list[list[float]], list[int]]:
    rows: list[list[float]] = []
    labels: list[int] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"label", *FEATURE_NAMES}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("Feature dataset does not contain the required columns")
        for record in reader:
            rows.append([float(record[name]) for name in FEATURE_NAMES])
            labels.append(int(record["label"]))
    if len(rows) < 8 or len(set(labels)) < 2:
        raise ValueError("Training requires at least eight rows containing both classes")
    return rows, labels


def _stratified_folds(labels: list[int], folds: int, seed: int) -> list[list[int]]:
    generator = random.Random(seed)
    groups = {0: [], 1: []}
    for index, label in enumerate(labels):
        groups[label].append(index)
    result = [[] for _ in range(folds)]
    for indices in groups.values():
        generator.shuffle(indices)
        for position, index in enumerate(indices):
            result[position % folds].append(index)
    return result


def train_and_compare(dataset: Path, model_output: Path, metrics_output: Path, seed: int = 42) -> dict[str, Any]:
    rows, labels = _load_dataset(dataset)
    try:
        dataset_reference = dataset.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        dataset_reference = str(dataset.resolve())
    minority = min(sum(labels), len(labels) - sum(labels))
    folds = min(5, minority)
    if folds < 2:
        raise ValueError("Not enough examples in the minority class for cross-validation")
    fold_indices = _stratified_folds(labels, folds, seed)
    trainers = {
        "logistic_regression": _train_logistic,
        "gaussian_naive_bayes": _train_gaussian_nb,
    }
    comparison: dict[str, Any] = {}
    for name, trainer in trainers.items():
        fold_metrics: list[dict[str, Any]] = []
        for test_indices in fold_indices:
            test_set = set(test_indices)
            train_rows = [row for index, row in enumerate(rows) if index not in test_set]
            train_labels = [label for index, label in enumerate(labels) if index not in test_set]
            test_rows = [rows[index] for index in test_indices]
            test_labels = [labels[index] for index in test_indices]
            model = trainer(train_rows, train_labels)
            probabilities = [_predict_probability(model, row) for row in test_rows]
            fold_metrics.append(_metrics(test_labels, probabilities))
        summary = {
            metric: round(statistics.fmean(item[metric] for item in fold_metrics), 6)
            for metric in ("accuracy", "precision", "recall", "specificity", "balanced_accuracy", "f1")
        }
        summary["folds"] = fold_metrics
        comparison[name] = summary

    best_name = max(
        comparison,
        key=lambda name: (comparison[name]["f1"], comparison[name]["recall"], comparison[name]["balanced_accuracy"]),
    )
    final_model = trainers[best_name](rows, labels)
    final_model["training"] = {
        "dataset": dataset_reference,
        "samples": len(rows),
        "vulnerable": sum(labels),
        "non_vulnerable": len(labels) - sum(labels),
        "seed": seed,
        "cross_validation_folds": folds,
        "selected_by": "mean cross-validated F1, then recall, then balanced accuracy",
        "comparison": comparison,
    }
    model_output.parent.mkdir(parents=True, exist_ok=True)
    metrics_output.parent.mkdir(parents=True, exist_ok=True)
    model_output.write_text(json.dumps(final_model, indent=2) + "\n", encoding="utf-8")
    evaluation = {
        "dataset": dataset_reference,
        "samples": len(rows),
        "class_distribution": {
            "vulnerable": sum(labels),
            "non_vulnerable": len(labels) - sum(labels),
        },
        "cross_validation_folds": folds,
        "models": comparison,
        "selected_model": best_name,
        "interpretation": "Metrics are cross-validated estimates on the supplied labelled dataset, not guarantees on unrelated production code.",
    }
    metrics_output.write_text(json.dumps(evaluation, indent=2) + "\n", encoding="utf-8")
    return evaluation


def load_model(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        model = json.load(handle)
    if model.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Model feature schema is incompatible with this ReleaseGuard version")
    return model


def predict_target(model_path: Path, target: Path) -> list[MLPrediction]:
    model = load_model(model_path)
    threshold = float(model.get("threshold", 0.5))
    files = discover_java_files(target)
    base = target if target.is_dir() else target.parent
    predictions: list[MLPrediction] = []
    for path in files:
        features = extract_features(path, base)
        row = [features[name] for name in FEATURE_NAMES]
        probability = _predict_probability(model, row)
        predictions.append(
            MLPrediction(
                file=path.resolve().relative_to(base.resolve()).as_posix(),
                vulnerability_probability=round(probability, 6),
                predicted_vulnerable=probability >= threshold,
                threshold=threshold,
            )
        )
    return predictions
