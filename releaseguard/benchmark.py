from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .scanner import scan_file


def evaluate_manifest(path: Path) -> dict[str, Any]:
    rows: list[tuple[Path, int]] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"path", "label"}.issubset(reader.fieldnames):
            raise ValueError("Benchmark manifest must contain path and label columns")
        for row in reader:
            rows.append(((path.parent / row["path"]).resolve(), int(row["label"])))
    if not rows:
        raise ValueError("Benchmark manifest is empty")

    tp = tn = fp = fn = 0
    details: list[dict[str, Any]] = []
    for source, expected in rows:
        findings, _ = scan_file(source, path.parent)
        predicted = int(any(item.severity in {"critical", "high"} for item in findings))
        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
        elif not predicted and expected:
            fn += 1
        else:
            tn += 1
        details.append(
            {
                "path": source.relative_to(path.parent).as_posix(),
                "expected": expected,
                "predicted": predicted,
                "finding_count": len(findings),
            }
        )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows)
    return {
        "samples": len(rows),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "details": details,
        "warning": "Bundled examples are smoke tests, not publishable empirical evidence.",
    }

