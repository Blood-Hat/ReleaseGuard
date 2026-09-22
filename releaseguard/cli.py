from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .benchmark import evaluate_manifest
from .features import prepare_owasp_dataset
from .ml import predict_target, train_and_compare
from .models import Assessment
from .reliability import analyze_failure_csv
from .reports import write_reports
from .scanner import rule_catalog, scan_target
from .scoring import DEFAULT_CONFIG, assess_gate


def _load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return DEFAULT_CONFIG
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="releaseguard",
        description="Explainable pre-release vulnerability and reliability assessment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan Java source and apply the release gate")
    scan.add_argument("target", type=Path, help="Java file or project directory")
    scan.add_argument("--failures", type=Path, help="CSV with time,cumulative_failures")
    scan.add_argument("--config", type=Path, help="JSON gate configuration")
    scan.add_argument("--model", type=Path, help="Trained vulnerability model JSON")
    scan.add_argument("--output", type=Path, default=Path("results/latest"))
    scan.add_argument("--no-fail-on-gate", action="store_true", help="Always exit 0 after writing reports")

    reliability = subparsers.add_parser("reliability", help="Fit the reliability growth model")
    reliability.add_argument("failures", type=Path)

    benchmark = subparsers.add_parser("benchmark", help="Evaluate high-risk classification on a manifest")
    benchmark.add_argument("manifest", type=Path)
    benchmark.add_argument("--output", type=Path)

    prepare = subparsers.add_parser("prepare-owasp", help="Build an ML feature dataset from OWASP BenchmarkJava")
    prepare.add_argument("benchmark_root", type=Path)
    prepare.add_argument("--output", type=Path, default=Path("datasets/processed/owasp_features.csv"))

    train = subparsers.add_parser("train", help="Cross-validate ML models and save the best one")
    train.add_argument("dataset", type=Path)
    train.add_argument("--model-output", type=Path, default=Path("models/vulnerability_model.json"))
    train.add_argument("--metrics-output", type=Path, default=Path("results/ml_evaluation.json"))
    train.add_argument("--seed", type=int, default=42)

    predict = subparsers.add_parser("predict", help="Apply a trained ML model to Java source")
    predict.add_argument("model", type=Path)
    predict.add_argument("target", type=Path)

    subparsers.add_parser("rules", help="Print the implemented security rule catalog")
    return parser


def _scan(args: argparse.Namespace) -> int:
    target = args.target.resolve()
    if not target.exists():
        raise ValueError(f"Target does not exist: {target}")
    findings, metrics = scan_target(target)
    predictions = predict_target(args.model.resolve(), target) if args.model else []
    if not metrics:
        raise ValueError(f"No Java files found under: {target}")
    reliability = analyze_failure_csv(args.failures.resolve()) if args.failures else None
    scores, gate = assess_gate(
        findings, metrics, reliability, predictions, _load_config(args.config)
    )
    assessment = Assessment(
        target=str(target),
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        metrics=metrics,
        ml_predictions=predictions,
        reliability=reliability,
        scores=scores,
        gate=gate,
    )
    paths = write_reports(assessment, args.output.resolve())
    print(f"Release decision: {gate['decision']} (overall score {scores['overall']}/100)")
    print(
        "Findings: "
        + ", ".join(f"{key}={value}" for key, value in gate["severity_counts"].items())
    )
    print("Reports:")
    for path in paths:
        print(f"  {path}")
    return 0 if args.no_fail_on_gate or gate["decision"] == "PASS" else 2


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "reliability":
            print(json.dumps(analyze_failure_csv(args.failures).to_dict(), indent=2))
            return 0
        if args.command == "benchmark":
            result = evaluate_manifest(args.manifest.resolve())
            content = json.dumps(result, indent=2)
            print(content)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(content + "\n", encoding="utf-8")
            return 0
        if args.command == "prepare-owasp":
            summary = prepare_owasp_dataset(args.benchmark_root.resolve(), args.output.resolve())
            print(json.dumps({"output": str(args.output.resolve()), **summary}, indent=2))
            return 0
        if args.command == "train":
            result = train_and_compare(
                args.dataset.resolve(),
                args.model_output.resolve(),
                args.metrics_output.resolve(),
                args.seed,
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "predict":
            predictions = predict_target(args.model.resolve(), args.target.resolve())
            print(json.dumps([item.to_dict() for item in predictions], indent=2))
            return 0
        if args.command == "rules":
            print(json.dumps(rule_catalog(), indent=2))
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 1
