from __future__ import annotations

from collections import Counter
from typing import Any

from .models import FileMetrics, Finding, MLPrediction, ReliabilityEstimate


DEFAULT_CONFIG: dict[str, Any] = {
    "thresholds": {
        "max_critical": 0,
        "max_high": 0,
        "min_security_score": 70.0,
        "min_maintainability_score": 60.0,
        "min_reliability_score": 60.0,
        "max_remaining_faults": 5.0,
        "min_model_r_squared": 0.75,
        "require_reliability_data": True,
        "max_ml_high_risk_files": 0,
        "ml_high_risk_probability": 0.65,
    },
    "weights": {"security": 0.5, "maintainability": 0.2, "reliability": 0.3},
}

_PENALTIES = {"critical": 30.0, "high": 15.0, "medium": 6.0, "low": 2.0}


def _security_score(findings: list[Finding]) -> float:
    penalty = sum(_PENALTIES.get(item.severity, 0.0) for item in findings)
    return round(max(0.0, 100.0 - penalty), 2)


def _maintainability_score(metrics: list[FileMetrics]) -> float:
    if not metrics:
        return 0.0
    penalties = 0.0
    for item in metrics:
        penalties += max(0, item.cyclomatic_complexity - 15) * 1.5
        penalties += max(0, item.lines_of_code - 300) / 20.0
        penalties += max(0, item.max_line_length - 120) / 10.0
        penalties += item.todo_count * 2.0
        if item.methods and item.cyclomatic_complexity / item.methods > 8:
            penalties += 5.0
    return round(max(0.0, 100.0 - penalties / len(metrics)), 2)


def _reliability_score(estimate: ReliabilityEstimate | None) -> float | None:
    if estimate is None:
        return None
    residual_penalty = min(60.0, estimate.estimated_remaining_faults * 8.0)
    fit_penalty = max(0.0, 0.85 - estimate.r_squared) * 100.0
    intensity_penalty = min(25.0, estimate.current_failure_intensity * 20.0)
    return round(max(0.0, 100.0 - residual_penalty - fit_penalty - intensity_penalty), 2)


def assess_gate(
    findings: list[Finding],
    metrics: list[FileMetrics],
    reliability: ReliabilityEstimate | None,
    ml_predictions: list[MLPrediction] | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[dict[str, float], dict[str, Any]]:
    config = config or DEFAULT_CONFIG
    thresholds = {**DEFAULT_CONFIG["thresholds"], **config.get("thresholds", {})}
    weights = {**DEFAULT_CONFIG["weights"], **config.get("weights", {})}
    counts = Counter(item.severity for item in findings)
    ml_predictions = ml_predictions or []
    security = _security_score(findings)
    maintainability = _maintainability_score(metrics)
    reliability_score = _reliability_score(reliability)

    available = {
        "security": security,
        "maintainability": maintainability,
        **({"reliability": reliability_score} if reliability_score is not None else {}),
    }
    denominator = sum(float(weights[key]) for key in available)
    overall = sum(float(weights[key]) * float(value) for key, value in available.items()) / denominator
    scores = {
        "security": security,
        "maintainability": maintainability,
        "reliability": reliability_score if reliability_score is not None else 0.0,
        "overall": round(overall, 2),
    }

    reasons: list[str] = []
    if counts["critical"] > int(thresholds["max_critical"]):
        reasons.append(f"critical findings {counts['critical']} exceed {thresholds['max_critical']}")
    if counts["high"] > int(thresholds["max_high"]):
        reasons.append(f"high findings {counts['high']} exceed {thresholds['max_high']}")
    if security < float(thresholds["min_security_score"]):
        reasons.append(f"security score {security} is below {thresholds['min_security_score']}")
    if maintainability < float(thresholds["min_maintainability_score"]):
        reasons.append(
            f"maintainability score {maintainability} is below {thresholds['min_maintainability_score']}"
        )
    if reliability is None:
        if bool(thresholds["require_reliability_data"]):
            reasons.append("reliability evidence is required but no failure data was supplied")
    else:
        if reliability_score is not None and reliability_score < float(thresholds["min_reliability_score"]):
            reasons.append(
                f"reliability score {reliability_score} is below {thresholds['min_reliability_score']}"
            )
        if reliability.estimated_remaining_faults > float(thresholds["max_remaining_faults"]):
            reasons.append(
                "estimated remaining faults "
                f"{reliability.estimated_remaining_faults} exceed {thresholds['max_remaining_faults']}"
            )
        if reliability.r_squared < float(thresholds["min_model_r_squared"]):
            reasons.append(
                f"model R² {reliability.r_squared} is below {thresholds['min_model_r_squared']}"
            )
    ml_high_risk = sum(
        item.vulnerability_probability >= float(thresholds["ml_high_risk_probability"])
        for item in ml_predictions
    )
    if ml_high_risk > int(thresholds["max_ml_high_risk_files"]):
        reasons.append(
            f"ML high-risk files {ml_high_risk} exceed {thresholds['max_ml_high_risk_files']} "
            f"at probability threshold {thresholds['ml_high_risk_probability']}"
        )

    gate = {
        "decision": "FAIL" if reasons else "PASS",
        "reasons": reasons or ["All configured pre-release thresholds were satisfied"],
        "severity_counts": {
            severity: counts[severity] for severity in ("critical", "high", "medium", "low")
        },
        "thresholds": thresholds,
        "ml_high_risk_files": ml_high_risk,
    }
    return scores, gate
