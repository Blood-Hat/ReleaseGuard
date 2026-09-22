from __future__ import annotations

import csv
import math
from pathlib import Path

from .models import ReliabilityEstimate


def read_failure_data(path: Path) -> list[tuple[float, float]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = {"time", "cumulative_failures"}
        if not reader.fieldnames or not expected.issubset(set(reader.fieldnames)):
            raise ValueError("Failure CSV must contain time and cumulative_failures columns")
        observations = [
            (float(row["time"]), float(row["cumulative_failures"]))
            for row in reader
            if row.get("time") and row.get("cumulative_failures")
        ]
    if len(observations) < 4:
        raise ValueError("At least four failure observations are required")
    for index, (time, failures) in enumerate(observations):
        if time <= 0 or failures < 0:
            raise ValueError("Times must be positive and cumulative failures non-negative")
        if index and time <= observations[index - 1][0]:
            raise ValueError("Times must be strictly increasing")
        if index and failures < observations[index - 1][1]:
            raise ValueError("Cumulative failures must not decrease")
    return observations


def _fit_for_b(data: list[tuple[float, float]], b: float) -> tuple[float, float]:
    basis = [1.0 - math.exp(-b * time) for time, _ in data]
    denominator = sum(value * value for value in basis)
    if denominator <= 0:
        return 0.0, math.inf
    a = sum(failures * value for value, (_, failures) in zip(basis, data)) / denominator
    error = sum(
        (failures - a * value) ** 2
        for value, (_, failures) in zip(basis, data)
    )
    return a, error


def fit_goel_okumoto(data: list[tuple[float, float]]) -> ReliabilityEstimate:
    """Fit m(t)=a(1-exp(-bt)) using a deterministic logarithmic grid search."""
    if len(data) < 4:
        raise ValueError("At least four observations are required")
    maximum_time = data[-1][0]
    minimum_b = 1e-5 / maximum_time
    maximum_b = 20.0 / maximum_time
    candidates = 3000
    log_min = math.log(minimum_b)
    log_max = math.log(maximum_b)

    best_a = 0.0
    best_b = 0.0
    best_error = math.inf
    for index in range(candidates):
        fraction = index / (candidates - 1)
        b = math.exp(log_min + fraction * (log_max - log_min))
        a, error = _fit_for_b(data, b)
        if a >= data[-1][1] and error < best_error:
            best_a, best_b, best_error = a, b, error

    if not math.isfinite(best_error):
        raise ValueError("Unable to fit the reliability growth model")

    values = [failures for _, failures in data]
    mean = sum(values) / len(values)
    total_variation = sum((value - mean) ** 2 for value in values)
    r_squared = 1.0 - (best_error / total_variation) if total_variation else 1.0
    current_time = data[-1][0]
    observed = data[-1][1]
    remaining = max(0.0, best_a - observed)
    intensity = best_a * best_b * math.exp(-best_b * current_time)
    mttf = (1.0 / intensity) if intensity > 1e-12 else None
    return ReliabilityEstimate(
        model="Goel-Okumoto NHPP",
        observations=len(data),
        test_time=round(current_time, 6),
        observed_failures=round(observed, 6),
        estimated_total_faults=round(best_a, 6),
        estimated_remaining_faults=round(remaining, 6),
        detection_rate=round(best_b, 8),
        current_failure_intensity=round(intensity, 8),
        estimated_mttf=round(mttf, 6) if mttf is not None else None,
        r_squared=round(r_squared, 6),
    )


def analyze_failure_csv(path: Path) -> ReliabilityEstimate:
    return fit_goel_okumoto(read_failure_data(path))

