from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    cwe: str
    severity: str
    file: str
    line: int
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FileMetrics:
    file: str
    lines_of_code: int
    logical_lines: int
    comment_lines: int
    classes: int
    methods: int
    cyclomatic_complexity: int
    max_line_length: int
    todo_count: int

    @property
    def comment_ratio(self) -> float:
        total = self.logical_lines + self.comment_lines
        return round(self.comment_lines / total, 4) if total else 0.0

    @property
    def complexity_density(self) -> float:
        return round(self.cyclomatic_complexity / max(self.logical_lines, 1), 4)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["comment_ratio"] = self.comment_ratio
        data["complexity_density"] = self.complexity_density
        return data


@dataclass(frozen=True)
class ReliabilityEstimate:
    model: str
    observations: int
    test_time: float
    observed_failures: float
    estimated_total_faults: float
    estimated_remaining_faults: float
    detection_rate: float
    current_failure_intensity: float
    estimated_mttf: float | None
    r_squared: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MLPrediction:
    file: str
    vulnerability_probability: float
    predicted_vulnerable: bool
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Assessment:
    target: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)
    metrics: list[FileMetrics] = field(default_factory=list)
    ml_predictions: list[MLPrediction] = field(default_factory=list)
    reliability: ReliabilityEstimate | None = None
    scores: dict[str, float] = field(default_factory=dict)
    gate: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "target": self.target,
            "generated_at": self.generated_at,
            "findings": [item.to_dict() for item in self.findings],
            "metrics": [item.to_dict() for item in self.metrics],
            "ml_predictions": [item.to_dict() for item in self.ml_predictions],
            "reliability": self.reliability.to_dict() if self.reliability else None,
            "scores": self.scores,
            "gate": self.gate,
        }
