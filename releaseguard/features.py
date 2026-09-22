from __future__ import annotations

import csv
import re
from pathlib import Path

from .scanner import scan_file


FEATURE_NAMES = [
    "lines_of_code",
    "logical_lines",
    "comment_ratio",
    "classes",
    "methods",
    "cyclomatic_complexity",
    "complexity_density",
    "max_line_length",
    "todo_count",
    "rule_findings",
    "high_risk_rule_findings",
    "request_parameter_sources",
    "request_header_sources",
    "database_sinks",
    "response_output_sinks",
    "file_system_sinks",
    "redirect_sinks",
    "cookie_operations",
    "crypto_operations",
    "string_concatenations",
    "prepared_statements",
    "encoding_or_validation_calls",
]

_FEATURE_PATTERNS = {
    "request_parameter_sources": re.compile(r"\b(?:getParameter|getParameterMap|getQueryString)\s*\("),
    "request_header_sources": re.compile(r"\b(?:getHeader|getCookies)\s*\("),
    "database_sinks": re.compile(r"\b(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\("),
    "response_output_sinks": re.compile(r"\b(?:getWriter|getOutputStream|sendError)\s*\("),
    "file_system_sinks": re.compile(r"new\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\("),
    "redirect_sinks": re.compile(r"\b(?:sendRedirect|setHeader)\s*\("),
    "cookie_operations": re.compile(r"\b(?:Cookie|addCookie|getCookies)\b"),
    "crypto_operations": re.compile(r"\b(?:MessageDigest|Cipher|Mac|SecureRandom|KeyGenerator)\b"),
    "string_concatenations": re.compile(r"\+"),
    "prepared_statements": re.compile(r"\bPreparedStatement\b|\.prepareStatement\s*\("),
    "encoding_or_validation_calls": re.compile(
        r"(?i)\b(?:encode|escape|sanitize|validate|matches|parseInt|allowlist|whitelist)\w*\s*\("
    ),
}


def extract_features(path: Path, root: Path | None = None) -> dict[str, float]:
    findings, metrics = scan_file(path, root or path.parent)
    text = path.read_text(encoding="utf-8", errors="replace")
    values: dict[str, float] = {
        "lines_of_code": float(metrics.lines_of_code),
        "logical_lines": float(metrics.logical_lines),
        "comment_ratio": metrics.comment_ratio,
        "classes": float(metrics.classes),
        "methods": float(metrics.methods),
        "cyclomatic_complexity": float(metrics.cyclomatic_complexity),
        "complexity_density": metrics.complexity_density,
        "max_line_length": float(metrics.max_line_length),
        "todo_count": float(metrics.todo_count),
        "rule_findings": float(len(findings)),
        "high_risk_rule_findings": float(
            sum(item.severity in {"critical", "high"} for item in findings)
        ),
    }
    for name, pattern in _FEATURE_PATTERNS.items():
        values[name] = float(len(pattern.findall(text)))
    return {name: values[name] for name in FEATURE_NAMES}


def prepare_owasp_dataset(benchmark_root: Path, output: Path) -> dict[str, int]:
    labels_path = benchmark_root / "expectedresults-1.2.csv"
    source_root = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    if not labels_path.exists():
        raise ValueError(f"OWASP labels not found: {labels_path}")
    if not source_root.exists():
        raise ValueError(f"OWASP Java test cases not found: {source_root}")

    source_files = {path.stem: path for path in source_root.glob("BenchmarkTest*.java")}
    rows: list[dict[str, str | float | int]] = []
    skipped = 0
    with labels_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames:
            reader.fieldnames = [
                name.strip().lstrip("#").strip().lower() for name in reader.fieldnames
            ]
        required = {"test name", "category", "real vulnerability", "cwe"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"Unexpected OWASP label columns: {reader.fieldnames}")
        for label in reader:
            name = label["test name"].strip()
            source = source_files.get(name)
            if source is None:
                skipped += 1
                continue
            features = extract_features(source, source_root)
            rows.append(
                {
                    "path": source.relative_to(benchmark_root).as_posix(),
                    "label": 1 if label["real vulnerability"].strip().lower() == "true" else 0,
                    "cwe": label["cwe"].strip(),
                    "category": label["category"].strip(),
                    **features,
                }
            )
    if not rows:
        raise ValueError("No labelled OWASP source files were matched")
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["path", "label", "cwe", "category", *FEATURE_NAMES]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    positives = sum(int(row["label"]) for row in rows)
    return {
        "rows": len(rows),
        "vulnerable": positives,
        "non_vulnerable": len(rows) - positives,
        "skipped": skipped,
    }
