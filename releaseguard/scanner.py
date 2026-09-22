from __future__ import annotations

import re
from pathlib import Path

from .models import FileMetrics, Finding


RULES: tuple[dict[str, object], ...] = (
    {
        "id": "RG001",
        "title": "Hard-coded credential",
        "cwe": "CWE-798",
        "severity": "high",
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*=\s*\"[^\"]{3,}\""
        ),
        "recommendation": "Load credentials from a secret manager or environment variable and rotate exposed values.",
    },
    {
        "id": "RG002",
        "title": "Broken or weak cryptographic hash",
        "cwe": "CWE-327",
        "severity": "high",
        "pattern": re.compile(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"", re.I),
        "recommendation": "Use a modern algorithm such as SHA-256 for integrity, or a password KDF for passwords.",
    },
    {
        "id": "RG003",
        "title": "Dynamic SQL construction",
        "cwe": "CWE-89",
        "severity": "critical",
        "pattern": re.compile(r"(?i)\b(?:select|insert|update|delete)\b[^;\n]*\+"),
        "recommendation": "Use PreparedStatement with placeholders and bind every untrusted value.",
    },
    {
        "id": "RG004",
        "title": "Unparameterized SQL statement API",
        "cwe": "CWE-89",
        "severity": "medium",
        "pattern": re.compile(r"\.createStatement\s*\("),
        "recommendation": "Prefer PreparedStatement and parameterized queries.",
    },
    {
        "id": "RG005",
        "title": "Operating-system command execution",
        "cwe": "CWE-78",
        "severity": "high",
        "pattern": re.compile(r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\("),
        "recommendation": "Avoid shell execution; use an allow-listed API and never concatenate untrusted input.",
    },
    {
        "id": "RG006",
        "title": "Predictable random generator in security-sensitive code",
        "cwe": "CWE-338",
        "severity": "medium",
        "pattern": re.compile(r"new\s+(?:java\.util\.)?Random\s*\("),
        "recommendation": "Use java.security.SecureRandom for tokens, identifiers, and secrets.",
    },
    {
        "id": "RG007",
        "title": "Unsafe native deserialization",
        "cwe": "CWE-502",
        "severity": "high",
        "pattern": re.compile(r"new\s+ObjectInputStream\s*\("),
        "recommendation": "Avoid native deserialization of untrusted data or enforce a strict ObjectInputFilter.",
    },
    {
        "id": "RG008",
        "title": "Stack trace disclosure",
        "cwe": "CWE-209",
        "severity": "low",
        "pattern": re.compile(r"\.printStackTrace\s*\("),
        "recommendation": "Log a controlled error through the application logger and return a generic message.",
    },
    {
        "id": "RG009",
        "title": "Permissive cross-origin policy",
        "cwe": "CWE-942",
        "severity": "high",
        "pattern": re.compile(r"@CrossOrigin\s*\([^)]*\*[^)]*\)"),
        "recommendation": "Allow only the explicitly required origins, methods, and headers.",
    },
    {
        "id": "RG010",
        "title": "Legacy SSL protocol requested",
        "cwe": "CWE-326",
        "severity": "medium",
        "pattern": re.compile(r"SSLContext\.getInstance\s*\(\s*\"SSL\""),
        "recommendation": "Use a current TLS protocol and the platform trust manager defaults.",
    },
)

_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*)")
_METHOD = re.compile(
    r"(?m)^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)*"
    r"[\w<>\[\],.?]+(?:\s+[\w<>\[\],.?]+)*\s+\w+\s*\([^;{}]*\)"
    r"\s*(?:throws\s+[^{]+)?\{"
)
_CLASS = re.compile(r"\b(?:class|interface|enum|record)\s+\w+")
_COMPLEXITY = re.compile(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?")


def discover_java_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() == ".java" else []
    ignored = {".git", "target", "build", "out", "node_modules", ".idea"}
    return sorted(
        path
        for path in target.rglob("*.java")
        if not any(part in ignored for part in path.parts)
    )


def _relative(path: Path, root: Path) -> str:
    base = root if root.is_dir() else root.parent
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def scan_file(path: Path, root: Path | None = None) -> tuple[list[Finding], FileMetrics]:
    root = root or path.parent
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    relative = _relative(path, root)
    findings: list[Finding] = []

    in_block_comment = False
    analysis_lines: list[str] = []
    comment_lines = 0
    for number, original in enumerate(lines, start=1):
        stripped = original.strip()
        if in_block_comment:
            comment_lines += 1
            if "*/" in stripped:
                in_block_comment = False
            analysis_lines.append("")
            continue
        if stripped.startswith("/*"):
            comment_lines += 1
            in_block_comment = "*/" not in stripped
            analysis_lines.append("")
            continue
        if _COMMENT_LINE.match(original):
            comment_lines += 1
            analysis_lines.append("")
            continue

        code = original.split("//", 1)[0]
        analysis_lines.append(code)
        for rule in RULES:
            pattern = rule["pattern"]
            assert isinstance(pattern, re.Pattern)
            match = pattern.search(code)
            if not match:
                continue
            evidence = code.strip()
            if len(evidence) > 180:
                evidence = evidence[:177] + "..."
            findings.append(
                Finding(
                    rule_id=str(rule["id"]),
                    title=str(rule["title"]),
                    cwe=str(rule["cwe"]),
                    severity=str(rule["severity"]),
                    file=relative,
                    line=number,
                    evidence=evidence,
                    recommendation=str(rule["recommendation"]),
                )
            )

    code_text = "\n".join(analysis_lines)
    logical = sum(1 for line in analysis_lines if line.strip())
    metrics = FileMetrics(
        file=relative,
        lines_of_code=len(lines),
        logical_lines=logical,
        comment_lines=comment_lines,
        classes=len(_CLASS.findall(code_text)),
        methods=len(_METHOD.findall(code_text)),
        cyclomatic_complexity=1 + len(_COMPLEXITY.findall(code_text)),
        max_line_length=max((len(line) for line in lines), default=0),
        todo_count=sum(line.upper().count("TODO") + line.upper().count("FIXME") for line in lines),
    )
    return findings, metrics


def scan_target(target: Path) -> tuple[list[Finding], list[FileMetrics]]:
    files = discover_java_files(target)
    findings: list[Finding] = []
    metrics: list[FileMetrics] = []
    for path in files:
        file_findings, file_metrics = scan_file(path, target)
        findings.extend(file_findings)
        metrics.append(file_metrics)
    findings.sort(key=lambda item: (item.file, item.line, item.rule_id))
    return findings, metrics


def rule_catalog() -> list[dict[str, str]]:
    return [
        {
            "id": str(rule["id"]),
            "title": str(rule["title"]),
            "cwe": str(rule["cwe"]),
            "severity": str(rule["severity"]),
            "recommendation": str(rule["recommendation"]),
        }
        for rule in RULES
    ]
