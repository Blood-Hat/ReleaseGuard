from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .models import Assessment
from .scanner import rule_catalog


def _markdown(assessment: Assessment) -> str:
    data = assessment.to_dict()
    gate = data["gate"]
    counts = gate["severity_counts"]
    lines = [
        "# ReleaseGuard assessment",
        "",
        f"- **Decision:** {gate['decision']}",
        f"- **Target:** `{data['target']}`",
        f"- **Generated:** {data['generated_at']}",
        f"- **Overall score:** {data['scores']['overall']}/100",
        f"- **Security:** {data['scores']['security']}/100",
        f"- **Maintainability:** {data['scores']['maintainability']}/100",
        f"- **Reliability:** {data['scores']['reliability']}/100",
        "",
        "## Gate rationale",
        "",
        *[f"- {reason}" for reason in gate["reasons"]],
        "",
        "## Finding summary",
        "",
        f"Critical: **{counts['critical']}** · High: **{counts['high']}** · "
        f"Medium: **{counts['medium']}** · Low: **{counts['low']}**",
        "",
        "## Findings",
        "",
    ]
    if not assessment.findings:
        lines.append("No rule-based findings were detected.")
    else:
        lines.extend(
            [
                "| Severity | Rule | CWE | Location | Finding |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in assessment.findings:
            lines.append(
                f"| {item.severity.upper()} | {item.rule_id} | {item.cwe} | "
                f"`{item.file}:{item.line}` | {item.title} |"
            )
    lines.extend(["", "## Reliability model", ""])
    if assessment.reliability:
        estimate = assessment.reliability
        lines.extend(
            [
                f"- Model: {estimate.model}",
                f"- Observed failures: {estimate.observed_failures}",
                f"- Estimated total faults: {estimate.estimated_total_faults}",
                f"- Estimated remaining faults: {estimate.estimated_remaining_faults}",
                f"- Current failure intensity: {estimate.current_failure_intensity}",
                f"- Estimated MTTF: {estimate.estimated_mttf or 'not finite'} test-time units",
                f"- Model R²: {estimate.r_squared}",
            ]
        )
    else:
        lines.append("No failure-growth CSV was supplied.")
    lines.extend(["", "## Machine-learning predictions", ""])
    if assessment.ml_predictions:
        lines.extend(
            [
                "| File | Vulnerability probability | Classification |",
                "| --- | ---: | --- |",
            ]
        )
        for item in sorted(
            assessment.ml_predictions,
            key=lambda value: value.vulnerability_probability,
            reverse=True,
        ):
            classification = "high risk" if item.predicted_vulnerable else "lower risk"
            lines.append(
                f"| `{item.file}` | {item.vulnerability_probability:.3f} | {classification} |"
            )
    else:
        lines.append("No trained ML model was supplied.")
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "This is a pre-release decision-support report, not proof that software is vulnerability-free. "
            "Findings require human review, and the reliability estimate is only valid when the supplied "
            "failure data represents a stable test process.",
            "",
        ]
    )
    return "\n".join(lines)


def _html(assessment: Assessment) -> str:
    data = assessment.to_dict()
    decision = data["gate"]["decision"]
    color = "#b42318" if decision == "FAIL" else "#067647"
    finding_rows = "".join(
        "<tr>"
        f"<td><span class='sev {html.escape(item.severity)}'>{html.escape(item.severity.upper())}</span></td>"
        f"<td>{html.escape(item.rule_id)}</td><td>{html.escape(item.cwe)}</td>"
        f"<td><code>{html.escape(item.file)}:{item.line}</code></td>"
        f"<td><strong>{html.escape(item.title)}</strong><br>{html.escape(item.recommendation)}</td>"
        "</tr>"
        for item in assessment.findings
    ) or "<tr><td colspan='5'>No rule-based findings detected.</td></tr>"
    reasons = "".join(f"<li>{html.escape(reason)}</li>" for reason in data["gate"]["reasons"])
    reliability = assessment.reliability
    reliability_html = (
        "<div class='grid'>"
        f"<div class='card'><span>Observed failures</span><strong>{reliability.observed_failures}</strong></div>"
        f"<div class='card'><span>Estimated remaining</span><strong>{reliability.estimated_remaining_faults}</strong></div>"
        f"<div class='card'><span>Failure intensity</span><strong>{reliability.current_failure_intensity}</strong></div>"
        f"<div class='card'><span>Model R²</span><strong>{reliability.r_squared}</strong></div>"
        "</div>"
        if reliability
        else "<p>No failure-growth CSV was supplied.</p>"
    )
    ml_rows = "".join(
        f"<tr><td><code>{html.escape(item.file)}</code></td>"
        f"<td>{item.vulnerability_probability:.3f}</td>"
        f"<td>{'high risk' if item.predicted_vulnerable else 'lower risk'}</td></tr>"
        for item in sorted(
            assessment.ml_predictions,
            key=lambda value: value.vulnerability_probability,
            reverse=True,
        )
    ) or "<tr><td colspan='3'>No trained ML model was supplied.</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReleaseGuard report</title><style>
:root{{--ink:#17202a;--muted:#667085;--paper:#f7f8fa;--card:#fff;--line:#e4e7ec}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Inter,Segoe UI,sans-serif}}
main{{max-width:1120px;margin:auto;padding:40px 22px 64px}} h1{{margin:0;font-size:38px}} h2{{margin-top:38px}}
.hero{{display:flex;justify-content:space-between;gap:24px;align-items:center;background:#101828;color:white;padding:30px;border-radius:18px}}
.decision{{font-size:30px;font-weight:800;color:white;background:{color};padding:12px 24px;border-radius:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:18px 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 3px 12px #1018280a}}
.card span{{display:block;color:var(--muted);font-size:13px}} .card strong{{display:block;font-size:26px;margin-top:5px}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden}} th,td{{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{background:#eef2f6}}
.sev{{font-weight:750}} .critical{{color:#b42318}} .high{{color:#c4320a}} .medium{{color:#b54708}} .low{{color:#175cd3}}
.note{{border-left:4px solid #667085;padding:12px 16px;background:white}} code{{white-space:nowrap}}
@media(max-width:700px){{.hero{{align-items:flex-start;flex-direction:column}}table{{display:block;overflow-x:auto}}}}
</style></head><body><main>
<section class="hero"><div><h1>ReleaseGuard</h1><p>Pre-release vulnerability and reliability assessment</p></div><div class="decision">{decision}</div></section>
<div class="grid">
<div class="card"><span>Overall</span><strong>{data['scores']['overall']}</strong></div>
<div class="card"><span>Security</span><strong>{data['scores']['security']}</strong></div>
<div class="card"><span>Maintainability</span><strong>{data['scores']['maintainability']}</strong></div>
<div class="card"><span>Reliability</span><strong>{data['scores']['reliability']}</strong></div>
</div>
<h2>Gate rationale</h2><ul>{reasons}</ul>
<h2>Security findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>CWE</th><th>Location</th><th>Action</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Reliability growth estimate</h2>{reliability_html}
<h2>Machine-learning predictions</h2><table><thead><tr><th>File</th><th>Probability</th><th>Class</th></tr></thead><tbody>{ml_rows}</tbody></table>
<h2>Scope note</h2><p class="note">This report supports a human release decision. It does not prove the absence of vulnerabilities. Reliability estimates depend on representative, stable test-failure data.</p>
<p><small>Target: {html.escape(data['target'])} · Generated: {html.escape(data['generated_at'])}</small></p>
</main></body></html>"""


def _sarif(assessment: Assessment) -> dict[str, Any]:
    catalog = {item["id"]: item for item in rule_catalog()}
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReleaseGuard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Blood-Hat",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": item["title"],
                                "shortDescription": {"text": item["title"]},
                                "help": {"text": item["recommendation"]},
                                "properties": {"tags": [item["cwe"], "security"]},
                            }
                            for rule_id, item in catalog.items()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": item.rule_id,
                        "level": level[item.severity],
                        "message": {"text": f"{item.title}: {item.recommendation}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": item.file},
                                    "region": {"startLine": item.line},
                                }
                            }
                        ],
                        "properties": {"severity": item.severity, "cwe": item.cwe},
                    }
                    for item in assessment.findings
                ],
            }
        ],
    }


def write_reports(assessment: Assessment, output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    files = {
        "report.json": json.dumps(assessment.to_dict(), indent=2),
        "report.md": _markdown(assessment),
        "report.html": _html(assessment),
        "report.sarif": json.dumps(_sarif(assessment), indent=2),
    }
    written: list[Path] = []
    for name, content in files.items():
        path = output / name
        path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")
        written.append(path)
    return written
