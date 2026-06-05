"""Markdown report generation for local synthetic scan results."""

from __future__ import annotations

from cloud_hardening_lab.models import Finding
from cloud_hardening_lab.reporting.summary import SAFETY_SCOPE, ReportContext, report_summary


def render_markdown_report(context: ReportContext) -> str:
    """Render a deterministic Markdown report."""
    summary = report_summary(context.findings)
    lines = [
        "# Cloud Infrastructure Hardening Report",
        "",
        f"Generated at: `{context.generated_at}`",
        "",
        "## Safety Scope",
        "",
        SAFETY_SCOPE,
        "",
        "## Executive Summary",
        "",
        f"- Input path: `{context.input_path}`",
        f"- Files scanned: `{context.files_scanned}`",
        f"- Total findings: `{summary['findings']}`",
        f"- Highest severity: `{summary['highest_severity']}`",
        f"- Max score: `{summary['max_score']}`",
        f"- Average score: `{summary['average_score']}`",
        "",
        "## Findings By Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(_count_rows(summary["by_severity"]))
    lines.extend(
        [
            "",
            "## Findings By Category",
            "",
            "| Category | Count |",
            "| --- | ---: |",
        ]
    )
    lines.extend(_count_rows(summary["by_category"]))
    lines.extend(
        [
            "",
            "## Detailed Findings",
            "",
            "| Rule ID | Severity | Score | Category | File Path | Title | Evidence | Remediation |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(_finding_row(finding) for finding in context.findings)
    lines.extend(
        [
            "",
            "## Remediation Summary",
            "",
        ]
    )
    lines.extend(_remediation_lines(context.findings))
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This report is generated from synthetic local files only. It is not a production security assessment, "
            + "does not authenticate to cloud providers, and does not inspect live infrastructure.",
            "",
        ]
    )
    return "\n".join(lines)


def _count_rows(counts: object) -> list[str]:
    if not isinstance(counts, dict) or not counts:
        return ["| None | 0 |"]
    return [f"| `{key}` | {value} |" for key, value in counts.items()]


def _finding_row(finding: Finding) -> str:
    return (
        f"| `{finding.rule_id}` | `{finding.severity}` | {finding.score} | `{finding.category}` | "
        f"`{finding.file_path}` | {escape_markdown(finding.title)} | "
        f"{escape_markdown(finding.evidence)} | {escape_markdown(finding.remediation or finding.recommendation)} |"
    )


def _remediation_lines(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["No findings were generated from the local synthetic input."]
    seen: set[str] = set()
    lines: list[str] = []
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        lines.append(f"- `{finding.rule_id}`: {finding.remediation or finding.recommendation}")
    return lines


def escape_markdown(value: object) -> str:
    """Escape table-sensitive Markdown characters."""
    return str(value).replace("|", "\\|").replace("\n", " ")
