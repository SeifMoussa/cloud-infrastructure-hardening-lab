"""Shared report context helpers."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_hardening_lab.models import Finding
from cloud_hardening_lab.scoring import summarize_findings

TOOL_NAME = "cloud-infrastructure-hardening-lab"
SCHEMA_VERSION = "1.0"
SAFETY_SCOPE = (
    "Synthetic offline lab report generated only from local sample files. "
    "No live cloud APIs, credentials, real customer data, or third-party scanning are used."
)


@dataclass(frozen=True)
class ReportContext:
    """Stable report context shared by Markdown and JSON generators."""

    input_path: str
    files_scanned: int
    findings: list[Finding]
    generated_at: str


def build_report_context(
    *,
    input_path: str,
    files_scanned: int,
    findings: list[Finding],
    generated_at: str,
) -> ReportContext:
    """Build a report context from local scan results."""
    return ReportContext(
        input_path=input_path,
        files_scanned=files_scanned,
        findings=findings,
        generated_at=generated_at,
    )


def report_summary(findings: list[Finding]) -> dict[str, object]:
    """Return summary fields for reports."""
    return summarize_findings(findings)
