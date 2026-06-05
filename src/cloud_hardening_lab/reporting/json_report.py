"""JSON report generation for local synthetic scan results."""

from __future__ import annotations

import json
from typing import Any

from cloud_hardening_lab.reporting.summary import SAFETY_SCOPE, SCHEMA_VERSION, TOOL_NAME, ReportContext, report_summary


def build_json_report(context: ReportContext) -> dict[str, Any]:
    """Build a stable JSON-serializable report payload."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": context.generated_at,
        "tool_name": TOOL_NAME,
        "safety_scope": SAFETY_SCOPE,
        "input_path": context.input_path,
        "files_scanned": context.files_scanned,
        "summary": report_summary(context.findings),
        "findings": [finding.to_dict() for finding in context.findings],
        "report_metadata": {
            "report_type": "json",
            "synthetic": True,
            "offline": True,
        },
    }


def render_json_report(context: ReportContext) -> str:
    """Render a JSON report string."""
    return json.dumps(build_json_report(context), indent=2, sort_keys=True) + "\n"
