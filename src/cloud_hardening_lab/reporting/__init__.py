"""Report generation for local synthetic scan results."""

from cloud_hardening_lab.reporting.json_report import build_json_report, render_json_report
from cloud_hardening_lab.reporting.markdown import render_markdown_report
from cloud_hardening_lab.reporting.summary import build_report_context

__all__ = ["build_json_report", "build_report_context", "render_json_report", "render_markdown_report"]
