"""Risk scoring helpers for synthetic local findings."""

from cloud_hardening_lab.scoring.risk import apply_scoring, score_finding, summarize_findings
from cloud_hardening_lab.scoring.severity import SEVERITY_RANGES, SEVERITY_WEIGHTS

__all__ = ["SEVERITY_RANGES", "SEVERITY_WEIGHTS", "apply_scoring", "score_finding", "summarize_findings"]
