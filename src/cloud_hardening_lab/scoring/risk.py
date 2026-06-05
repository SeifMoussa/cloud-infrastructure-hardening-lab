"""Deterministic risk scoring for local synthetic findings."""

from __future__ import annotations

from dataclasses import replace
from statistics import mean

from cloud_hardening_lab.models import Finding
from cloud_hardening_lab.scoring.severity import SEVERITY_RANGES, SEVERITY_WEIGHTS

CATEGORY_WEIGHTS = {
    "iam": 3,
    "public_exposure": 4,
    "network": 2,
    "storage": 1,
    "kubernetes": 1,
}

CONFIDENCE_WEIGHTS = {
    "high": 2,
    "medium": 0,
    "low": -3,
}


def score_finding(finding: Finding) -> Finding:
    """Return a finding enriched with deterministic score fields."""
    severity_weight = SEVERITY_WEIGHTS[finding.severity]
    category_weight = CATEGORY_WEIGHTS.get(finding.category, 0)
    confidence_weight = CONFIDENCE_WEIGHTS.get(finding.confidence, 0)
    minimum, maximum = SEVERITY_RANGES[finding.severity]
    score = min(maximum, max(minimum, severity_weight + category_weight + confidence_weight))
    scoring_reason = (
        f"Base severity {finding.severity}={severity_weight}; "
        f"category {finding.category}={category_weight}; confidence {finding.confidence}={confidence_weight}; "
        f"clamped to {minimum}-{maximum}."
    )
    return replace(
        finding,
        score=score,
        severity_weight=severity_weight,
        category_weight=category_weight,
        confidence_weight=confidence_weight,
        scoring_reason=scoring_reason,
    )


def apply_scoring(findings: list[Finding]) -> list[Finding]:
    """Apply scoring to all findings."""
    return [score_finding(finding) for finding in findings]


def summarize_findings(findings: list[Finding]) -> dict[str, object]:
    """Build a stable scan summary for console JSON output."""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    scores = [finding.score for finding in findings if finding.score is not None]
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    highest = findings[0].severity if findings else None
    return {
        "findings": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_category": dict(sorted(by_category.items())),
        "highest_severity": highest,
        "max_score": max(scores) if scores else None,
        "average_score": round(mean(scores), 2) if scores else None,
    }
