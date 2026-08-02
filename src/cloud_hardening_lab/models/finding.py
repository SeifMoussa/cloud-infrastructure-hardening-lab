"""Security finding model for local synthetic detections."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """Normalized security finding produced by the detector package."""

    rule_id: str
    title: str
    description: str
    category: str
    severity: str
    file_path: str
    evidence: str
    recommendation: str
    confidence: str
    synthetic: bool = True
    resource_name: str | None = None
    metadata: dict[str, Any] | None = field(default=None)
    score: int | None = None
    severity_weight: int | None = None
    confidence_weight: int | None = None
    category_weight: int | None = None
    scoring_reason: str | None = None
    remediation: str | None = None
    cis_control_id: str | None = None
    cis_benchmark: str | None = None
    cis_confidence: str | None = None
    cis_note: str | None = None

    def __post_init__(self) -> None:
        """Enforce safe evidence length and synthetic-only findings."""
        object.__setattr__(self, "evidence", self.evidence[:200])
        object.__setattr__(self, "synthetic", True)

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-serializable finding dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "resource_name": self.resource_name,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "remediation": self.remediation or self.recommendation,
            "confidence": self.confidence,
            "score": self.score,
            "severity_weight": self.severity_weight,
            "confidence_weight": self.confidence_weight,
            "category_weight": self.category_weight,
            "scoring_reason": self.scoring_reason,
            "synthetic": self.synthetic,
            "metadata": self.metadata or {},
            "cis_control_id": self.cis_control_id,
            "cis_benchmark": self.cis_benchmark,
            "cis_confidence": self.cis_confidence,
            "cis_note": self.cis_note,
        }
