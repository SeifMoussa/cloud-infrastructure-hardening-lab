"""CIS control mapping for detector rule IDs.

See docs/compliance-mapping.md for the full CIS AWS Foundations Benchmark and
CIS Kubernetes Benchmark version citations, source links, confidence levels,
and known caveats behind each mapping below.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from cloud_hardening_lab.models import Finding

NOT_COVERED_NOTE = (
    "Not covered by the CIS AWS Foundations Benchmark or the CIS Kubernetes Benchmark. See docs/compliance-mapping.md."
)
CAVEAT_NOTE = "See docs/compliance-mapping.md for the benchmark version and mapping caveats."


@dataclass(frozen=True)
class CisMapping:
    """A single rule's CIS control mapping, or the lack of one."""

    control_id: str | None
    benchmark: str | None
    confidence: str | None
    note: str | None


CIS_MAPPING_BY_RULE_ID: dict[str, CisMapping] = {
    "IAM-001": CisMapping("1.16", "CIS AWS Foundations Benchmark v1.4.0", "medium", CAVEAT_NOTE),
    "IAM-002": CisMapping("1.16", "CIS AWS Foundations Benchmark v1.4.0", "medium", CAVEAT_NOTE),
    "IAM-003": CisMapping("2.1.4", "CIS AWS Foundations Benchmark v3.0.0", "low", CAVEAT_NOTE),
    "EXP-001": CisMapping("2.1.4", "CIS AWS Foundations Benchmark v3.0.0", "high", None),
    "EXP-002": CisMapping("2.3.3", "CIS AWS Foundations Benchmark v3.0.0", "high", None),
    "NET-001": CisMapping("5.2", "CIS AWS Foundations Benchmark v3.0.0", "medium", CAVEAT_NOTE),
    "STO-001": CisMapping(None, None, None, NOT_COVERED_NOTE),
    "STO-002": CisMapping(None, None, None, NOT_COVERED_NOTE),
    "K8S-001": CisMapping("5.2.2", "CIS Kubernetes Benchmark v1.8.0", "medium", CAVEAT_NOTE),
    "K8S-002": CisMapping(None, None, None, NOT_COVERED_NOTE),
}


def cis_mapping_for_rule(rule_id: str) -> CisMapping:
    """Return the CIS mapping for a known rule, or an unmapped placeholder."""
    return CIS_MAPPING_BY_RULE_ID.get(
        rule_id,
        CisMapping(None, None, None, "Rule is not present in the CIS control mapping table."),
    )


def apply_cis_mapping(findings: list[Finding]) -> list[Finding]:
    """Attach CIS control mapping fields to every finding."""
    mapped: list[Finding] = []
    for finding in findings:
        mapping = cis_mapping_for_rule(finding.rule_id)
        mapped.append(
            replace(
                finding,
                cis_control_id=mapping.control_id,
                cis_benchmark=mapping.benchmark,
                cis_confidence=mapping.confidence,
                cis_note=mapping.note,
            )
        )
    return mapped
