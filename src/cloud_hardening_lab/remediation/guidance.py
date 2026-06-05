"""Defensive remediation guidance for Phase 4 rule IDs."""

from __future__ import annotations

from dataclasses import replace

from cloud_hardening_lab.models import Finding

REMEDIATION_BY_RULE_ID = {
    "IAM-001": "Replace wildcard actions with the minimum specific actions required for the synthetic lab role.",
    "IAM-002": "Scope permissions to specific fake lab resources instead of using a wildcard resource.",
    "IAM-003": "Restrict access to trusted synthetic identities and remove public principals.",
    "EXP-001": "Disable public storage access unless there is a documented lab requirement.",
    "EXP-002": "Disable public database access and restrict connectivity to approved synthetic network paths.",
    "NET-001": "Restrict management ingress to the smallest documented lab CIDR and expose only required ports.",
    "STO-001": "Enable encryption at rest for the synthetic storage resource.",
    "STO-002": "Enable versioning or a retention control appropriate for the synthetic storage sample.",
    "K8S-001": "Disable privileged mode and use the least container permissions needed for the lab workload.",
    "K8S-002": "Define CPU and memory requests and limits for the synthetic Kubernetes container.",
}


def remediation_for_rule(rule_id: str) -> str:
    """Return safe remediation guidance for a known rule."""
    return REMEDIATION_BY_RULE_ID.get(rule_id, "Review and restrict this synthetic configuration.")


def apply_remediation(findings: list[Finding]) -> list[Finding]:
    """Apply safe remediation guidance to all findings."""
    remediated: list[Finding] = []
    for finding in findings:
        remediation = remediation_for_rule(finding.rule_id)
        remediated.append(replace(finding, remediation=remediation, recommendation=remediation))
    return remediated
