"""Detection orchestration for static local config analysis."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from cloud_hardening_lab.detectors.iam import (
    detect_iam_public_principal,
    detect_iam_wildcard_action,
    detect_iam_wildcard_resource,
)
from cloud_hardening_lab.detectors.kubernetes import (
    detect_kubernetes_missing_resource_limits,
    detect_kubernetes_privileged_container,
)
from cloud_hardening_lab.detectors.network import detect_public_management_ingress
from cloud_hardening_lab.detectors.public_exposure import (
    detect_public_database_exposure,
    detect_public_storage_exposure,
)
from cloud_hardening_lab.detectors.storage import detect_storage_missing_encryption, detect_storage_missing_versioning
from cloud_hardening_lab.loaders.inventory import load_config_tree
from cloud_hardening_lab.models import ConfigFile, Finding, ParseStatus
from cloud_hardening_lab.remediation import apply_remediation
from cloud_hardening_lab.scoring import apply_scoring
from cloud_hardening_lab.scoring.severity import SEVERITY_PRIORITY

Detector = Callable[[ConfigFile], list[Finding]]


def load_default_detectors() -> list[Detector]:
    """Return all default detector functions in deterministic order."""
    return [
        detect_iam_wildcard_action,
        detect_iam_wildcard_resource,
        detect_iam_public_principal,
        detect_public_storage_exposure,
        detect_public_database_exposure,
        detect_public_management_ingress,
        detect_storage_missing_encryption,
        detect_storage_missing_versioning,
        detect_kubernetes_privileged_container,
        detect_kubernetes_missing_resource_limits,
    ]


def run_detectors(config_files: list[Path], recursive: bool = True) -> list[Finding]:
    """Run all registered detectors against provided local config file paths."""
    findings: list[Finding] = []
    detectors = load_default_detectors()
    for input_path in config_files:
        for config in load_config_tree(input_path, recursive=recursive):
            if config.parse_status == ParseStatus.ERROR:
                continue
            for detector in detectors:
                findings.extend(detector(config))
    return sort_findings(apply_scoring(apply_remediation(findings)))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by score/severity, category, file path, and rule ID."""
    return sorted(
        findings,
        key=lambda finding: (
            -(finding.score if finding.score is not None else 0),
            -SEVERITY_PRIORITY.get(finding.severity, 0),
            finding.category,
            finding.file_path,
            finding.rule_id,
        ),
    )
