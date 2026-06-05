"""Storage security checks for synthetic samples."""

from __future__ import annotations

from cloud_hardening_lab.detectors.common import make_finding, normalize_key, walk_key_values
from cloud_hardening_lab.models import ConfigFile, Finding


def detect_storage_missing_encryption(config: ConfigFile) -> list[Finding]:
    """Detect explicit synthetic missing encryption indicators."""
    raw_lower = config.raw_text.lower()
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            normalized_key = normalize_key(key)
            if normalized_key in {"encryptionenabled", "encryption_enabled"} and value is False:
                return [_missing_encryption_finding(config, f"{key}: false")]
            if normalized_key == "encryption_status" and isinstance(value, str) and value.lower() == "disabled":
                return [_missing_encryption_finding(config, f"{key}: {value}")]
    if "encryption_status" in raw_lower and "disabled" in raw_lower:
        return [_missing_encryption_finding(config, 'encryption_status = "disabled"')]
    return []


def detect_storage_missing_versioning(config: ConfigFile) -> list[Finding]:
    """Detect explicit synthetic missing versioning indicators."""
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) in {"versioningenabled", "versioning_enabled"} and value is False:
                return [
                    make_finding(
                        config=config,
                        rule_id="STO-002",
                        title="Missing storage versioning",
                        description="A synthetic storage resource explicitly disables versioning.",
                        category="storage",
                        severity="low",
                        evidence=f"{key}: false",
                    )
                ]
    return []


def _missing_encryption_finding(config: ConfigFile, evidence: str) -> Finding:
    return make_finding(
        config=config,
        rule_id="STO-001",
        title="Missing storage encryption",
        description="A synthetic storage resource explicitly disables encryption.",
        category="storage",
        severity="medium",
        evidence=evidence,
    )
