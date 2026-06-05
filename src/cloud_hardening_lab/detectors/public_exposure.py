"""Public exposure checks for synthetic samples."""

from __future__ import annotations

import re

from cloud_hardening_lab.detectors.common import make_finding, normalize_key, walk_key_values
from cloud_hardening_lab.models import ConfigFile, Finding


def detect_public_storage_exposure(config: ConfigFile) -> list[Finding]:
    """Detect synthetic public storage access indicators."""
    raw_lower = config.raw_text.lower()
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            normalized_key = normalize_key(key)
            if normalized_key in {"public_read", "public_access"} and value is True:
                return [_public_storage_finding(config, f"{key}: true")]
            if normalized_key == "principal" and isinstance(value, str) and value.lower() == "public":
                if "bucket" in raw_lower or "storage" in raw_lower:
                    return [_public_storage_finding(config, f"{key}: {value}")]
    elif re.search(r"public_read\s*=\s*true", raw_lower):
        return [_public_storage_finding(config, "public_read = true")]
    return []


def detect_public_database_exposure(config: ConfigFile) -> list[Finding]:
    """Detect synthetic public database exposure indicators."""
    raw_lower = config.raw_text.lower()
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) == "publiclyaccessible" and value is True:
                return [
                    make_finding(
                        config=config,
                        rule_id="EXP-002",
                        title="Public database exposure",
                        description="A synthetic database sample is marked publicly accessible.",
                        category="public_exposure",
                        severity="high",
                        evidence=f"{key}: true",
                    )
                ]
    if "publiclyaccessible" in raw_lower and "true" in raw_lower:
        return [
            make_finding(
                config=config,
                rule_id="EXP-002",
                title="Public database exposure",
                description="A synthetic database sample is marked publicly accessible.",
                category="public_exposure",
                severity="high",
                evidence="PubliclyAccessible: true",
            )
        ]
    return []


def _public_storage_finding(config: ConfigFile, evidence: str) -> Finding:
    return make_finding(
        config=config,
        rule_id="EXP-001",
        title="Public storage exposure",
        description="A synthetic storage resource allows public access.",
        category="public_exposure",
        severity="high",
        evidence=evidence,
    )
