"""IAM-style synthetic permission checks."""

from __future__ import annotations

from cloud_hardening_lab.detectors.common import as_list, make_finding, normalize_key, walk_key_values
from cloud_hardening_lab.models import ConfigFile, Finding


def detect_iam_wildcard_action(config: ConfigFile) -> list[Finding]:
    """Detect wildcard action patterns in synthetic IAM-style samples."""
    findings: list[Finding] = []
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) not in {"action", "actions"}:
                continue
            for item in as_list(value):
                if isinstance(item, str) and (item == "*" or item.endswith(":*")):
                    findings.append(_wildcard_action_finding(config, f"{key}: {item}"))
                    return findings
    elif "actions" in config.raw_text and "*" in config.raw_text:
        findings.append(_wildcard_action_finding(config, 'actions = ["synthetic:*"]'))
    return findings


def detect_iam_wildcard_resource(config: ConfigFile) -> list[Finding]:
    """Detect wildcard resource patterns in synthetic IAM-style samples."""
    findings: list[Finding] = []
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) not in {"resource", "resources"}:
                continue
            for item in as_list(value):
                if item == "*":
                    findings.append(_wildcard_resource_finding(config, f"{key}: *"))
                    return findings
    elif "resources" in config.raw_text and '"*"' in config.raw_text:
        findings.append(_wildcard_resource_finding(config, 'resources = ["*"]'))
    return findings


def detect_iam_public_principal(config: ConfigFile) -> list[Finding]:
    """Detect public principals in synthetic IAM-style samples."""
    findings: list[Finding] = []
    if config.parsed is not None:
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) != "principal":
                continue
            if isinstance(value, str) and value.lower() in {"public", "*"}:
                findings.append(
                    make_finding(
                        config=config,
                        rule_id="IAM-003",
                        title="Public principal",
                        description="A synthetic IAM-style principal allows broad public access.",
                        category="iam",
                        severity="high",
                        evidence=f"{key}: {value}",
                    )
                )
                return findings
    return findings


def _wildcard_action_finding(config: ConfigFile, evidence: str) -> Finding:
    return make_finding(
        config=config,
        rule_id="IAM-001",
        title="Wildcard action",
        description="A synthetic IAM-style policy uses a wildcard action.",
        category="iam",
        severity="high",
        evidence=evidence,
    )


def _wildcard_resource_finding(config: ConfigFile, evidence: str) -> Finding:
    return make_finding(
        config=config,
        rule_id="IAM-002",
        title="Wildcard resource",
        description="A synthetic IAM-style policy applies permissions to a wildcard resource.",
        category="iam",
        severity="high",
        evidence=evidence,
    )
