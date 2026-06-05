"""Network configuration checks for synthetic samples."""

from __future__ import annotations

from typing import Any

from cloud_hardening_lab.detectors.common import make_finding, normalize_key, walk_key_values
from cloud_hardening_lab.models import ConfigFile, Finding

MANAGEMENT_PORTS = {22, 3389}


def detect_public_management_ingress(config: ConfigFile) -> list[Finding]:
    """Detect synthetic management-port ingress from the documentation CIDR."""
    if config.parsed is not None and _parsed_has_public_management_ingress(config.parsed):
        return [_network_finding(config, "port: 22 or 3389 with cidr: 203.0.113.0/24")]

    raw_lower = config.raw_text.lower()
    if "203.0.113.0/24" in raw_lower and ("from_port   = 22" in raw_lower or '"port": 22' in raw_lower):
        return [_network_finding(config, "port 22 with cidr 203.0.113.0/24")]
    return []


def _parsed_has_public_management_ingress(parsed: Any) -> bool:
    has_doc_cidr = False
    has_management_port = False
    for key, value in walk_key_values(parsed):
        normalized_key = normalize_key(key)
        if normalized_key in {"cidr", "cidrblock"} and value == "203.0.113.0/24":
            has_doc_cidr = True
        if normalized_key in {"port", "fromport", "toport"} and value in MANAGEMENT_PORTS:
            has_management_port = True
    return has_doc_cidr and has_management_port


def _network_finding(config: ConfigFile, evidence: str) -> Finding:
    return make_finding(
        config=config,
        rule_id="NET-001",
        title="Public management ingress",
        description="A synthetic network rule allows management access from a documentation CIDR.",
        category="network",
        severity="medium",
        evidence=evidence,
    )
