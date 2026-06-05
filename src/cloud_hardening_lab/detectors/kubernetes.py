"""Kubernetes security checks for synthetic manifests."""

from __future__ import annotations

from typing import Any

from cloud_hardening_lab.detectors.common import make_finding, normalize_key, walk_key_values
from cloud_hardening_lab.models import ConfigFile, Finding


def detect_kubernetes_privileged_container(config: ConfigFile) -> list[Finding]:
    """Detect privileged synthetic Kubernetes containers."""
    if config.parsed is None:
        return []
    for key, value in walk_key_values(config.parsed):
        if normalize_key(key) == "privileged" and value is True:
            return [
                make_finding(
                    config=config,
                    rule_id="K8S-001",
                    title="Privileged container",
                    description="A synthetic Kubernetes container is marked privileged.",
                    category="kubernetes",
                    severity="high",
                    evidence="privileged: true",
                )
            ]
    return []


def detect_kubernetes_missing_resource_limits(config: ConfigFile) -> list[Finding]:
    """Detect synthetic Kubernetes Deployment containers without resource limits."""
    if not isinstance(config.parsed, dict) or config.parsed.get("kind") != "Deployment":
        return []
    for container in _containers(config.parsed):
        resources = container.get("resources") if isinstance(container, dict) else None
        limits = resources.get("limits") if isinstance(resources, dict) else None
        if not limits:
            return [
                make_finding(
                    config=config,
                    rule_id="K8S-002",
                    title="Missing resource limits",
                    description="A synthetic Kubernetes Deployment container does not define resource limits.",
                    category="kubernetes",
                    severity="low",
                    evidence="container resources.limits missing",
                    resource_name=container.get("name") if isinstance(container, dict) else None,
                )
            ]
    return []


def _containers(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        containers = value.get("containers")
        if isinstance(containers, list):
            return [container for container in containers if isinstance(container, dict)]
        for nested_value in value.values():
            found = _containers(nested_value)
            if found:
                return found
    if isinstance(value, list):
        for nested_value in value:
            found = _containers(nested_value)
            if found:
                return found
    return []
