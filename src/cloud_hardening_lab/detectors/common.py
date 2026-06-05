"""Shared utilities for static, local-only detector functions."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from cloud_hardening_lab.models import ConfigFile, Finding

DEFAULT_RECOMMENDATION = "Review and restrict this synthetic configuration."


def walk_values(value: Any) -> Iterator[Any]:
    """Yield all nested values from parsed JSON/YAML/TOML content."""
    yield value
    if isinstance(value, dict):
        for nested_value in value.values():
            yield from walk_values(nested_value)
    elif isinstance(value, list):
        for nested_value in value:
            yield from walk_values(nested_value)


def walk_key_values(value: Any) -> Iterator[tuple[str, Any]]:
    """Yield all nested dictionary key/value pairs."""
    if isinstance(value, dict):
        for key, nested_value in value.items():
            yield str(key), nested_value
            yield from walk_key_values(nested_value)
    elif isinstance(value, list):
        for nested_value in value:
            yield from walk_key_values(nested_value)


def string_values(value: Any) -> Iterator[str]:
    """Yield nested string values."""
    for nested_value in walk_values(value):
        if isinstance(nested_value, str):
            yield nested_value


def normalize_key(key: str) -> str:
    """Normalize a key for simple detector matching."""
    return key.replace("-", "_").lower()


def as_list(value: Any) -> list[Any]:
    """Treat scalars as a one-item list for detector comparisons."""
    return value if isinstance(value, list) else [value]


def make_finding(
    *,
    config: ConfigFile,
    rule_id: str,
    title: str,
    description: str,
    category: str,
    severity: str,
    evidence: str,
    confidence: str = "high",
    resource_name: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    """Create a safe Finding with a standard placeholder recommendation."""
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        file_path=config.relative_path.as_posix(),
        resource_name=resource_name or find_resource_name(config),
        evidence=clean_evidence(evidence),
        recommendation=DEFAULT_RECOMMENDATION,
        confidence=confidence,
        synthetic=True,
        metadata=metadata,
    )


def clean_evidence(evidence: str) -> str:
    """Normalize evidence to a compact, safe excerpt."""
    return " ".join(evidence.split())[:200]


def find_resource_name(config: ConfigFile) -> str | None:
    """Best-effort resource name extraction for synthetic samples."""
    if isinstance(config.parsed, dict):
        for key, value in walk_key_values(config.parsed):
            if normalize_key(key) in {"name", "bucket"} and isinstance(value, str):
                return value

    for pattern in (
        r'name\s*=\s*"([^"]+)"',
        r'resource\s+"[^"]+"\s+"([^"]+)"',
    ):
        match = re.search(pattern, config.raw_text)
        if match:
            return match.group(1)
    return None
