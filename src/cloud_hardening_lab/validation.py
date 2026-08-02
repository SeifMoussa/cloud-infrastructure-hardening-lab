"""Validation helpers for loaded configs and sample trees."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_hardening_lab.loaders.common import MAX_CONFIG_SIZE_BYTES, SUPPORTED_EXTENSIONS
from cloud_hardening_lab.loaders.inventory import detect_file_type, is_supported_config_file, load_config_tree
from cloud_hardening_lab.models import ConfigFile, ParseStatus
from cloud_hardening_lab.safety import validate_sample_file


def validate_loaded_config(config: ConfigFile) -> bool:
    """Validate normalized loader output without applying security detections."""
    if config.path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return False
    if config.size_bytes >= MAX_CONFIG_SIZE_BYTES:
        return False
    if config.file_type != detect_file_type(config.path):
        return False
    if config.parse_status == ParseStatus.ERROR:
        return False
    if config.file_type in {"json", "yaml", "toml"} and not isinstance(
        config.parsed,
        dict | list | str | int | float | bool | type(None),
    ):
        return False
    return bool(config.raw_text)


def validate_supported_extensions(paths: list[Path]) -> list[str]:
    """Return unsupported path strings from a list of local paths."""
    return [str(path) for path in paths if not is_supported_config_file(path)]


def validate_sample_tree(samples_root: Path) -> list[dict[str, Any]]:
    """Validate a sample tree and return stable result dictionaries."""
    resolved_samples_root = samples_root.resolve()
    results: list[dict[str, Any]] = []
    configs = load_config_tree(resolved_samples_root)
    for config in configs:
        issues: list[str] = []
        if not validate_loaded_config(config):
            issues.append("loaded config validation failed")
        if config.parse_status == ParseStatus.ERROR and config.error_message:
            issues.append(config.error_message)
        issues.extend(issue.message for issue in validate_sample_file(config.path, resolved_samples_root))

        results.append(
            {
                "path": config.relative_path.as_posix(),
                "file_type": config.file_type,
                "parse_status": config.parse_status.value,
                "synthetic": config.synthetic,
                "valid": not issues,
                "issues": issues,
            }
        )

    return sorted(results, key=lambda item: item["path"])
