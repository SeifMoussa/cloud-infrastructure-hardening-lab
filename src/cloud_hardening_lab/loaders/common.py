"""Shared utilities for local-only config loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_hardening_lab.models import ConfigFile, ParseStatus
from cloud_hardening_lab.safety import REQUIRED_SYNTHETIC_MARKER

MAX_CONFIG_SIZE_BYTES = 10 * 1024 * 1024
SUPPORTED_EXTENSIONS = frozenset({".json", ".yaml", ".yml", ".toml", ".tf"})


class ConfigLoadError(ValueError):
    """Controlled error raised for invalid local config loading requests."""


def ensure_existing_path(path: Path) -> Path:
    """Resolve an existing local path or raise a controlled error."""
    if not path.exists():
        raise ConfigLoadError(f"input path does not exist: {path}")
    return path.resolve()


def ensure_under_root(path: Path, root: Path) -> Path:
    """Resolve path and reject traversal outside the requested input root."""
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise ConfigLoadError(f"path is outside input root: {path}")
    return resolved_path


def read_text_file(path: Path) -> str:
    """Read a local text file with size and encoding safeguards."""
    size_bytes = path.stat().st_size
    if size_bytes > MAX_CONFIG_SIZE_BYTES:
        raise ConfigLoadError(f"file exceeds lab size limit of {MAX_CONFIG_SIZE_BYTES} bytes: {path}")
    return path.read_text(encoding="utf-8")


def is_acceptable_parsed_content(parsed: Any) -> bool:
    """Return whether parsed JSON/YAML/TOML content has an expected top-level shape."""
    return parsed is None or isinstance(parsed, dict | list | str | int | float | bool)


def build_config_file(
    *,
    path: Path,
    root: Path,
    file_type: str,
    raw_text: str,
    parsed: Any,
    parse_status: ParseStatus,
    error_message: str | None = None,
) -> ConfigFile:
    """Build a normalized ConfigFile model."""
    resolved_path = ensure_under_root(path, root)
    relative_path = resolved_path.relative_to(root.resolve())
    return ConfigFile(
        path=resolved_path,
        relative_path=relative_path,
        file_type=file_type,
        raw_text=raw_text,
        parsed=parsed,
        parse_status=parse_status,
        error_message=error_message,
        synthetic=REQUIRED_SYNTHETIC_MARKER in raw_text,
        size_bytes=resolved_path.stat().st_size,
    )
