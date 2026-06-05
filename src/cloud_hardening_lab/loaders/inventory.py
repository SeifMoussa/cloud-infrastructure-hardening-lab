"""File discovery and loading orchestration for local config files."""

from __future__ import annotations

from pathlib import Path

from cloud_hardening_lab.loaders.common import (
    SUPPORTED_EXTENSIONS,
    ConfigLoadError,
    ensure_existing_path,
    ensure_under_root,
)
from cloud_hardening_lab.loaders.json_loader import load_json_file
from cloud_hardening_lab.loaders.text_loader import load_text_file
from cloud_hardening_lab.loaders.toml_loader import load_toml_file
from cloud_hardening_lab.loaders.yaml_loader import load_yaml_file
from cloud_hardening_lab.models import ConfigFile


def is_supported_config_file(path: Path) -> bool:
    """Return whether the path has a supported config extension."""
    return path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS


def detect_file_type(path: Path) -> str:
    """Detect the supported file type from extension."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".toml":
        return "toml"
    if suffix == ".tf":
        return "terraform_text"
    return "unsupported"


def list_config_files(input_path: Path, recursive: bool = True) -> list[Path]:
    """List supported config files under a local input path."""
    resolved_input = ensure_existing_path(input_path)

    if resolved_input.is_file():
        return [resolved_input] if is_supported_config_file(resolved_input) else []

    iterator = resolved_input.rglob("*") if recursive else resolved_input.glob("*")
    config_files: list[Path] = []
    for candidate in iterator:
        if not candidate.is_file():
            continue
        resolved_candidate = ensure_under_root(candidate, resolved_input)
        if is_supported_config_file(resolved_candidate):
            config_files.append(resolved_candidate)
    return sorted(config_files)


def load_config_file(path: Path) -> ConfigFile:
    """Load one supported config file from its parent directory as root."""
    resolved_path = ensure_existing_path(path)
    if not resolved_path.is_file():
        raise ConfigLoadError(f"input path is not a file: {path}")
    if not is_supported_config_file(resolved_path):
        raise ConfigLoadError(f"unsupported config extension: {path.suffix}")
    return _load_config_file_under_root(resolved_path, resolved_path.parent)


def load_config_tree(path: Path, recursive: bool = True) -> list[ConfigFile]:
    """Load supported config files from a file or directory."""
    resolved_input = ensure_existing_path(path)
    root = resolved_input.parent if resolved_input.is_file() else resolved_input
    return [
        _load_config_file_under_root(config_path, root) for config_path in list_config_files(resolved_input, recursive)
    ]


def _load_config_file_under_root(path: Path, root: Path) -> ConfigFile:
    file_type = detect_file_type(path)
    if file_type == "json":
        return load_json_file(path, root)
    if file_type == "yaml":
        return load_yaml_file(path, root)
    if file_type == "toml":
        return load_toml_file(path, root)
    if file_type == "terraform_text":
        return load_text_file(path, root)
    raise ConfigLoadError(f"unsupported config extension: {path.suffix}")
