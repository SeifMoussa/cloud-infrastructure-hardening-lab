"""Safe YAML loader for local synthetic config files."""

from __future__ import annotations

from pathlib import Path

import yaml

from cloud_hardening_lab.loaders.common import (
    ConfigLoadError,
    build_config_file,
    is_acceptable_parsed_content,
    read_text_file,
)
from cloud_hardening_lab.models import ConfigFile, ParseStatus


def load_yaml_file(path: Path, root: Path) -> ConfigFile:
    """Load a YAML file with yaml.safe_load into a normalized ConfigFile."""
    try:
        raw_text = read_text_file(path)
        parsed = yaml.safe_load(raw_text)
        if not is_acceptable_parsed_content(parsed):
            raise ConfigLoadError("YAML top-level content type is not supported")
        return build_config_file(
            path=path,
            root=root,
            file_type="yaml",
            raw_text=raw_text,
            parsed=parsed,
            parse_status=ParseStatus.PARSED,
        )
    except Exception as exc:
        raw_text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        return build_config_file(
            path=path,
            root=root,
            file_type="yaml",
            raw_text=raw_text,
            parsed=None,
            parse_status=ParseStatus.ERROR,
            error_message=str(exc),
        )
