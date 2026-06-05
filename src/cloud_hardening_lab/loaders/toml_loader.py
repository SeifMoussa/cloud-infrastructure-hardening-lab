"""TOML loader for local synthetic config files."""

from __future__ import annotations

import tomllib
from pathlib import Path

from cloud_hardening_lab.loaders.common import (
    ConfigLoadError,
    build_config_file,
    is_acceptable_parsed_content,
    read_text_file,
)
from cloud_hardening_lab.models import ConfigFile, ParseStatus


def load_toml_file(path: Path, root: Path) -> ConfigFile:
    """Load a TOML file with Python 3.12 tomllib into a normalized ConfigFile."""
    try:
        raw_text = read_text_file(path)
        parsed = tomllib.loads(raw_text)
        if not is_acceptable_parsed_content(parsed):
            raise ConfigLoadError("TOML top-level content type is not supported")
        return build_config_file(
            path=path,
            root=root,
            file_type="toml",
            raw_text=raw_text,
            parsed=parsed,
            parse_status=ParseStatus.PARSED,
        )
    except Exception as exc:
        raw_text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        return build_config_file(
            path=path,
            root=root,
            file_type="toml",
            raw_text=raw_text,
            parsed=None,
            parse_status=ParseStatus.ERROR,
            error_message=str(exc),
        )
