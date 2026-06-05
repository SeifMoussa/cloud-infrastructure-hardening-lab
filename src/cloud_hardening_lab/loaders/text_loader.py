"""Raw text loader for local Terraform-like samples."""

from __future__ import annotations

from pathlib import Path

from cloud_hardening_lab.loaders.common import build_config_file, read_text_file
from cloud_hardening_lab.models import ConfigFile, ParseStatus


def load_text_file(path: Path, root: Path) -> ConfigFile:
    """Load a text file without parsing its cloud syntax."""
    try:
        raw_text = read_text_file(path)
        return build_config_file(
            path=path,
            root=root,
            file_type="terraform_text",
            raw_text=raw_text,
            parsed=None,
            parse_status=ParseStatus.RAW_TEXT,
        )
    except Exception as exc:
        raw_text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        return build_config_file(
            path=path,
            root=root,
            file_type="terraform_text",
            raw_text=raw_text,
            parsed=None,
            parse_status=ParseStatus.ERROR,
            error_message=str(exc),
        )
