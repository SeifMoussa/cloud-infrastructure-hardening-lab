"""Config file model used by the local loaders."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class ParseStatus(StrEnum):
    """Parse status for a loaded local config file."""

    PARSED = "parsed"
    RAW_TEXT = "raw_text"
    ERROR = "error"


@dataclass(frozen=True)
class ConfigFile:
    """Normalized representation of a local config file."""

    path: Path
    relative_path: Path
    file_type: str
    raw_text: str
    parsed: Any
    parse_status: ParseStatus
    error_message: str | None
    synthetic: bool
    size_bytes: int
