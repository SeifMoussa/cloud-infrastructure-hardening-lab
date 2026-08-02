"""Placeholder scan model reserved for future loader-level summaries."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanSummary:
    """Placeholder only. Reporting and scoring live in their own modules."""

    files_loaded: int
