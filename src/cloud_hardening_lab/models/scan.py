"""Placeholder scan model for future phases."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanSummary:
    """Placeholder only. Reporting and scoring are out of scope for Phase 3."""

    files_loaded: int
