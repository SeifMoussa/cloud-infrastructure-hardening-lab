"""Severity constants for deterministic scoring."""

SEVERITY_RANGES = {
    "critical": (90, 100),
    "high": (70, 89),
    "medium": (40, 69),
    "low": (10, 39),
    "informational": (0, 9),
}

SEVERITY_WEIGHTS = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 25,
    "informational": 5,
}

SEVERITY_PRIORITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}
