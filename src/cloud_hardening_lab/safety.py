"""Lightweight safety helpers for synthetic sample files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ALLOWED_SAMPLE_ROOTS = (
    Path("samples/terraform"),
    Path("samples/cloudformation"),
    Path("samples/kubernetes"),
    Path("samples/generic"),
)

ALLOWED_SAMPLE_EXTENSIONS = frozenset({".json", ".yaml", ".yml", ".toml", ".tf"})

ALLOWED_ACCOUNT_IDS = frozenset({"000000000000", "123456789012"})
ALLOWED_DOMAINS = frozenset({"example.com", "example.org", "example.net", "lab.example.com"})
ALLOWED_DOMAIN_SUFFIXES = (".test",)
ALLOWED_CIDRS = frozenset({"203.0.113.0/24"})
REQUIRED_SYNTHETIC_MARKER = "synthetic-lab"

_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AWS_ARN_RE = re.compile(r"\barn:aws:[A-Za-z0-9:/_.+=,@-]+\b")
_ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


@dataclass(frozen=True)
class SafetyIssue:
    """A lightweight validation issue for synthetic sample hygiene."""

    path: Path
    message: str


def list_sample_files(root: Path) -> list[Path]:
    """List supported sample files under the approved sample roots."""
    sample_files: list[Path] = []
    for sample_root in ALLOWED_SAMPLE_ROOTS:
        directory = root / sample_root
        if not directory.exists():
            continue
        sample_files.extend(
            path for path in directory.rglob("*") if path.is_file() and path.suffix.lower() in ALLOWED_SAMPLE_EXTENSIONS
        )
    return sorted(sample_files)


def validate_sample_file(path: Path, root: Path) -> list[SafetyIssue]:
    """Validate one sample file using raw text safety checks."""
    issues: list[SafetyIssue] = []
    relative_path = path.relative_to(root)

    if path.suffix.lower() not in ALLOWED_SAMPLE_EXTENSIONS:
        issues.append(SafetyIssue(relative_path, "unsupported sample file extension"))

    text = path.read_text(encoding="utf-8")
    if REQUIRED_SYNTHETIC_MARKER not in text:
        issues.append(SafetyIssue(relative_path, "missing synthetic lab marker"))

    if _AWS_ACCESS_KEY_RE.search(text):
        issues.append(SafetyIssue(relative_path, "credential-shaped AWS access key found"))

    if _PRIVATE_KEY_RE.search(text):
        issues.append(SafetyIssue(relative_path, "private key block found"))

    for account_id in _ACCOUNT_ID_RE.findall(text):
        if account_id not in ALLOWED_ACCOUNT_IDS:
            issues.append(SafetyIssue(relative_path, f"non-allowed account ID found: {account_id}"))

    for arn in _AWS_ARN_RE.findall(text):
        if arn != "arn:aws:iam::123456789012:role/fake-lab-role":
            issues.append(SafetyIssue(relative_path, f"non-allowed ARN found: {arn}"))

    for ip_or_cidr in _IPV4_RE.findall(text):
        if ip_or_cidr not in ALLOWED_CIDRS:
            issues.append(SafetyIssue(relative_path, f"non-allowed IP or CIDR found: {ip_or_cidr}"))

    for domain in _DOMAIN_RE.findall(text):
        if domain in ALLOWED_DOMAINS or domain.endswith(ALLOWED_DOMAIN_SUFFIXES):
            continue
        issues.append(SafetyIssue(relative_path, f"non-allowed domain found: {domain}"))

    return issues


def validate_samples(root: Path) -> list[SafetyIssue]:
    """Validate all supported sample files under the approved sample roots."""
    issues: list[SafetyIssue] = []
    for sample_file in list_sample_files(root):
        issues.extend(validate_sample_file(sample_file, root))
    return issues
