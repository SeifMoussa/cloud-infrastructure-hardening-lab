"""Validate documentation and sample safety for the offline synthetic lab."""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCS = [
    "README.md",
    "docs/design.md",
    "docs/safety-scope.md",
    "docs/detection-rules.md",
    "docs/sample-findings.md",
    "docs/testing-guide.md",
    "docs/release-checklist.md",
    "TESTING_REPORT.md",
    "PROJECT_COMPLETION_CHECKLIST.md",
    "CHANGELOG.md",
]

REQUIRED_REPORTS = [
    "reports/examples/cloud_hardening_report.md",
    "reports/examples/cloud_hardening_report.json",
]

REQUIRED_README_COMMANDS = [
    "python -m cloud_hardening_lab --help",
    "python -m cloud_hardening_lab inventory --input samples --format json",
    "python -m cloud_hardening_lab validate-samples --input samples",
    "python -m cloud_hardening_lab scan --input samples --format json",
    "python -m cloud_hardening_lab scan --input samples --format text --min-severity medium",
    "python -m cloud_hardening_lab scan --input samples --format json --min-severity high",
    "python -m cloud_hardening_lab scan --input samples --format json --fail-on high",
    "python -m cloud_hardening_lab report --input samples --output "
    "reports/examples/cloud_hardening_report.md --format markdown",
    "python -m cloud_hardening_lab report --input samples --output "
    "reports/examples/cloud_hardening_report.json --format json",
]

ALLOWED_ACCOUNT_IDS = {"000000000000", "123456789012"}
ALLOWED_ARNS = {"arn:aws:iam::123456789012:role/fake-lab-role"}
ALLOWED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "lab.example.com",
}
ALLOWED_REAL_PROJECT_DOMAINS = {
    "github.com",
    "img.shields.io",
}
FILE_EXTENSION_WORDS = {
    "coverage.xml",
    "ci.yml",
    "codeql.yml",
    "dependabot.yml",
    "check-docs.py",
    "resources.limits",
}
CODE_REFERENCE_SUFFIXES = (".py", ".json", ".yaml", ".yml", ".toml", ".tf", ".md", ".xml")

PRIVATE_OR_RESERVED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
SECRET_VALUE_RE = re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{12,}")
ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
ARN_RE = re.compile(r"\barn:aws:[^\s\"'`,)]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

PROHIBITED_CLAIMS = [
    "ci passed on github",
    "codeql passed on github",
    "github actions passed",
    "codeql passed",
]
PROHIBITED_PRODUCT_CLAIMS = [
    "production cspm",
    "production cnapp",
    "cnapp replacement",
    "cspm replacement",
    "cloud scanner coverage",
]
OFFENSIVE_INSTRUCTION_PATTERNS = [
    "run exploit",
    "exploit this",
    "privilege escalation steps",
    "gain unauthorized access",
]
REQUIRED_SCOPE_PHRASES = [
    "offline",
    "local",
    "synthetic",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def tracked_text_files() -> list[Path]:
    roots = [ROOT / "docs", ROOT / "samples", ROOT / "reports"]
    paths: list[Path] = []
    for root in roots:
        if root.exists():
            paths.extend(path for path in root.rglob("*") if path.is_file())
    return paths


def markdown_files() -> list[Path]:
    paths = [ROOT / "README.md"]
    paths.extend((ROOT / "docs").glob("*.md"))
    return paths


def is_allowed_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return any(address in network for network in PRIVATE_OR_RESERVED_NETWORKS)


def is_allowed_domain(value: str) -> bool:
    normalized = value.lower().rstrip(".")
    if normalized in ALLOWED_DOMAINS or normalized in ALLOWED_REAL_PROJECT_DOMAINS:
        return True
    if normalized.endswith(".test"):
        return True
    if normalized.endswith(CODE_REFERENCE_SUFFIXES):
        return True
    return normalized in FILE_EXTENSION_WORDS


def check_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_DOCS + REQUIRED_REPORTS:
        if not (ROOT / relative).is_file():
            errors.append(f"Missing required file: {relative}")


def check_local_markdown_links(errors: list[str]) -> None:
    for path in markdown_files():
        text = read_text(path)
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            local_target = target.split("#", maxsplit=1)[0]
            if not local_target:
                continue
            if not (path.parent / local_target).resolve().exists():
                errors.append(f"Broken local markdown link in {path.relative_to(ROOT)}: {target}")


def check_honest_ci_status(errors: list[str]) -> None:
    text = "\n".join(read_text(path).lower() for path in markdown_files())
    for claim in PROHIBITED_CLAIMS:
        if claim in text and "not yet github-verified" not in text:
            errors.append(f"Documentation appears to claim unverified status: {claim}")
    required_phrase = "ci/codeql configured but not yet github-verified"
    if required_phrase not in text:
        errors.append("Documentation must state: CI/CodeQL configured but not yet GitHub-verified.")


def check_scope_and_product_claims(errors: list[str]) -> None:
    docs_text = "\n".join(read_text(path).lower() for path in markdown_files())
    if not all(phrase in docs_text for phrase in REQUIRED_SCOPE_PHRASES):
        errors.append("Documentation must clearly state offline/local synthetic scope.")
    for claim in PROHIBITED_PRODUCT_CLAIMS:
        if claim in docs_text and "not a production" not in docs_text:
            errors.append(f"Documentation contains unsupported production coverage claim: {claim}")


def check_sensitive_content(errors: list[str]) -> None:
    for path in tracked_text_files():
        try:
            text = read_text(path)
        except UnicodeDecodeError:
            errors.append(f"File is not UTF-8 text-readable: {path.relative_to(ROOT)}")
            continue

        relative = path.relative_to(ROOT)
        if AWS_ACCESS_KEY_RE.search(text):
            errors.append(f"Credential-shaped AWS access key found in {relative}")
        if SECRET_VALUE_RE.search(text):
            errors.append(f"Credential-like secret value found in {relative}")

        for account_id in ACCOUNT_ID_RE.findall(text):
            if account_id not in ALLOWED_ACCOUNT_IDS:
                errors.append(f"Unexpected 12-digit account ID in {relative}: {account_id}")

        for arn in ARN_RE.findall(text):
            if arn not in ALLOWED_ARNS:
                errors.append(f"Unexpected ARN in {relative}: {arn}")

        for ip_value in IPV4_RE.findall(text):
            if not is_allowed_ip(ip_value):
                errors.append(f"Unexpected public IP in {relative}: {ip_value}")

        for domain in DOMAIN_RE.findall(text):
            if not is_allowed_domain(domain):
                errors.append(f"Unexpected domain in {relative}: {domain}")

        lower_text = text.lower()
        for pattern in OFFENSIVE_INSTRUCTION_PATTERNS:
            if pattern in lower_text:
                errors.append(f"Offensive instruction wording found in {relative}: {pattern}")


def check_reports(errors: list[str]) -> None:
    for relative in REQUIRED_REPORTS:
        path = ROOT / relative
        if not path.exists():
            continue
        text = read_text(path).lower()
        if "synthetic" not in text or "offline" not in text:
            errors.append(f"Example report must mention synthetic/offline lab data: {relative}")


def check_readme_commands(errors: list[str]) -> None:
    readme = read_text(ROOT / "README.md")
    for command in REQUIRED_README_COMMANDS:
        if command not in readme:
            errors.append(f"README is missing documented CLI command: {command}")


def main() -> int:
    errors: list[str] = []
    check_required_files(errors)
    check_local_markdown_links(errors)
    check_honest_ci_status(errors)
    check_scope_and_product_claims(errors)
    check_sensitive_content(errors)
    check_reports(errors)
    check_readme_commands(errors)

    if errors:
        for error in errors:
            print(f"docs-check: {error}", file=sys.stderr)
        return 1

    print("Documentation and sample safety checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
