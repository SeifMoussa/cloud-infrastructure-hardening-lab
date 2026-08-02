# Testing Guide

The project uses local automated checks to keep the scanner, reports, and documentation stable and public-safe. The validation strategy is intentionally practical: test the implemented detector behavior, enforce synthetic-only boundaries, and verify that the documented CLI flows keep working.

## What The Test Suite Covers

- Package and CLI entrypoint behavior
- File inventory and sample validation
- JSON, YAML, TOML, and text loader behavior
- Detector coverage for the implemented rule set
- Deterministic finding ordering
- Scoring and remediation enrichment
- Markdown and JSON reporting
- CLI error handling, filtering, and fail-on behavior
- Documentation consistency and safety checks
- Local CI, CodeQL, and Dependabot configuration files

## Current Verified Local Baseline

- 113 tests passed
- 97.97% coverage
- 90% coverage gate
- Ruff check passed
- Ruff format check passed
- docs check passed

These are local validation results. CI/CodeQL configured but not yet GitHub-verified.

## Required Safety Assertions

The tests and docs checks are designed to keep the repository within these boundaries:

- Defensive-only
- Offline-only
- Local synthetic files only
- No live AWS/Azure/GCP/Kubernetes API calls
- No real credentials
- No real cloud accounts
- No third-party scanning
- No offensive use
- No privilege escalation instructions
- Not a production CSPM/CNAPP replacement

## Core Test Areas

### Sample Safety

- Required synthetic markers
- Allowed fake account IDs and ARN values
- Allowed reserved example domains and documentation IP ranges
- Rejection of credential-shaped content, unsafe secrets, and private keys

### Functional Coverage

- Inventory of supported sample types
- Sample validation command output
- Scan JSON and text output
- Severity filtering with `--min-severity`
- Exit-code gating with `--fail-on`
- Markdown and JSON report generation

### Documentation And Workflow Coverage

- README command examples
- Honest CI/CodeQL wording
- Required report/example file presence
- Workflow YAML structure for local GitHub Actions and CodeQL setup

## Commands

```bash
python -m pytest
python -m pytest --cov=cloud_hardening_lab --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
```

## CLI Smoke Commands

```bash
python -m cloud_hardening_lab --help
python -m cloud_hardening_lab inventory --input samples --format json
python -m cloud_hardening_lab validate-samples --input samples
python -m cloud_hardening_lab scan --input samples --format json
python -m cloud_hardening_lab scan --input samples --format text --min-severity medium
python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.md --format markdown
python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.json --format json
```

## Honest Interpretation

Passing local tests shows that the implemented offline synthetic workflow is stable in this repository. It does not mean the project has already passed GitHub Actions or CodeQL on GitHub, and it does not mean the tool is production-ready for real cloud estates.
