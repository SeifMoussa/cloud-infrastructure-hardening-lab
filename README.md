# Cloud Infrastructure Hardening Lab

[![CI](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cloud Infrastructure Hardening Lab is a defensive-only, offline-only portfolio project for reviewing synthetic cloud configuration files on a local workstation. It is designed for local learning, recruiter review, and safe public GitHub presentation. It does not connect to AWS, Azure, GCP, Kubernetes clusters, or any third-party scanning service.

CI/CodeQL configured but not yet GitHub-verified. The workflows exist locally and should not be treated as passed until the repository is published and they run on GitHub.

## Project Summary

This lab simulates a small cloud security review workflow against synthetic infrastructure-as-code and configuration samples. The tool inventories local files, validates synthetic safety markers, runs deterministic misconfiguration checks, enriches findings with scores and remediation guidance, and generates Markdown or JSON reports suitable for portfolio demonstration.

## Target Job Relevance

- Cloud Security Engineer
- Security Engineer
- SOC / Blue Team Analyst
- DevSecOps / Security Automation roles

## What This Project Demonstrates

- Building a local defensive scanner for synthetic infrastructure configuration data
- Translating cloud hardening concepts into deterministic detection logic
- Representing findings with severity, score, confidence, and remediation metadata
- Producing recruiter-readable Markdown reports and machine-readable JSON output
- Enforcing documentation honesty, sample safety, and local quality gates with tests and linting

## Evidence Sources

- Synthetic config samples under `samples/`
- Loaders and validation logic under `src/cloud_hardening_lab/loaders/`, `validation.py`, and `safety.py`
- Detectors under `src/cloud_hardening_lab/detectors/`
- Scoring and remediation logic under `src/cloud_hardening_lab/scoring/` and `remediation/`
- Markdown and JSON reports under `reports/examples/`
- Automated tests under `tests/`
- Documentation consistency checks under `scripts/check-docs.py`

## Features

- Local file inventory across multiple sample folders and config styles
- Sample validation for synthetic markers, fake identifiers, and unsafe content rejection
- Detection rules for IAM-style risks, public exposure, storage hardening, network exposure, and Kubernetes hardening
- Deterministic scoring with transparent score ranges and scoring reasons
- Safe remediation guidance focused on hardening intent rather than provider-specific live commands
- CLI filtering with `--min-severity`
- Local quality-gate behavior with `--fail-on`
- Markdown and JSON report generation for public portfolio examples

## Tech Stack

- Python 3.12
- Pytest
- Coverage.py
- Ruff
- PyYAML
- TOML parsing via the Python standard library / compatible tooling already used in the project
- GitHub Actions and CodeQL workflow files configured locally

## Supported Sample Types

- Terraform-like `.tf` raw text
- CloudFormation-like JSON/YAML
- Kubernetes YAML
- Generic JSON/YAML/TOML

## Safety Boundaries

- Defensive-only and offline-only
- Local synthetic files only
- No live cloud API calls
- No live AWS, Azure, GCP, or Kubernetes API calls
- No real credentials
- No real cloud accounts
- No third-party scanning
- No offensive use
- No privilege escalation instructions
- No real cloud accounts or production environments
- Synthetic configs only
- Not a production CSPM/CNAPP replacement

## Detection Categories

- IAM-style policy risks
- Public exposure
- Storage hardening
- Network exposure
- Kubernetes hardening

## Scoring And Remediation

Each finding is enriched with a deterministic score, severity, confidence, score rationale, and a short defensive remediation statement. The scoring model keeps results inside fixed severity bands so the output remains stable and easy to explain in an interview or code review.

## Report Generation

The `report` command writes either Markdown or JSON to an explicit local output path. Reports include a safety-scope statement, scan summary, findings by severity and category, detailed findings, remediation guidance, and limitations. Example public-safe reports are included under [`reports/examples/cloud_hardening_report.md`](reports/examples/cloud_hardening_report.md) and [`reports/examples/cloud_hardening_report.json`](reports/examples/cloud_hardening_report.json).

These example reports are real local outputs generated from the synthetic sample set in this repository. No screenshots are required to validate the project, and no screenshots should be fabricated.

## CLI Examples

```bash
python -m cloud_hardening_lab --help
python -m cloud_hardening_lab inventory --input samples --format json
python -m cloud_hardening_lab validate-samples --input samples
python -m cloud_hardening_lab scan --input samples --format json
python -m cloud_hardening_lab scan --input samples --format text
python -m cloud_hardening_lab scan --input samples --format json --min-severity high
python -m cloud_hardening_lab scan --input samples --format text --min-severity medium
python -m cloud_hardening_lab scan --input samples --format json --fail-on high
python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.md --format markdown
python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.json --format json
```

## Quality Status

- 105 tests passed
- 97.89% coverage
- 90% coverage gate
- Ruff passed
- docs check passed

## CI And CodeQL Status

- Configured locally
- Not yet GitHub-verified until first push

## Project Structure

```text
cloud-infrastructure-hardening-lab/
|-- .github/
|   |-- workflows/
|   `-- dependabot.yml
|-- docs/
|-- reports/
|   `-- examples/
|-- samples/
|   |-- cloudformation/
|   |-- generic/
|   |-- kubernetes/
|   `-- terraform/
|-- scripts/
|-- src/
|   `-- cloud_hardening_lab/
|       |-- detectors/
|       |-- loaders/
|       |-- models/
|       |-- remediation/
|       |-- reporting/
|       `-- scoring/
|-- tests/
|-- README.md
|-- TESTING_REPORT.md
|-- PROJECT_COMPLETION_CHECKLIST.md
`-- CHANGELOG.md
```

## Known Limitations

- The detector set is intentionally small and transparent rather than broad CSPM coverage.
- Terraform-like `.tf` files are inspected as raw text, not full HCL-parsed plans or state.
- The lab does not authenticate to live cloud accounts and cannot validate runtime drift.
- The project does not replace production CSPM, CNAPP, Kubernetes admission control, or managed cloud security monitoring.
- CI and CodeQL are configured locally but remain unverified on GitHub until first publication.

## License

This project is released under the [MIT License](LICENSE).
