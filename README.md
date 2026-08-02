# Cloud Infrastructure Hardening Lab

[![CI](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/cloud-infrastructure-hardening-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cloud Infrastructure Hardening Lab is a defensive-only, offline-only portfolio project for reviewing synthetic cloud configuration files on a local workstation. It is designed for local learning, recruiter review, and safe public GitHub presentation. It does not connect to AWS, Azure, GCP, Kubernetes clusters, or any third-party scanning service.

CI/CodeQL configured but not yet GitHub-verified. The workflows exist locally and should not be treated as passed until the repository is published and they run on GitHub.

## Project Summary

This lab simulates a small cloud security review workflow against synthetic infrastructure-as-code and configuration samples. The tool inventories local files, validates synthetic safety markers, runs deterministic misconfiguration checks, enriches findings with scores and remediation guidance, and generates Markdown or JSON reports suitable for portfolio demonstration.

## Why This Lab Is Different From My Other Security Labs

This project works at the cloud configuration and infrastructure-as-code layer. The packet lab inspects network captures, the host lab watches endpoint artifacts, the YARA lab matches file and log patterns, and the alert-triage lab organizes security events. Here, the input is Terraform-like text, CloudFormation, Kubernetes manifests, and generic configuration files; the output is a deterministic CSPM-style review of IAM, public exposure, storage, network, and Kubernetes hardening decisions. The useful boundary is before deployment: explain a risky configuration and a remediation direction without needing a live account.

## Target Job Relevance

- Cloud Security Engineer
- Security Engineer
- SOC / Blue Team Analyst
- DevSecOps / Security Automation roles

## What This Project Demonstrates

- Building a local defensive scanner for synthetic infrastructure configuration data
- Translating cloud hardening concepts into deterministic detection logic
- Representing findings with severity, score, confidence, and remediation metadata
- Mapping detector rules to CIS Benchmark controls, with honest confidence levels and an explicit "not covered" note where no verified control exists
- Producing recruiter-readable Markdown reports and machine-readable JSON output
- Enforcing documentation honesty, sample safety, and local quality gates with tests and linting

## Evidence Sources

- Synthetic config samples under `samples/`
- Loaders and validation logic under `src/cloud_hardening_lab/loaders/`, `validation.py`, and `safety.py`
- Detectors under `src/cloud_hardening_lab/detectors/`
- Scoring and remediation logic under `src/cloud_hardening_lab/scoring/` and `remediation/`
- CIS control mapping under `src/cloud_hardening_lab/compliance/`
- Markdown and JSON reports under `reports/examples/`
- Automated tests under `tests/`
- Documentation consistency checks under `scripts/check-docs.py`

## Features

- Local file inventory across multiple sample folders and config styles
- Sample validation for synthetic markers, fake identifiers, and unsafe content rejection
- Detection rules for IAM-style risks, public exposure, storage hardening, network exposure, and Kubernetes hardening
- Deterministic scoring with transparent score ranges and scoring reasons
- Safe remediation guidance focused on hardening intent rather than provider-specific live commands
- CIS AWS Foundations Benchmark and CIS Kubernetes Benchmark control mapping per rule, with confidence levels and source citations in [`docs/compliance-mapping.md`](docs/compliance-mapping.md)
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

- 113 tests passed
- 97.97% coverage
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
`-- CHANGELOG.md
```

## Known Limitations

- The detector set is intentionally small and transparent rather than broad CSPM coverage.
- Every fixture is synthetic and local; no real customer configuration, credential, account, or production state belongs in the lab.
- The scanner does not connect to a live AWS, Azure, GCP, or Kubernetes environment, so it cannot detect runtime drift, inherited organization policy, or controls applied outside the reviewed files.
- Terraform-like `.tf` files are inspected as raw text, not full HCL-parsed plans or state.
- The project does not replace production CSPM, CNAPP, Kubernetes admission control, or managed cloud security monitoring.
- CI and CodeQL are configured locally but remain unverified on GitHub until first publication.

## What I Would Improve Next

I would replace the raw Terraform text checks with parsed HCL and plan support so findings can follow module values and resource relationships. I would also add explicit rule metadata for cloud provider and framework mappings, plus fixture-based tests for cross-resource cases such as a private resource made public by a separate policy. Live cloud collection would remain a separate, opt-in adapter with read-only permissions rather than being folded into the offline scanner.

## How to Verify It Works

Install the package, run the same lint, format, test, coverage, and documentation checks used by CI, then exercise the local sample scan:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m pytest --cov=cloud_hardening_lab --cov-report=term-missing --cov-fail-under=90
python scripts/check-docs.py
python -m cloud_hardening_lab validate-samples --input samples
python -m cloud_hardening_lab scan --input samples --format text --min-severity medium
```

These commands verify deterministic behavior against the repository's synthetic fixtures. They do not validate a live cloud environment or establish production readiness.

## License

This project is released under the [MIT License](LICENSE).
