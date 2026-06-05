# Design

Cloud Infrastructure Hardening Lab is a defensive-only, offline-only Python project that reviews local synthetic cloud configuration files. The design favors transparency, deterministic output, and recruiter-readable implementation over broad provider coverage. It does not make live AWS, Azure, GCP, Kubernetes, or third-party API calls.

## Design Goals

- Keep all analysis local to explicitly provided files and directories
- Support multiple common infrastructure configuration shapes without needing live cloud access
- Make findings stable, explainable, and easy to validate in tests
- Preserve a strict public-safe scope: no real credentials, no real cloud accounts, no offensive workflows
- Produce outputs that work both as engineering artifacts and as portfolio evidence

## End-To-End Flow

1. `inventory` walks the local sample tree and records supported files.
2. `validate-samples` checks that the inputs remain synthetic, clearly marked, and free from unsafe content.
3. `scan` loads supported files, runs local detector rules, and enriches findings with scores and remediation guidance.
4. `report` renders the enriched results as Markdown or JSON at an explicit local output path.

The CLI is intentionally narrow. It is built for offline analysis of local synthetic files only.

## Input Model

The project accepts four sample styles:

- Terraform-like `.tf` raw text
- CloudFormation-like JSON/YAML
- Kubernetes YAML
- Generic JSON/YAML/TOML

This mix demonstrates handling both parsed structured data and simpler raw-text inspection. The `.tf` handling is deliberately lightweight and does not claim full Terraform or HCL semantic support.

## Core Modules

- `src/cloud_hardening_lab/loaders/`
  Loads JSON, YAML, TOML, and text inputs into a consistent internal scan model.
- `src/cloud_hardening_lab/validation.py` and `src/cloud_hardening_lab/safety.py`
  Enforce local-only and synthetic-only boundaries, including fake identifier policy and unsafe content rejection.
- `src/cloud_hardening_lab/detectors/`
  Implements the rule engine and the current defensive detection categories.
- `src/cloud_hardening_lab/scoring/`
  Applies deterministic severity-based scoring and summary aggregation.
- `src/cloud_hardening_lab/remediation/`
  Maps rule IDs to concise hardening guidance.
- `src/cloud_hardening_lab/reporting/`
  Produces Markdown and JSON reports with safety scope, findings, and limitations.
- `src/cloud_hardening_lab/cli.py`
  Exposes the user-facing workflow through `inventory`, `validate-samples`, `scan`, and `report`.

## Detection Design

The implemented rules focus on common cloud hardening interview themes:

- IAM-style policy risks
- Public exposure
- Storage hardening
- Network exposure
- Kubernetes hardening

The rule set is intentionally conservative. Each rule produces a deterministic finding with a rule ID, category, severity, confidence, evidence excerpt, and resource name where available.

## Scoring And Remediation Design

Scoring is explainable by design. A finding score is derived from severity, category weight, and confidence weight, then clamped into its severity range. This keeps outputs stable across runs and makes the scoring logic easy to discuss during review.

Remediation guidance is also constrained on purpose. The project gives defensive hardening intent, not provider-specific live commands, no offensive instructions, and no privilege escalation content.

## Reporting Design

Reporting serves two audiences:

- Recruiters or hiring managers who want a readable artifact
- Engineers or automation workflows that need machine-readable data

The Markdown report emphasizes clarity: summary tables, detailed findings, remediation summary, and limitations. The JSON report preserves the same content in a structured form suitable for follow-on automation or testing.

## Safety And Trust Boundaries

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

## CI And Verification Status

CI/CodeQL configured but not yet GitHub-verified. Workflow files are present locally, but no claim should be made that GitHub Actions or CodeQL have passed until the repository is pushed and those workflows run on GitHub.
