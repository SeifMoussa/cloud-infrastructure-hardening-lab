# Safety Scope

Cloud Infrastructure Hardening Lab is restricted to defensive-only, offline-only review of local synthetic cloud configuration files. The repository is intended to remain safe for public GitHub hosting, recruiter review, and local educational use.

## In Scope

- Local synthetic sample files under `samples/`
- Synthetic IAM-style policy examples
- Synthetic CloudFormation-like JSON/YAML
- Synthetic Kubernetes YAML
- Synthetic generic JSON/YAML/TOML
- Deterministic local scanning, scoring, remediation guidance, and report generation
- Documentation and tests that enforce safe portfolio boundaries

## Out Of Scope

- Live AWS, Azure, GCP, or Kubernetes API calls
- Real cloud accounts
- Real credentials, tokens, secrets, certificates, or private keys
- Third-party scanning
- Runtime cloud assessment
- Offensive use
- Privilege escalation instructions
- Unauthorized access workflows
- Production CSPM or CNAPP coverage claims

## Local-Only Execution Model

The CLI operates on explicit local paths only. It inventories files, validates sample safety, scans the supported formats, and writes reports to a requested local output path. It does not authenticate to providers, enumerate subscriptions or accounts, inspect live clusters, or send data to remote scanning services.

## Supported Sample Types

- Terraform-like `.tf` raw text
- CloudFormation-like JSON/YAML
- Kubernetes YAML
- Generic JSON/YAML/TOML

## Synthetic Data Rules

The project relies on clear synthetic markers and reserved example identifiers so the repository stays public-safe:

- Allowed fake account IDs: `000000000000`, `123456789012`
- Allowed fake ARN: `arn:aws:iam::123456789012:role/fake-lab-role`
- Allowed domains: `example.com`, `example.org`, `example.net`, `lab.example.com`, and `.test`
- Allowed documentation network ranges include `203.0.113.0/24`

These values exist only to model defensive detection scenarios. They do not represent real tenants, subscriptions, clusters, or customer infrastructure.

## Safety Commitments

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

## Public Portfolio Positioning

This repository is a portfolio lab, not a live environment assessment tool. It demonstrates engineering judgment around safe sample creation, local validation, rule implementation, scoring transparency, and documentation honesty.

## CI And Verification Status

CI/CodeQL configured but not yet GitHub-verified. Workflow files are present locally, but the project should not claim GitHub Actions or CodeQL success until the first push and actual GitHub execution.
