# Detection Rules

The current detector set is intentionally small, readable, and interview-friendly. It models a focused subset of defensive cloud hardening issues against local synthetic files only. It does not call cloud APIs, Kubernetes APIs, third-party scanners, or provider SDKs.

## Detection Categories

- IAM-style policy risks
- Public exposure
- Storage hardening
- Network exposure
- Kubernetes hardening

## Implemented Rules

| Rule ID | Category | Title | Severity | What It Flags | CIS Control |
| --- | --- | --- | --- | --- | --- |
| `IAM-001` | `iam` | Wildcard action | `high` | IAM-style action lists that use broad wildcard permissions | `1.16` (CIS AWS Foundations Benchmark v1.4.0) |
| `IAM-002` | `iam` | Wildcard resource | `high` | IAM-style policies that target `*` resources | `1.16` (CIS AWS Foundations Benchmark v1.4.0) |
| `IAM-003` | `iam` | Public principal | `high` | Public access principals in synthetic policy examples | `2.1.4` (CIS AWS Foundations Benchmark v3.0.0) |
| `EXP-001` | `public_exposure` | Public storage exposure | `high` | Synthetic storage resources exposed publicly | `2.1.4` (CIS AWS Foundations Benchmark v3.0.0) |
| `EXP-002` | `public_exposure` | Public database exposure | `high` | Synthetic databases marked publicly accessible | `2.3.3` (CIS AWS Foundations Benchmark v3.0.0) |
| `NET-001` | `network` | Public management ingress | `medium` | Management ports exposed to a documentation CIDR | `5.2` (CIS AWS Foundations Benchmark v3.0.0) |
| `STO-001` | `storage` | Missing storage encryption | `medium` | Synthetic storage objects with encryption disabled | Not covered |
| `STO-002` | `storage` | Missing storage versioning | `low` | Synthetic storage examples without versioning enabled | Not covered |
| `K8S-001` | `kubernetes` | Privileged container | `high` | Containers set to privileged mode | `5.2.2` (CIS Kubernetes Benchmark v1.8.0) |
| `K8S-002` | `kubernetes` | Missing resource limits | `low` | Kubernetes containers without defined CPU or memory limits | Not covered |

See [`docs/compliance-mapping.md`](compliance-mapping.md) for the confidence level, source citations, and specific caveat behind each CIS control mapping above.

## Detection Behavior

- JSON, YAML, and TOML files are loaded into structured data and inspected locally.
- Terraform-like `.tf` files are inspected as raw text rather than fully parsed HCL.
- Findings are sorted deterministically to keep test output and public example reports stable.
- Evidence snippets are short, local, and synthetic-only.

## Why These Rules

The rule set is built around common cloud security review themes that are easy to explain in a portfolio:

- Excessive permissions
- Public data exposure
- Weak storage defaults
- Overly broad network access
- Basic Kubernetes workload hardening

This is enough to show detection engineering and secure-by-default thinking without overstating the project as a broad production platform.

## Finding Shape

Each finding includes:

- Rule ID
- Category
- Severity
- Confidence
- Evidence excerpt
- Resource name when available
- Deterministic score
- Scoring reason
- Defensive remediation guidance
- CIS control mapping (control ID, benchmark, and confidence, or an explicit "not covered" note)

## Known Detection Limitations

- No live cloud context, identity graph, or runtime telemetry
- No provider-specific Terraform plan analysis
- No container image, package, or vulnerability scanning
- No Kubernetes admission-control or cluster-state integration
- No claim of production CSPM/CNAPP replacement coverage

## Safety Notes

- Defensive-only
- Offline-only
- Local synthetic files only
- No live AWS/Azure/GCP/Kubernetes API calls
- No real credentials
- No real cloud accounts
- No third-party scanning
- No offensive use
- No privilege escalation instructions

## CI And Verification Status

CI/CodeQL configured but not yet GitHub-verified.
