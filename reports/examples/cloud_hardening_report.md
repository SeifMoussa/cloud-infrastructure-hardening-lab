# Cloud Infrastructure Hardening Report

Generated at: `2026-06-05T13:41:33Z`

## Safety Scope

Synthetic offline lab report generated only from local sample files. No live cloud APIs, credentials, real customer data, or third-party scanning are used.

## Executive Summary

- Input path: `samples`
- Files scanned: `19`
- Total findings: `15`
- Highest severity: `high`
- Max score: `86`
- Average score: `74.27`

## Findings By Severity

| Severity | Count |
| --- | ---: |
| `high` | 10 |
| `low` | 1 |
| `medium` | 4 |

## Findings By Category

| Category | Count |
| --- | ---: |
| `iam` | 5 |
| `kubernetes` | 2 |
| `network` | 2 |
| `public_exposure` | 4 |
| `storage` | 2 |

## Detailed Findings

| Rule ID | Severity | Score | Category | File Path | Title | Evidence | Remediation |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| `EXP-001` | `high` | 86 | `public_exposure` | `cloudformation/public_bucket_policy.json` | Public storage exposure | Principal: public | Disable public storage access unless there is a documented lab requirement. |
| `EXP-002` | `high` | 86 | `public_exposure` | `cloudformation/public_database.yaml` | Public database exposure | PubliclyAccessible: true | Disable public database access and restrict connectivity to approved synthetic network paths. |
| `EXP-001` | `high` | 86 | `public_exposure` | `generic/generic_public_storage.toml` | Public storage exposure | public_access: true | Disable public storage access unless there is a documented lab requirement. |
| `EXP-001` | `high` | 86 | `public_exposure` | `terraform/public_storage_bucket.tf` | Public storage exposure | public_read = true | Disable public storage access unless there is a documented lab requirement. |
| `IAM-003` | `high` | 85 | `iam` | `cloudformation/public_bucket_policy.json` | Public principal | Principal: public | Restrict access to trusted synthetic identities and remove public principals. |
| `IAM-001` | `high` | 85 | `iam` | `generic/generic_broad_permissions.yaml` | Wildcard action | actions: synthetic:* | Replace wildcard actions with the minimum specific actions required for the synthetic lab role. |
| `IAM-002` | `high` | 85 | `iam` | `generic/generic_broad_permissions.yaml` | Wildcard resource | resources: * | Scope permissions to specific fake lab resources instead of using a wildcard resource. |
| `IAM-001` | `high` | 85 | `iam` | `terraform/broad_iam_policy.tf` | Wildcard action | actions = ["synthetic:*"] | Replace wildcard actions with the minimum specific actions required for the synthetic lab role. |
| `IAM-002` | `high` | 85 | `iam` | `terraform/broad_iam_policy.tf` | Wildcard resource | resources = ["*"] | Scope permissions to specific fake lab resources instead of using a wildcard resource. |
| `K8S-001` | `high` | 83 | `kubernetes` | `kubernetes/privileged_pod.yaml` | Privileged container | privileged: true | Disable privileged mode and use the least container permissions needed for the lab workload. |
| `NET-001` | `medium` | 59 | `network` | `generic/generic_open_admin_port.json` | Public management ingress | port: 22 or 3389 with cidr: 203.0.113.0/24 | Restrict management ingress to the smallest documented lab CIDR and expose only required ports. |
| `NET-001` | `medium` | 59 | `network` | `terraform/open_security_group.tf` | Public management ingress | port 22 with cidr 203.0.113.0/24 | Restrict management ingress to the smallest documented lab CIDR and expose only required ports. |
| `STO-001` | `medium` | 58 | `storage` | `cloudformation/missing_storage_encryption.yml` | Missing storage encryption | EncryptionEnabled: false | Enable encryption at rest for the synthetic storage resource. |
| `STO-001` | `medium` | 58 | `storage` | `terraform/missing_encryption.tf` | Missing storage encryption | encryption_status = "disabled" | Enable encryption at rest for the synthetic storage resource. |
| `K8S-002` | `low` | 28 | `kubernetes` | `kubernetes/missing_resource_limits.yaml` | Missing resource limits | container resources.limits missing | Define CPU and memory requests and limits for the synthetic Kubernetes container. |

## Remediation Summary

- `EXP-001`: Disable public storage access unless there is a documented lab requirement.
- `EXP-002`: Disable public database access and restrict connectivity to approved synthetic network paths.
- `IAM-003`: Restrict access to trusted synthetic identities and remove public principals.
- `IAM-001`: Replace wildcard actions with the minimum specific actions required for the synthetic lab role.
- `IAM-002`: Scope permissions to specific fake lab resources instead of using a wildcard resource.
- `K8S-001`: Disable privileged mode and use the least container permissions needed for the lab workload.
- `NET-001`: Restrict management ingress to the smallest documented lab CIDR and expose only required ports.
- `STO-001`: Enable encryption at rest for the synthetic storage resource.
- `K8S-002`: Define CPU and memory requests and limits for the synthetic Kubernetes container.

## Limitations

This report is generated from synthetic local files only. It is not a production security assessment, does not authenticate to cloud providers, and does not inspect live infrastructure.
