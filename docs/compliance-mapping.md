# Compliance Mapping

Each detector rule is tagged with the CIS Benchmark control it corresponds to, where a control could be verified against a primary or clearly authoritative source. This mapping is a portfolio-scale illustration of compliance-aware reporting, not a certified benchmark assessment. Three rules have no verified CIS control and are marked as such rather than assigned a guessed number.

## How To Read This Table

- **CIS Control** and **Benchmark** identify the exact control and the benchmark version it was verified against. Control numbering is not stable across benchmark versions, so the version matters as much as the number.
- **Confidence** reflects how closely the detector's actual match logic lines up with the CIS control's literal wording, not whether the control itself exists. `high` means the detector's check condition matches the control's stated condition closely. `medium` and `low` mean the mapping is directionally correct but the detector tests something narrower, broader, or otherwise different from the control's exact language.
- **Caveat** is the specific reason a mapping isn't a precise 1:1 match, in plain language.

## Rule Mappings

| Rule ID | CIS Control | Benchmark | Confidence | Caveat |
| --- | --- | --- | --- | --- |
| `IAM-001` | `1.16` | CIS AWS Foundations Benchmark v1.4.0 | medium | This detector fires on a wildcard `Action` alone. The CIS control's literal recommendation is about a policy that combines a wildcard action **and** a wildcard resource into full `*:*` administrative privileges. The two detectors in this repo (`IAM-001`, `IAM-002`) each test one half of that condition independently. This control was also removed from the benchmark in v3.0.0 and v5.0.0, so it only exists as a distinctly numbered control in v1.4.0 (and as `1.22` in v1.2.0). |
| `IAM-002` | `1.16` | CIS AWS Foundations Benchmark v1.4.0 | medium | Same control and caveat as `IAM-001`: this detector tests wildcard `Resource` alone, which is the other half of the same CIS condition. |
| `IAM-003` | `2.1.4` | CIS AWS Foundations Benchmark v3.0.0 | low | No CIS AWS control was found that is specifically about a generic IAM-style policy `Principal: "*"`. This maps to the closest verified analog, the S3 block-public-access control, but `IAM-003` is not S3-specific in this codebase and the mapping is a best-effort analogy rather than a confirmed match. |
| `EXP-001` | `2.1.4` | CIS AWS Foundations Benchmark v3.0.0 | high | Direct match: the CIS control ("S3 general purpose buckets should have block public access settings enabled") addresses the same public storage access condition this detector checks. |
| `EXP-002` | `2.3.3` | CIS AWS Foundations Benchmark v3.0.0 | high | Direct match: the CIS control's literal test is the `PubliclyAccessible` configuration flag, which is exactly what this detector inspects. |
| `NET-001` | `5.2` | CIS AWS Foundations Benchmark v3.0.0 | medium | The CIS control's literal test is ingress from `0.0.0.0/0` to a management port. This repository's synthetic sample intentionally uses the reserved documentation CIDR `203.0.113.0/24` instead of a real public range, per this repo's safety rules for synthetic data. The security intent (open management ports) matches; the literal network condition in the sample does not. |
| `STO-001` | Not covered | — | — | No CIS AWS Foundations Benchmark control was found for a generic storage-encryption check. CIS encrypts-at-rest requirements are service-specific (for example, EBS default encryption or RDS encryption at rest), and this repository's synthetic storage samples use a made-up `Synthetic::Storage::Bucket` resource type rather than a real AWS service, so no single numbered control applies precisely. |
| `STO-002` | Not covered | — | — | No CIS AWS Foundations Benchmark control was found for plain storage versioning. The closest related control requires MFA delete (which itself depends on versioning being enabled), but that is a different, stricter requirement than this detector's plain versioning check. |
| `K8S-001` | `5.2.2` | CIS Kubernetes Benchmark v1.8.0 | medium | Title and control number were confirmed against two independent mirrors of the official benchmark text for v1.8.0. This control's number is not stable across benchmark versions: some tooling maps the same recommendation to `5.2.1` for benchmark releases aligned to older Kubernetes versions, so any consumer of this mapping should treat the number as tied to v1.8.0 specifically. |
| `K8S-002` | Not covered | — | — | No CIS Kubernetes Benchmark control was found for container CPU/memory resource limits. CIS Kubernetes Benchmark section 5.2 (Pod Security Standards) covers privileged mode, host namespaces, capabilities, and seccomp, not resource limits. Resource-limit enforcement is more commonly associated with general Kubernetes operational guidance than with a CIS Benchmark control. |

## Sources

- [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html) — AWS's official control-ID-to-CIS-version mapping page. Used to verify `IAM-001`, `IAM-002`, `IAM-003`, `EXP-001`, `EXP-002`, and `NET-001`.
- [Tenable audit: CIS Kubernetes Benchmark v1.8.0 Level 1 Master](https://www.tenable.com/audits/items/CIS_Kubernetes_v1.8.0_Level_1_Master.audit:a6b2d980c1bdf84ff67264aabac8dad5) — used to verify `K8S-001` for v1.8.0.
- [Aqua Security compliance database: CIS Kubernetes Benchmark v1.23](https://avd.aquasec.com/compliance/kubernetes/cis-kubernetes-benchmarks-v1.23-1.23/5.2.2/) — corroborating source for `K8S-001`.

## Known Gaps

- `STO-001`, `STO-002`, and `K8S-002` carry no CIS control ID by design. They are not omitted from the mapping table; they are explicitly recorded as unmapped so the gap is visible rather than silently missing.
- This mapping does not attempt to cover every CIS AWS Foundations Benchmark or CIS Kubernetes Benchmark control, only the ten detector rules implemented in this repository.
- Confidence levels and caveats reflect a one-time research pass against publicly available sources. They are not a substitute for a formal CIS certification or a compliance audit.
