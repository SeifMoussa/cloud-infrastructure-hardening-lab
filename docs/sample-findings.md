# Sample Findings

This project ships with synthetic local samples that intentionally trigger a small set of cloud hardening findings. The goal is to demonstrate how the lab represents issues, scores them, and recommends defensive remediation without using live cloud resources.

## Sample Sources

- `samples/terraform/`
  Terraform-like `.tf` raw text
- `samples/cloudformation/`
  CloudFormation-like JSON/YAML
- `samples/kubernetes/`
  Kubernetes YAML
- `samples/generic/`
  Generic JSON/YAML/TOML

All included findings come from local synthetic files only.

## Example Finding Shape

```json
{
  "category": "iam",
  "confidence": "high",
  "description": "A synthetic IAM-style policy uses a wildcard action.",
  "evidence": "actions = [\"synthetic:*\"]",
  "file_path": "terraform/broad_iam_policy.tf",
  "metadata": {},
  "recommendation": "Replace wildcard actions with the minimum specific actions required for the synthetic lab role.",
  "remediation": "Replace wildcard actions with the minimum specific actions required for the synthetic lab role.",
  "resource_name": "fake-lab-role",
  "rule_id": "IAM-001",
  "score": 85,
  "scoring_reason": "Base severity high=80; category iam=3; confidence high=2; clamped to 70-89.",
  "severity": "high",
  "severity_weight": 80,
  "confidence_weight": 2,
  "category_weight": 3,
  "synthetic": true,
  "title": "Wildcard action",
  "cis_control_id": "1.16",
  "cis_benchmark": "CIS AWS Foundations Benchmark v1.4.0",
  "cis_confidence": "medium",
  "cis_note": "See docs/compliance-mapping.md for the benchmark version and mapping caveats."
}
```

Rules without a verified CIS control, such as `STO-001`, carry `cis_control_id`, `cis_benchmark`, and `cis_confidence` set to `null` and a `cis_note` explaining the gap, for example:

```json
{
  "cis_control_id": null,
  "cis_benchmark": null,
  "cis_confidence": null,
  "cis_note": "Not covered by the CIS AWS Foundations Benchmark or the CIS Kubernetes Benchmark. See docs/compliance-mapping.md."
}
```

See [`docs/compliance-mapping.md`](compliance-mapping.md) for the full rule-by-rule CIS mapping, confidence levels, and caveats.

## Current Example Findings

The bundled synthetic samples currently demonstrate:

- IAM-style wildcard actions and wildcard resources
- Public principals
- Public storage exposure
- Public database exposure
- Public management ingress
- Missing storage encryption
- Privileged containers
- Missing Kubernetes resource limits

The examples are intentionally simple and public-safe. They are not drawn from real production incidents, real accounts, or real infrastructure inventories.

## Report Outputs

Example reports generated from the sample set live at:

- [`reports/examples/cloud_hardening_report.md`](../reports/examples/cloud_hardening_report.md)
- [`reports/examples/cloud_hardening_report.json`](../reports/examples/cloud_hardening_report.json)

Those reports include safety scope, finding details, scores, remediation guidance, and limitations suitable for public GitHub review.

## Interpretation Guidance

- A higher severity does not imply real-world risk because the lab uses synthetic local files only.
- Scores are deterministic and designed for explainability, not enterprise risk quantification.
- Remediation text explains hardening direction, not exact live-environment change procedures.

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
- Not a production CSPM/CNAPP replacement

## CI And Verification Status

CI/CodeQL configured but not yet GitHub-verified.
