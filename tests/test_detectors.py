from pathlib import Path

from cloud_hardening_lab.detectors.engine import load_default_detectors, run_detectors, sort_findings
from cloud_hardening_lab.models import Finding

EXPECTED_RULE_IDS = {
    "IAM-001",
    "IAM-002",
    "IAM-003",
    "EXP-001",
    "EXP-002",
    "NET-001",
    "STO-001",
    "STO-002",
    "K8S-001",
    "K8S-002",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def test_default_detectors_load() -> None:
    detectors = load_default_detectors()

    assert len(detectors) == 10
    assert all(callable(detector) for detector in detectors)


def test_run_detectors_finds_expected_synthetic_sample_rules() -> None:
    root = Path(__file__).resolve().parents[1]

    findings = run_detectors([root / "samples"])
    rule_ids = {finding.rule_id for finding in findings}

    assert len(findings) == 15
    assert {
        "IAM-001",
        "IAM-002",
        "IAM-003",
        "EXP-001",
        "EXP-002",
        "NET-001",
        "STO-001",
        "K8S-001",
        "K8S-002",
    }.issubset(rule_ids)
    assert all(finding.synthetic for finding in findings)
    assert all(len(finding.evidence) <= 200 for finding in findings)
    assert all(finding.rule_id in EXPECTED_RULE_IDS for finding in findings)
    assert all(finding.severity in VALID_SEVERITIES for finding in findings)


def test_unique_rule_ids_for_known_rule_set() -> None:
    assert len(EXPECTED_RULE_IDS) == 10


def test_specific_sample_detections() -> None:
    root = Path(__file__).resolve().parents[1]
    cases = {
        root / "samples" / "terraform" / "broad_iam_policy.tf": {"IAM-001", "IAM-002"},
        root / "samples" / "generic" / "generic_broad_permissions.yaml": {"IAM-001", "IAM-002"},
        root / "samples" / "cloudformation" / "public_bucket_policy.json": {"IAM-003", "EXP-001"},
        root / "samples" / "terraform" / "public_storage_bucket.tf": {"EXP-001"},
        root / "samples" / "cloudformation" / "public_database.yaml": {"EXP-002"},
        root / "samples" / "cloudformation" / "missing_storage_encryption.yml": {"STO-001"},
        root / "samples" / "terraform" / "open_security_group.tf": {"NET-001"},
        root / "samples" / "kubernetes" / "privileged_pod.yaml": {"K8S-001"},
        root / "samples" / "kubernetes" / "missing_resource_limits.yaml": {"K8S-002"},
    }

    for path, expected_rule_ids in cases.items():
        findings = run_detectors([path])
        assert {finding.rule_id for finding in findings} == expected_rule_ids


def test_clean_samples_do_not_produce_findings() -> None:
    root = Path(__file__).resolve().parents[1]
    clean_paths = [
        root / "samples" / "terraform" / "clean_storage_bucket.tf",
        root / "samples" / "cloudformation" / "clean_stack.json",
        root / "samples" / "kubernetes" / "clean_deployment.yaml",
        root / "samples" / "generic" / "generic_clean_config.json",
    ]

    findings = run_detectors(clean_paths)

    assert findings == []


def test_clean_samples_produce_no_high_or_critical_findings() -> None:
    root = Path(__file__).resolve().parents[1]
    findings = run_detectors(
        [
            root / "samples" / "terraform" / "clean_storage_bucket.tf",
            root / "samples" / "cloudformation" / "clean_stack.json",
            root / "samples" / "kubernetes" / "clean_deployment.yaml",
            root / "samples" / "generic" / "generic_clean_config.json",
        ]
    )

    assert not [finding for finding in findings if finding.severity in {"critical", "high"}]


def test_sort_findings_orders_by_severity_then_rule_id() -> None:
    findings = [
        _finding(rule_id="ZZZ-001", severity="low"),
        _finding(rule_id="IAM-002", severity="high"),
        _finding(rule_id="IAM-001", severity="high"),
        _finding(rule_id="AAA-001", severity="critical"),
    ]

    sorted_findings = sort_findings(findings)

    assert [(finding.severity, finding.rule_id) for finding in sorted_findings] == [
        ("critical", "AAA-001"),
        ("high", "IAM-001"),
        ("high", "IAM-002"),
        ("low", "ZZZ-001"),
    ]


def test_finding_truncates_evidence_and_serializes() -> None:
    finding = _finding(evidence="x" * 250)

    payload = finding.to_dict()

    assert len(finding.evidence) == 200
    assert payload["synthetic"] is True
    assert payload["metadata"] == {}
    assert "score" in payload
    assert "remediation" in payload


def _finding(rule_id: str = "TST-001", severity: str = "low", evidence: str = "safe evidence") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test finding",
        description="Synthetic test finding.",
        category="storage",
        severity=severity,
        file_path="samples/test.json",
        resource_name=None,
        evidence=evidence,
        recommendation="Review and restrict this synthetic configuration.",
        confidence="high",
        synthetic=True,
        metadata=None,
    )
