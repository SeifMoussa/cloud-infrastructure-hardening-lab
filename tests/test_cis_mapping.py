import json
from pathlib import Path

from cloud_hardening_lab.compliance import CIS_MAPPING_BY_RULE_ID, apply_cis_mapping, cis_mapping_for_rule
from cloud_hardening_lab.detectors.engine import run_detectors
from cloud_hardening_lab.loaders.inventory import list_config_files
from cloud_hardening_lab.models import Finding
from cloud_hardening_lab.reporting import build_report_context, render_json_report, render_markdown_report

EXPECTED_MAPPED_CONTROLS = {
    "IAM-001": ("1.16", "CIS AWS Foundations Benchmark v1.4.0"),
    "IAM-002": ("1.16", "CIS AWS Foundations Benchmark v1.4.0"),
    "IAM-003": ("2.1.4", "CIS AWS Foundations Benchmark v3.0.0"),
    "EXP-001": ("2.1.4", "CIS AWS Foundations Benchmark v3.0.0"),
    "EXP-002": ("2.3.3", "CIS AWS Foundations Benchmark v3.0.0"),
    "NET-001": ("5.2", "CIS AWS Foundations Benchmark v3.0.0"),
    "K8S-001": ("5.2.2", "CIS Kubernetes Benchmark v1.8.0"),
}

EXPECTED_UNMAPPED_RULES = {"STO-001", "STO-002", "K8S-002"}

SAMPLE_RULE_CASES = {
    "terraform/broad_iam_policy.tf": {"IAM-001", "IAM-002"},
    "cloudformation/public_bucket_policy.json": {"IAM-003", "EXP-001"},
    "cloudformation/public_database.yaml": {"EXP-002"},
    "terraform/open_security_group.tf": {"NET-001"},
    "cloudformation/missing_storage_encryption.yml": {"STO-001"},
    "kubernetes/privileged_pod.yaml": {"K8S-001"},
    "kubernetes/missing_resource_limits.yaml": {"K8S-002"},
}


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test finding",
        description="Synthetic test finding.",
        category="storage",
        severity="low",
        file_path="samples/test.json",
        evidence="safe evidence",
        recommendation="Review and restrict this synthetic configuration.",
        confidence="high",
    )


def test_cis_mapping_table_covers_every_known_rule_id() -> None:
    known_rule_ids = set(EXPECTED_MAPPED_CONTROLS) | EXPECTED_UNMAPPED_RULES
    assert set(CIS_MAPPING_BY_RULE_ID) == known_rule_ids


def test_mapped_rules_carry_their_verified_cis_control_id() -> None:
    for rule_id, (control_id, benchmark) in EXPECTED_MAPPED_CONTROLS.items():
        mapping = cis_mapping_for_rule(rule_id)

        assert mapping.control_id == control_id
        assert mapping.benchmark == benchmark
        assert mapping.confidence in {"high", "medium", "low"}


def test_high_confidence_mappings_carry_no_stale_caveat() -> None:
    for rule_id in ("EXP-001", "EXP-002"):
        mapping = cis_mapping_for_rule(rule_id)

        assert mapping.confidence == "high"
        assert mapping.note is None


def test_unmapped_rules_carry_none_with_an_explicit_reason() -> None:
    for rule_id in EXPECTED_UNMAPPED_RULES:
        mapping = cis_mapping_for_rule(rule_id)

        assert mapping.control_id is None
        assert mapping.benchmark is None
        assert mapping.confidence is None
        assert "not covered" in mapping.note.lower()


def test_apply_cis_mapping_attaches_fields_for_a_mapped_and_an_unmapped_rule() -> None:
    findings = apply_cis_mapping([_finding("EXP-001"), _finding("STO-001")])
    mapped, unmapped = findings

    assert mapped.cis_control_id == "2.1.4"
    assert mapped.cis_benchmark == "CIS AWS Foundations Benchmark v3.0.0"
    assert mapped.cis_confidence == "high"

    assert unmapped.cis_control_id is None
    assert unmapped.cis_benchmark is None
    assert unmapped.cis_confidence is None
    assert "not covered" in unmapped.cis_note.lower()


def test_run_detectors_attaches_the_expected_cis_control_per_sample_category() -> None:
    root = Path(__file__).resolve().parents[1] / "samples"

    for relative_path, expected_rule_ids in SAMPLE_RULE_CASES.items():
        findings = run_detectors([root / relative_path])
        by_rule = {finding.rule_id: finding for finding in findings}

        assert set(by_rule) == expected_rule_ids
        for rule_id in expected_rule_ids:
            finding = by_rule[rule_id]
            if rule_id in EXPECTED_MAPPED_CONTROLS:
                control_id, benchmark = EXPECTED_MAPPED_CONTROLS[rule_id]
                assert finding.cis_control_id == control_id
                assert finding.cis_benchmark == benchmark
            else:
                assert finding.cis_control_id is None
                assert finding.cis_note


def test_json_report_carries_cis_fields_for_mapped_and_unmapped_findings() -> None:
    root = Path(__file__).resolve().parents[1]
    findings = run_detectors([root / "samples"])
    context = build_report_context(
        input_path="samples",
        files_scanned=len(list_config_files(root / "samples")),
        findings=findings,
        generated_at="2024-01-01T00:00:00Z",
    )

    payload = json.loads(render_json_report(context))
    by_rule = {finding["rule_id"]: finding for finding in payload["findings"]}

    assert by_rule["EXP-001"]["cis_control_id"] == "2.1.4"
    assert by_rule["EXP-001"]["cis_benchmark"] == "CIS AWS Foundations Benchmark v3.0.0"
    assert by_rule["STO-001"]["cis_control_id"] is None
    assert "not covered" in by_rule["STO-001"]["cis_note"].lower()


def test_markdown_report_shows_a_cis_control_column() -> None:
    root = Path(__file__).resolve().parents[1]
    findings = run_detectors([root / "samples"])
    context = build_report_context(
        input_path="samples",
        files_scanned=len(list_config_files(root / "samples")),
        findings=findings,
        generated_at="2024-01-01T00:00:00Z",
    )

    markdown = render_markdown_report(context)

    assert "CIS Control" in markdown
    assert "1.16 (CIS AWS Foundations Benchmark v1.4.0" in markdown
    assert "Not covered" in markdown
