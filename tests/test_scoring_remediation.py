from pathlib import Path

from cloud_hardening_lab.detectors.engine import run_detectors, sort_findings
from cloud_hardening_lab.models import Finding
from cloud_hardening_lab.remediation import REMEDIATION_BY_RULE_ID, apply_remediation
from cloud_hardening_lab.scoring import SEVERITY_RANGES, apply_scoring, score_finding, summarize_findings

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

BANNED_REMEDIATION_TERMS = {"exploit", "payload", "privilege escalation", "exfiltrate"}


def test_severity_to_score_mapping_ranges() -> None:
    for severity, expected_range in SEVERITY_RANGES.items():
        scored = score_finding(_finding(severity=severity))

        assert expected_range[0] <= scored.score <= expected_range[1]
        assert scored.severity_weight is not None
        assert scored.scoring_reason


def test_scoring_is_deterministic() -> None:
    finding = _finding(severity="high", category="iam", confidence="high")

    assert score_finding(finding).score == score_finding(finding).score


def test_category_weighting_changes_score_within_range() -> None:
    iam_score = score_finding(_finding(severity="medium", category="iam")).score
    storage_score = score_finding(_finding(severity="medium", category="storage")).score

    assert iam_score > storage_score
    assert SEVERITY_RANGES["medium"][0] <= iam_score <= SEVERITY_RANGES["medium"][1]


def test_remediation_exists_for_every_default_rule() -> None:
    assert set(REMEDIATION_BY_RULE_ID) == EXPECTED_RULE_IDS
    assert all(REMEDIATION_BY_RULE_ID[rule_id] for rule_id in EXPECTED_RULE_IDS)


def test_remediation_text_is_defensive_and_safe() -> None:
    for guidance in REMEDIATION_BY_RULE_ID.values():
        lowered = guidance.lower()
        assert not any(term in lowered for term in BANNED_REMEDIATION_TERMS)
        assert not any(marker in lowered for marker in ("aws ", "az ", "gcloud ", "kubectl "))


def test_scan_findings_include_score_and_remediation() -> None:
    root = Path(__file__).resolve().parents[1]
    findings = run_detectors([root / "samples"])

    assert findings
    assert all(finding.score is not None for finding in findings)
    assert all(finding.scoring_reason for finding in findings)
    assert all(finding.remediation for finding in findings)
    assert all(finding.to_dict()["remediation"] for finding in findings)


def test_score_sorting_is_deterministic() -> None:
    findings = apply_scoring(
        apply_remediation(
            [
                _finding(rule_id="NET-001", severity="medium", category="network", file_path="b.yaml"),
                _finding(rule_id="IAM-001", severity="high", category="iam", file_path="a.yaml"),
                _finding(rule_id="EXP-001", severity="high", category="public_exposure", file_path="c.yaml"),
            ]
        )
    )

    sorted_findings = sort_findings(findings)

    assert [finding.rule_id for finding in sorted_findings] == ["EXP-001", "IAM-001", "NET-001"]


def test_summary_helper_counts_findings() -> None:
    findings = apply_scoring(
        [
            _finding(rule_id="IAM-001", severity="high", category="iam"),
            _finding(rule_id="STO-001", severity="medium", category="storage"),
        ]
    )

    summary = summarize_findings(findings)

    assert summary["findings"] == 2
    assert summary["by_severity"] == {"high": 1, "medium": 1}
    assert summary["by_category"] == {"iam": 1, "storage": 1}
    assert summary["highest_severity"] == "high"
    assert summary["max_score"] is not None


def _finding(
    rule_id: str = "IAM-001",
    severity: str = "low",
    category: str = "iam",
    confidence: str = "high",
    file_path: str = "samples/test.yaml",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Synthetic finding",
        description="Synthetic local finding.",
        category=category,
        severity=severity,
        file_path=file_path,
        resource_name="fake-lab-role",
        evidence="safe evidence",
        recommendation="Review and restrict this synthetic configuration.",
        confidence=confidence,
        synthetic=True,
    )
