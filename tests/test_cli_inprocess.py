import json
import sys
from pathlib import Path

import pytest

from cloud_hardening_lab import __main__ as module_main
from cloud_hardening_lab.cli import (
    build_parser,
    filter_findings,
    has_findings_at_or_above,
    main,
    run_inventory,
    run_report,
    run_scan,
    run_validate_samples,
    safe_output_path,
)
from cloud_hardening_lab.loaders.common import ConfigLoadError
from cloud_hardening_lab.models import Finding

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_build_parser_no_command_help() -> None:
    parser = build_parser()
    help_text = parser.format_help()

    assert "Defensive offline cloud hardening lab" in help_text
    assert "inventory" in help_text
    assert "scan" in help_text
    assert "report" in help_text


def test_run_inventory_inprocess_outputs_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_inventory(str(SAMPLES), recursive=True)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["summary"]["files_loaded"] == 19
    assert payload["summary"]["errors"] == 0


def test_run_validate_samples_inprocess_outputs_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_validate_samples(str(SAMPLES))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["summary"]["files_validated"] == 19
    assert payload["summary"]["invalid"] == 0


def test_run_scan_inprocess_json_and_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_scan(str(SAMPLES), "json", min_severity="high", fail_on="high")
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["summary"]["findings"] == 10
    assert payload["summary"]["min_severity"] == "high"
    assert payload["summary"]["fail_on"] == "high"


def test_run_scan_inprocess_text_verbose(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = run_scan(str(SAMPLES), "text", min_severity="medium", recursive=True, verbose=True)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Findings: 14" in output
    assert "Minimum severity: medium" in output
    assert "LOW" not in output


def test_run_report_inprocess_markdown_and_all(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    markdown_path = tmp_path / "report.md"
    all_path = tmp_path / "combined.out"

    markdown_exit = run_report(str(SAMPLES), str(markdown_path), "markdown", min_severity="high")
    markdown_payload = json.loads(capsys.readouterr().out)
    all_exit = run_report(str(SAMPLES), str(all_path), "all")
    all_payload = json.loads(capsys.readouterr().out)

    assert markdown_exit == 0
    assert all_exit == 0
    assert markdown_path.is_file()
    assert markdown_payload["outputs"] == [str(markdown_path)]
    assert (tmp_path / "combined.md").is_file()
    assert (tmp_path / "combined.json").is_file()
    assert len(all_payload["outputs"]) == 2


def test_safe_output_path_rejects_parent_traversal() -> None:
    with pytest.raises(ConfigLoadError):
        safe_output_path(Path("reports") / ".." / "outside.md")


def test_filter_and_fail_helpers() -> None:
    findings = [
        Finding(
            rule_id="LOW-001",
            title="Low",
            description="Low finding",
            category="storage",
            severity="low",
            file_path="sample.json",
            evidence="synthetic",
            recommendation="Review synthetic setting.",
            confidence="high",
            score=20,
        ),
        Finding(
            rule_id="HIGH-001",
            title="High",
            description="High finding",
            category="iam",
            severity="high",
            file_path="sample.json",
            evidence="synthetic",
            recommendation="Restrict synthetic setting.",
            confidence="high",
            score=80,
        ),
    ]

    filtered = filter_findings(findings, "medium")

    assert [finding.rule_id for finding in filtered] == ["HIGH-001"]
    assert has_findings_at_or_above(findings, "high")
    assert not has_findings_at_or_above(findings, "critical")


def test_main_dispatches_no_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["cloud-hardening-lab"])

    assert main() == 0


def test_main_returns_controlled_error_for_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["cloud-hardening-lab", "inventory", "--input", "missing"])

    assert main() == 2
    assert "error:" in capsys.readouterr().err


def test_module_main_calls_cli_main(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["cloud-hardening-lab"])

    assert module_main.main() == 0
