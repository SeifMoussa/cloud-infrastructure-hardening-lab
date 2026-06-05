import json
import subprocess
import sys
from pathlib import Path


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cloud_hardening_lab", *args],
        capture_output=True,
        check=False,
        text=True,
    )


def test_command_help_is_safety_aware() -> None:
    for command in ((), ("inventory",), ("validate-samples",), ("scan",), ("report",)):
        result = run_cli(*command, "--help")

        assert result.returncode == 0
        assert "local" in result.stdout.lower() or "offline" in result.stdout.lower()


def test_scan_invalid_input_path_fails_safely() -> None:
    result = run_cli("scan", "--input", "missing-path", "--format", "json")

    assert result.returncode == 2
    assert "input path does not exist" in result.stderr


def test_scan_invalid_format_fails_clearly() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "xml")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_scan_invalid_min_severity_fails_clearly() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "json", "--min-severity", "urgent")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_scan_invalid_fail_on_fails_clearly() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "json", "--fail-on", "informational")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_scan_fail_on_high_returns_nonzero_when_high_findings_exist() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "json", "--fail-on", "high")

    payload = json.loads(result.stdout)
    assert result.returncode == 1
    assert payload["summary"]["fail_on"] == "high"
    assert payload["summary"]["findings"] == 15


def test_scan_fail_on_critical_returns_zero_for_current_samples() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "json", "--fail-on", "critical")

    assert result.returncode == 0


def test_scan_min_severity_filters_json_output() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "json", "--min-severity", "high")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["findings"] == 10
    assert set(payload["summary"]["by_severity"]) == {"high"}
    assert all(finding["severity"] == "high" for finding in payload["findings"])


def test_scan_min_severity_filters_text_output() -> None:
    result = run_cli("scan", "--input", "samples", "--format", "text", "--min-severity", "medium")

    assert result.returncode == 0
    assert "Findings: 14" in result.stdout
    assert "LOW score=" not in result.stdout
    assert "MEDIUM score=" in result.stdout


def test_report_min_severity_filters_json_report(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "report.json"
    result = run_cli(
        "report",
        "--input",
        "samples",
        "--output",
        str(output),
        "--format",
        "json",
        "--min-severity",
        "high",
    )
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert output.exists()
    assert payload["summary"]["findings"] == 10
    assert all(finding["severity"] == "high" for finding in payload["findings"])


def test_report_output_parent_directory_creation(tmp_path: Path) -> None:
    output = tmp_path / "new" / "deep" / "report.md"
    result = run_cli("report", "--input", "samples", "--output", str(output), "--format", "markdown")

    assert result.returncode == 0
    assert output.exists()


def test_report_output_parent_traversal_fails_safely(tmp_path: Path) -> None:
    output = tmp_path / ".." / "report.md"
    result = run_cli("report", "--input", "samples", "--output", str(output), "--format", "markdown")

    assert result.returncode == 2
    assert "parent traversal" in result.stderr


def test_empty_directory_scan_behavior(tmp_path: Path) -> None:
    result = run_cli("scan", "--input", str(tmp_path), "--format", "json")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["findings"] == 0
    assert payload["findings"] == []


def test_non_recursive_scan_ignores_nested_files(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "config.json").write_text('{"synthetic-lab": true, "public_access": true}', encoding="utf-8")

    result = run_cli("scan", "--input", str(tmp_path), "--format", "json", "--no-recursive")
    payload = json.loads(result.stdout)

    assert result.returncode == 0
    assert payload["summary"]["findings"] == 0
