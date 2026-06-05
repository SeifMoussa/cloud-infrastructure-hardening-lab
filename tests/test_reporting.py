import json
import subprocess
import sys
from pathlib import Path

from cloud_hardening_lab.detectors.engine import run_detectors
from cloud_hardening_lab.loaders.inventory import list_config_files
from cloud_hardening_lab.reporting import (
    build_json_report,
    build_report_context,
    render_json_report,
    render_markdown_report,
)


def test_markdown_report_generation_contains_required_sections() -> None:
    context = _context()

    report = render_markdown_report(context)

    assert "# Cloud Infrastructure Hardening Report" in report
    assert "## Safety Scope" in report
    assert "Synthetic offline lab report" in report
    assert "## Findings By Severity" in report
    assert "## Findings By Category" in report
    assert "## Detailed Findings" in report
    assert "## Remediation Summary" in report
    assert "score" not in report.lower() or "Score" in report
    assert "Disable public storage access" in report


def test_json_report_generation_contains_required_fields() -> None:
    context = _context()

    payload = build_json_report(context)

    assert payload["schema_version"] == "1.0"
    assert payload["generated_at"] == "2024-01-01T00:00:00Z"
    assert payload["tool_name"] == "cloud-infrastructure-hardening-lab"
    assert payload["files_scanned"] == 19
    assert payload["summary"]["findings"] == 15
    assert payload["findings"][0]["score"] is not None
    assert payload["findings"][0]["remediation"]
    assert payload["report_metadata"] == {"offline": True, "report_type": "json", "synthetic": True}


def test_json_report_rendering_is_stable_json() -> None:
    rendered = render_json_report(_context())
    payload = json.loads(rendered)

    assert payload["summary"]["max_score"] == 86
    assert rendered.endswith("\n")


def test_report_does_not_include_unsafe_content() -> None:
    markdown = render_markdown_report(_context()).lower()
    json_report = render_json_report(_context()).lower()
    combined = f"{markdown}\n{json_report}"

    assert "akia" not in combined
    assert "secret access key" not in combined
    assert "exploit" not in combined
    assert "privilege escalation" not in combined
    assert "production cspm" not in combined


def test_cli_report_markdown_writes_file(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "cloud_hardening_report.md"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "report",
            "--input",
            str(root / "samples"),
            "--output",
            str(output),
            "--format",
            "markdown",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert output.exists()
    assert "# Cloud Infrastructure Hardening Report" in output.read_text(encoding="utf-8")


def test_cli_report_json_writes_file(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "cloud_hardening_report.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "report",
            "--input",
            str(root / "samples"),
            "--output",
            str(output),
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result.returncode == 0
    assert payload["summary"]["findings"] == 15
    assert payload["safety_scope"]


def test_cli_report_invalid_format_fails_safely(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "report",
            "--input",
            str(root / "samples"),
            "--output",
            str(tmp_path / "report.txt"),
            "--format",
            "xml",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_cli_report_missing_output_fails_safely() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "report",
            "--input",
            str(root / "samples"),
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert "required" in result.stderr


def _context():
    root = Path(__file__).resolve().parents[1]
    findings = run_detectors([root / "samples"])
    return build_report_context(
        input_path="samples",
        files_scanned=len(list_config_files(root / "samples")),
        findings=findings,
        generated_at="2024-01-01T00:00:00Z",
    )
