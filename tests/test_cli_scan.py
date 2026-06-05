import json
import subprocess
import sys
from pathlib import Path


def test_scan_cli_outputs_stable_json() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "scan",
            "--input",
            str(root / "samples"),
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["summary"]["findings"] == 15
    assert payload["summary"]["max_score"] is not None
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["score"] is not None
    assert payload["findings"][0]["remediation"]
    assert all(finding["synthetic"] for finding in payload["findings"])


def test_scan_cli_outputs_text() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "scan",
            "--input",
            str(root / "samples" / "terraform" / "broad_iam_policy.tf"),
            "--format",
            "text",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert "Findings: 2" in result.stdout
    assert "score=" in result.stdout
    assert "IAM-001" in result.stdout
    assert "IAM-002" in result.stdout


def test_scan_cli_invalid_path_exits_nonzero() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "scan",
            "--input",
            "missing-local-path",
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode != 0
    assert "input path does not exist" in result.stderr
