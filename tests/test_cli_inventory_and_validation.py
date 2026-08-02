import json
import subprocess
import sys
from pathlib import Path


def test_inventory_cli_outputs_stable_json() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "inventory",
            "--input",
            str(root / "samples" / "generic"),
            "--format",
            "json",
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["summary"]["files_loaded"] == 4
    assert payload["summary"]["errors"] == 0
    assert [item["path"] for item in payload["files"]] == sorted(item["path"] for item in payload["files"])


def test_validate_samples_cli_outputs_stable_json() -> None:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "validate-samples",
            "--input",
            str(root / "samples"),
        ],
        capture_output=True,
        check=False,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["summary"] == {"files_validated": 19, "invalid": 0}


def test_cli_invalid_path_exits_nonzero() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cloud_hardening_lab",
            "inventory",
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
