import subprocess
import sys


def test_module_help_command() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "cloud_hardening_lab", "--help"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 0
    assert "Defensive offline cloud hardening lab" in result.stdout
