import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_docs_check_script_exists_and_passes() -> None:
    script = ROOT / "scripts" / "check-docs.py"

    assert script.is_file()
    result = subprocess.run([sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert "Documentation and sample safety checks passed." in result.stdout


def test_docs_are_honest_about_unverified_ci_and_codeql() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release_checklist = (ROOT / "docs" / "release-checklist.md").read_text(encoding="utf-8")

    combined = f"{readme}\n{release_checklist}"

    assert "CI/CodeQL configured but not yet GitHub-verified" in combined
    assert "- [ ] GitHub Actions passed on GitHub." in release_checklist
    assert "- [ ] CodeQL passed on GitHub." in release_checklist
    assert "- [ ] Repository published." in release_checklist
    assert "- [ ] Release created." in release_checklist


def test_readme_documents_implemented_cli_commands() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    expected_commands = [
        "python -m cloud_hardening_lab inventory --input samples --format json",
        "python -m cloud_hardening_lab validate-samples --input samples",
        "python -m cloud_hardening_lab scan --input samples --format json --min-severity high",
        "python -m cloud_hardening_lab scan --input samples --format text --min-severity medium",
        "python -m cloud_hardening_lab scan --input samples --format json --fail-on high",
        "python -m cloud_hardening_lab report --input samples --output "
        + "reports/examples/cloud_hardening_report.md --format markdown",
        "python -m cloud_hardening_lab report --input samples --output "
        + "reports/examples/cloud_hardening_report.json --format json",
    ]

    for command in expected_commands:
        assert command in readme
