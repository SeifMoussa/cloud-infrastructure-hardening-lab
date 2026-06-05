from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_workflow(path: str) -> dict:
    return yaml.load((ROOT / path).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_ci_workflow_has_required_jobs_and_triggers() -> None:
    workflow = load_workflow(".github/workflows/ci.yml")

    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert "workflow_dispatch" in workflow["on"]
    assert set(workflow["jobs"]) == {"tests", "docs", "cli-smoke"}


def test_ci_workflow_uses_python_312_and_coverage_gate() -> None:
    workflow = load_workflow(".github/workflows/ci.yml")
    serialized = str(workflow)

    assert serialized.count("'python-version': '3.12'") == 3
    assert 'python -m pip install -e ".[dev]"' in serialized
    assert "--cov=cloud_hardening_lab" in serialized
    assert "--cov-fail-under=90" in serialized
    assert "python scripts/check-docs.py" in serialized
    assert "python -m cloud_hardening_lab scan --input samples --format text --min-severity medium" in serialized
    assert "--fail-on high" not in serialized


def test_codeql_workflow_analyzes_python_with_security_quality_queries() -> None:
    workflow = load_workflow(".github/workflows/codeql.yml")
    serialized = str(workflow)
    supported_init_versions = {"github/codeql-action/init@v3", "github/codeql-action/init@v4"}
    supported_analyze_versions = {"github/codeql-action/analyze@v3", "github/codeql-action/analyze@v4"}

    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert "schedule" in workflow["on"]
    assert "workflow_dispatch" in workflow["on"]
    assert "languages': 'python'" in serialized
    assert "queries': 'security-and-quality'" in serialized
    assert any(version in serialized for version in supported_init_versions)
    assert any(version in serialized for version in supported_analyze_versions)


def test_dependabot_uses_weekly_pip_and_actions_updates_without_docker() -> None:
    config = yaml.load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    ecosystems = {entry["package-ecosystem"]: entry for entry in config["updates"]}

    assert set(ecosystems) == {"pip", "github-actions"}
    assert ecosystems["pip"]["schedule"]["interval"] == "weekly"
    assert ecosystems["github-actions"]["schedule"]["interval"] == "weekly"
    assert "docker" not in ecosystems
