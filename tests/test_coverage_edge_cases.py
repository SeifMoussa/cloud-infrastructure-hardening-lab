import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from cloud_hardening_lab.cli import main as cli_main
from cloud_hardening_lab.cli import run_report, write_report_outputs
from cloud_hardening_lab.detectors.common import find_resource_name, string_values, walk_values
from cloud_hardening_lab.detectors.engine import run_detectors
from cloud_hardening_lab.detectors.kubernetes import detect_kubernetes_missing_resource_limits
from cloud_hardening_lab.detectors.public_exposure import detect_public_database_exposure
from cloud_hardening_lab.detectors.storage import detect_storage_missing_encryption, detect_storage_missing_versioning
from cloud_hardening_lab.loaders import text_loader
from cloud_hardening_lab.loaders.common import MAX_CONFIG_SIZE_BYTES, ConfigLoadError, read_text_file
from cloud_hardening_lab.loaders.inventory import load_config_file
from cloud_hardening_lab.loaders.text_loader import load_text_file
from cloud_hardening_lab.models import ConfigFile, ParseStatus
from cloud_hardening_lab.models.scan import ScanSummary
from cloud_hardening_lab.reporting import build_report_context, render_markdown_report
from cloud_hardening_lab.safety import validate_sample_file, validate_samples
from cloud_hardening_lab.validation import validate_loaded_config, validate_sample_tree

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def make_config(tmp_path: Path, raw_text: str, parsed: object = None, suffix: str = ".yaml") -> ConfigFile:
    path = tmp_path / f"sample{suffix}"
    path.write_text(raw_text, encoding="utf-8")
    return ConfigFile(
        path=path.resolve(),
        relative_path=path.name,
        file_type="yaml" if suffix in {".yaml", ".yml"} else "terraform_text",
        raw_text=raw_text,
        parsed=parsed,
        parse_status=ParseStatus.PARSED if parsed is not None else ParseStatus.RAW_TEXT,
        error_message=None,
        synthetic=True,
        size_bytes=path.stat().st_size,
    )


def test_scan_summary_placeholder_model_has_files_loaded() -> None:
    summary = ScanSummary(files_loaded=3)

    assert summary.files_loaded == 3


def test_walk_values_and_string_values_cover_nested_lists() -> None:
    value = {"outer": ["alpha", {"inner": "beta"}, 3]}

    assert "alpha" in list(walk_values(value))
    assert list(string_values(value)) == ["alpha", "beta"]


def test_find_resource_name_returns_none_when_no_name_or_text_match(tmp_path: Path) -> None:
    config = make_config(tmp_path, "synthetic-lab: true\nkind: ConfigMap\n", parsed={"kind": "ConfigMap"})

    assert find_resource_name(config) is None


def test_detector_no_match_edges_are_safe(tmp_path: Path) -> None:
    clean = make_config(
        tmp_path,
        "synthetic-lab: true\nkind: Deployment\n",
        parsed={
            "kind": "Deployment",
            "spec": {"template": {"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "100m"}}}]}}},
        },
    )

    assert detect_public_database_exposure(clean) == []
    assert detect_storage_missing_encryption(clean) == []
    assert detect_storage_missing_versioning(clean) == []
    assert detect_kubernetes_missing_resource_limits(clean) == []


def test_detectors_skip_parse_error_configs(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.json"
    malformed.write_text('{"synthetic-lab": true,', encoding="utf-8")

    assert run_detectors([malformed]) == []


def test_load_config_file_rejects_directory_and_large_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigLoadError, match="not a file"):
        load_config_file(tmp_path)

    large_file = tmp_path / "large.json"
    large_file.write_text("synthetic-lab: true", encoding="utf-8")
    monkeypatch.setattr(Path, "stat", lambda self: type("Stat", (), {"st_size": MAX_CONFIG_SIZE_BYTES + 1})())

    with pytest.raises(ConfigLoadError, match="file exceeds lab size limit"):
        read_text_file(large_file)


def test_text_loader_error_path_preserves_replacement_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "broken.tf"
    sample.write_bytes(b"synthetic-lab: true\n\xff")

    def fail_read_text_file(path: Path) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(text_loader, "read_text_file", fail_read_text_file)

    loaded = load_text_file(sample, tmp_path)

    assert loaded.parse_status == ParseStatus.ERROR
    assert "synthetic-lab: true" in loaded.raw_text
    assert loaded.error_message


def test_validation_rejects_bad_metadata_and_parse_errors(tmp_path: Path) -> None:
    bad_suffix = make_config(tmp_path, "synthetic-lab: true", parsed={})
    bad_suffix = replace(bad_suffix, path=(tmp_path / "bad.unsupported").resolve())

    too_large = make_config(tmp_path, "synthetic-lab: true", parsed={})
    too_large = replace(too_large, size_bytes=MAX_CONFIG_SIZE_BYTES)

    wrong_type = make_config(tmp_path, "synthetic-lab: true", parsed={})
    wrong_type = replace(wrong_type, file_type="json")

    unacceptable = make_config(tmp_path, "synthetic-lab: true", parsed=object())

    error_config = make_config(tmp_path, "synthetic-lab: true", parsed={})
    error_config = replace(error_config, parse_status=ParseStatus.ERROR)

    assert not validate_loaded_config(bad_suffix)
    assert not validate_loaded_config(too_large)
    assert not validate_loaded_config(wrong_type)
    assert not validate_loaded_config(unacceptable)
    assert not validate_loaded_config(error_config)


def test_validate_sample_file_reports_all_safety_issues(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe.json"
    sample.write_text(
        "\n".join(
            [
                '{"account": "999999999999",',
                '"arn": "arn:aws:iam::999999999999:role/real-role",',
                '"key": "AKIAABCDEFGHIJKLMNOP",',
                '"cidr": "8.8.8.8/32",',
                '"domain": "real-example.invalid",',
                '"private": "-----BEGIN RSA PRIVATE KEY-----"}',
            ]
        ),
        encoding="utf-8",
    )

    issues = validate_sample_file(sample, tmp_path)
    messages = {issue.message for issue in issues}

    assert "missing synthetic lab marker" in messages
    assert "credential-shaped AWS access key found" in messages
    assert "private key block found" in messages
    assert any(message.startswith("non-allowed account ID found") for message in messages)
    assert any(message.startswith("non-allowed ARN found") for message in messages)
    assert any(message.startswith("non-allowed IP or CIDR found") for message in messages)
    assert any(message.startswith("non-allowed domain found") for message in messages)


def test_validate_samples_handles_missing_category_directories(tmp_path: Path) -> None:
    assert validate_samples(tmp_path) == []


def test_validate_sample_tree_includes_loader_errors(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.json"
    malformed.write_text('{"synthetic-lab": true,', encoding="utf-8")

    results = validate_sample_tree(tmp_path)

    assert len(results) == 1
    assert not results[0]["valid"]
    assert "loaded config validation failed" in results[0]["issues"]
    assert any("Expecting property name" in issue for issue in results[0]["issues"])


def test_markdown_report_empty_findings_has_none_rows_and_no_findings_message() -> None:
    context = build_report_context(
        input_path="samples/clean",
        files_scanned=0,
        findings=[],
        generated_at="2024-01-01T00:00:00Z",
    )

    report = render_markdown_report(context)

    assert "| None | 0 |" in report
    assert "No findings were generated from the local synthetic input." in report


def test_write_report_outputs_rejects_unsupported_format(tmp_path: Path) -> None:
    context = build_report_context(
        input_path="samples",
        files_scanned=0,
        findings=[],
        generated_at="2024-01-01T00:00:00Z",
    )

    with pytest.raises(ConfigLoadError, match="unsupported report format"):
        write_report_outputs(context, tmp_path / "report.txt", "xml")


def test_run_report_invalid_format_returns_controlled_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "report.txt"
    argv = [
        "cloud-hardening-lab",
        "report",
        "--input",
        str(SAMPLES),
        "--output",
        str(output),
        "--format",
        "xml",
    ]

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as exc:
            cli_main()

    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_run_report_json_inprocess(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "report.json"

    assert run_report(str(SAMPLES), str(output), "json", min_severity="critical") == 0
    payload = json.loads(capsys.readouterr().out)

    assert output.is_file()
    assert payload["outputs"] == [str(output)]
