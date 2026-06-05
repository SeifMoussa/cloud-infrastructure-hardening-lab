from pathlib import Path

from cloud_hardening_lab.loaders.inventory import load_config_file
from cloud_hardening_lab.validation import validate_loaded_config, validate_sample_tree, validate_supported_extensions


def test_validate_loaded_config_accepts_valid_config(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"synthetic-lab": true, "name": "lab-public-bucket"}', encoding="utf-8")
    config = load_config_file(path)

    assert validate_loaded_config(config) is True


def test_validate_loaded_config_rejects_parse_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"synthetic-lab": true', encoding="utf-8")
    config = load_config_file(path)

    assert validate_loaded_config(config) is False


def test_validate_supported_extensions_returns_unsupported_paths(tmp_path: Path) -> None:
    supported = tmp_path / "config.json"
    unsupported = tmp_path / "notes.txt"
    supported.write_text('{"synthetic-lab": true}', encoding="utf-8")
    unsupported.write_text("synthetic-lab: true", encoding="utf-8")

    assert validate_supported_extensions([supported, unsupported]) == [str(unsupported)]


def test_validate_sample_tree_returns_stable_results() -> None:
    root = Path(__file__).resolve().parents[1] / "samples"

    results = validate_sample_tree(root)

    assert len(results) == 19
    assert all(result["valid"] for result in results)
    assert results == sorted(results, key=lambda item: item["path"])
