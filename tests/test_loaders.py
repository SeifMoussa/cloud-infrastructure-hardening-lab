from pathlib import Path

import pytest

from cloud_hardening_lab.loaders.common import ConfigLoadError, ensure_under_root
from cloud_hardening_lab.loaders.inventory import (
    detect_file_type,
    is_supported_config_file,
    list_config_files,
    load_config_file,
    load_config_tree,
)
from cloud_hardening_lab.models import ParseStatus


def write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_json_loader_success_with_schema_validation(tmp_path: Path) -> None:
    path = write_file(tmp_path / "config.json", '{"synthetic-lab": true, "name": "lab-public-bucket"}')

    config = load_config_file(path)

    assert config.file_type == "json"
    assert config.parse_status == ParseStatus.PARSED
    assert config.parsed["synthetic-lab"] is True
    assert config.synthetic is True


def test_yaml_loader_success_with_yaml_extension(tmp_path: Path) -> None:
    path = write_file(tmp_path / "config.yaml", "synthetic-lab: true\nname: lab-security-group\n")

    config = load_config_file(path)

    assert config.file_type == "yaml"
    assert config.parse_status == ParseStatus.PARSED
    assert config.parsed["name"] == "lab-security-group"


def test_yml_loader_success_with_schema_validation(tmp_path: Path) -> None:
    path = write_file(tmp_path / "config.yml", "synthetic-lab: true\nname: lab-public-bucket\n")

    config = load_config_file(path)

    assert config.file_type == "yaml"
    assert config.parse_status == ParseStatus.PARSED
    assert config.parsed["synthetic-lab"] is True


def test_toml_loader_success_with_schema_validation(tmp_path: Path) -> None:
    path = write_file(tmp_path / "config.toml", 'synthetic-lab = true\nname = "lab-public-bucket"\n')

    config = load_config_file(path)

    assert config.file_type == "toml"
    assert config.parse_status == ParseStatus.PARSED
    assert config.parsed["name"] == "lab-public-bucket"


def test_text_loader_preserves_tf_content(tmp_path: Path) -> None:
    raw_text = '# synthetic-lab: true\nresource "synthetic_storage_bucket" "lab" {}\n'
    path = write_file(tmp_path / "config.tf", raw_text)

    config = load_config_file(path)

    assert config.file_type == "terraform_text"
    assert config.parse_status == ParseStatus.RAW_TEXT
    assert config.raw_text == raw_text
    assert config.parsed is None


def test_malformed_json_returns_controlled_error(tmp_path: Path) -> None:
    path = write_file(tmp_path / "bad.json", '{"synthetic-lab": true')

    config = load_config_file(path)

    assert config.parse_status == ParseStatus.ERROR
    assert config.error_message


def test_malformed_yaml_returns_controlled_error(tmp_path: Path) -> None:
    path = write_file(tmp_path / "bad.yaml", "synthetic-lab: true\nname: [unterminated\n")

    config = load_config_file(path)

    assert config.parse_status == ParseStatus.ERROR
    assert config.error_message


def test_malformed_toml_returns_controlled_error(tmp_path: Path) -> None:
    path = write_file(tmp_path / "bad.toml", 'synthetic-lab = true\nname = "unterminated\n')

    config = load_config_file(path)

    assert config.parse_status == ParseStatus.ERROR
    assert config.error_message


def test_unsupported_extension_is_skipped_in_inventory_and_errors_on_direct_load(tmp_path: Path) -> None:
    path = write_file(tmp_path / "notes.txt", "synthetic-lab: true\n")

    assert list_config_files(tmp_path) == []
    assert is_supported_config_file(path) is False
    with pytest.raises(ConfigLoadError):
        load_config_file(path)


def test_directory_recursive_scan_discovers_nested_supported_files(tmp_path: Path) -> None:
    json_path = write_file(tmp_path / "nested" / "one.json", '{"synthetic-lab": true}')
    yaml_path = write_file(tmp_path / "nested" / "two.yaml", "synthetic-lab: true\n")
    write_file(tmp_path / "nested" / "skip.txt", "synthetic-lab: true\n")

    files = list_config_files(tmp_path)

    assert files == sorted([json_path.resolve(), yaml_path.resolve()])


def test_single_file_loading_works(tmp_path: Path) -> None:
    path = write_file(tmp_path / "config.json", '{"synthetic-lab": true}')

    configs = load_config_tree(path)

    assert len(configs) == 1
    assert configs[0].relative_path == Path("config.json")


def test_path_traversal_rejection(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside.json"
    root.mkdir()
    write_file(outside, '{"synthetic-lab": true}')

    with pytest.raises(ConfigLoadError):
        ensure_under_root(outside, root)


def test_detect_file_type() -> None:
    assert detect_file_type(Path("config.json")) == "json"
    assert detect_file_type(Path("config.yaml")) == "yaml"
    assert detect_file_type(Path("config.yml")) == "yaml"
    assert detect_file_type(Path("config.toml")) == "toml"
    assert detect_file_type(Path("config.tf")) == "terraform_text"
    assert detect_file_type(Path("config.txt")) == "unsupported"
