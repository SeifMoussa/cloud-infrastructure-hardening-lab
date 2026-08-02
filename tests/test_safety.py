from pathlib import Path

from cloud_hardening_lab.safety import ALLOWED_SAMPLE_EXTENSIONS, list_sample_files, validate_samples


def test_sample_inventory_contains_expected_file_count_and_extensions() -> None:
    root = Path(__file__).resolve().parents[1]
    sample_files = list_sample_files(root)

    assert len(sample_files) == 19
    assert all(path.suffix in ALLOWED_SAMPLE_EXTENSIONS for path in sample_files)


def test_bundled_samples_pass_safety_validation() -> None:
    root = Path(__file__).resolve().parents[1]
    issues = validate_samples(root)

    assert issues == []
