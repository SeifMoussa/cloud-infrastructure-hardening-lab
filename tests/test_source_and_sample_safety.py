import ast
import re
from pathlib import Path

from cloud_hardening_lab.detectors.engine import load_default_detectors

BANNED_IMPORT_ROOTS = {"boto3", "botocore", "azure", "google", "kubernetes", "requests", "httpx"}
BANNED_IMPORT_MODULES = {"urllib.request"}
BANNED_TERMS = {
    "exploit",
    "payload",
    "penetration testing command",
}
ALLOWED_ACCOUNT_IDS = {"000000000000", "123456789012"}
ALLOWED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "lab.example.com",
    "docs.aws.amazon.com",
    "www.tenable.com",
    "avd.aquasec.com",
}


def test_detectors_do_not_import_cloud_sdks_or_network_clients() -> None:
    detector_dir = Path(__file__).resolve().parents[1] / "src" / "cloud_hardening_lab" / "detectors"

    for source_path in detector_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots = {node.module.split(".")[0]}
                assert node.module not in BANNED_IMPORT_MODULES, source_path
            else:
                continue
            assert imported_roots.isdisjoint(BANNED_IMPORT_ROOTS), source_path


def test_default_detectors_have_no_live_api_marker_names() -> None:
    detector_names = [detector.__name__ for detector in load_default_detectors()]

    assert not any("api" in name.lower() or "client" in name.lower() for name in detector_names)


def test_samples_docs_and_detectors_do_not_contain_real_credentials_or_disallowed_ids() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *list((root / "samples").rglob("*")),
        *list((root / "docs").rglob("*.md")),
        *list((root / "src" / "cloud_hardening_lab" / "detectors").glob("*.py")),
    ]

    for path in [candidate for candidate in paths if candidate.is_file()]:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", text), path
        assert "-----BEGIN " not in text, path
        assert all(account_id in ALLOWED_ACCOUNT_IDS for account_id in re.findall(r"\b\d{12}\b", text)), path
        assert "arn:aws:" not in text or "arn:aws:iam::123456789012:role/fake-lab-role" in text, path


def test_samples_docs_and_detectors_use_only_allowed_domains() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *list((root / "samples").rglob("*")),
        *list((root / "docs").rglob("*.md")),
        *list((root / "src" / "cloud_hardening_lab" / "detectors").glob("*.py")),
    ]
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|test)\b")

    for path in [candidate for candidate in paths if candidate.is_file()]:
        text = path.read_text(encoding="utf-8")
        domains = domain_pattern.findall(text)
        assert all(domain in ALLOWED_DOMAINS or domain.endswith(".test") for domain in domains), path


def test_no_offensive_instruction_language_in_samples_docs_or_detectors() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *list((root / "samples").rglob("*")),
        *list((root / "docs").rglob("*.md")),
        *list((root / "src" / "cloud_hardening_lab" / "detectors").glob("*.py")),
    ]

    for path in [candidate for candidate in paths if candidate.is_file()]:
        text = path.read_text(encoding="utf-8").lower()
        assert not any(term in text for term in BANNED_TERMS), path


def test_no_live_api_urls_in_source_docs_samples_or_reports() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        *list((root / "samples").rglob("*")),
        *list((root / "docs").rglob("*.md")),
        *list((root / "src").rglob("*.py")),
        *list((root / "reports").rglob("*")),
    ]
    live_url_pattern = re.compile(
        r"https?://(?!example\.com|example\.org|example\.net"
        r"|docs\.aws\.amazon\.com|www\.tenable\.com|avd\.aquasec\.com)[^\s)]+"
    )

    for path in [candidate for candidate in paths if candidate.is_file()]:
        text = path.read_text(encoding="utf-8")
        assert not live_url_pattern.search(text), path


def test_sample_files_remain_text_readable_and_small() -> None:
    root = Path(__file__).resolve().parents[1]

    for path in [candidate for candidate in (root / "samples").rglob("*") if candidate.is_file()]:
        assert path.stat().st_size < 10 * 1024 * 1024
        path.read_text(encoding="utf-8")
