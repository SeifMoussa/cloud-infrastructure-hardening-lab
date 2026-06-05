"""Command line interface for local-only lab helpers."""

import json
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, BooleanOptionalAction
from datetime import UTC, datetime
from pathlib import Path

from cloud_hardening_lab.detectors.engine import run_detectors
from cloud_hardening_lab.loaders.common import ConfigLoadError
from cloud_hardening_lab.loaders.inventory import list_config_files, load_config_tree
from cloud_hardening_lab.models import ConfigFile, Finding
from cloud_hardening_lab.reporting import build_report_context, render_json_report, render_markdown_report
from cloud_hardening_lab.scoring import summarize_findings
from cloud_hardening_lab.scoring.severity import SEVERITY_PRIORITY
from cloud_hardening_lab.validation import validate_sample_tree

SEVERITY_CHOICES = ["informational", "low", "medium", "high", "critical"]
FAIL_ON_CHOICES = ["low", "medium", "high", "critical"]


def build_parser() -> ArgumentParser:
    """Build the argument parser."""
    parser = ArgumentParser(
        prog="cloud-hardening-lab",
        description="Defensive offline cloud hardening lab for local synthetic configuration files.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="cloud-hardening-lab 0.1.0",
    )
    subparsers = parser.add_subparsers(dest="command")

    inventory_parser = subparsers.add_parser(
        "inventory",
        help="Inventory supported local synthetic config files.",
        description="List supported local config files without contacting cloud providers.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    inventory_parser.add_argument("--input", required=True, help="Local file or directory to inventory.")
    inventory_parser.add_argument("--format", choices=["json"], default="json", help="Output format.")
    inventory_parser.add_argument(
        "--recursive",
        action=BooleanOptionalAction,
        default=True,
        help="Recursively inventory directories.",
    )

    validate_parser = subparsers.add_parser(
        "validate-samples",
        help="Validate local synthetic sample files.",
        description="Validate synthetic sample hygiene and supported local file structure.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    validate_parser.add_argument("--input", required=True, help="Local sample root to validate.")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run local synthetic misconfiguration detectors.",
        description="Run defensive static checks against local synthetic config files only.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    scan_parser.add_argument("--input", required=True, help="Local file or directory to scan.")
    scan_parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format.")
    scan_parser.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="informational",
        help="Only include findings at or above this severity.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        help="Exit non-zero when any finding is at or above this severity.",
    )
    scan_parser.add_argument(
        "--recursive",
        action=BooleanOptionalAction,
        default=True,
        help="Recursively scan directories.",
    )
    scan_parser.add_argument("--verbose", action="store_true", help="Include extra execution details in text output.")

    report_parser = subparsers.add_parser(
        "report",
        help="Generate a local synthetic scan report file.",
        description="Write a Markdown or JSON report from local synthetic scan results.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    report_parser.add_argument("--input", required=True, help="Local file or directory to scan.")
    report_parser.add_argument("--output", required=True, help="Local report output path.")
    report_parser.add_argument(
        "--format",
        choices=["markdown", "json", "all"],
        required=True,
        help="Report format to write.",
    )
    report_parser.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default="informational",
        help="Only include findings at or above this severity in the report.",
    )
    report_parser.add_argument(
        "--recursive",
        action=BooleanOptionalAction,
        default=True,
        help="Recursively scan directories.",
    )

    return parser


def config_to_inventory_item(config: ConfigFile) -> dict[str, object]:
    """Convert a ConfigFile to stable CLI inventory JSON."""
    return {
        "path": config.relative_path.as_posix(),
        "file_type": config.file_type,
        "parse_status": config.parse_status.value,
        "synthetic": config.synthetic,
        "size_bytes": config.size_bytes,
        "error_message": config.error_message,
    }


def run_inventory(input_path: str, recursive: bool = True) -> int:
    """Run local inventory command."""
    configs = load_config_tree(Path(input_path), recursive=recursive)
    payload = {
        "input": str(Path(input_path)),
        "files": [config_to_inventory_item(config) for config in configs],
        "summary": {
            "files_loaded": len(configs),
            "errors": sum(1 for config in configs if config.error_message),
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def run_validate_samples(input_path: str) -> int:
    """Run local sample validation command."""
    results = validate_sample_tree(Path(input_path))
    invalid_count = sum(1 for result in results if not result["valid"])
    payload = {
        "input": str(Path(input_path)),
        "results": results,
        "summary": {
            "files_validated": len(results),
            "invalid": invalid_count,
        },
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if invalid_count else 0


def run_scan(
    input_path: str,
    output_format: str,
    min_severity: str = "informational",
    fail_on: str | None = None,
    recursive: bool = True,
    verbose: bool = False,
) -> int:
    """Run local detector scan command."""
    findings = filter_findings(run_detectors([Path(input_path)], recursive=recursive), min_severity)
    exit_code = 1 if fail_on and has_findings_at_or_above(findings, fail_on) else 0
    if output_format == "text":
        print(f"Findings: {len(findings)}")
        if verbose:
            print(f"Input: {input_path}")
            print(f"Minimum severity: {min_severity}")
            print(f"Fail on: {fail_on or 'disabled'}")
        for finding in findings:
            print(
                f"{finding.severity.upper()} score={finding.score} {finding.rule_id} {finding.title} "
                f"({finding.file_path}) - {finding.recommendation}"
            )
        return exit_code

    payload = {
        "input": str(Path(input_path)),
        "findings": [finding.to_dict() for finding in findings],
        "summary": summarize_findings(findings),
    }
    payload["summary"]["min_severity"] = min_severity
    payload["summary"]["fail_on"] = fail_on
    payload["summary"]["recursive"] = recursive
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def run_report(
    input_path: str,
    output_path: str,
    output_format: str,
    min_severity: str = "informational",
    recursive: bool = True,
) -> int:
    """Run local report generation command."""
    input_path_obj = Path(input_path)
    output_path_obj = Path(output_path)
    findings = filter_findings(run_detectors([input_path_obj], recursive=recursive), min_severity)
    files_scanned = len(list_config_files(input_path_obj, recursive=recursive))
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    context = build_report_context(
        input_path=str(input_path_obj),
        files_scanned=files_scanned,
        findings=findings,
        generated_at=generated_at,
    )
    written_paths = write_report_outputs(context, output_path_obj, output_format)
    print(json.dumps({"outputs": [str(path) for path in written_paths]}, indent=2, sort_keys=True))
    return 0


def write_report_outputs(context: object, output_path: Path, output_format: str) -> list[Path]:
    """Write report output to explicit local paths."""
    output_path = safe_output_path(output_path)
    if output_format == "markdown":
        write_text_output(output_path, render_markdown_report(context))
        return [output_path]
    if output_format == "json":
        write_text_output(output_path, render_json_report(context))
        return [output_path]
    if output_format == "all":
        markdown_path = output_path.with_suffix(".md")
        json_path = output_path.with_suffix(".json")
        write_text_output(markdown_path, render_markdown_report(context))
        write_text_output(json_path, render_json_report(context))
        return [markdown_path, json_path]
    raise ConfigLoadError(f"unsupported report format: {output_format}")


def safe_output_path(output_path: Path) -> Path:
    """Resolve output path and reject parent traversal in the provided output value."""
    if ".." in output_path.parts:
        raise ConfigLoadError(f"report output path must not contain parent traversal: {output_path}")
    return output_path


def write_text_output(output_path: Path, content: str) -> None:
    """Write a local report file after creating its parent directory."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def filter_findings(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Filter findings at or above the requested severity."""
    minimum = SEVERITY_PRIORITY[min_severity]
    return [finding for finding in findings if SEVERITY_PRIORITY.get(finding.severity, 0) >= minimum]


def has_findings_at_or_above(findings: list[Finding], severity: str) -> bool:
    """Return whether any finding meets the fail-on threshold."""
    threshold = SEVERITY_PRIORITY[severity]
    return any(SEVERITY_PRIORITY.get(finding.severity, 0) >= threshold for finding in findings)


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "inventory":
            return run_inventory(args.input, args.recursive)
        if args.command == "validate-samples":
            return run_validate_samples(args.input)
        if args.command == "scan":
            return run_scan(args.input, args.format, args.min_severity, args.fail_on, args.recursive, args.verbose)
        if args.command == "report":
            return run_report(args.input, args.output, args.format, args.min_severity, args.recursive)
        return 0
    except ConfigLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
