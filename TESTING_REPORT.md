# Testing Report

## Current Verified Local Baseline

- 113 tests passed
- 97.97% coverage
- 90% coverage gate
- Ruff check passed
- Ruff format check passed
- docs check passed

CI/CodeQL configured but not yet GitHub-verified.

## Test File Status

| Test File | Status | Notes |
| --- | --- | --- |
| `tests/test_package.py` | Pass | Package version import test. |
| `tests/test_cli.py` | Pass | CLI help test. |
| `tests/test_cli_inprocess.py` | Pass | In-process CLI dispatch, filtering, report, and error-path tests. |
| `tests/test_cli_inventory_and_validation.py` | Pass | Inventory and validation CLI tests. |
| `tests/test_cli_scan.py` | Pass | Scan JSON/text and invalid input tests. |
| `tests/test_cli_options_and_error_handling.py` | Pass | CLI UX, filtering, fail-on, report negative, and recursion tests. |
| `tests/test_cis_mapping.py` | Pass | CIS control mapping table, unmapped-rule handling, and report field tests. |
| `tests/test_coverage_edge_cases.py` | Pass | Edge-case loader, validation, reporting, and CLI branch coverage tests. |
| `tests/test_detectors.py` | Pass | Finding model, detector rule, ordering, and clean sample tests. |
| `tests/test_documentation_consistency.py` | Pass | Docs safety, README command, and CI/CodeQL honesty tests. |
| `tests/test_loaders.py` | Pass | Loader success/failure and inventory tests. |
| `tests/test_source_and_sample_safety.py` | Pass | SDK import, content safety, domain, and offline-scope tests. |
| `tests/test_reporting.py` | Pass | Markdown/JSON report generator and report CLI tests. |
| `tests/test_scoring_remediation.py` | Pass | Scoring, summary, sorting, and remediation tests. |
| `tests/test_safety.py` | Pass | Synthetic sample safety tests. |
| `tests/test_validation.py` | Pass | Loaded config and sample tree validation tests. |
| `tests/test_workflows.py` | Pass | Local CI, CodeQL, and Dependabot workflow configuration tests. |

## Documentation Validation

This pass focused on documentation polish, example report review, and public portfolio readiness for a defensive-only, offline-only lab. The commands below were rerun after the documentation rewrite and report regeneration.

| Command | Status | Notes |
| --- | --- | --- |
| `python -m pytest` | Pass | 105 tests passed. |
| `python -m pytest --cov=cloud_hardening_lab --cov-report=term-missing --cov-fail-under=90` | Pass | 105 tests passed with 97.89% total coverage against the 90% gate. |
| `python -m ruff check .` | Pass | All checks passed. |
| `python -m ruff format --check .` | Pass | 50 files already formatted. |
| `python scripts/check-docs.py` | Pass | Documentation and sample safety checks passed. |
| `python -m py_compile scripts/check-docs.py` | Pass | Docs check script compiled successfully. |
| `python -m cloud_hardening_lab --help` | Pass | Root help displayed the four local defensive commands. |
| `python -m cloud_hardening_lab inventory --input samples --format json` | Pass | Loaded 19 synthetic local files with 0 errors. |
| `python -m cloud_hardening_lab validate-samples --input samples` | Pass | Validated 19 files with 0 invalid. |
| `python -m cloud_hardening_lab scan --input samples --format json` | Pass | Returned 15 synthetic findings with summary metadata. |
| `python -m cloud_hardening_lab scan --input samples --format text` | Pass | Returned 15 readable findings across high, medium, and low severities. |
| `python -m cloud_hardening_lab scan --input samples --format text --min-severity medium` | Pass | Returned 14 medium-or-higher findings and excluded the low-severity Kubernetes limits finding. |
| `python -m cloud_hardening_lab scan --input samples --format json --fail-on high` | Pass | Intentional exit code 1 because high findings are present; JSON output remained stable. |
| `python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.md --format markdown` | Pass | Regenerated the public-safe Markdown example report from synthetic local samples. |
| `python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.json --format json` | Pass | Regenerated the public-safe JSON example report from synthetic local samples. |

## CIS Control Mapping Validation

This pass added CIS AWS Foundations Benchmark and CIS Kubernetes Benchmark control mapping per detector rule, including the three rules with no verified CIS control. The commands below were rerun after the mapping module, `Finding` fields, and report changes landed.

| Command | Status | Notes |
| --- | --- | --- |
| `python -m pytest` | Pass | 113 tests passed. |
| `python -m pytest --cov=cloud_hardening_lab --cov-report=term-missing --cov-fail-under=90` | Pass | 113 tests passed with 97.97% total coverage against the 90% gate. |
| `python -m ruff check .` | Pass | All checks passed. |
| `python -m ruff format --check .` | Pass | 53 files already formatted. |
| `python scripts/check-docs.py` | Pass | Documentation and sample safety checks passed. |
| `python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.md --format markdown` | Pass | Regenerated the example Markdown report with the new CIS Control column. |
| `python -m cloud_hardening_lab report --input samples --output reports/examples/cloud_hardening_report.json --format json` | Pass | Regenerated the example JSON report with `cis_control_id`, `cis_benchmark`, `cis_confidence`, and `cis_note` fields. |

## Documentation Notes

- Documentation language was normalized to match the repo safety tests and avoid banned offensive terms.
- Example reports remain synthetic-only, offline-only, and suitable for public GitHub exposure.
- GitHub Actions and CodeQL remain unverified until the first actual GitHub run.

## Release-Prep Notes

- Final local QA was rerun before release preparation notes were written.
- `docs/release-checklist.md` tracks publishing commands, post-push checks, and release-plan notes.
- Repository metadata, future badge paths, and first-push caveats were documented without claiming GitHub execution success.
- Release preparation does not publish the repository, create a tag, or create a release.
