# Changelog

## Unreleased

- Removed the internal completion checklist and the remaining phase-numbered narration from docs, the changelog, and a handful of module docstrings; renamed the phase-numbered test files and test functions to describe what they actually check.
- Mapped each detector rule to its CIS AWS Foundations Benchmark or CIS Kubernetes Benchmark control where one could be verified from an authoritative source, added `docs/compliance-mapping.md` with the confidence level and caveat behind each mapping, and surfaced the mapping in both report formats. Strengthened coverage to 113 passing tests with 97.97% coverage.
- Added release-preparation notes, publishing command guidance, and a release checklist without publishing, tagging, or claiming GitHub verification.
- Polished the README and supporting docs for recruiter-ready portfolio presentation, aligned all safety and offline-scope statements, regenerated the public-safe example reports, and reran the full local validation suite.
- Strengthened coverage to 105 passing tests with 97.89% coverage and raised the configured coverage gate to 90%.
- Added local GitHub Actions CI, CodeQL, Dependabot, docs safety checks, and workflow validation tests.
- Added CLI UX polish, severity filters, fail-on behavior, negative tests, and safety hardening.
- Added Markdown and JSON report generation with example reports.
- Added deterministic risk scoring and safe remediation guidance.
- Added the local synthetic detection engine and scan CLI.
- Added local config loaders and a validation CLI.
- Added synthetic samples and safety validation.
- Created the repository scaffold.

## [0.1.0] - Pending

- Reserved for the eventual first public release.
