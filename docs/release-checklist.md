# Release Checklist

This checklist tracks readiness for a future public repository release. It does not publish the repository, create a tag, or create a release by itself.

## Phase Status

- [x] Phase 1 scaffold complete.
- [x] Phase 2 synthetic samples complete.
- [x] Phase 3 loaders/validation complete.
- [x] Phase 4 detection engine complete.
- [x] Phase 5 risk scoring/remediation complete.
- [x] Phase 6 reporting complete.
- [x] Phase 7 CLI/final UX complete.
- [x] Phase 8 CI/CodeQL configured locally.
- [x] Phase 9 documentation polish complete.
- [x] Phase 10 final QA/release preparation complete.

## Documentation Readiness Goals

- [x] README is recruiter-ready and technically accurate.
- [x] Safety scope is consistent across documentation.
- [x] Detection, findings, and testing docs reflect the current implementation.
- [x] Example reports are public-safe and generated from synthetic local samples.
- [x] Tracking documents record Phase 9 validation honestly.

## Final Local Verification

- [x] Code complete through Phase 9.
- [x] Tests passing: 105 passed.
- [x] Coverage passing: 97.89%.
- [x] Coverage gate: 90%.
- [x] Ruff passing.
- [x] Docs check passing.
- [x] CLI smoke passing.
- [x] Markdown and JSON example reports generated.
- [x] CI workflow configured locally but not GitHub-verified yet.
- [x] CodeQL configured locally but not GitHub-verified yet.

## GitHub Verification Status

- [ ] GitHub Actions passed on GitHub.
- [ ] CodeQL passed on GitHub.
- [ ] Repository published.
- [ ] Release created.

CI/CodeQL configured but not yet GitHub-verified.

## Safety Gates

- [x] Defensive-only
- [x] Offline-only
- [x] Local synthetic files only
- [x] No live AWS/Azure/GCP/Kubernetes API calls
- [x] No real credentials
- [x] No real cloud accounts
- [x] No third-party scanning
- [x] No offensive use
- [x] No privilege escalation instructions
- [x] Not a production CSPM/CNAPP replacement
- [x] No fake screenshots
- [x] Pending first-push items clearly documented
- [x] No publishing/tag/release yet
