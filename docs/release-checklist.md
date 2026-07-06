# Release Checklist

This checklist tracks readiness for a future public repository release. It does not publish the repository, create a tag, or create a release by itself.

## Implementation Status

- [x] Scaffold complete.
- [x] Synthetic samples complete.
- [x] Loaders and validation complete.
- [x] Detection engine complete.
- [x] Risk scoring and remediation guidance complete.
- [x] Reporting complete.
- [x] CLI and final UX complete.
- [x] CI and CodeQL configured locally.
- [x] Documentation polish complete.
- [x] Final QA and release preparation complete.

## Documentation Readiness Goals

- [x] README is recruiter-ready and technically accurate.
- [x] Safety scope is consistent across documentation.
- [x] Detection, findings, and testing docs reflect the current implementation.
- [x] Example reports are public-safe and generated from synthetic local samples.
- [x] Tracking documents record current validation honestly.

## Final Local Verification

- [x] Code complete for the current scope.
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
