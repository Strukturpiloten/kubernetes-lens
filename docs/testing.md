# Testing

The complete gate is `./scripts/check-all.sh --check`; `--fix` performs the same checks with formatting
first. `format-lint.sh` runs no tests. Lightweight contracts cover trusted-base PR planning, aggregate
failure/skip propagation, repository/release boundaries, and real Renovate extraction and policy.
Renovate tests import the locked tool itself and require its RE2 engine to be available.

Rust check, Clippy, test, doctest, Rustdoc, MSRV, cargo-deny, and local package validation run against
the locked package. The empty native library honestly has zero runtime unit tests and zero doctests. A repository-only
Cargo integration harness executes the Python policy suite; it is not native conformance.
There is no native coverage ratchet or conformance gate yet; do not fabricate passing fixture,
coverage, version or cluster evidence. Native suites and meaningful thresholds belong to #7.

PR prose changes may select documentation and lockfile age checks only. Executable examples and all
other changes select every job. Main, manual dispatch and release validation always select every
job. Unknown paths, invalid comparison, changed policy, and first rollout fail full. Missing, failed,
cancelled or unexpectedly skipped selected jobs make the PR gate fail. Test the inline bootstrap
fallback as executed Python, not only as YAML strings.

At most one complete or heavy workspace gate may run at a time. Use worktree-local target storage;
never reuse another checkout's fixture-path-sensitive artifacts. Native runtime evidence is future work.

The documentation phase checks the [frozen compatibility specification](compatibility/README.md),
independent schema witnesses, concrete native-kind scenarios and exact gate/command evidence cells.
Its regressions cover numeric version bounds, removed APIs, gate defaults/settings, template
contexts, per-field/profile obligations and mutated source facts. All native outcomes remain pending.
Compatibility documentation always selects the full validation plan.
