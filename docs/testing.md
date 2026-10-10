# Testing

The complete gate is `./scripts/check-all.sh --check`; `--fix` performs the same checks with formatting
first. `format-lint.sh` runs no tests. Lightweight contracts cover trusted-base PR planning, aggregate
failure/skip propagation, repository/release boundaries, and real Renovate extraction and policy.
Renovate tests import the locked tool itself and require its RE2 engine to be available.

Rust check, Clippy, test, doctest, Rustdoc, MSRV, cargo-deny, and local package validation run against
the locked package. Offline native unit/integration tests and doctests verify the delivered
foundation and typed resource cohorts. A separate Cargo integration harness executes the Python
policy suite. These tests do not establish API-server or runtime conformance.
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

## Offline foundation

Run focused development checks with `cargo test --locked --lib --test foundation` and
`cargo clippy --locked --lib --tests -- -D warnings`. Public tests cover strict source syntax,
Unicode source positions, each parser budget, aliases, identities, Lists, target versions/gates,
privacy, deterministic generation, explicit edits, supplied references and Linux acquisition.
Genuine test-only codec tests independently exercise downcast edits, known-leaf deltas, keyed
item reordering, retained unknown descendants, unchanged null/absence, atomic conflicts, and
registry/identity divergence. Independent review regressions cover read-only provenance,
cluster collision identity, owner scope and malformed-source evidence, empty opaque containers,
and retained/flattened wrapper admission, privacy, observations and API removal boundaries.
Wrapper-subject regressions distinguish equal-position sources, multiple documents, nested Lists
and failed decode attempts without disclosing source values. They are not fake production codecs or runtime conformance.

Foundation fixture provenance is in `fixtures/foundation/README.md`. All named compatibility
cells remain pending. Focused checks never replace the primary agent's final complete gate.

JSON primitive checks are `cargo test --locked --test exact_json_number --test protected_json`.
Internal snapshot cases cover raw numeric magnitude, duplicate keys, malformed numbers and private
budget failures. These tests establish neither CRD evaluation nor API-server numeric parity.

Access/policy development checks use `cargo test --locked --lib --test access`. Independent cases
cover all eighteen roots, generated fixed points, source-free validation, API removals, feature gates,
RBAC/selector resolution and protected evidence. Quota scopes, HPA Create context and LimitRange
relationships use authenticated native source expectations. Cumulative work/payload and report tests
retain one pathless terminal finding. Local code checks do not establish native runtime conformance.

Configuration/storage development checks use `cargo test --locked --lib --test configuration_storage
--test access_modes`. Independent cases cover all five roots, protected configuration/secret
values, supplied key domains, known-invalid selectors with unknown descendants, immutable
version boundaries and finite PV Create/source/affinity checks. Processing exhaustion stays
pathless and sticky. Static witness and code evidence do not establish API-server, controller,
binding or provisioning conformance; those domains remain pending.

## Official fixture preparation and admission

The [official fixture corpus](fixtures/official-corpus.md) has 97 source-only Python regressions
for receipt integrity, private offline preparation, companion notices, closure, budgets and
renderer admission expectations. Run `python3 scripts/test-repository-policy.py` for the existing
repository policies and both fixture modules, or
`python3 -m unittest discover -s scripts/fixtures -p 'test_*.py'` for fixture-only feedback.

The policy runner discovers each fixture test once and requires the source-receipt and renderer
expectation witness IDs from their respective modules. Missing modules, absent witness tests,
discovery/import errors and assertion failures make policy validation fail. The existing Cargo
`repository_policy` harness (`cargo ci-policy`, including MSRV) and documentation phase both
invoke that runner, so the complete gate includes these tests without an optional fixture switch.
Gate regressions execute the real policy hook with synthetic fixtures and fake build/tool commands;
they prove independent assertion, missing-module and wrong-test-ID failures stop validation.

These tests neither acquire official sources nor execute Helm/Kustomize, native corpus acceptance,
API validation or runtime commands. Corpus bytes remain in caller-owned public caches and private
destinations; metadata and scripts remain excluded from the Cargo package. Actual package-list
verification and the final complete gate remain required during primary integration. Passing
preparation/admission tests does not satisfy the pending #14 native acceptance or #2 runtime cells.
