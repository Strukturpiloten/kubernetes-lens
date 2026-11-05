# ADR 0102: Shared workflow adoption

Status: Accepted; amends ADRs 0001 and 0028 for automation ownership and dependency updates.

## Decision

BoxFerry owns the shared workflow implementation, Python tooling, and Renovate presets.
KubernetesLens owns its native tests and validation policy; it gains no dependency on BoxFerry
product crates. Consumers use immutable full commit SHAs and one atomic Renovate update group.
Until the first infrastructure release exists, an honest automation interface comment accompanies
these full-SHA pins. A branch is used only to discover updates and is never executed as a pin.

Trusted PR-base and merge-queue-base policy selects checks from actual changed paths. Pure prose
avoids Rust builds; executable documentation, unknown changes, and unreliable comparisons fail
back to complete validation. `Required CI` always runs and rejects unplanned skips. The reusable admission reader
resolves implementation A from the exact trusted base Git object's `.github/automation.json`,
executes A and requires A's receipt even when the candidate proposes implementation B.
Main, manual,
local pre-publication, and release validation retain the complete gate. The first adoption seeds
the task policy while retaining existing Rust jobs until that policy is trusted on main.

Complete and executable-documentation plans execute the full repository policy and fixture suite
once through the unchanged all-target, all-feature Rust tests. Normal Rust and MSRV tasks retain
`cargo ci-policy --no-run` to build and link the original default-feature policy target under each
toolchain; MSRV also retains all-target, all-feature typechecking. The standalone policy alias and
Python runner remain executable. Pure prose keeps its existing file/link-only profile. Every
non-prose profile must require the Rust job, and the aggregate rejects its failure or skip.
Trusted older task lists remain runnable and may repeat policy execution during adoption; the
candidate never bypasses trusted-base commands. Distinct Rust and native source-contract suites,
including the external kind-runtime self-test, remain unchanged. This changes execution ownership,
not fixture cases, native qualification, resource budgets or publication authority.

Dependency upgrades need automated integrity, compatibility, and admission checks rather than
manual Dashboard approval. Ordinary third-party updates wait 72 hours. A verified first-party
package-update PR is wholly exempt, including its necessary lockfile closure. A trusted service
persists first-seen time where authoritative publication time is unavailable and automatically
rechecks waiting candidates. Age applies to introduced PR/queue deltas; it is not a new clock for
accepted graphs during main, manual, or release validation.

The privileged admission listener uses trusted `workflow_run` and scheduled default-branch events,
delegates only to an immutable shared implementation, and never checks out or executes candidate
code with write permissions. A scoped trigger-block security-audit exception records this
boundary; regression tests reject candidate triggers, steps, mutable pins, and mismatched refs.

Shared workflow code uses uv, Ruff, and ty. Existing native-fixture Python controls retain their
source-contract tests. Native cluster/VM contracts, budgets, cleanup, and pending qualification
are unchanged. The maintainer keeps the qualified Fedora CoreOS VM fixed for this overhaul.
Only the exact `scripts/kind-vm-image.json` dependency is excluded from routine Renovate upgrades;
its extractor, checksum coupling, ADR 0101 safety premises, and historical evidence are retained.
No automatic qualification pipeline is added. KubernetesLens remains unpublished: release automation is read-only validation,
and software publication still requires separate maintainer approval.

API baselines follow [BoxFerry ADR 0096](https://github.com/Strukturpiloten/boxferry/blob/main/docs/decisions/0096-development-and-published-api-baselines.md).
The existing `rust` job wraps canonical Rust quality and API validation without changing trusted
job selection. Ordinary development uses trusted Git history; release validation explicitly uses
published purpose and requires its exact API candidate before exposing aggregate success.
Canonical absence requires the unfiltered positive foundation suite, never absence alone.
The package stays private and publication disabled.

## Consequences

Repository-specific version groups and exact update extractors remain where required. Historical
evidence and compatibility anchors never become operational update targets. New automation is
reported as delivered only after complete per-consumer validation and real protected-check
evidence. See BoxFerry #549 and KubernetesLens #75 for rollout evidence.
