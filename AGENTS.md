# Repository guidance for coding agents

Read README.md, docs/architecture.md, docs/decisions/README.md, and relevant accepted ADRs before
changes. Also read API, testing, dependency, release, platform and development policies for your scope.
Use the installed codebase-memory skill for structural exploration, verify index coverage, then an
existing CodeGraph index if available; never create one without authorization. Use rg for literals
and config, and targeted reads as a fallback. Use Context7 for current library/tool documentation.

## Boundaries

KubernetesLens owns native Kubernetes formats and cannot depend on BoxFerry product crates. The
unpublished implementation exports the reviewed native APIs and claims no unexecuted native
conformance. Implement native code
originally; never copy or mechanically translate external oracle implementations. Record oracle
version, command, provenance, license and redistribution status when later evidence is introduced.
Treat input as fallible, retain source evidence and explicit versions, redact protected values by
default, and never silently discard configuration. Do not apply output or mutate runtime resources
unless a separate explicit task authorizes disposable conformance testing.

Rust 2024, MSRV 1.85.0. Start repository-owned YAML with `---`. Pin Actions to full SHAs with exact
release comments. Keep Cargo and npm locks, Renovate extraction/overlap/replacement and effective
rule-order tests current with every pin change. Preserve the existing license and unrelated work.
Shared devcontainer tools and Kubernetes pins belong to BoxFerry; do not create duplicate inventories.

## Verification and authorization

Run `./scripts/format-lint.sh --fix` and the complete `./scripts/check-all.sh --check` after the final
edit. Formatting is not validation evidence; focused checks never replace the complete gate.
A check-only verifier never edits source. At most one complete/heavy gate runs across the workspace.
The primary owns integration, the final gate, Git and GitHub writes, and exact-head PR readback.
No worker commits, stages, pushes, tags, creates branches/worktrees, publishes, deploys or writes GitHub.

For authorized task-related primary Git work, use the issue branch, preserve unrelated work, stage
explicit paths, inspect the exact diff, and run every required check before commit/push/ready PR.
Independently review the exact head and require successful protected checks before a normal merge;
never bypass protections. Synchronize and clean only recorded task worktrees/merged branches.
This standing workflow authorizes no release or publication. All release workflows remain validation-only.

## Agent roles

The maintainer explicitly selects the primary `gpt-6.1-sol` with `xhigh` reasoning for this repository.
Implementation/specification/review use `gpt-6.1-sol` with `high`; bounded read-only exploration and
check-only verification use `gpt-6-luna` with `high`. Define task, repository, checkout and file
ownership before delegation. At most eight subagents plus primary (nine total); no nested agents to
evade the limit and no two writers in one checkout. Workers respect hard write boundaries and report
files, behavior, focused tests, and unresolved risks. Reviewers assess original requirements and
independent expected behavior. The primary owns all cross-repository integration and writes.

## Infrastructure changes

Compare local/PR/main/manual/release contracts together and record immutable baseline commits and
all consumers in docs/bootstrap-parity.md. Equivalent definitions must align or have justified linked
follow-ups. Preserve least privilege, exact-candidate evidence, failure propagation, budgets and cleanup.
Renovate owns every operational pin exactly once; manual integrity rules come after generic automerge.
Preserve historical fixtures and fixed compatibility anchors. A passing repository does not prove
workspace rollout. Repository settings follow-up #16 remains visible until an administrator verifies it.
