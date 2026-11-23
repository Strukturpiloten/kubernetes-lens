# Release boundaries

KubernetesLens is unpublished. Cargo restricts publication to `crates-io`; release-plz disables
publishing, tags and GitHub releases. The manual `Release validation` workflow defaults to
`validation_only=true`, calls complete CI, the shared exact-candidate release gate and the
single-crate inventory, then packages without registry credentials. Main, PR, push and default
dispatches cannot publish. Local `cargo package --locked --offline --allow-dirty` verifies an
archive without publication. [ADR 0105](decisions/0105-explicit-shared-crate-publisher.md) defines
the explicit future publisher and its separate approval requirements.

CHANGELOG.md records only Unreleased work. Do not invent numbered published sections or a crates.io baseline.
Release validation explicitly requests published-purpose API checks: canonical registry history
when available, otherwise the positive initial foundation contract after verified canonical absence.
`Required CI` requires the exact `published_api_candidate_sha` before exposing generic candidate
success to the canonical release gate. The gate checks both candidate receipts. The inventory
receives the gate result and its distinct generic and published-API outputs before validating
the single workspace member with locked Cargo metadata. The package job retains the verified
archive, checksum and `release-proof.json` in `prepared-crate-<candidate SHA>`. The proof records
candidate, automation and published-purpose API identities and explicitly pending native status.

For first publication the proposed version is 0.1.0; the release notes remain the reviewed
CHANGELOG Unreleased section until the maintainer authorizes their release. Review package contents,
LICENSE, README, API docs and all supported GVK/field/tool profiles in the compatibility ledger.
The ledger's pending native/renderer/API/runtime evidence remains a release prerequisite under
[#15](https://github.com/Strukturpiloten/kubernetes-lens/issues/15); CI source controls and coverage
do not establish conformance. Do not approve publication until every required acceptance item is met.

Before a real dispatch an administrator must verify required reviewers and restrict the `release` environment to the default branch, and protect all eligible workflow
definitions. These settings are not installed by this patch; #16 remains visible. A crate owner
must separately verify crates.io Trusted Publishing for this repository, `release.yml` and `release`,
or provision an environment-only `CARGO_REGISTRY_BOOTSTRAP_TOKEN` for the exact 0.1.0 bootstrap.
The coordinator's read-only environments endpoint readback on 2026-11-23 returned `total_count=0`.
The publication authorization job therefore fails closed today: it requires a readable `release`
environment with required reviewers and a branch policy admitting the default branch (either protected
branches or an explicit custom main branch rule). The maintainer may dispatch and approve as
two distinct actions; never use an administrator override. Missing/unreadable settings
stop the publisher before OIDC. The environment itself then requires approval. If the workflow token
cannot read the settings, an administrator must resolve that prerequisite; do not weaken the check.
No registration, token or environment approval is claimed here. Revoke/remove the temporary token
after publication and verify Trusted Publishing before the next version.

The maintainer then explicitly dispatches `validation_only=false` on the reviewed default-branch
candidate and approves the environment for that exact SHA, version, notes and retained proof.
The publisher rechecks the complete gate through the pinned shared action before registry access.
It uses job-local OIDC or the version-limited bootstrap credential, waits for registry visibility
and retains the producer's idempotent existing-version behavior. It creates no tag, GitHub Release
or deployment. Actual publication and hosted validation dispatch are separately authorized tasks.

Before authorized Git/PR work, the primary inspects status and scoped diff, uses the issue branch,
formats, runs the complete gate after the final edit, independently reviews and checks the exact
head. Failures or incomplete checks block commit/push/PR. The primary owns Git/GitHub writes and
exact-head merge safeguards; workers cannot perform them. Follow repository protections without
admin override. External settings that could not be read or changed are tracked in #16.

Packaging includes the renderer Rust sources, focused source-only tests and `docs/formats.md`.
The helper and gate binaries require `supervised-renderer`; provisioning the system broker remains
an explicit consumer operation. Packaging is not publication, deployment, official tool acceptance
or live containment evidence. All existing complete-gate and separate-publication requirements apply.
