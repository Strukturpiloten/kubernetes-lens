# ADR 0105: Explicit shared crate publisher

Status: Accepted source contract; hosted validation and maintainer publication approval pending.
Amends ADR 0001 and ADR 0102 only for publication readiness.

Issue #15 requests a usable future publisher and a credential-free handoff while KubernetesLens
is still unpublished. Cargo now restricts publication to crates.io. The shared release policy
enables the explicit publisher and limits a bootstrap token to version 0.1.0. This removes the
private-manifest obstacle without authorizing a release. Release-plz remains disabled.

The manual workflow defaults to validation only. Complete CI retains quality, coverage, MSRV,
dependencies, documentation, native source controls and the positive initial API contract.
The shared release gate and one-crate inventory require separate generic and published-purpose
candidate receipts. Credential-free preparation builds a verified archive and checksum and retains
a JSON proof binding it to source, automation and API receipts. Its pending native status is explicit.

Only an explicit non-validation dispatch on the canonical default branch can reach the `release`
environment. Its required maintainer review must cover the exact candidate, package version,
release notes, package proof and all issue #15 native acceptance evidence. Required reviewers
and default-branch deployment restrictions must be verified by
an administrator before registry credentials or Trusted Publishing are provisioned. The source
does not establish that those external protections or registrations exist; #16 remains open.
The coordinator's 2026-11-23 readback found zero environments. Before the publisher is eligible,
a read-only job checks the actual release environment for required reviewers and a deployment policy admitting the default branch, including the
shared custom main branch plus v* tag configuration. Dispatch and approval are separate maintainer
actions; a second person is not required. Never use an administrator override. Missing settings and API access failure refuse publication before the OIDC job.

After approval the caller uses the immutable shared-crate-publish action, read-only repository
access and job-local OIDC. The environment-scoped CARGO_REGISTRY_BOOTSTRAP_TOKEN is optional:
the shared producer accepts it only for 0.1.0, covering first publication before Trusted Publishing
is registered. A crate owner must supply that narrowly scoped credential separately, or verify a
usable Trusted Publisher registration for this repository, release.yml and release environment.
Remove the temporary token after first publication. No tags, GitHub releases or deployment are
created by this caller. Those are separate future tasks.

No native completion, first-release API comparison, approval or hosted success is fabricated.
Canonical absence selects the existing positive foundation contract; later published-purpose
checks use real registry history. Offline preparation and successful CI never authorize publication.
