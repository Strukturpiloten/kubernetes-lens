# Release boundaries

KubernetesLens is unpublished. Cargo sets `publish = false`; release-plz disables publishing, tags
and GitHub releases. No release-plz workflow or credentials are installed. A read-only manual
`Release validation` workflow calls complete CI and then the shared exact-candidate release gate.
Its typed policy explicitly disables publication and requires every prerequisite at the same SHA.
Main/PR/manual workflows cannot publish crates, images, charts, tags or GitHub releases.
Local `cargo package --locked --allow-dirty` validates an archive without publication.

CHANGELOG.md records only Unreleased work. Do not invent numbered published sections or a crates.io baseline.
Release validation explicitly requests published-purpose API checks: canonical registry history
when available, otherwise the positive initial foundation contract after verified canonical absence.
`Required CI` requires the exact `published_api_candidate_sha` before exposing generic candidate
success to the canonical release verifier, which reads only that generic output. Development API
success cannot satisfy this guard. Publication remains disabled until a separately authorized
publication after KubernetesLens #15. That request must enable and
independently review release permissions, credentials, provenance and a real API baseline.

Before authorized Git/PR work, the primary inspects status and scoped diff, uses the issue branch,
formats, runs the complete gate after the final edit, independently reviews and checks the exact
head. Failures or incomplete checks block commit/push/PR. The primary owns Git/GitHub writes and
exact-head merge safeguards; workers cannot perform them. Follow repository protections without
admin override. External settings that could not be read or changed are tracked in #16.

Packaging includes the renderer Rust sources, focused source-only tests and `docs/formats.md`.
The helper and gate binaries require `supervised-renderer`; provisioning the system broker remains
an explicit consumer operation. Packaging is not publication, deployment, official tool acceptance
or live containment evidence. All existing complete-gate and separate-publication requirements apply.
