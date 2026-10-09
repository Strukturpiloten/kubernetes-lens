# Dependency and pin ownership

Foundation dependencies use exact reviewed Cargo pins and locked registry integrity. Cargo.lock is committed, exact dependencies must be
reviewed with license and MSRV evidence, and normal builds use `--locked`. The normal toolchain is
owned by the native `rust-toolchain` manager; MSRV 1.85.0 is a fixed compatibility anchor.

The operational Renovate test tool is the official slim OCI artifact in `scripts/renovate-tool.json`,
pinned to an exact version and verified multiarchitecture index digest. There is no local npm product
or operational-tool dependency graph. Its bundled modules are extracted from a disposable, never
started container into ignored `.ci-tools/renovate`; the source image and contained package version
are verified before the actual RE2 suite runs. File-formatting tools still belong to the shared
development environment. The upstream OCI artifact supplies its locked implementation graph;
updates require manual review of its provenance, version/digest pairing and real-engine tests.

Operational pin owners:

| Pin                                  | Sole Renovate manager | Review                                              |
| ------------------------------------ | --------------------- | --------------------------------------------------- |
| Cargo dependencies, when introduced  | `cargo`               | Locked, MSRV and license checks                     |
| Renovate OCI version/index digest    | `custom.regex`        | Manual tool group, Dashboard approval, no automerge |
| Normal Rust toolchain                | `rust-toolchain`      | Separate group, Dashboard approval, no automerge    |
| Action SHA and exact release comment | `github-actions`      | Immutable pin and grouped updates                   |
| Hosted runner label                  | `github-actions`      | Manual runner group and Dashboard approval          |
| Shared tools/policy checkout SHA     | `custom.regex`        | Manual integrity review after generic rules         |

`.github/renovate.json` restricts enabled managers and explicitly enables `custom.regex`. Actual
production file patterns and RE2 named captures are exercised, with missing/duplicate/moved-file and
native overlap failures. Actions and shared refs are replaced with Renovate's own update code, then
re-extracted to check identity and immutable version pairing. Later package rules preserve manual
approval and disable automerge for integrity-sensitive pins after generic compatible automerge.

The immutable shared BoxFerry checkout owns all its image tags/digests, feature lock, downloaded
tool checksums and Kubernetes versions. They are not copied or re-extracted as KubernetesLens pins.
Updating that SHA requires upstream native manager/custom overlap, checksum coupling, amd64/arm64
and image replacement evidence. BoxFerry #446 records remaining arm64 execution. Fixtures,
historical evidence and the future Kubernetes 1.20 compatibility anchor cannot auto-advance.

The official [container distribution](https://docs.renovatebot.com/getting-started/running/#docker-images)
was checked through Context7. Registry manifest bytes are retained in
[evidence](evidence/renovate-image-2026-10-09.manifest); SHA-256 is the digest recorded in the production
pin, with linux/amd64 and linux/arm64 descriptors. Actual extraction/RE2 evidence here is amd64 only.
The inherited shared lockfile release-age guard remains unchanged and applies to the new Cargo graph; no local npm product graph is introduced. [#17](https://github.com/Strukturpiloten/kubernetes-lens/issues/17)
records its separately observed metadata-budget limitation; no guard was weakened.

No Renovate regression command opens PRs or performs platform writes. The pinned Renovate internal
API is test-only; tool updates intentionally require the regression suite to remain compatible.
Sources: [regex manager](https://github.com/renovatebot/renovate/blob/main/lib/modules/manager/custom/regex/readme.md)
and [package rules](https://docs.renovatebot.com/configuration-options/#packagerules), retrieved through
Context7 on 2026-10-09. RE2 does not support lookahead or backreferences, and later matching rules override
previous options. A Python regex match alone is insufficient evidence.

## Frozen compatibility inputs

`docs/compatibility/**` and `schemas/capabilities/**` are explicit Renovate exclusions. Historical
conformance tools, node images, immutable schema/feature sources and the 1.20–1.37 ceiling are
reviewed fixture/specification anchors, not operational update targets. Their exact provenance,
licenses, checksums and exclusions live in the capability ledger. Modern profiles reference the
canonical immutable BoxFerry installer instead of introducing another checksum owner or manager.
Actual Renovate/RE2 regressions verify exclusions and show that removing them exposes extraction
even if a future manager recognizes a compatibility path. Operational shared-reference/image
managers, grouping, manual approvals and native conformance boundaries remain unchanged.

## Foundation parser dependency evidence

The reviewed parser choice is yaml-rust2 0.13.0 with default encoding features disabled, using
custom marked events rather than YamlLoader. Its declared MSRV is Rust 1.85; license is
MIT OR Apache-2.0. Exact serde/serde_json pins and `raw_value` support ordered strict duplicate
checking and preserved numeric lexemes; their declared MSRVs are below 1.85 and licenses are
MIT OR Apache-2.0. Cargo.lock records normal registry checksums for all transitive packages.
No checksum was invented, license policy weakened, or age guard bypassed. Current versions are
owned once by Cargo declarations and the existing native Renovate Cargo manager; extraction,
missing-manager and effective grouping/approval regressions cover the newly introduced pins.

The embedded immutable Kubernetes capability ledger retains upstream source attribution and
source/license links. Package inclusion explicitly retains the ledger and Apache-2.0 license
asset. Those source/compatibility anchors remain excluded from operational Renovate updates.
The separately tracked #17 npm whole-metadata budget problem does not justify an exception:
the Cargo guard already requests bounded per-version crate metadata and still fails closed.

Linux acquisition also pins libc 0.2.190 (Rust 1.65 MSRV, MIT OR Apache-2.0), solely for safe
`OpenOptionsExt` no-follow/nonblocking/directory constants. It introduces no unsafe code.
Its per-version registry record is unyanked, published 2026-10-02, and Cargo.lock records the
normal verified registry checksum. The dependency is Linux-target-gated and owned by the same
Cargo Renovate manager; source facts and runtime tool pins are unchanged.
