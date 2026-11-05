# Dependencies and automation pins

[BoxFerry automation](https://github.com/Strukturpiloten/boxferry/blob/main/docs/automation.md)
owns common workflow mechanics, Python tools, and Renovate settings.
[ADR 0102](decisions/0102-shared-workflow-adoption.md) supersedes the former manual
Dashboard approvals for dependency upgrades. KubernetesLens retains its exact Cargo declarations,
committed lockfile, native tests, and repository-specific update groups.

## Update admission

Ordinary third-party upgrades wait 72 hours and merge automatically after required checks. A
verified first-party package-update PR is wholly age-exempt, including its necessary transitive
lockfile changes. Unknown provenance, invalid timestamps, missing integrity, or failed
compatibility checks stop admission with a reason. Missing authoritative publication timestamps
require trusted persisted first-seen evidence; stream/build timestamps are not substitutes.
The qualified Fedora CoreOS VM is the fixed conformance target for this overhaul. Its exact
version/digest is excluded from routine Renovate upgrades; ADR 0101 qualification, integrity,
and historical evidence remain unchanged. No automatic qualification pipeline is introduced.

Age checks apply to introduced PR and merge-queue deltas. Main, manual, and release validation
retain full integrity and compatibility checks without starting a fresh age clock for accepted
dependencies. Software publication remains a separate maintainer decision.

## Sole owners

| Declaration                                      | Renovate owner                                                    |
| ------------------------------------------------ | ----------------------------------------------------------------- |
| Cargo dependencies and Cargo.lock                | Native Cargo manager                                              |
| Normal Rust toolchain                            | Native rust-toolchain manager                                     |
| Action/workflow SHAs and hosted runners          | Native github-actions manager                                     |
| Shared implementation, manifest, and preset SHAs | Shared exact-path custom managers                                 |
| Official Renovate OCI version and index digest   | Repository custom manager                                         |
| Qualified Fedora CoreOS QEMU image               | Exact-path routine updates disabled; integrity extractor retained |
| Python and downloaded check-tool integrity       | BoxFerry shared automation inventory                              |

Every shared adoption reference advances atomically in one Renovate group. Executed pins remain
full immutable SHAs; `automation-v1` is discovery only. The initial infrastructure pin comment
honestly records that interface instead of inventing a release tag. Native/custom overlap,
missing owners, replacement coupling, effective rules, and historical exclusions are tested with
the exact official Renovate runtime.

Historical native versions, capability ledgers, conformance receipts, and fixture anchors never
auto-advance. Shared Kubernetes and development-container pins remain owned by BoxFerry.
[Dependency provenance](evidence/dependency-provenance.md) retains reviewed checksums, licenses,
source commands, redistribution notes, and earlier evidence limitations.
