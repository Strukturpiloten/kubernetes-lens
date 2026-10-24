# Bootstrap parity and provenance

Audit date: 2026-10-09. KubernetesLens #6 owns this bootstrap. References are read-only;
no other repository was modified. Existing/in-flight checkout changes were inspected and preserved.
Only committed infrastructure was selected; native/oracle implementation source was not copied.

## Immutable reviewed baselines

| Repository  | Commit                                     | Selected use                                                                                              |
| ----------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| BoxFerry    | `da5570e3af4e894aaeb5fed35d633538ef1fca33` | Canonical shared development tools, `scripts/format-lint.sh` contract and policy reference                |
| ComposeLens | `785029be92ec4e8cdce7f13d7df07f0f5261390d` | Single-crate aliases, file checks, trusted-base planner/tests, CI structure, agent roles and lint configs |
| PodmanLens  | `f29e9e6131103021452906cd37a0e718d40587de` | Read-only independent-library/native-runtime comparison                                                   |
| QuadletLens | `9beb0038f79707329fd7e48ec86c9823eb4526cd` | Read-only matrix/Renovate ownership and native generator comparison                                       |
| DockerLens  | `dd8c29435ff7734a567eb1ed4cda7d422d946bcb` | Read-only unpublished-package and release-validation comparison; not a blanket CI template                |
| Website     | `6e15f70495c246e436b4b2fb55ef29bb9b74ce1f` | Read-only Node/file-quality, PR planner and deployment boundary comparison                                |

Copied/adapted paths from ComposeLens: `.editorconfig`, `.markdownlint.json`, `.vscode/settings.json`,
`clippy.toml`, `rustfmt.toml`, `deny.toml`, `lychee.toml`, `docs/schemas/tombi-cargo-offline.schema.json`,
`scripts/check-files.sh`, `scripts/validation-plan.py`, `scripts/test-validation-plan.py`,
`.codex/agents/{implementation-worker,specification-researcher,reviewer,verifier}.toml`, and
`.github/workflows/ci.yml`. Product names/paths and bootstrap-specific jobs were adapted.
BoxFerry `scripts/format-lint.sh` supplies the separate format/lint-only task and job limit.
The crate, native-status documents, complete phase runner, policy/provisioning/gate tests,
Renovate configuration and real-engine tests are authored for this repository.

## Canonical definitions and consumers

| Concern                        | Canonical definition                                                                                                           | Existing consumers compared                                                                       | KubernetesLens contract / justified difference                                                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cargo/MSRV/lock                | Lens `Cargo.toml`, `.cargo/config.toml`, `rust-toolchain.toml`                                                                 | BoxFerry, Compose, Podman, Quadlet, Docker                                                        | Independent Rust 2024/MSRV 1.98.1; normal 1.98.1 toolchain; no product dependencies; committed lock; local version 0.1.0 is unpublished                                                                  |
| File quality                   | Compose `scripts/check-files.sh` and lint/editor configs; shared BoxFerry tools                                                | All six references, website uses Node product tools too                                           | Same file formats/YAML markers/offline TOML contract; no duplicated local file-tool package or installer                                                                                                 |
| Format/lint task               | BoxFerry `scripts/format-lint.sh`                                                                                              | BoxFerry; Docker has a separate task                                                              | Adapted task, same fix/check modes, two-job default and no tests; only environment variable prefix differs                                                                                               |
| Complete local gate            | Lens `scripts/check-all.sh`; BoxFerry format/check contracts                                                                   | All six, with repository-specific native/product suites                                           | Complete local phases `rust`, `msrv`, `dependencies`, `documentation`; worktree-owned artifacts and immediate failure propagation; no absent native/coverage/SemVer baseline reported as passing         |
| Change-aware planning          | Compose/BoxFerry `scripts/validation-plan.py`, policy, regression tests                                                        | Compose, Podman, Quadlet, website and BoxFerry                                                    | Vendored standard-library contract; trusted PR base; rollout fails full; prose only documentation+age, executable/unknown full; main/manual/release full                                                 |
| PR/main/manual checks          | Compose `.github/workflows/ci.yml`                                                                                             | BoxFerry/Compose/Podman/Quadlet/website `ci.yml`; Docker `check.yml`/`native-validation.yml`      | Stable Rust/MSRV/dependency/documentation/age job names and tested aggregate `Required CI`; no placeholder API or coverage jobs                                                                          |
| Shared/reusable infrastructure | BoxFerry `.devcontainer/Dockerfile`, `scripts/install-file-tools.sh`, `package{,-lock}.json`; shared `.github` lockfile policy | All workspace repositories; existing standalone definitions are upstream-owned                    | Immutable tool checkout; provision only needed file tools, reading upstream versions/locks/checksums; no second image, Kubernetes pin inventory or cross-repository product suite                        |
| Editor/workspace setup         | Compose `.vscode/settings.json` / `.editorconfig`; BoxFerry workspace mounts                                                   | All six                                                                                           | Shared sibling checkout, Rust analyzer/formatting settings; no standalone devcontainer. Local primary-created worktree preparation is not a shipped container feature                                    |
| Agent roles                    | Compose `.codex/agents/*.toml`; current official schema                                                                        | All six                                                                                           | Primary explicitly GPT-6.1 Sol/xhigh; worker/research/review Sol/high, verification Luna/high; at most eight spawned threads plus primary                                                                |
| Release/package                | Lens `release-plz.toml`; Docker `release-validation.yml` boundary                                                              | Published Compose/Podman/Quadlet/BoxFerry release paths, Docker validation and website deployment | `publish=false`, no release-plz automation, no tags/releases; manual read-only release validation calls CI and local packaging; publication after #15 requires separate maintainer action                |
| Renovate                       | Shared `.github/renovate.json` conventions and reviewed ownership tests                                                        | All six; Docker uses root `renovate.json`                                                         | Restricted native managers + shared-commit and operational-image regex managers; actual RE2/extraction/replacement and all inherited preset rules tested; checksum/tool inventory remains upstream-owned |
| GitHub settings                | Inherited organization ruleset and task-required exact-head gate                                                               | KubernetesLens actual remote readback; other repos only read-only references                      | Existing protection preserved; administrator follow-up #16 for unavailable read/write permissions and exact required check settings                                                                      |

The owners of intentional bootstrap differences are KubernetesLens #6 (infrastructure), #7
(native/API/conformance/coverage transition), #15 (maintainer publication), and #16 (external settings).
BoxFerry #445/#447 already delivered shared Kubernetes tools; #446 owns outstanding arm64 execution.
No cross-repository change is required by this scaffold: it consumes existing immutable definitions
without changing their files, public APIs, tool versions or application suites. This audit does not
claim a new automation rollout in other repositories or that every existing divergence is resolved.

## Operational pin and integrity inventory

KubernetesLens #54 aligns the active minimum with the existing Rust 1.98.1 normal toolchain.
`Cargo.toml` is the minimum-version authority: `scripts/check-all.sh` preflight and
`scripts/run-checks.sh msrv` read it directly; CI's MSRV job reads Cargo metadata and manual
release validation calls that CI workflow. Clippy's explicit minimum is checked against Cargo.
The existing native `rust-toolchain` Renovate manager still owns the normal pin once, and its
later rule retains Dashboard approval and disables automerge. Extraction paths and values,
shared checkout refs, dependency locks and tool integrity records are unchanged; no Renovate
configuration change is needed. Original audit commits and native compatibility evidence remain
historical provenance, not new workspace validation evidence.

Production pin ownership is derived from actual checked-in files in `scripts/test-renovate.mjs`,
not a second maintained version list. Native `github-actions` owns literal Action SHA/tag pairs and
runner labels; YAML aliases share their single literal declaration. The native `rust-toolchain` manager owns the normal toolchain. One custom regex manager owns
immutable `Strukturpiloten/boxferry` and `Strukturpiloten/.github` checkout refs, and another owns the
single official Renovate OCI version/index-digest pair. There is no local npm dependency graph.
Renovate explicitly enables `custom.regex` and validates
required capture/templates and real RE2 compatibility. The shared Node setup input is a derived
expression, disabled as a second local pin and tested as such.

The immutable shared tool checkout owns all downloaded-tool versions/checksums, image release/tag/
digest pairs, features/feature locks and Kubernetes tool versions. CI provisions only Tombi, shfmt,
ShellCheck, Hadolint, actionlint, lychee, zizmor and locked Node file-quality tools from that inventory;
it does not install Kubernetes tools. Cargo tool installs use each release's `--locked` resolution.
The native file installer verifies reviewed amd64/arm64 checksums. Actionlint follows the established
upstream-release checksum manifest: it verifies bytes against that HTTPS manifest, which is not an
independently signed checksum attestation. No stronger integrity claim or fabricated checksum is made.
Manual shared-ref approval gates review version/checksum, image/digest and feature/lock coupling
upstream. KubernetesLens tests reject missing/duplicate source versions and mismatching downloaded
checksums; they do not claim to re-run upstream image/arm64 conformance.

The operational test runtime is `ghcr.io/renovatebot/renovate:44.139.0` at verified multiarchitecture
index digest `sha256:67e76082eded90c6fa1d1552cc9d8d93d1eb06e13e81591aab57b6f4994217be`.
Registry bytes are retained in [the immutable manifest](evidence/renovate-image-2026-10-09.manifest),
which advertises linux/amd64 and linux/arm64. The official slim artifact contains Renovate 44.139.0,
Node 24.21.0 and its resolved implementation dependencies. A disposable stopped container supplies
only `/usr/local/renovate` to ignored validation storage; no package resolution or Renovate platform
operation runs. The image was inspected with `skopeo inspect --raw`, pulled by exact digest and
inspected with outbound network disabled. Actual RE2/extraction/replacement evidence was exercised
against its amd64 modules. Arm64 is an advertised artifact, not executed bootstrap evidence.

The packaging choice keeps operational tool integrity at one immutable artifact boundary rather
than adding a local npm graph. The unchanged inherited 72-hour guard still applies to introduced
third-party Cargo/npm dependencies, of which this bootstrap has none. A separately observed shared
registry metadata-size limitation is recorded in
[#17](https://github.com/Strukturpiloten/kubernetes-lens/issues/17); this source change does not edit,
weaken or claim to fix the external guard. The official image version/digest owner requires Dashboard
approval and disables automerge after generic rules. Its real Renovate/RE2 tests still run; packaging
is not a substitute for engine evidence.

## Agent configuration evidence

Current [official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents)
was fetched through the OpenAI docs skill on 2026-10-09. It supports `agents.enabled`,
`agents.max_concurrent_threads_per_session` (excluding primary), `default_subagent_model` and
`default_subagent_reasoning_effort`; standalone agent TOML files require name, description and
developer instructions and support model/reasoning/sandbox settings. Installed CLI reports
`codex-cli 0.162.0-alpha.2`. Repository tests parse the configuration and enforce the explicitly
selected primary and nine-agent ceiling; this does not assert account-specific model availability.

## Workflow audit and remaining external setup

CI triggers on PR, main push, manual dispatch and reusable workflow_call without path-filter holes.
Jobs use explicit timeouts, fixed runner labels, read-only contents, checkout credentials disabled,
trusted-base PR policy and an always-running aggregate that rejects every unexpected skip/failure.
Untrusted metadata reaches scripts through environment variables, not interpolated shell text.
The documentation budget is 90 minutes for only required shared tool provisioning; other jobs retain
bounded native quality/policy limits. CI concurrency cancels superseded ordinary runs; manual release
validation does not cancel another validation. No release token, write permission, runtime cluster,
coverage/native evidence artifact, or mutable cache is introduced. Tool caches are not proof and
this scaffold does not claim publication artifacts or cleanup of externally owned worktrees.

The default branch is `main`. Inherited organization ruleset 17023551 protects deletion/non-fast-forward,
requires PR/thread resolution, squash merge and linear history, and enables code-quality warnings.
Repository settings still advertise all three merge methods and disable automatic branch deletion.
The host token's metadata says admin but Actions-permission GET and repository PATCH returned HTTP403
(`Resource not accessible by personal access token`). No restriction was bypassed.
[#16](https://github.com/Strukturpiloten/kubernetes-lens/issues/16) tracks actual administrator readback
of Actions allowlist/default permissions/fork controls, release environments, squash/delete settings
and the protected exact required check `Required CI`. Source validation cannot verify remote execution,
required checks or those inaccessible settings; exact-head CI/readback remains the primary's gate.

## Required-check name correction

The 2026-10-22 read-only effective-rule endpoint for `main` reports that inherited organization
ruleset 17023551 requires the exact `Required CI` status context. The bootstrap emitted `PR gate`,
so PR #57 remained blocked even after every candidate job passed. The earlier required-name
statement above was incorrect; direct branch-protection access still returns HTTP 403. This
correction changes the aggregate display name and protects its unique placement with executable
wrong-name, missing-name, duplicate-name and wrong-job mutations. It preserves job ID `pr-gate`,
the trusted-base verifier, all prerequisites, triggers, permissions, timeouts and failure/skip rules.
The organization ruleset is unchanged; no status is synthesized and no protection is bypassed.

The committed-reference comparison for [#58](https://github.com/Strukturpiloten/kubernetes-lens/issues/58)
selected these immutable sources; no reference checkout, pin, installer or Renovate owner changed:

| Repository     | Reviewed commit                            | Aggregate contract                                                                               |
| -------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| BoxFerry       | `ebb1cf18548218c90fcfb5b8414f0b9fa80d73b9` | Canonical `.github/workflows/ci.yml`: job `pr-gate`, display `Required CI`                       |
| ComposeLens    | `3ee9c28e567f58b9aacd2a2f3f1a2f0491fc943c` | Same job/display contract                                                                        |
| PodmanLens     | `cd8d176b45d77b07fccbb4b9fa6b879940493571` | Same job/display contract                                                                        |
| QuadletLens    | `5c54b69dbd46d42f48641dfd2226f0eb9c4b0183` | Same job/display contract                                                                        |
| Website        | `de27d5d74b42787a4381ac304a54f7879417a9bd` | Same job/display contract                                                                        |
| DockerLens     | `96d83f6d6959dba6079e3e9bdc35db3b27635609` | Split `check.yml`/`native-validation.yml`; no unified named aggregate in this committed baseline |
| KubernetesLens | `24807149369c9cb2aebdbd8411794f59a01213a4` | `pr-gate` incorrectly emitted `PR gate`; corrected here                                          |

DockerLens' effective `main` rules also require `Required CI`. Its split-workflow mismatch is an
out-of-scope coordination follow-up linked to the ongoing
[DockerLens #31](https://github.com/Strukturpiloten/docker-lens/issues/31) work; it is not repaired
or represented as delivered by this change. KubernetesLens
[#16](https://github.com/Strukturpiloten/kubernetes-lens/issues/16) retains the remaining administrator
settings/readback obligations. PR, main, manual and release-validation calls all consume the same
KubernetesLens aggregate definition; only exact-head execution can establish remote success.

## Explicit file-formatter configuration

PR #49 exposed an environment-dependent Prettier configuration: the shared
workspace parent selected BoxFerry's 100-column configuration, while an
independent hosted checkout selected Prettier's 80-column default. Local
complete-gate success therefore did not establish hosted formatting parity.

KubernetesLens now copies `.prettierrc.json` byte-exact from the already reviewed
BoxFerry commit `da5570e3af4e894aaeb5fed35d633538ef1fca33` and passes its absolute
repository path to every Prettier call in `scripts/check-files.sh`. Existing
EditorConfig behavior, file exclusions and the immutable shared tool inventory
are preserved. This is an explicit local definition with canonical provenance,
not another Prettier version owner. No software pin, manager extraction, rule,
approval or automerge setting changes; the complete actual Renovate regressions
still verify their existing consumers.

Actual-Prettier regressions run the production script with conflicting parent
and nearer descendant configurations, an unrelated working directory,
independently expected width/prose output, format/check convergence and missing
or malformed owning configuration. The documentation phase requires them;
Rust-only MSRV checks do not acquire a second file-tool inventory.

Other Lens consumers remain read-only references. The inherited discovery
pattern needs a separately scoped parity audit before claiming equivalent
behavior across those repositories; KubernetesLens validation establishes only
this consumer's behavior. [#50](https://github.com/Strukturpiloten/kubernetes-lens/issues/50) records
the supplemental committed consumer inventory and follow-up; it grants no
authority to change the other consumers.

## Owned VM prerequisite pin (issue #62)

The reviewed KubernetesLens baseline for this addition is
`9653165bfce1ab76ea71444ecdf709bc28d3630d`. Its existing shared BoxFerry checkout, installer,
Renovate OCI image, Actions, Rust and node-image compatibility pins remain unchanged. The local owned
rootful-kind VM prerequisite adds one canonical `scripts/kind-vm-image.json` tuple and one exact-path
Renovate custom-regex owner/custom datasource; no other repository or workflow receives a competing
installer or pin. The native harness is its consumer. This deliberate local-only prerequisite differs
from GitHub's existing explicit runner/runtime choice; no hosted workflow or application suite is
changed here. Actual selected-engine regressions validate this repository's ownership, replacement,
manual grouping and timestamp-required update holding; they make no cross-repository rollout or
VM-execution claim. Shared tools remain under BoxFerry's immutable inventory. Publication controls,
workflow triggers/gates/permissions and historical fixture exclusions are unchanged.
