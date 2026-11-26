# Automation parity and repository exceptions

The reviewed KubernetesLens starting revision is
`bb87aff8fab6cbf58c7b52a910f0bbbf3d6953fa`. The current shared implementation revision is
recorded once in `.github/automation.json`; executed workflows and Renovate presets must match
it. See [ADR 0102](decisions/0102-shared-workflow-adoption.md) and the
[shared guide](https://github.com/Strukturpiloten/boxferry/blob/main/docs/automation.md).

| Contract                                   | Canonical definition                 | KubernetesLens exception                                                                                                                    |
| ------------------------------------------ | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust quality and minimum version           | BoxFerry shared Rust workflow        | Policy retains every existing alias, warning-denying Rustdoc, and package validation; minimum comes from Cargo                              |
| Rust source coverage                       | BoxFerry shared Rust workflow        | Candidate tool declaration plus trusted commands and ratchet                                                                                |
| Dependency/license policy                  | BoxFerry shared dependency workflow  | All features remain checked                                                                                                                 |
| Change planning and required gate          | BoxFerry locked Python package       | Repository policy owns job membership and documentation roots                                                                               |
| Python automation                          | Shared uv, Ruff, ty and lockfile     | Local pyproject config covers automation entrypoints; native fixture controls retain independent source tests                               |
| Prettier and Markdown lint                 | Shared locked npm graph and launcher | Local, prose/full hosted and manual/release documentation tasks call the same consumer file-check script with explicit owning configuration |
| Development tools and Kubernetes inventory | BoxFerry development container       | Six check tools use canonical integrity records; no second tool inventory or Kubernetes installer                                           |
| Renovate                                   | Shared presets and OCI runtime       | KubernetesLens owns native assertions, the exact FCOS extractor and native dependency groups                                                |
| Release validation                         | Shared exact-candidate release gate  | Unpublished package; explicit protected publication follows ADR 0105                                                                        |
| Native qualification                       | KubernetesLens fixture/VM contracts  | No cluster, VM, or conformance execution in ordinary CI                                                                                     |

Pure prose runs file/link checks and dependency admission without Rust builds, native fixture
suites, or Renovate OCI extraction. Executable/unknown changes and full events preserve complete
validation. PR and merge-queue selection uses trusted base policy; only planned skips are valid.
The local pre-publication gate and main/manual/release checks remain complete.

Formatter migration #123 starts at consumer commit
`280808e9bc739113e1cc193bd1300ffd83088b4e`. Local `check-files.sh`, `format-lint.sh`,
`check-all.sh`, the policy's prose/full documentation tasks and hosted `setup-ci-tools.sh`
now use the selected shared acquisition instead of PATH formatter discovery or a separate
`.ci-tools/node` npm installation. The installer retains its six canonical binaries and
Cargo-installed Zizmor. There is no consumer npm manifest, lock, image, or formatter Renovate
extractor to remove; the existing grouped automation revision remains the only update owner.
The interface-1 launcher is synchronized once for concurrent cold dispatch. The consumer
selects the admitted BoxFerry #728 formatter provider through `.github/automation.json`
and its grouped workflow and Renovate references. BoxFerry owns package versions and the
npm lock; KubernetesLens retains its product tests, file lists, configuration and ignores.
Development fixture checks are provisional and do not establish a hosted gate, image
qualification, or completed fleet rollout under BoxFerry #723.

The Renovate runtime migration in [#122](https://github.com/Strukturpiloten/kubernetes-lens/issues/122)
starts from KubernetesLens `2b27d579a6ef0080b37f5a4f0924c6aa383fc03c` and uses the already
selected BoxFerry `0aece357141870375bb872d5fd258a4e12961850`. The BoxFerry installer and
`automation/renovate-runtime.json` supply the same 44.139.0 image and digest as the former local
pin. The complete local gate and standalone documentation phase pass Podman explicitly. Full PR,
merge-queue, main and manual documentation jobs pass Docker explicitly. Release validation calls
the same CI workflow. Both engines install into checkout-local `.ci-tools/renovate`. The
trusted documentation task list retains its original regression entry point. The real Renovate
suite checks the producer's tag/digest replacement and registry observation rule alongside the
consumer's own extraction, replacement and effective policy.

On 2026-11-26, local Podman 6.2.0 extracted the pinned image into a checkout without a
prepared runtime. The source marker matched the selected pin, the package reported 44.139.0,
and the native suite passed extraction, replacement and effective-rule checks for 72 local pins.
The acquisition left no stopped extraction container. Hosted evidence is pending.

Local phase commands and shared task lists execute the policy fixture suite once through
`cargo ci-test`. Both retain default-feature policy-target build/link checks with
`cargo ci-policy --no-run` under the normal and minimum toolchains, plus all-target/all-feature
MSRV typechecking. Standalone policy commands and older trusted task lists remain runnable;
older PR-base policy may still repeat the suite until the new policy is trusted on main.
Documentation-only feedback is focused; complete and executable-documentation plans require
Rust success. No distinct integration, kind-runtime self-test, doctest or package check is removed.

The bootstrap change first seeds the authority manifest, task policy and trusted eligibility
service on main;
the adoption then activates shared selective jobs and the read-only admission reader. Track
actual per-repository evidence under [BoxFerry #549](https://github.com/Strukturpiloten/boxferry/issues/549)
and [KubernetesLens #75](https://github.com/Strukturpiloten/kubernetes-lens/issues/75). Local checks
do not establish other consumers or repository settings; settings verification remains in
[#16](https://github.com/Strukturpiloten/kubernetes-lens/issues/16).

The owned Fedora CoreOS image remains bound to the source-qualification record in
[ADR 0101](decisions/0101-kernel-bounded-live-resource-envelope.md). A version/digest change cannot
borrow qualification from an older kernel. The maintainer keeps that exact qualified conformance
target fixed for this overhaul, with a narrow routine-update exclusion. Source qualification,
integrity, and historical evidence remain intact; no automatic qualification pipeline is added.

[Historical parity and provenance](evidence/bootstrap-parity-before-shared.md) preserves the
original immutable baselines, licensing, extraction evidence, and native limitations.

Direct quality and API calls replace the local reusable wrapper under
[ADR 0103](decisions/0103-direct-api-jobs-and-trusted-policy-transition.md). The exact trusted
old five-job policy retains its serialized plan and original six aggregate outcomes;
the separately validated API outcome alone is projected out. The six-job policy
uses all seven raw outcomes normally. Both paths require real joint candidate/API
proof before the unchanged canonical gate and aggregate outputs. Ordinary read-only
permissions, initial foundation proof, publication refusal and fixed FCOS evidence remain.

The issue #92 draft began at consumer baseline `4c3fb5723f207417e661a69e0de9670bd9bee98d`.
Final adoption uses trusted baseline `c4d0b455edf41c5904bd0b7dd58e333153e79ac1` after
[PR #83](https://github.com/Strukturpiloten/kubernetes-lens/pull/83) admitted the dependency
security update and version-independent Renovate replacement test. It selects shared source
`7b9ce867e0de8b05ee5d084581cad7de54d06459`, admitted by
[producer main CI](https://github.com/Strukturpiloten/boxferry/actions/runs/42633773417) and
[verified distribution](https://github.com/Strukturpiloten/boxferry/actions/runs/42635876331).
Both shared presets, every reusable workflow, explicit source input and automation checkout
advance with the manifest. The source's common/Rust presets retain the previous revision's
rules without changes. Rust quality and MSRV now require explicitly configured trusted-base
tasks; that baseline already contains their exact command lists and 1800-second task budgets.
MSRV retains `cargo ci-check` followed by `cargo ci-policy --no-run`. Consumer regressions run
the selected producer's real preflight and command runner, including missing/malformed trusted
task refusals before execution and ordered configured-command success. Candidate task changes
cannot replace trusted commands. Local, PR, queue, main/manual and release prerequisites,
Required CI, API purposes, native suites and deferred qualification remain unchanged.

The eligibility listener repair starts from KubernetesLens main
`b12340439ffd46d19419e59713583860c7822fba` and advances the existing manifest,
CI and Release validation inputs, listener and Renovate presets together to the
[admitted BoxFerry revision](https://github.com/Strukturpiloten/boxferry/commit/527ec4a4c6c2761256e903dfe69513211be87370).
The listener denies Actions cache access at workflow scope so the shared recovery
reader can still verify the exact skipped eligibility job. Local and hosted lint
use the shared tool inventory. Native qualification and repository administration
retain their separate evidence requirements. DockerLens adopted the same listener
boundary in [#216](https://github.com/Strukturpiloten/docker-lens/pull/216).
Track the remaining callers in [BoxFerry #552](https://github.com/Strukturpiloten/boxferry/issues/552).

KubernetesLens [#108](https://github.com/Strukturpiloten/kubernetes-lens/issues/108) starts
from `c2954c5aefb0518aa41c95b2b4b25d84897dfdc2`. The candidate declares its coverage tool in
`scripts/cargo-llvm-cov.version`. The local gate and hosted `coverage` job use the same strict shared Cargo
tool verifier and task policy. The PR and queue planner reads the exact trusted base, with the
historical transition in [ADR 0104](decisions/0104-shared-rust-coverage.md). Main, manual and
reusable release CI use the complete policy, including coverage and an exact success receipt.

First merge [BoxFerry #708](https://github.com/Strukturpiloten/boxferry/issues/708) and verify
its distribution to `automation-v1`. A separate pin-only KubernetesLens PR must then advance
every matching automation reference, including the dependency eligibility listener, to the
admitted SHA on main. Verify that revision on main before rebasing #108 to add
`scripts/cargo-llvm-cov.version` and enable coverage. The previous trusted-base reader cannot
evaluate a version file introduced by the same PR that advances the automation pin.

KubernetesLens [#109](https://github.com/Strukturpiloten/kubernetes-lens/issues/109) starts from
`a23a199e787a6ff972e870aabab2850125cab234`. It adds the shared read-only inventory after the
exact-candidate release gate. The inventory consumes the gate's actual result and its two
candidate receipts. Adopt a single distributed BoxFerry revision that includes the common
ten-minute inventory budget and explicit private workspace support. Advance the manifest,
workflow refs and inputs, eligibility listener and Renovate presets together. Use the same
verified pin-only base for [#108](https://github.com/Strukturpiloten/kubernetes-lens/issues/108)
when the distributed revision also contains its coverage prerequisites. Verify the listener on
main before introducing the coverage tool version file.

The issue #15 publisher adoption starts at `ef970435de3b149723854ef20af04bc850fbb8cc`
and retains distributed producer `cf3578f47416e1b27b770fe4a81918844fb2d58b` as-is.
Local and PR/main quality, API, coverage and native source controls are unchanged. Manual/default
release validation adds credential-free packaging and proof after the existing distinct API and
generic candidate receipts and one-crate inventory. Only explicit non-validation dispatch on the
default branch reaches the protected publisher; see ADR 0105. Release-plz stays disabled. These
consumers share one Renovate owner group for workflow refs, checkouts and automation-sha inputs.
External review protections, credentials/Trusted Publisher registration, complete native acceptance
and the exact-main validation-only hosted run remain pending; #16 and BoxFerry #555 track them.
