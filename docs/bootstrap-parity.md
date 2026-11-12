# Automation parity and repository exceptions

The reviewed KubernetesLens starting revision is
`bb87aff8fab6cbf58c7b52a910f0bbbf3d6953fa`. The current shared implementation revision is
recorded once in `.github/automation.json`; executed workflows and Renovate presets must match
it. See [ADR 0102](decisions/0102-shared-workflow-adoption.md) and the
[shared guide](https://github.com/Strukturpiloten/boxferry/blob/main/docs/automation.md).

| Contract                                   | Canonical definition                | KubernetesLens exception                                                                                       |
| ------------------------------------------ | ----------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Rust quality and minimum version           | BoxFerry shared Rust workflow       | Policy retains every existing alias, warning-denying Rustdoc, and package validation; minimum comes from Cargo |
| Dependency/license policy                  | BoxFerry shared dependency workflow | All features remain checked                                                                                    |
| Change planning and required gate          | BoxFerry locked Python package      | Repository policy owns job membership and documentation roots                                                  |
| Python automation                          | Shared uv, Ruff, ty and lockfile    | Local pyproject config covers automation entrypoints; native fixture controls retain independent source tests  |
| Development tools and Kubernetes inventory | BoxFerry development container      | Six check tools use canonical integrity records; no second tool inventory or Kubernetes installer              |
| Renovate                                   | Shared common and Rust presets      | Exact local OCI/FCOS extractors and native dependency groups remain                                            |
| Release validation                         | Shared exact-candidate release gate | Unpublished package; publication stays disabled                                                                |
| Native qualification                       | KubernetesLens fixture/VM contracts | No cluster, VM, or conformance execution in ordinary CI                                                        |

Pure prose runs file/link checks and dependency admission without Rust builds, native fixture
suites, or Renovate OCI extraction. Executable/unknown changes and full events preserve complete
validation. PR and merge-queue selection uses trusted base policy; only planned skips are valid.
The local pre-publication gate and main/manual/release checks remain complete.

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
