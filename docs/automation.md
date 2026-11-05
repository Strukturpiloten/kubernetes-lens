# Repository automation

Use the [shared BoxFerry guide](https://github.com/Strukturpiloten/boxferry/blob/main/docs/automation.md)
for workflow mechanics and the [dependency policy](dependency-policy.md) for admission rules.
The immutable revision is `.github/automation.json`; `scripts/shared-ci.py` is the canonical
launcher; it delegates tool setup to the selected shared runtime. The admission reader executes
the exact trusted-base implementation, so a proposed
automation upgrade is admitted under the policy already trusted on main. Python tooling versions and hashes come from the shared locked project; this repository
configures Ruff and ty for its automation entrypoints. Native fixture controls retain their
existing independent source-contract suite.

KubernetesLens keeps its Rust, minimum-version, dependency/license, repository-policy, package,
and documentation tests in `scripts/validation-policy.json`. Its unpublished release workflow
validates the complete candidate and cannot publish. Ordinary checks never start a cluster or VM.
Native qualification remains independently pending.

For change-aware feedback, run `python3 scripts/validation-plan.py run-local`. Finish with
`./scripts/format-lint.sh --fix` and `./scripts/check-all.sh --check` before submitting changes.
The complete gate is publication evidence only after all required checks succeed on the final
candidate.

Rollout is tracked in [KubernetesLens #75](https://github.com/Strukturpiloten/kubernetes-lens/issues/75).
The bootstrap first trusts policy tasks and the privileged admission service on main. A subsequent
change activates selective shared jobs and the read-only exact-candidate admission reader.
A staged draft or one passing consumer does not establish complete rollout.

The API caller pins the admitted shared implementation in `.github/automation.json`. Source
admission alone does not establish consumer readiness: independent review, both complete consumer
gates and hosted exact-candidate checks remain required before rollout.
See [BoxFerry ADR 0096](https://github.com/Strukturpiloten/boxferry/blob/main/docs/decisions/0096-development-and-published-api-baselines.md)
for development versus published API baselines.
