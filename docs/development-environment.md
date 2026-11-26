# Development environment

Use the existing BoxFerry development container and its mounted KubernetesLens sibling checkout.
BoxFerry owns the workspace container, installer, feature lock, Kubernetes tool matrix and
file-quality inventory. KubernetesLens declares its coverage tool in
`scripts/cargo-llvm-cov.version`.

The bootstrap CI checks out the immutable BoxFerry revision recorded in [parity](bootstrap-parity.md)
and provisions only repository-check tools from that canonical inventory. No separate image build
is required on hosted runners. It uses the same validation phases as the local environment. It does
not run BoxFerry application suites, provision clusters or install an independent Kubernetes inventory.
A container is a disposable validation environment; no generated configuration is applied.

For explicit native runtime work, the [owned-QEMU prerequisite](fixtures/owned-qemu.md) selects
an independently reviewed host QEMU/KVM and user-manager profile with an official Fedora CoreOS
image. This route runs outside the devcontainer and has no implicit fallback. It does not require
a new workflow container image or install host/guest packages. Hosted kind qualification remains
separate pending work in #62; ordinary CI, manual and release validation do not boot this guest.

Prerequisites: the shared Rust/file-quality tools, Git, Python 3.11 or newer (standard-library tomllib),
Node from the shared environment and Podman for local operational artifact extraction.
The complete local gate prepares the Renovate runtime during documentation checks. For a focused
run, use `python3 scripts/prepare-renovate.py --engine podman` followed by
`node scripts/test-renovate.mjs`. Hosted full documentation checks use the same launcher with
`--engine docker`.
The immutable shared bootstrap provisions checksum-verified uv and the locked project supplies
its reviewed Python version and hashed Ruff/ty requirements. Six downloaded check binaries use
the same canonical tool-artifacts inventory and installer; Zizmor retains its shared Cargo lock
and Node tools use the shared npm lock. This repository declares no second tool-version inventory.
The launcher verifies the BoxFerry commit selected by `.github/automation.json` and runs its
Renovate installer with its own OCI pin. The installer verifies the image digest, the contained
package version and native RE2, then records the source image in ignored `.ci-tools/renovate`.
It extracts from a stopped container and removes the container before installing the result.
The regression suite checks the local runtime against the same pin and runs without registry or
platform access once the shared source and runtime are available.

File checks acquire Prettier and markdownlint-cli2 through the same immutable automation
revision as the other shared tasks. A prepared BoxFerry sibling or formatter on PATH is
not required. Run individual commands from an ordinary checkout with
`python3 scripts/shared-ci.py node-tool --cwd "$PWD" prettier --config "$PWD/.prettierrc.json" --ignore-path "$PWD/.prettierignore" --check README.md`
or `python3 scripts/shared-ci.py node-tool --cwd "$PWD" markdownlint-cli2 --config "$PWD/.markdownlint.json" :README.md`.
Initial acquisition requires Git, Python, Node/npm and network access; managed calls use
the producer's locked npm graph under ignored `target/boxferry-node-tools/`. Other file
tools still come from the shared development container or the hosted canonical installer.
KubernetesLens owns no Dockerfile or image; the BoxFerry workspace image supplies the
development environment. Image qualification belongs to that producer, including offline,
read-only, non-root execution. The consumer keeps its explicit 100-column configuration,
preserved prose, file lists, YAML markers, ignores and native checks unchanged.

Run `cargo ci-check`, `cargo ci-clippy`, `cargo ci-test`, `cargo ci-doctest`, `cargo ci-doc`, and
`cargo ci-policy` for focused work. The policy alias runs a Cargo integration harness that delegates the repository Python contracts.
`./scripts/format-lint.sh --fix` formats/lints only and caps Clippy at two jobs unless
`KUBERNETES_LENS_LINT_JOBS` is set. Finish with `./scripts/check-all.sh --check` after the final edit.
Use `python3 scripts/validation-plan.py run-local` for feedback, never as publication evidence.

The complete gate requires MSRV 1.98.1 already installed; a missing toolchain fails preflight.
It accepts only worktree-local CARGO_TARGET_DIR. Keep build artifacts, caches and local graphs ignored.
Coverage requires the `llvm-tools-preview` rustup component for the configured Rust channel
and the exact Cargo subcommand declared in `scripts/cargo-llvm-cov.version`. The local gate verifies
the active tool. The hosted job installs and verifies the candidate's declaration through the
shared Cargo tool installer.
