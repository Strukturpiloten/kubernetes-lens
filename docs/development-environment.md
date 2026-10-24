# Development environment

Use the existing BoxFerry development container and its mounted KubernetesLens sibling checkout.
This repository intentionally has no standalone `.devcontainer`, installer, feature lock, Kubernetes
tool matrix or duplicated file-quality inventory. BoxFerry owns the workspace container and pins;
its tooling setup does not make this library depend on BoxFerry product crates.

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
Node from the shared environment, and Docker or Podman to retrieve the operational test artifact.
Run `./scripts/install-renovate-tool.sh` once (or set `KUBERNETES_LENS_CONTAINER_ENGINE=podman`).
It extracts the verified official OCI runtime into ignored `.ci-tools`, without starting Renovate or
contacting a platform API. The actual-engine regression suite fails if RE2 is unavailable or if the
contained package version/source image does not match the immutable pin. CI uses the same artifact.
After source preparation the regression suite itself requires no registry or platform access.

Run `cargo ci-check`, `cargo ci-clippy`, `cargo ci-test`, `cargo ci-doctest`, `cargo ci-doc`, and
`cargo ci-policy` for focused work. The policy alias runs a Cargo integration harness that delegates the repository Python contracts.
`./scripts/format-lint.sh --fix` formats/lints only and caps Clippy at two jobs unless
`KUBERNETES_LENS_LINT_JOBS` is set. Finish with `./scripts/check-all.sh --check` after the final edit.
Use `python3 scripts/validation-plan.py run-local` for feedback, never as publication evidence.

The complete gate requires MSRV 1.98.1 already installed; a missing toolchain fails preflight.
It accepts only worktree-local CARGO_TARGET_DIR. Keep build artifacts, caches and local graphs ignored.
