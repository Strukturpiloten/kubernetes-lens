# Platform support

The byte-oriented offline Rust foundation uses edition 2024 and MSRV 1.85.0. Explicit file/directory
acquisition currently supports Linux only, with regular-file identity and opened-descriptor
containment verification through procfs. If those checks are unavailable or fail, acquisition
refuses input. Other platforms can supply bounded UTF-8 bytes directly; acquisition fails closed.
Focused execution evidence currently covers Linux amd64 in the shared development environment.

No Kubernetes minor, renderer backend, arm64 runtime, API server or live cluster conformance is
claimed. Kubernetes 1.20–1.37 are frozen target/source facts, not a supported runtime-version list.
Shared tools remain BoxFerry-owned; #446 tracks upstream arm64 evidence. Native cohorts and
independent runtime/renderer evidence remain separately required by #7 and the completion gate.

The optional `supervised-renderer` implementation and its helper/gate binaries are Linux-only.
Default builds retain subprocess-free native input, local plans and generated projects. Unsupported
platforms or missing explicit broker/runtime prerequisites have no automatic fallback. See
[renderer interfaces](formats.md) for provisioning and the still-pending independent evidence.
