# Platform support

The native library has no supported Kubernetes versions or runtime profiles yet. Kubernetes 1.20
is a future compatibility anchor, not an operational dependency to advance with Renovate.
The Rust build contract is edition 2024 and MSRV 1.85.0. CI uses ubuntu-24.04 for repository checks.

Shared tools belong to BoxFerry; its Kubernetes tooling is delivered in #445/#447, and #446 tracks
remaining arm64 execution evidence. A successful bootstrap gate does not prove native Kubernetes,
arm64 runtime or cluster conformance. Follow-up #7 owns native implementation and evidence.
