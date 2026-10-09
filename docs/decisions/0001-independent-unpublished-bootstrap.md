# ADR 0001: Independent unpublished bootstrap

Status: Accepted; empty-library/public-API statements superseded by ADR 0003

## Context

The repository initially contains LICENSE only. Workspace libraries already define Rust, local,
CI and Renovate conventions. Kubernetes native work has separate prerequisites, and publication
is reserved for the maintainer after KubernetesLens #15.

## Decision

Create a Rust 2024 library, MSRV 1.85.0, pinned normal toolchain and locked dependencies. Keep the
existing MPL-2.0 license. Export no functionality until native contracts are implemented. Use the
shared BoxFerry development tools rather than a second container definition or Kubernetes pin list.
Pin its CI checkout to an immutable reviewed revision; upstream owns nested tools and checksums.

The complete local gate and equivalent PR/main/manual checks fail on every selected prerequisite
failure. Change-aware PR classification executes trusted-base policy and fails full on rollout or
unknown changes. Release automation only validates; Cargo publishing, tags and GitHub releases
remain disabled. An unpublished crate has no fabricated published SemVer baseline.

## Consequences

Infrastructure tests protect actual extraction, replacements, approvals and aggregate contracts.
Coverage and conformance are unavailable for the empty native library and must become meaningful
requirements during native implementation. Shared tool changes require review of their immutable
revision and upstream integrity evidence. Repository administration follow-up #16 remains visible.

## Alternatives

A copied standalone container would duplicate tool ownership. A copied published-crate release
workflow would enable unauthorized publication and fail against a nonexistent API baseline.
