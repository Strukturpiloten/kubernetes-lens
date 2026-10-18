# ADR 0028: Rust 1.98.1 minimum

Status: Accepted; supersedes the Rust minimum in ADR 0001

## Context

The normal toolchain is already pinned to Rust 1.98.1, while ADR 0001 and active compatibility
declarations retain Rust 1.85.0. KubernetesLens #54 aligns the supported minimum with the reviewed
normal toolchain across the Lens workspace.

## Decision

Require Rust 1.98.1 for this Rust 2024 package. Keep the minimum explicit in Cargo and Clippy;
local preflight, the MSRV phase and CI read that minimum rather than adding independent pins.
Manual release validation continues to call the complete CI contract. The normal toolchain
remains owned by Renovate's native `rust-toolchain` manager with manual approval and no automerge.
The minimum is a reviewed compatibility anchor, not an automatically advanced operational pin.

## Consequences

Consumers using Rust 1.85.0 must install Rust 1.98.1 or newer. The unpublished package version,
dependency graph, native target facts and conformance boundaries do not change. Historical ADR
text and dependency/oracle MSRV evidence remain intact; this decision replaces only the active
package minimum. The complete gate remains required after integration.

The higher Clippy baseline requires behavior-preserving source cleanup. Current evaluation-source
bindings are recomputed from those exact bytes; authenticated historical schema observations and
their provenance remain unchanged. This source-only rebinding is not new native conformance.
