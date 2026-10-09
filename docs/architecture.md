# Architecture

KubernetesLens owns native Kubernetes formats and remains independent of BoxFerry and other Lens
libraries. BoxFerry owns orchestration, neutral types and semantic adapters. This repository cannot
depend on those application crates or run their application suites.

The bootstrap has a library target with documentation and no public API. Future source-aware native
contracts are owned by KubernetesLens #1–#4 and the implementation tracker #7. Do not introduce a
placeholder parser or represent zero native tests as conformance.

Infrastructure may adapt reviewed workspace scripts. The shared BoxFerry development container is
a tooling dependency, pinned separately from product dependencies; no BoxFerry application source is
compiled by this repository. Native implementation must be original, without copying or mechanical
translation of external oracle code. Record external tool version, command, provenance, license and
redistribution permission when future conformance evidence is introduced.

[ADR 0001](decisions/0001-independent-unpublished-bootstrap.md) records these boundaries.

[ADR 0002](decisions/0002-frozen-native-compatibility-contract.md) freezes the native compatibility
specification. Its offline checks prove source facts and pending expectations; they do not add a
native parser, public API or runtime capability.
