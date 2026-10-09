# ADR 0002: Freeze an executable native compatibility contract

Status: Accepted

## Context

The independent unpublished bootstrap in ADR 0001 has no native implementation. Cohort work needs
one finite source-backed contract before parallel native types, validation, rendering and runtime
evidence can make compatibility claims. An OpenAPI definition alone cannot establish API serving,
feature-gate availability, native semantics or runtime acceptance.

## Decision

Freeze Kubernetes 1.20–1.37, the agreed 35 kinds, exact API serving intervals, explicit root/helper
field lists, finite value/context predicates, protected-source behavior and evidence obligations in
[machine ledgers](../compatibility/README.md). Retain independent schema witnesses and immutable
schema/documentation/tool provenance with license and integrity records. The offline checker
verifies these facts and rejects scope expansion or native-success claims.

Every TargetProfile explicitly selects finite gate settings. Documentation defaults remain separate
from observations. Most optional pre-stable fields are PreserveOnly; the named sidecar and PVC
retention profiles admit explicit enabled stages. Shared Pod/Job restrictions propagate through
all named workload templates. Unsupported semantics and unknown descendants retain source evidence
and structured findings; generic object wrapping or pointer-prefix admission is insufficient.

Separate user-only exports, explicit bounded offline renderers and external owned-cluster harness
commands. Freeze exact tool/artifact/mode/version evidence cells and independent native kind
scenarios. KubernetesLens never acquires a live cluster or applies/deploys output. Modern tool
installation remains BoxFerry-owned; fixed compatibility anchors are excluded from Renovate.

All native evidence remains pending. No supported minor, published API, live compatibility or
operator behavior is claimed by this specification. Later native implementation must be original
and pass every required cell with exact provenance before the completion gate can advertise support.

## Consequences

The specification is reviewable and runs offline without shipping the full upstream schema corpus.
Conservative exclusions require a reviewed contract change, source evidence and new cases before
selection. New versions, enum branches, field families and tool profiles cannot become supported
merely because a schema or operational dependency advances. ADR 0001 remains accepted; no product
library or cross-repository API is introduced by this decision.
