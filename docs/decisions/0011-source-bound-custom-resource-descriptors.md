# ADR 0011: Source-bound custom-resource descriptors

Status: Accepted

Refines ADRs 0002–0004 for explicitly supplied custom resources and CRDs. It makes no claim about API-server validation, admission, conversion execution, controller behavior, or runtime conformance.

## Decision

An offline custom-document check may bind a supplied custom resource only to one unique supplied CRD with matching group, kind, served version, and scope. The binding carries a sealed descriptor for the actual CRD `ResourceId`, selected nested version, and selected schema, with source pointers that preserve the original CRD and custom-document locations, including List items.

Descriptors are sealed to the exact resource set, current effective supplied CRD and full target profile. Graph resolution reruns the bounded check and compares this authority before accepting a replayed descriptor. Matching input-local IDs or GVKs alone confer no authority. Exhausted passes return a terminal error rather than a successful vector with an omitted tail.

Only a complete supported-subset local schema check with no reported violations can produce a positive graph dependency. That dependency targets the actual supplied CRD document and retains the selected version and schema as evidence. Missing, ambiguous, invalid, unserved, unsupported, locally violated, incomplete, limit-exceeded, and target-profile-required outcomes remain distinct graph statuses; none implies a positive dependency. Targetless graph collection does not guess a schema result.

Every recognized custom document has an external, unverified operator prerequisite. This records only that controller reconciliation is needed; it does not identify a controller or establish its installation, behavior, availability, or result. Conversion-webhook Service and remote URL prerequisites are collected only from explicit endpoint fields. No callback, network access, controller inference, or runtime operation is performed.

The check uses the graph's shared bounded processing session. Protected source values and bytes remain private unless explicitly revealed through source access. Typed CRD declarations alone do not bind arbitrary custom resources; callers use the offline checker to establish source-bound relationships.
