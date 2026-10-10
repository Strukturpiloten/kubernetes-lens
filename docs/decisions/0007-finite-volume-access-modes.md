# ADR 0007: Finite volume access modes and supplied occurrence preservation

Status: Accepted

Refines ADR 0002's selected access-mode constraint evidence and ADR 0004's unpublished typed
claim-template API. Versions 1.20–1.37, 35 kinds, served APIs, fields, helper membership and
feature gates remain unchanged.

## Decision

`EstablishedVolumeAccessMode` admits only `ReadWriteOnce`, `ReadOnlyMany` and `ReadWriteMany`.
`AccessModes` is an opaque ordered collection. Caller construction accepts finite enum values;
native decoding privately retains every unsupported string, duplicate and original index.
Finite inspection returns completeness together with indexed values. Partial inspection cannot
establish complete access, binding or driver facts. Unsupported strings and original sequences
require `ExplicitSourceAccess`; default Debug is redacted. `Presence` continues to distinguish
absence, null and an empty collection. Required/cardinality checks belong to the owning desired
resource/template; duplicates are retained without inventing native invalidity.

The existing `enum` constraint records select these three values for the PV/PVC root fields and
PVC spec/status helpers. All other strings, including `ReadWriteOncePod` at every historical
stage, remain preservation-only and produce indexed `UnadmittedField` findings. Malformed native
shapes remain separate errors. Existing scalar enum constraints use the scalar field path.
Evaluation uses the operation's cumulative work and diagnostic budgets.

Ordinary output blocks unadmitted modes. Explicit opaque preservation plus protected output may
retain a complete unchanged sequence only at its original supplied destination occurrence.
Immutable original and effective trees establish the sequence; cached holder provenance cannot
provide authorization. Each ancestor sequence must retain a unique original source occurrence
at the same destination index. Typed encoding supplies sealed leaf/object identity candidates;
only the immutable per-document/path table captured with original-known encoding can bind them.
Candidates are captured before effective redecoding; newly minted effective tokens never refresh
original anchors. Plain source positions remain untouched, and opaque roots retain conservative
source-position proof. Identity alone never authorizes output. Reorders, transplants, ambiguous
aliases and overlapping explicit patches fail closed. Neighboring typed edits are allowed. A deliberate finite replacement or
removal remains subject to ordinary owning-field and unknown-loss rules.

Complete source-free authoring snapshots explicitly reject partial `AccessModes`, including
copied decoded holders. An internal authoring-snapshot marker is independent of unknown-field
serialization and propagates through source-context clones. `NativeAuthored` never supplies the
original supplied evidence required for preservation. Authored-intent observation stripping
precedes the remaining unadmitted-output checks.

## Migration and evidence

`PersistentVolumeSpec.access_modes`, `PersistentVolumeClaimSpec.access_modes` and
`ClaimTemplateStatus.access_modes` intentionally
change from `Presence<Vec<String>>` to `Presence<AccessModes>` before publication. Construct a
finite collection with `AccessModes::new(Vec<EstablishedVolumeAccessMode>)`. For decoded input,
consume both components of `selected()`; use explicit source access only when raw strings are
required. No public unsupported-string constructor is supplied.

The four added constraint records refine current evaluation evidence. Historical upstream schema,
source and observation projections retain their authenticated bindings. Offline regression tests
establish this local source/output contract. Schema/API-server/runtime/tool conformance remains
pending; this decision introduces no storage controller, driver, binding or runtime operation.
