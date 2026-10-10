# ADR 0008: Exact numbers and protected structured JSON

Status: Accepted

Extends ADR 0006 for CRD-schema JSON leaves. Schema evaluation, extension registrations, operator
behavior and API-server evidence remain separate obligations.

## Decision

`ExactJsonNumber` retains a private strict JSON lexeme of at most 512 bytes; its exponent token is
at most 11 bytes and must fit i32. Malformed grammar is invalid; valid numbers outside finite
representation limits yield `LimitExceeded`. Normalized sign/coefficient and checked i64 decimal
scale establish mathematical equality, including signed zero. Ordering uses symbolic decimal ranks
and conceptual zero padding; a budgeted comparison precharges 513 work units even for shortcuts.
No floating point, exponent expansion or Kubernetes schema `double` parity is claimed.

`ProtectedJsonBuilder` builds a flat arena of null, boolean, exact number, string, array and object
nodes. Opaque handles belong to one builder and reference only earlier nodes, making cycles
unconstructible. Object keys are unique and order-insensitive; arrays remain ordered. Clone shares
immutable backing and drop is nonrecursive. Native decode, encoding and budgeted comparison are
iterative and inherit the sticky operation. Public structural equality is bounded by sealed shape;
native evaluators must use the budgeted interface.

Every repeated child contributes to checked expanded nodes, events, depth, scalar/key bytes and
maximum scalar size. Effective ceilings are at most 500,000 nodes, 1,000,000 events, 8 MiB expanded
scalar/key payload and 1 MiB per scalar/key. Caller-selected valid depth is at most 128. Serialized
bytes have independent snapshot bounds. New traversal/index/node buffers and payload copies are
precharged. Consumed caller buffers are not counted as invented copies; shape/work accounting still
applies. Unreachable nodes confer no supplied-source authority.

Construction requires no source seed. Parsing yields a value without resource provenance. Explicit
source access permits private serialization; Debug and failures hide keys, values and digests.
The entire private snapshot boundary removes traversal paths from verification/serialization errors
while preserving code and phase. Owning codecs may attach only an admitted leaf path. Raw numeric
snapshot validation uses strict raw grammar, avoiding a floating-point magnitude restriction;
unknown supplied numbers outside typed numeric bounds can remain raw evidence.

Null is a real JSON member, distinct from absence. The future schema-example owner must enforce
one canonical explicit-null representation and reject or normalize `Presence::Value(null)` before
claiming a typed fixed point after reparsing it as `Presence::Null`. Protected-output permission
alone does not authorize unsupported schema/custom semantics.

## Migration and evidence

These unpublished value APIs add no dependency or tool pins. Boundary/privacy tests establish local
value behavior, not schema evaluation, numeric server precision or runtime conformance. Parser and
ResourceSet operations retain their existing shared processing and evidence contracts.
