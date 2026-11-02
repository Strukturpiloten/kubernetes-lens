# ADR0094: Compact complete-root server dry-run JSON

Status: Proposed source-only refinement of ADR0091 and ADR0093. Primary review,
integration, complete validation and any separately adopted native attempt remain
pending. Source compatibility and inert controls do not grant execution authority.

## Decision

For the existing fixed server-side Deployment dry-run, select ordinary kubectl
JSONPath current-root output rather than the indented JSON printer. Use one fixed
quoted literal output selector for both frozen admitted kubectl versions, 1.20.15 and 1.37.0.
Shell quoting keeps the selector as one argv element without changing that argument.
It serializes the complete returned object map as compact JSON. Do not project
selected fields, flatten arrays, add delimiters, stringify values, omit unknown
fields, truncate output or add a profile branch.

Retain the complete authenticated request fixture, server-side dry-run operation,
existing capture 4096/4096, and every exact response predicate. The four existing jq
checks still require apiVersion, kind, metadata.namespace and metadata.name to have
the same exact string values. Non-string values and array-shaped parents remain
subject to those unchanged checks. Printer success is never response acceptance.
There is no complete effective/defaulted configuration equivalence claim.

## Frozen official source contract

The [source facts](../compatibility/kubectl-root-jsonpath-sources.json) record exact
public release-tag resolution, immutable revisions, source URLs, bytes, SHA256 and
Apache-2.0 license references for both versions. Current-object parsing preserves
the root input; map results use JSON marshaling. The create path uses unstructured
objects and JSONPath reads their content map directly, preserving available fields
and nested JSON value types. Both output routes retain the same TypeSetter.
The separate typed-object marshal/unmarshal fallback is not a promise of numeric
precision for arbitrary runtime types. No upstream implementation is copied.

This is semantic response preservation, not byte equivalence: whitespace, key order,
escaping representation and final newline can differ. In 1.37.0 the original JSON
printer defaults to omitting managedFields on a deep copy; ordinary JSONPath retains
those returned fields. Modern output can therefore grow despite compact encoding.
Neither profile has a guaranteed actual 4096-byte fit or native/runtime acceptance.
An oversized compact response still fails the original cap; no fallback discards
fields or raises capacity.

## Unchanged authority, history and accounting

Only the existing dry-run output selector changes. Native invocation and utility
counts, capture helpers/process substitutions, actors, queries, slots, sentinels,
FD lifetimes, original work/cleanup ends, source evidence and outside retirement
remain unchanged. V12 spec/result pairing, k4 attribution, raw POSIX status fields,
protected values and public redaction retain their original meanings. ADR0093's
explicit helper23 still means only the source-bound already-checked numeric size
exceeded its selected cap; other failures remain opaque and old traces are unchanged.

The strict current-to-frozen inverse restores the exact 65378-byte ADR0093 receiver,
SHA256 `5bc0d84d747686cb27e327589a49c120e2e9276528d77ebad05a9bc65c77256f`,
before the unchanged predecessor inverses. Existing test-method bodies, assertions,
source deltas and 314 diagnostic patterns remain intact; current enrollment scalars
migrate independently. The fixed quoted selector change adds 10 bytes, yielding 65388 bytes,
20 below integration 65408 and 148 below hard 65536 after canonical formatting.

No binary, image, dependency, installer or operational pin changes. The new source
facts are historical documentation under the existing `docs/compatibility/**`
Renovate exclusion. Existing shared tool ownership, extraction, grouping, approvals
and checksum coupling are unchanged. Receiver enrollment is manually reviewed source evidence, not another operational
tool pin or installer inventory. Static policy/path inspection supplies no-change
evidence; it is not an actual-engine regression result.

## Validation boundary

Additive inert controls check exact argv and one-call sequencing, mandatory original
response admission, native/capture/error refusal, unchanged source methods/history,
source provenance and receiver bounds. Fixed fake tools and injected status DATA
exercise shell control flow; they do not execute kubectl, a server, constructor,
probe or runtime. Source proof covers both frozen printer contracts only. Final
complete validation, independent review and any fresh exact-source admission remain
primary-owned and separate from this proposal.
