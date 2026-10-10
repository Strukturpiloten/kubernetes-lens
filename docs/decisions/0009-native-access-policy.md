# ADR 0009: Finite native access and policy support

Status: Accepted

Refines ADRs 0002–0004 with eighteen delivered access/policy API roots for thirteen built-in kinds.
Historical source/schema projections and conformance obligations remain unchanged.

## Decision

Use sealed native codecs, shared protected values, operation-wide processing sessions and streamed
unknown scopes for Namespace, ServiceAccount, RBAC, HPA, PDB, quotas, limits, PriorityClass,
RuntimeClass and historical PSP. Native typed authoring and source-backed edits share validation,
supplied-only graph resolution and deterministic protected generation. API spelling is never relabeled.

Native admission facts and controller behavior remain separate. HPA target kind/name use path-segment
rules; API validation is Create-specific from 1.34 and preserves the native permissive split.
Unspecified context cannot decide old-object grandfathering. No local lookup proves a scale subresource,
metrics availability, permissions, quota enforcement or Pod Security Admission enforcement.

Quota scope availability follows exact version/gate facts. Scope collection conflicts remain independent,
selector cardinality is finite and standard hard-resource applicability excludes custom/count keys.
LimitRange supplied-field comparisons use only the reviewed nonnegative integral int64 domain.
Fractional/capped/negative native arithmetic, ratio ceilings and implicit defaults remain explicit gaps;
they do not justify discarding desired values or inventing native invalidity.

The selected toleration operator enum includes the explicit empty spelling, meaning Equal throughout
the frozen interval. Historical schema/source evidence remains unchanged; current enum admission is
bound separately. The capability ledger and immutable source receipts distinguish code expectations,
source inspection and pending API/runtime evidence.

## Consequences

All roots preserve unknown/protected values and explicit null/absence; output requires explicit private
artifact access. Lower caller budgets remain cumulative and sticky, with one safe pathless terminal.
Offline tests establish finite code behavior only. #2 retains API/server and runtime obligations;
Tracker Tracker #7 cannot close until the whole native/resource/renderer goal and #15 handoff are complete.
