# ADR 0005: Closed supplied networking relationships and topology export

Status: Accepted

Refines ADR 0004's supplied graph and explicit observation-output contracts. Independence, exact
finite admission, unpublished status, privacy, boundedness and explicit publication authority remain
unchanged. This is an intentional unpublished source migration for exhaustive enum matches.

## Decision

Add only closed native networking operations. ServicePorts facts retain exact front-port declaration
paths, names and protocols. ServicePortExists takes the native name-or-number backend selector;
missing Service, complete missing port, one port, multiple ports and unavailable evidence remain
separate. A ServicePort subject is never a Pod/container/node/target port, and Ingress protocol
absence never chooses one TCP/UDP supplier arbitrarily.

Retain both Presence selectors in each NetworkPolicyPeer. Evaluate their conjunction within one
entry and separate entries independently. Only actual supplied objects/templates are selected.
Namespace labels require admitted facts; absent suppliers are unknown, empty namespace selectors are
universal without namespace documents, and duplicate supplied identities remain ambiguous. A known
false conjunct excludes despite unknown evidence in the other. Existing allow rules with absent
versus explicit-empty from/to have explicit NetworkPolicyAllPeers results, without imaginary subjects.
Null/invalid peers and IPBlock/selector mixtures cannot establish membership. Standalone IPBlock is
external address evidence, without packet evaluation.

GroupKindName carries native group/kind/name without manufacturing a served version. Collision
identity excludes served version; group absence has core comparison meaning only and null remains
unavailable. Native backend/class scope rules preserve absent defaults in output. NamedServiceTargetPort
combines a nonempty native Service selector with admitted Pod/template container-port names and
protocol. Comparison-only absent or empty Service protocol as TCP requires the immutable exact target witness; Pod supplier protocol keeps its separate absent-only rule. Complete missing
port evidence stays separate from partial positive/unavailable supplier results.

Stable EndpointSlice deprecatedTopology remains PreserveOnly and non-writable. Generate may downgrade
its preservation limitation to a warning only for unchanged source-backed payloads under explicit
ProtectedOutput::Include, OpaqueFieldPolicy::PreserveWithFinding and a preservation intent (PreserveObservation or
PreserveDocument). Source-free
generation and changed payloads remain blocked. AuthoredIntent removes exact topology observation
paths with recorded removal findings. Field admission and immutable source evidence do not change.

All operations use effective projections, budgeted scans/comparisons/evidence, exact supplier IDs and
paths, and the immutable GraphTargetWitness. Sealed test codecs establish core expected results;
real native supplier cohorts establish separate integration evidence. Neither is native runtime,
server, routing, enforcement or controller conformance.

Native networking admission is separate from historical schema enum selection. Only empty scalar
Service type/sessionAffinity/protocol and Endpoints protocol have a finite semantic selection
exception; their authored spelling and explicit defaulting context remain intact. Version, gate,
shape and other-cohort checks remain unchanged, and immutable source witnesses are not rewritten.
Unsupported selectors remain explicit graph edges and preservation findings, without positive
selection from dropping unknown members. Nil optional pointers carry no required scalar descendants.

The core/v1 Service generateName lexical envelope delegates to the witnessed native prefix callback
before generic identity admission. It preserves shared type/nonempty/253-byte ceilings and raw
spelling, uses UTF-8-safe retained-prefix checks, and leaves explicit names, namespaces and all other
GVK identity rules unchanged. The separate Service label-length and target/gate checks still apply;
callback acceptance establishes neither an eventual concrete name nor API-server Create success.

## Migration and limits

Consumers update exhaustive matches for added ReferenceTarget, ReferencePredicate, GraphSubject,
Resolution variants. Protected values and source paths retain redacted Debug. No plugin,
raw-JSON fact authority, implicit namespace/default, network lookup or runtime mutation is added.
The real access cohort supplies native Namespace label facts. The enabled public integration
regression checks conjunction and separate-entry union offline; API-server/CNI conformance remains
pending.
Networking uses ADR 0006's retained cumulative processing session for decoding, validation, graph
comparison/evidence and observation output. Canonical gate corrections remain separately owned
work; focused tests do not substitute for the primary's final complete gate.

Normalized duplicate Service merge keys, including absent or empty Service protocol plus explicit TCP at the same
front port, keep ADR 0004's association safety guard: the supplier is unavailable with MergeConflict
at `/spec/ports`, and generation is refused until an explicit repair. Immutable source evidence and
unknown neighbors remain intact; repair never authors an implicit protocol default. Distinct TCP/UDP
keys with the same numeric front port yield AmbiguousServicePorts because Ingress supplies no
protocol. This distinction describes Lens merge safety, not universal API-server rejection.
