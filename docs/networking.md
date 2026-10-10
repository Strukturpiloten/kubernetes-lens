# Native networking checkpoint

The networking module provides real sealed codecs for Service and Endpoints `v1`, EndpointSlice
`discovery.k8s.io/v1` and `v1beta1`, Ingress `networking.k8s.io/v1`, `v1beta1` and
`extensions/v1beta1`, IngressClass `networking.k8s.io/v1` and `v1beta1`, and NetworkPolicy
`networking.k8s.io/v1`. Their ten concrete roots preserve exact served identity. The selected
117 root field occurrences and 36 networking-owned helper declarations follow the frozen
capability inventory. Metadata, selectors and integer-or-string values retain foundation
ownership; object references reuse common declarations.

Every selected member retains absence, null and explicit values through its sealed codec.
Private unknown holders retain unadmitted neighbors, including status, endpoint hints,
NetworkPolicy `endPort` and traffic distribution values outside the frozen `PreferClose` subset.
Unselected Service traffic distribution values remain in the typed value and immutable source evidence,
but finite enum admission blocks generation even with explicit private/opaque preservation permission.
Selecting `PreferClose` does not establish another value's target or feature-gate support.
Typed construction uses concrete roots, `Presence` members and `From` into `AuthoredResource`;
`ResourceSet::from_authored` requires an explicit target and bounded construction limits.
No serde/raw-object escape or public native plugin is introduced. Debug and findings redact
native payloads. Exporting protected/opaque data and revealing artifact bytes remain separate
explicit actions.

## Native validation and availability

Service and Endpoints retain their frozen 1.20–1.37 API profiles. EndpointSlice stable starts at
1.21; beta ends at 1.24. Ingress and IngressClass beta profiles end at 1.21. Output never relabels
one API as another. Endpoints deprecation does not remove its API or synthesize resources.

The finite field descriptors retain exact selected helper bindings, field availability and
stable gate floors: app protocol 1.20, EndpointSlice node name 1.21, dual stack and namespaced
class parameters 1.23, load-balancer node-port control and class 1.24, internal traffic policy
and terminating endpoint conditions 1.26, and traffic distribution 1.33. Explicit pre-stable
activation cannot expand the stable-only subset. API removal still takes precedence. The
removed load-balancer-class gate control does not remove the field.

IngressClass baseline parameter fields use the existing common reference type. Explicit scope
or namespace selects the API-specific shape; baseline overlap alone does not infer a source
minor. Target admission controls the 1.20/1.21 shape transition and the 1.23 scope gate.
Absent scope is retained without authoring a cluster default. Native scope/namespace consistency
and cluster-scoped class metadata are checked independently.

Checks include required-member profile boundaries, port ranges/names/protocols, native enums,
Service cross-field restrictions, endpoint address families, Ingress backend and port unions,
path types/paths/hosts, label selector grammar, policy peer discriminator exclusivity, and
IPBlock CIDR syntax/subnet/family constraints. The frozen schema removes NetworkPolicy
`podSelector` requiredness after 1.33 and EndpointSlice stable `endpoints` requiredness after
1.35; retaining absence does not author empty values or establish selector knowledge.
Readiness null/absence and source numeric/string values remain distinct. No DNS or network lookup,
server defaulting, CNI evaluation or controller execution occurs.

EndpointSlice stable `deprecatedTopology` remains a preservation-only, non-writable native
observation with a finding. It is retained under explicit opaque/private export permission;
it does not represent a desired topology update. Beta `topology` is a separate native field.
Load-balancer-class creation checks retain native type/name constraints. Unspecified operation
context produces a context-required warning; server old-state/update immutability and transitions
are not claimed.

## Merge, evidence and graph integration

Service ports use their declared `(port, protocol)` map identity; comparison-only absent/empty Service TCP
semantics belong to core and never materialize a protocol. EndpointSlice arrays and other native
arrays without map identities use conservative atomic replacement. Address arrays retain set
identity. No keys are inferred from host, address, CIDR or strategic-patch port-only annotations.
Unknown-bearing atomic changes must refuse loss until an explicit replacement resolves it.
Original source bytes, positions and evidence remain immutable after typed edits and explicit
patches; graph and output operate on the effective projection.

Native hooks emit Service selector relationships, explicit headless and front-port facts,
EndpointSlice service-label and explicit target references, Ingress Service/TLS/class identities,
and NetworkPolicy applied-pod and peer selectors. Resolved identity/label subjects establish only
supplied membership; exact front-port subjects establish declaration existence. Neither establishes
routing, readiness or enforcement.
No relationship is inferred from an absent Service selector, object name or endpoint topology.
An explicit empty Service selector also emits no Pod-selection relationship. Endpoint target
references use declared cluster scope for known cluster-scoped kinds and the source namespace
for known namespaced kinds when their namespace is absent; unknown kinds remain scope-unknown.
Explicit namespace and null evidence are retained separately.

The closed additive graph operations now distinguish Service front-port subjects from Service
identity, Pod container ports, targetPort and nodePort. Stable and beta Ingress backend forms retain
their source spelling. Named or numeric front-port matching distinguishes absent Service, duplicate
Service identity, complete missing port, one declared port, protocol-ambiguous declarations and
unavailable evidence. Named Service targetPort combines the nonempty Service selector with admitted
Pod/template container-port names and protocol. Absent/empty Service protocol compares as TCP under an
exact target witness; Pod supplier protocol keeps its separate absent-only rule. No protocol default is emitted. Positive selected suppliers remain alongside
incomplete suppliers.

One NetworkPolicy peer target retains both selector presences: namespace AND Pod selection within
that entry, OR across separate entries. Pod-only peers use the established policy namespace.
Explicit empty namespace selectors are universal without requiring Namespace documents. Nonempty
selectors require admitted Namespace label facts; absent suppliers are unknown, and duplicate
Namespace identities retain ambiguity and actual evidence. A known false conjunct excludes even if
the other is unknown. Existing allow rules with absent versus explicit empty from/to have separate
universal presence outcomes without imagined universal subjects. Peers without any effective nonnil selector or IPBlock, and IPBlock/selector mixtures, are
unavailable; standalone IPBlock remains external address evidence. Native peer cardinality ignores
null optional selector pointers, preserves their authored spelling and does not invent graph
membership from unavailable selector semantics.
The native access cohort is integrated. The enabled
`native_namespace_and_pod_selectors_conjoin_within_each_peer_and_union_across_peers` regression
uses actual `v1` Namespace documents through public parse and graph APIs. It checks supplied-only
conjunction and separate-entry union through delivered codecs, without claiming API-server or
network enforcement conformance.

Ingress resource backends and IngressClass parameters use group/kind/scope/name collision identity
without inventing a served version. Explicit supplied versions remain candidate evidence, and
multiple served versions sharing that identity are ambiguous. Group absence compares as core only;
null remains unavailable. Backend resources use the Ingress namespace. Class parameters use their
explicit Namespace-scope namespace or native Cluster comparison without authoring an absent scope.
Unknown custom scope remains unavailable.

Stable EndpointSlice deprecatedTopology stays PreserveOnly and non-writable. Explicit private and
opaque inclusion may export unchanged source-backed data under PreserveObservation or PreserveDocument with
limitation findings. Source-free authored observations or changed payloads remain blocked. AuthoredIntent
removes exact topology observation paths with recorded removal findings. No descriptor becomes Typed.

[ADR 0005](decisions/0005-native-networking-relations.md) records the unpublished exhaustive-enum
migration. All operations recompute effective paths and bind supplier evidence to the immutable exact
target witness. They remain offline declarations, not routing, readiness or enforcement evidence.

Focused offline tests cover ten API roots and source-free construction, native failures and version
boundaries, unknown/null preservation, typed and explicit edits, private output and existing graph
hooks. They are not native API-server, renderer, controller, CNI or runtime conformance. The frozen
native conformance evidence remains pending. The [local cohort evidence](../schemas/capabilities/networking-code-evidence.json)
records code hashes and focused offline tests. The primary owns integration and the complete gate.

Normalized duplicate Service merge keys, including absent or empty Service protocol plus explicit TCP at the same
front port, keep ADR 0004's association safety guard: the supplier is unavailable with MergeConflict
at `/spec/ports`, and generation is refused until an explicit repair. Immutable source evidence and
unknown neighbors remain intact; repair never authors an implicit protocol default. Distinct TCP/UDP
keys with the same numeric front port yield AmbiguousServicePorts because Ingress supplies no
protocol. This distinction describes Lens merge safety, not universal API-server rejection.

## Cumulative processing limits

Networking codecs, native validation, selector fanout, graph evidence and observation output use the
same retained operation as the shared core. Caller ceilings can only lower source/edit/authoring
ceilings. Work, charged payload copies and report retention stop with one terminal `LimitExceeded`
finding. A late graph failure clears previously collected positive evidence; observation comparison
or authored stripping cannot downgrade exhaustion into successful output. These are conservative
processing counters, not allocator/RSS measurements. Namespace selectors use a name dictionary
built once per peer operation, without a Namespace-by-Pod cross-product.

## Finite static validation and context

The final static corrections distinguish native defaulting from raw authored presence. Headless
Services can omit ports. ExternalName accepts one final dot and preserves it. Service/Endpoints
front-port names use the 63-byte DNS label predicate; named target ports keep their separate
15-byte grammar. Nonzero node-port duplicates use effective protocol plus nodePort. The historical
LoadBalancer front-port 10250 restriction applies through 1.32 and is absent from 1.33. It is not a
general prohibition on port 10250.

Service empty type, affinity and scalar protocol, and targetPort zero/empty, retain their authored
values with `NativeContextRequired` at the affected field. None/default-None affinity clears any
nonnil sessionAffinityConfig in native defaulting; Lens retains that supplied object and reports
its defaulting consequence instead of validating a configuration the native path clears. ClientIP
can default omitted config/timeout. No server defaults are authored. Service-specific empty
protocol also has comparison-only TCP meaning for merge identity and named target-port evidence;
empty targetPort does not manufacture a named-port dependency. Duplicate effective Service map
keys still trigger the separate Lens association-safety guard.

Supplied dual-stack Service addresses must use different families and agree positionally with
supplied ipFamilies and their applicable cardinality. ExternalName forbids nonempty clusterIPs,
nonempty ipFamilies and nonnil ipFamilyPolicy; omission, empty collections and explicit null stay
distinct. Source ranges are restricted to LoadBalancer. externalIPs receive the native non-special
IP predicate, without a fabricated duplicate-address prohibition. Raw clusterIPs without clusterIP
receive context-required evidence: the modern normalization/allocation call path remains
unestablished, so the library does not assert universal acceptance or rejection.

An Endpoints subset must contain ready or not-ready addresses; an empty outer subsets list remains
valid. Multiple subset ports need distinct nonempty front-port names. EndpointSlice ports are
limited to 100 and names compare after nil-name defaulting to empty; two unnamed ports conflict.
Omitted/null protocol pointers receive native nil defaulting; an explicit empty EndpointSlice protocol remains invalid. Lens preserves authored null with defaulting context. Beta topology admits at most 16 labels,
checked at each key/value path. Stable deprecatedTopology remains preservation-only. Authored
EndpointSlice address duplicates are retained without a native uniqueness error. The non-special
IP predicate rejects unspecified, loopback, link-local unicast and link-local multicast addresses;
it does not reject all multicast addresses or IPv4 broadcast. These are static validation facts,
not reachability or routability evidence.

Special-IP validation for EndpointSlice entered the 1.20.7 and 1.21.1 patch lines. The public target
stores only a reviewed major/minor; the ledger's 1.20.15 runtime profile does not establish a patch
floor for every target. Special addresses at both minor-only 1.20 and 1.21 therefore receive
`NativeContextRequired`; later frozen minors use the established check. Ordinary canonical
addresses do not acquire a patch warning. The current local EndpointSlice numeric-port range
check remains in place, with Lens-versus-native enforcement unresolved: omission of a range check
from the inspected imperative validator is not proof that every schema/storage/server path accepts
arbitrary numbers.

Ingress HTTP rules need paths. Beta wildcard compatibility skips HTTP-subtree semantic checks,
including its backends, while still checking the rule host and independent default backend.
Stable Create performs the selected checks; Unspecified wildcard/TLS-name cases retain old-object
context rather than assuming Create. Raw selected schema requiredness is preserved separately.
TLS hosts use DNS/wildcard grammar without the rule-host IP exclusion. Resource backend and class
parameter kind/name use nonempty path segments: underscores can pass, while slash, percent, dot
and dot-dot cannot. Graph binding uses the same reference grammar: a valid reference without a
supplied object remains missing, without claiming a custom object has a known scope. Present
empty apiGroup is invalid; omission remains allowed. IngressClass
controller paths accept the witnessed HTTP-path punctuation under the total 250-byte ceiling.
Backend Service names use DNS1035 through 1.33. Numeric-leading DNS1123 names require unavailable
relaxed-gate/old-object context in 1.34–1.36 and pass the locked-enabled gate in 1.37.

NetworkPolicy permits an empty policyTypes list and duplicate valid types under the finite native
validator; more than two entries and invalid enum values fail. Canonical ordinary IP/CIDR Create
values do not need a StrictIPCIDR warning merely because the gate exists. Sloppy/noncanonical,
IPv4-mapped and CIDR host-bit variants receive explicit context where lexical equivalence or gate
behavior is unresolved. The selected target vocabulary does not represent StrictIPCIDRValidation,
and Update old values can be allowed across an object's rules. Plausible IP spellings unsupported
by the local parser remain actionable gaps rather than a claim of native parser equivalence.
Clearly malformed shape and known canonical subnet/family contradictions still get structured
invalid findings. endPort remains outside the admitted selection.

New collection scratch and private IP-formatting buffers share the existing processing session;
report refusal stops later traversal. Direct helper regressions exercise terminal pathless limits,
without turning exhausted parsing into field invalidity. Independent fixtures cover the corrected
boundaries, supplied and source-free output reparse/fixed points, raw default preservation, and
Service merge/graph comparison behavior. The formerly ignored native Namespace integration test is enabled against the delivered access
codec. Focused success does not discharge the primary complete gate or native conformance obligations.

The static expectations come from immutable Apache-2.0 Kubernetes implementation/API witnesses,
including [the exact-floor discovery validator](https://github.com/kubernetes/kubernetes/blob/8f1e5bf0b9729a899b8df86249b56e2c74aebc55/pkg/apis/discovery/validation/validation.go),
[the 1.20.7 backport](https://github.com/kubernetes/kubernetes/blob/132a687512d7fb058d0f5890f07d4121b3f0a2e2/pkg/apis/discovery/validation/validation.go),
[modern core validation](https://github.com/kubernetes/kubernetes/blob/f54c212e3a2f75d674b717a9b29052b20b60aefc/pkg/apis/core/validation/validation.go),
[modern networking validation](https://github.com/kubernetes/kubernetes/blob/f54c212e3a2f75d674b717a9b29052b20b60aefc/pkg/apis/networking/validation/validation.go)
and [modern gate definitions](https://github.com/kubernetes/kubernetes/blob/f54c212e3a2f75d674b717a9b29052b20b60aefc/pkg/features/kube_features.go).
Current official conceptual documentation is pinned separately with CC-BY-4.0 provenance. The
97-record authenticated research receipt and bounded contract remain primary handoff artifacts.
Witnesses were inspected as local research, not executed, redistributed as fixtures, copied or
mechanically translated. API-server, runtime, controller, CNI, allocation and patch/gate/parser
conformance evidence remains pending.

## Integrated native validation corrections

Service metadata names use a single native label, with DNS1035 through 1.33, unavailable relaxed-gate
context in 1.34–1.36, and the locked-enabled DNS1123 label rule in 1.37. The separate generateName
prefix callback is checked without inventing a generated concrete name. Callback acceptance alone
establishes neither generated-name success nor API-server Create acceptance.

Ingress backend port union selects the effective nonempty name or nonzero number. An explicit empty
name beside a valid number, or zero number beside a valid name, stays authored in output and uses the
same branch in supplied Service-port resolution. Both effective branches, or neither, are invalid.
Rule hosts reject recognized decimal IPv4 variants such as `127.000.0.1` and `010.000.000.001` from
1.23 onward. The 1.20–1.22 witnesses call Go's compiler-dependent IP parser; without a historical Go
parser/version witness those spellings receive context. TLS hosts retain their separate DNS grammar.
Wildcard rule/TLS host limits include the original `*.` prefix before checking the suffix. Empty
Endpoints address hostname is an optional scalar value; an explicit empty EndpointSlice hostname
pointer remains invalid.

Selected native pointers preserve authored null for Ingress ingressClassName, IngressClass parameters,
Service/EndpointSlice appProtocol and resource apiGroup. Nil backend pointers have no required scalar
members. Null internalTrafficPolicy and class parameter scope retain explicit defaulting context;
required scalar names and nonnil empty appProtocol remain invalid. Unknown policy selector members
stay in analysis and yield retained Unsupported edges, including own-Pod and peer selectors. No
partial positive selection is inferred from dropping unknown members. Named targetRef objects with
missing or invalid API witness remain explicit Unsupported dependencies without fabricated API,
group, version or scope; absent/null targetRef still contributes no dependency.

Networking root and parameter wrappers use the shared streamed unknown-scope visitor and bounded
unknown capture introduced by the access integration. The shared processing session remains inherited.
A finite networking-owned exception admits only scalar empty Service type/sessionAffinity/protocol
and Endpoints protocol beyond the historical enum selection. It preserves native defaulting context
and source spelling, and leaves schema, version and gate checks intact. No historical schema/source
witness is mutated; invalid nonempty values and other cohorts retain their existing checks.
