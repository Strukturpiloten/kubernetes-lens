# ADR 0004: Native authoring, effective facts and reviewed observations

Status: Accepted

Supersedes ADR 0003's source-only authoring and zero-production-codec milestone statements and
refines its selector, provenance, graph and generation contracts. ADR 0002 remains authoritative
for the finite schema inventory and pending compatibility evidence. Independence, unpublished
status, privacy, boundedness and separately authorized publication remain unchanged.

## Decision

Integrate real workload native codecs through the sealed registry. Add opaque delivered-kind typed
authoring with explicit target and cumulative resource/tree/byte limits. Canonical snapshots are
strictly reparsed and redecoded, carry NativeAuthored origin, no source version, Generated field
origins and no external positions. Arbitrary plugins, defaults and implicit runtime access remain
excluded. Unknown values are retained; their preservation does not establish admission.

Use Presence as the sole selector member authority and retain private unknown members. Null or
unadmitted selectors cannot be flattened into empty knowledge. This is an intentional unpublished
source break; constructors and explicit Presence inspection replace earlier struct literals.

Graph operations derive identity, facts, references and observation descriptors from one bounded
effective tree and the registered decoder. Source originals remain immutable. No stale typed fact
survives a failed effective decode. Core rechecks exact field/ancestor admission, supplied paths,
scopes, duplicates and fact completeness. Contributions bind to actual supplying object/template/key
subjects with redacted evidence. Every target graph retains its complete immutable target/gate
origin witness and bundled ledger digest. No-target analysis never assumes gates/defaults.

Future StatefulSet and generic ephemeral claim patterns are closed identity expectations, not
created resources. Explicit inputs and supplied candidates remain separate; checked arithmetic
avoids per-replica allocation. Missing ownership stays Unknown, explicit contradictory ownership
is incompatible, and equal ephemeral name compositions are diagnosed. No binding/readiness or
runtime existence is inferred. Graph work, supplying-document scans and cached payload/provenance comparisons consume finite
budgets; failed supplying PVC projection leaves claim evidence incomplete. Constructor scalar
and mapping-key bytes are charged cumulatively before cloning, then final trees and snapshots
are checked independently. Ephemeral ownership uses a structurally valid controlling UID, without
adding kind/name equality to the reviewed ownership rule.

Observation emitters borrow the exact original/effective object tree; core accepts only reviewed
finite GVK/path/role/version descriptors. Supplied ClusterExport observations retain Observed
origin only while unchanged. AuthoredIntent removes maximal present reviewed server/subresource
paths with findings before remaining opaque/private checks. Invalid template status and arbitrary
unknown neighbors remain preserved and unadmitted. Immutable source evidence is never rewritten. Root status roles require exact GVK/profile schema
evidence: supplied source versions take precedence, effective roles otherwise use the target, and
no-profile roles require all admitted profiles to agree. NetworkPolicy status is reviewed only for
1.24–1.27. An independent finite expectation table authenticates schema hashes and binds its
report/ledger/witness; this is observation evidence, not source-server conformance. ListMetadata
observations include only resourceVersion, selfLink, continue and remainingItemCount. Arbitrary
wrapper status and ObjectMetadata-shaped neighbors remain preserved.

Absent protocol has a finite comparison-only TCP meaning for reviewed port map-list keys. No
protocol default is authored, no field is admitted by that rule, and opaque descendants cannot be
silently lost or reassigned during rekey/deletion. Unchanged
malformed keys preserve precise native validation evidence; duplicate scanning still examines
every valid key. Edited malformed associations require deliberate explicit repair/replacement/
removal rather than silently remapping retained source data.

NativeValidationIntent defaults to Unspecified. Explicit Create context reaches the same effective
validation path through a public validation entrypoint and generation option. Neither source-free
authoring nor source/output origin establishes a server operation. Operation-dependent inline
CronJob timezone rules without context produce a safe NativeContextRequired warning retained in
artifacts; malformed syntax and independent validation errors are unchanged. Update/old-object
validation and complete create conformance remain deferred.

## Consequences

Source consumers migrate selector literals, source-origin checks, exhaustive graph matches and
explicit GenerationOptions literals. Sealed facts/observation hooks stay private and do not expose
raw syntax. Nine served workload registrations do not establish the full 35-kind product, native
API-server validation, renderer behavior or supported runtime minors. Remaining cohort evidence
must be delivered independently; no placeholders or fake factories count as native capability.
