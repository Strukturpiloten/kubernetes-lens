# Foundation API and cohort integration

This unpublished library implements offline foundation behavior and the workload cohort. Nine
served workload registrations are delivered; the full 35-kind inventory and runtime conformance
remain incomplete. ADRs 0003 and 0004 record the foundation and workload integration decisions.

## Public boundaries

- `parser::parse_source(SourceInput, &ParseLimits)` accepts explicit bounded bytes and returns
  private immutable `ParsedInput`. YAML marked events are pulled iteratively and stop on the
  first budget violation; the recursive upstream loader is never used. `flatten_resources` and `ResourceSet::from_inputs` retain
  source IDs, syntax arenas, originals, per-field positions, and nested List order/metadata.
- `ResourceDocument::identity` returns `Result<ResourceIdentity, Finding>` computed from live
  encoding/patches. `original_identity` remains original evidence. Input-local `id()`, source
  coordinates `source()`, and enclosing wrapper path `collection()` are read-only getters;
  mutable document access cannot overwrite provenance or detach wrapper items. `ListDocument`
  likewise exposes `id()`, `source()`, `item_ids()` and `collection()` as read-only getters.
  A usable authored
  name or generated-name prefix is required. Cluster collision keys exclude namespace null/absence
  while original identity retains that distinction. `resource`/`resource_mut`
  downcast only delivered native structs. Edits to supplied CRD group/kind/scope/served-version
  evidence are blocked until an explicit semantic conversion contract can recompute dependents. Explicit set-from-parsed-source, null, and remove
  patches preserve caller intent; invalid paths fail during derived-view/generation checks.
- `capability` defines the finite version, kind, feature-gate and renderer vocabulary. A caller
  explicitly chooses complete gate settings or `TargetProfile::documented_defaults`, which
  uses immutable source evidence and never asserts an observed cluster setting. Removed stable
  gate toggles are invalid. Declared APIs are separate from registry admission.
- `graph` resolves explicitly emitted/caller-declared references solely against the supplied set.
  Namespace context is separately caller-declared. Exact references and owners ignore served
  version for lookup; unknown scopes, UID mismatches, ambiguity, no matches, external/operator
  prerequisites and cycles remain structured outcomes. Owner scope uses supplied target/CRD
  evidence. Malformed owner records produce private path/source findings; unknown owner keys
  remain unadmitted evidence rather than disappearing silently.
- `generation::generate` returns private deterministic in-memory native artifacts. Default
  opaque/protected policies block output. Explicit preservation/inclusion retains values and
  findings without claiming typed support. YAML and JSON preserve nested source Lists or explicitly
  flatten them; JSON separately selects one native document or a generic List. Every retained
  wrapper, including empty/nested/typed Lists, passes admission, privacy, target availability and
  observation checks before either route. Wrapper metadata/unknown-field losses on flattening
  produce `collection-field-removed` findings. Authored intent records removal of wrapper server
  observations. Opaque wrapper fields and pagination tokens require explicit protected inclusion.
  Exact field admission applies to empty objects/lists; a parent never admits an unknown empty
  descendant. `Finding::wrapper` carries a public `diagnostic::WrapperSubject` containing the
  source ID/document index (`SourceRef`) and input-local List ID. Equal-position sources and nested
  wrappers remain distinguishable without revealing any path or source text. Resource findings
  retain their existing `ResourceId`; a malformed contained item may also carry its enclosing
  wrapper subject. Failed wrapper decoding records the attempted wrapper ID and keeps the nearest
  nested subject. All wrapper availability, admission, privacy, observation and flattening findings
  retain these coordinates. No output file is written.
- `acquisition::acquire` accepts one explicit regular file or directory, finite file/entry/depth/
  byte budgets and selected extensions. Linux no-follow/nonblocking flags, held root descriptors,
  opened-file containment and identity checks
  fail closed on symlinks, duplicates, special files, races and unsupported extensions. Other
  platforms refuse acquisition; caller-byte parsing is portable.
- `Presence`, `Protected`, exact `Quantity`, `IntOrString`, `IntOrPercent`, `LabelSelector`, shared
  `Metadata`, `OwnerReference`, and recursively retained `UnknownFields` are foundation types.
  Raw access tokens authorize values explicitly; ordinary Debug never reveals private values.

## Sealed codec contract

`src/registry.rs` owns `NativeResource`, `DecodeFn`, contexts, sinks, registrations and builder.
`DecodeFn` receives `&TreeNode`, `&SourceEvidence`, `&DecodeContext`. The private syntax types are
never public serialization/raw-content APIs. `NativeResource` supplies downcasts, explicit
reference emission, required protected-path emission, target validation and `encode_known` through
`SyntaxBuilder`. Protected paths are checked against the current merged tree; inclusion is explicit. It intentionally
has no cached `identity()` method. Decode/encode must retain authored null/absent semantics and
capture/append unknown fields at every extensible nested object/sequence-item boundary.

`RegistryBuilder::register` rejects duplicate GVKs, capability/GVK/scope mismatches and undeclared
built-ins. `register_list` separately registers native typed wrapper/item relationships; declaring
a typed List is not evidence of a delivered resource codec. `ResourceRegistration.capability`
provides exact delivered field pointers (use `*` for sequence/map items), gates, availability,
admission and explicit merge keys. A parent field never prefix-admits arbitrary descendants.

The fixed aggregator is `src/resources/mod.rs`. Its planned slots are `workloads`, `networking`,
`configuration_storage`, `identity_access`, and `extensions`; their source modules/register calls
are added only when actual cohort implementations exist. Each future file provides
`pub(crate) fn register(&mut RegistryBuilder) -> Result<(), Finding>` and owns only its assigned
native structs/fixtures/tests. No placeholder resource modules or dummy codecs are delivered.

Native facts and observation descriptors are sealed extensions. Fact emitters receive the exact
bounded effective object tree, GVK, supplied source evidence, optional target profile and finite
capability declaration. Core rechecks occurrence paths and ancestor admission before using facts.
Observation emitters borrow the exact original tree during initial provenance classification and
exact effective tree during generation; they never re-encode a known-only substitute. Descriptors
classify reviewed operational roles and do not admit unknown descendants. Effective decode failures
remain findings and cannot supply stale typed facts or references.

Encoding contexts share cumulative constructor, tree and byte budgets. Ordinary known baselines
exclude unknown fields; only bounded complete authoring snapshots include recursively retained
unknown data. Narrow expected-unused markers remain only for test-exercised future sealed extension
items; production use must remove them rather than weakening unfulfilled-expectation lints.

## Reviewed shared helper ownership

The primary froze this dependency plan after independent specification research. The workload
cohort (#9) runs first and is the sole writer of `resources/common.rs`, alongside workload native
structs. The primary owns the aggregator declaration. Cohorts #10–#13 then work in parallel in
separate checkouts, importing the completed common module read-only. No other cohort edits it.

Foundation retains five shared source helpers: Quantity, LabelSelector, SelectorRequirement,
IntOrString, and OwnerReference (plus shared metadata/presence/protection). Common owns the other
21 helpers: LocalObjectReference, TypedLocalObjectReference, ObjectReference; NodeSelector,
NodeSelectorTerm, NodeSelectorRequirement; SELinuxOptions; Toleration; ResourceRequirements,
VolumeResourceRequirements; FC, Flocker, GCE, vSphere, Quobyte, Portworx, Photon, NFS, HostPath,
AzureDisk, and AWS volume sources. It additionally owns shared PersistentVolumeClaimSpec, needed
by both workload generic-ephemeral claim templates and the storage cohort's top-level PVC.

PodSpec, StatefulSet and PVC-template wrappers remain workload-owned; the top-level PVC resource
is storage-owned. Cross-cohort relationships use core graph identities/references, never concrete
peer resource structs. Field/gate admission stays context-specific and exact; importing a helper
cannot prefix-admit new fields. Portworx remains preservation-only. Shared helpers are delivered with the workload cohort;
using a helper does not establish another cohort's native capability.

## Source-free typed authoring and selector migration

`ResourceSet::from_authored(Vec<AuthoredResource>, &TargetProfile, &AuthoringLimits)` accepts
only delivered native roots through their real `From` implementations. The opaque wrapper has no
public arbitrary-codec constructor. Construction requires explicit target and finite resource,
parser and aggregate snapshot byte limits. It creates a bounded canonical snapshot, reparses it
strictly and uses the same registered decoder and validation path as supplied input. It does not
infer names, namespaces, defaults, native API versions or create operations. No file, renderer or
runtime is invoked.

`EvidenceOrigin::NativeAuthored` distinguishes these snapshots from
`EvidenceOrigin::Supplied(InputOrigin)`. Native-authored evidence has no source Kubernetes version,
all fields are `Generated`, and source positions are absent; canonical local snapshots never
pretend to be external source coordinates. Ordinary supplied origins remain immutable. Changed
fields and descendants of changed/reordered sequences conservatively become Generated with no
position. Graph provenance comparisons are cached per effective projection and consume the graph
budget; exhaustion cannot leave a positive relationship result.

Selectors now store `match_labels` and `match_expressions` as `Presence` values with a private
unknown-field holder. Migrate struct literals to `LabelSelector::new` or `from_match_labels`, and
explicitly inspect Presence when reading members. Absent and explicit empty remain distinct;
null, malformed or unadmitted selector data cannot be treated as an empty match. Shared Metadata
also retains explicit finalizers. Default Debug continues to redact labels, keys, UIDs and values.

## Supplied graph facts and future claims

Object, template and key `GraphSubject` values remain distinct. Pod-template selection uses Pod
semantics and never reports a controller as a deployed Pod. Key and headless predicates require
finite delivered facts, scope checks and duplicate checks. Optional missing objects/keys use
`OptionalMissing`; optionality never suppresses ambiguity, unknown scope or invalid data. Partial
selector matches retain unavailable candidate gaps. No codec means unknown/unadmitted facts,
not a manufactured empty map or a missing relationship.

`FactEvidence` binds every contribution to its actual supplying ResourceId, SourceRef, subject,
exact path, origin and original position where still valid. Supplier records remain distinct for
multiple documents or List items sharing a source. Each target-specific graph retains an immutable
`GraphTargetWitness` containing the complete copied target, all resolved gate states and their
origins, and the exact bundled ledger digest. Empty graphs retain the witness; no-target graphs
retain None. No-target gated/value-dependent facts require explicit target evidence.

StatefulSet claims use explicit template/controller names, replica count and starting ordinal.
Missing inputs remain symbolic; explicit zero is an established empty range. Evaluation examines
supplied PVCs with bounded arithmetic and never allocates one object per replica. Actual-Pod
ephemeral claims distinguish an established naming rule from supplied ownership: missing Pod UID
or owner evidence means Unknown; admitted explicit ownerReferences: [] or contradictory supplied
controller UID is incompatible. Template metadata does not establish a future Pod name. Equal
Pod/volume name compositions produce `claim-identity-collision` findings without merging owners.
Matching supplied PVCs never prove binding, readiness, creation or runtime existence.

## Observations, merge keys and validation intent

`OutputIntent::PreserveObservation` retains supplied observations under the existing target,
opaque and protected checks. Explicit AuthoredIntent removes only present maximal reviewed
server-owned/subresource paths, before judging remaining opaque/private output, and records every
removal. Immutable original evidence remains accessible. Root status, exact template server
metadata, StatefulSet full claim-template status/metadata and generic ephemeral claim-template
metadata have separate reviewed rules. Unexpected status in PodTemplate, JobTemplate or generic
ephemeral wrappers is not silently stripped. Standalone Pod ephemeralContainers is only a reviewed
opaque subresource observation in supported profiles; nested template occurrences are not.

Map-list port matching uses absent protocol as TCP only at the reviewed Service and workload
container/initContainer paths and served APIs. This is a comparison rule: it inserts no defaults,
rewrites no evidence and adds no admission. Unchanged malformed keys preserve raw values and unknown neighbors for precise native validation.
Every valid key is still checked for duplicates, including after malformed siblings. Editing a
malformed association or deleting/rekeying retained unknown descendants fails with structured
findings unless an explicit field repair, replacement or removal resolves it.

`NativeValidationIntent::Unspecified` is the default for `validate_for_target`, source-free
construction and `GenerationOptions::validation_intent`. Call
`validate_for_target_with_intent(..., NativeValidationIntent::Create)` or select that generation
option to evaluate reviewed create-specific rules. No operation is inferred from source origin,
output intent or edits. Otherwise an operation-dependent inline CronJob timezone rule yields a safe
`native-context-required` warning, retained in generated artifacts. Malformed schedules and all
independent API, gate, privacy and field errors remain errors. There is no Update/old-object mode,
ambient timezone lookup, server request or complete create-conformance claim.

## Finite root and List observation roles

Root `status` classification requires an exact admitted GVK and a reviewed schema profile; a
matching kind name, custom API, arbitrary status-shaped member or List is insufficient. The
independent 48-GVK expectation table authenticates all 18 schema source hashes and binds the
reviewed report, capability ledger and schema-witness bytes. It establishes observation roles,
not complete native or API-server conformance. NetworkPolicy status is an observation only in
1.24–1.27. Original evidence uses an explicit supplied source version; without one it requires
agreement across every admitted profile. Effective classification uses that source version first,
otherwise the explicit target, otherwise the same all-profile agreement. Source-version retention
does not establish validation against the source server.

ListMetadata observation removal applies only to `resourceVersion`, `selfLink`, `continue` and
`remainingItemCount`. ObjectMetadata-shaped neighbors and arbitrary wrapper `status` remain
preserved and subject to ordinary admission/privacy rules. Edited observations remain classified
by current roles, but immutable source positions/origins never change; changed effective payloads
carry generated evidence.

Constructor limits count string, numeric and mapping-key bytes cumulatively before cloning,
then independently check final trees and encoded snapshots. Graph supplying-document scans and
payload comparisons consume the graph work budget; exhaustion cannot retain a positive result.
Failed supplying PVC decoding leaves claim outcomes incomplete. Ephemeral claim ownership uses
a structurally valid controlling owner UID; kind/name equality is not added to that UID rule.
Absent or malformed ownership stays unknown, and contradictory ownership remains incompatible.
