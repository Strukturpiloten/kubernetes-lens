# Foundation API and cohort integration

This unpublished issue-one milestone implements offline foundation behavior. It does not deliver
35 native codecs or declare supported Kubernetes minors. ADR 0003 records the API refinements.

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

Temporary item-level non-test `expect(dead_code)` markers cover `ReferenceSink::push`,
`FindingSink::push`, `DecodeContext`, `EncodeContext`, `ValidationContext`,
`RegistryBuilder::register`, `UnknownFields::capture`/`append_to`, and
`SyntaxBuilder::set_root`. Genuine test-only codec coverage exercises each interface. Remove each
marker when production integration uses that item; do not suppress unfulfilled expectations.

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
cannot prefix-admit new fields. Portworx remains preservation-only. No common helper code or fake
capability is delivered by this milestone.

There is currently no public new-from-typed authoring factory. Generation uses source-backed
ResourceSet documents and explicit edits; source originals are required for delta/evidence
semantics. A future factory must be separately integrated and reviewed under primary ownership.
The documentation does not advertise source-free typed authoring.
