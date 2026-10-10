# API stability

The unpublished package now exports the offline [foundation API](foundation-api.md).
[ADR 0003](decisions/0003-offline-native-foundation.md) supersedes ADR 0001's empty API statement.
[ADR 0004](decisions/0004-native-authoring-facts-observations.md) supersedes its source-only
authoring and empty-codec milestone statements.
[ADR 0005](decisions/0005-native-networking-relations.md) adds closed Service port subjects,
NetworkPolicy peer conjunctions, versionless GroupKind binding and named target-port evidence.
These additions retain supplied-only semantics and immutable source evidence.
Rustdoc and independent foundation tests define the local source/behavior contract; no crates.io
baseline or registry comparison is fabricated. Pre-1.0 intentional API breaks require an explicit
ADR/migration decision. Publication remains separately authorized after the completion gate.

Private raw input/output, diagnostic redaction, finite target selection, unknown retention,
null-versus-absence, current identity recomputation and preservation-versus-admission are public
behavior boundaries. Sealed codec internals are crate-private integration contracts. Source-backed
schema descriptors establish only their reviewed offline supported-subset contract in ADR 0011. Renderer execution is deferred; finite
renderer identifiers do not freeze an invocation, artifact-tree or supervisor API.

The issue-nine unpublished API intentionally changes selector members to Presence values with a
private unknown holder, source origin to EvidenceOrigin, and adds opaque typed authoring, explicit
graph subjects/facts/claim outcomes and target witnesses. Selector struct literals migrate to
constructors; source-origin comparisons distinguish Supplied from NativeAuthored. Exhaustive graph
matches and GenerationOptions literals must include the new variants/validation_intent or use
Default. NativeValidationIntent defaults to Unspecified, independent of source/output origin;
explicit Create evaluates only reviewed operation-specific rules. Context-required warnings do not
establish native conformance. See the foundation API for behavior and migration details.

Reviewed root status and ListMetadata roles use exact GVK/profile evidence and preserve immutable
source evidence. Source versions take precedence over target profiles for these operational roles;
retaining a version does not claim source-server validation. Unchanged malformed map-list keys
retain precise native evidence, while duplicate valid keys and unsafe edited associations remain
errors unless the caller supplies a deliberate explicit repair/removal. Constructor and graph
budgets are cumulative and never authorize a positive outcome after exhaustion.

[ADR 0006](decisions/0006-shared-native-processing.md) adds ParseLimits.processing,
GenerationOptions.processing and ReferenceContext.processing. Existing literals migrate using
Default or explicit members. SourceEvidence retains its effective ceilings; caller overrides cannot
raise them. NativeBytes exposes protected decoded bytes only with explicit source access, while
quantity ordering reports exact supplied order separately from native arithmetic uncertainty.
Sealed field/native hook contexts now preserve one operation session through projections and
reparsing. These intentional unpublished integration changes do not establish native conformance.

[ADR 0008](decisions/0008-exact-protected-json.md) adds `ExactJsonNumber`, `ProtectedJsonBuilder`,
opaque `JsonNodeId` and `ProtectedJsonValue`. Their exact mathematical/structured comparisons and
bounded private-value factories remain separate from server precision and schema evaluation.
Private snapshot failures now omit traversal paths while retaining their code and phase.

[ADR 0007](decisions/0007-finite-volume-access-modes.md) intentionally changes
PersistentVolumeSpec.access_modes, PersistentVolumeClaimSpec.access_modes and
ClaimTemplateStatus.access_modes from
Presence<Vec<String>> to Presence<AccessModes>. Construct selected modes with the finite
EstablishedVolumeAccessMode enum. Decoded selected() inspection returns completeness and
original indexes together; unsupported strings require ExplicitSourceAccess. Copied partial
holders cannot authorize source-free authoring or destination preservation.

The access/policy cohort adds eighteen concrete API roots with typed authoring, supplied references
and finite native validation. HPA Create rules are operation-specific; arbitrary grouped targets do
not establish a scale subresource. LimitRange comparisons expose their conservative native arithmetic
boundary, while unresolved rounding/defaulting remains explicit. See [ADR 0009](decisions/0009-native-access-policy.md).

The configuration/storage cohort adds five typed API roots. ConfigMap `data` values use
`Protected<String>` and require explicit source access, just like binary and secret values;
ordinary Debug, findings and default output never reveal them. Public holders retain field
presence and unknown source data. Selected `immutable` fields follow the frozen stable-only
profile (typed from 1.21). PV/PVC validation requires explicit Create intent for reviewed
operation-specific rules; static validity does not prove binding, scheduling or driver behavior.
See [ADR 0010](decisions/0010-native-configuration-storage.md).

[ADR 0011](decisions/0011-source-bound-custom-resource-descriptors.md) adds six typed extension
roots, family-correct borrowed schema helpers and source-bound custom-document descriptors.
Positive graph evidence requires the same current supplied set, effective CRD/schema, custom document
and explicit target profile. Stale, cross-set, unsupported or exhausted checks cannot establish a
positive dependency. Unknown schema/CEL/defaulting/conversion and controller behavior remain explicit
limitations. See [extension support](extensions.md); API-server and official corpus evidence are pending.
