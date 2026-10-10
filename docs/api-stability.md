# API stability

The unpublished package now exports the offline [foundation API](foundation-api.md).
[ADR 0003](decisions/0003-offline-native-foundation.md) supersedes ADR 0001's empty API statement.
[ADR 0004](decisions/0004-native-authoring-facts-observations.md) supersedes its source-only
authoring and empty-codec milestone statements.
Rustdoc and independent foundation tests define the local source/behavior contract; no crates.io
baseline or registry comparison is fabricated. Pre-1.0 intentional API breaks require an explicit
ADR/migration decision. Publication remains separately authorized after the completion gate.

Private raw input/output, diagnostic redaction, finite target selection, unknown retention,
null-versus-absence, current identity recomputation and preservation-versus-admission are public
behavior boundaries. Sealed codec internals are crate-private integration contracts. Source-backed
schema descriptors are not delivered native capability. Renderer execution is deferred; finite
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
