# API stability

The unpublished package now exports the offline [foundation API](foundation-api.md).
[ADR 0003](decisions/0003-offline-native-foundation.md) supersedes ADR 0001's empty API statement.
Rustdoc and independent foundation tests define the local source/behavior contract; no crates.io
baseline or registry comparison is fabricated. Pre-1.0 intentional API breaks require an explicit
ADR/migration decision. Publication remains separately authorized after the completion gate.

Private raw input/output, diagnostic redaction, finite target selection, unknown retention,
null-versus-absence, current identity recomputation and preservation-versus-admission are public
behavior boundaries. Sealed codec internals are crate-private integration contracts. Source-backed
schema descriptors are not delivered native capability. Renderer execution is deferred; finite
renderer identifiers do not freeze an invocation, artifact-tree or supervisor API.
