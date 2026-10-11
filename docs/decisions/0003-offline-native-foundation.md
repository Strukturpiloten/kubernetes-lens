# ADR 0003: Offline native foundation with sealed admission

Status: Accepted

Supersedes the empty-library/public-API statements in ADR 0001. Its independence, unpublished
package, MPL-2.0, shared tooling, and publication boundaries remain accepted. ADR 0002 continues
to own source facts and pending native compatibility evidence.

## Decision

Implement bounded strict YAML/JSON input, immutable private syntax/source evidence, native
identity and List wrappers, finite Kubernetes 1.20–1.37 target profiles, a supplied-only graph,
merge-safe typed edits, and deterministic private in-memory YAML/JSON output. File/directory
acquisition is separately explicit and bounded. No renderer execution, runtime client, ambient
namespace, filesystem output, API relabel migration, or live discovery is introduced.

Declared built-ins and delivered codecs remain separate. The five cohort registration slots have
zero production codecs at this milestone. Known kinds are preservation-only with findings;
unknown kinds require supplied CRD scope evidence before scope is established. Preserving a
manifest never proves native validation, admission, controllers or compatibility.

The sealed decoder receives a private materialized syntax tree for exactly its object rather than
an entire source document. Each resource and List also retains the full immutable syntax arena,
original source bytes, collection coordinates and field positions. This preserves original tags,
styles, anchors, aliases, numeric lexemes and unknown descendants independently of typed edits.

A codec has one live editable metadata/known-value store. Effective identity is returned as an
owned fallible value computed from current encoding and explicit patches; no duplicate mutable
identity snapshot is authoritative. Original identity remains immutable evidence. Every graph,
collision check and generation recomputes effective identity, ignoring served version for exact
lookup/collisions and refusing GVK relabeling or contradictory scope.

Generation applies only changed known leaves to original syntax. Explicit map-list keys match
items through edits and reordering; atomic replacements that lose unknown descendants block
until an explicit field patch resolves the conflict. Null and absent values remain distinct.
Unknown-field retention is not availability admission. Source-backed unavailable APIs/fields and
gate requirements still block explicit opaque preservation. Protected output defaults to denial;
explicit inclusion emits actual bytes, never placeholders. Raw source and artifacts require
separate explicit access tokens. Debug and diagnostics omit arbitrary source content.

## Consequences

The foundation tests prove library behavior only. The 35 resource cohorts and all runtime,
renderer and compatibility evidence remain pending. JSON-compatible flow documents are emitted
as deterministic YAML with document markers; comments, layout and alias spellings are immutable
source evidence, not promised generated formatting.

The private extension methods are temporarily expected-unused only in non-test builds. Genuine
test-only codecs exercise these interfaces without publishing fake production capability.
Unfulfilled lint expectations remain enabled, so integration must remove the expectations as
real cohort implementations begin using each item. Exact locations and ownership are recorded
in the foundation API document.

## Renderer milestone refinement

[ADR 0012](0012-explicit-offline-renderer-selection.md) supersedes the no-renderer-execution
milestone only: explicit offline execution requires caller selection and provisioned isolation.
Native parsing remains subprocess-free, and independent conformance evidence remains required.
