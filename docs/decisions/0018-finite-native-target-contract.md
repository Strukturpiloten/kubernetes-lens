# ADR 0018: Finite native target validation and finding transport

Status: Accepted

Refines ADRs 0002–0004, 0006, 0010, 0013 and 0017 for #47. It does not complete #43,
the original native evidence cells, an external host bridge or Kubernetes support.

## Decision

The independently reviewed finite rules establish expected results before implementation.
Current native parsed values, findings and generated artifacts never define the expectation oracle.
The machine contract is `schemas/capabilities/kubernetes-finite-native-contract.json`; immutable
schema/feature provenance remains in the original ledger. Historical evidence remains historical.

Keep the public fallible `IntOrString::Int(i64)` carrier. Enforce the signed int32 native domain
at admitted wire decoding, authored validation and generation. Never clip, coerce numeric-looking
strings or emit an int64-only native alternative. Wire discriminant failures are
`MalformedDocument/Error/Decoding`; source-free authored construction and generation use their
actual Generation boundary, while explicit target validation uses Validation. Only actual decoder
evidence supplies positions; authored failures never manufacture Decoding provenance. Null refusal is
field-scoped to the reviewed direct values `ServicePort.targetPort`, `HTTPGetAction.port` and
`TCPSocketAction.port`. The eleven remaining declared IntOrString occurrences retain explicit
`Presence::Null`; the machine contract lists them. This preservation does not grant native target
admission or replace their existing contextual predicates. The direct primitive decoder still
rejects a null value union.

Independently bind container `SecurityContext.runAsGroup` to RunAsGroup. At 1.20 a complete
documented-default or explicitly enabled context admits the beta field; false/unresolved settings
produce a concrete `FeatureGateRequired/Error/Validation` path. The feature is stable in 1.21–1.22
and persists after removal of the configurable toggle in 1.23. Existing ordinary/init containers
and admitted workload templates share this exact helper binding. PodSecurityContext is not added
by inference from this decision or the separate PodSecurityPolicy binding.

Shared supplied metadata checks validate qualified label/annotation keys and label values. Annotation
key plus value UTF-8 bytes total at most 262144, inclusive. The first supplied annotation leaf
crossing that aggregate ceiling identifies the failure. Supplied security/grace integers remain
nonnegative, including every supplementalGroups element and overridden pod values. Container
precedence remains per member: explicit false/zero is supplied, absence may use a supplied pod
member for context only. No image UID, OS, default or kernel observation is invented.

Finite quantity admission is separate from the broader exact Quantity API. Reviewed native magnitude
is at most i64::MAX and precision is an exact multiple of 0.001; CPU requires nonnegative integral
millicores and memory nonnegative integral bytes. The scaled-millicore int64 helper is not this
magnitude predicate. Explicit matching container requests must be no larger than limits. An absent
counterpart stays absent, and PVC rules are not borrowed from containers. Unreviewed native
rounding/capping/precision receives `NativeContextRequired`, without changing exact Lens arithmetic
or source lexemes. All scans, paths, comparisons and findings inherit the sticky operation budget.

Nonempty ContainerPort names are unique across every admitted occurrence in each Pod/template,
including ordinary and init containers; separate Pods/templates are isolated. Empty unnamed ports
remain unnamed. Duplicate capability-drop values are retained; ALL is reviewed, and unreviewed
names/empty strings receive contextual warnings. At 1.20 the documented mountPath colon prohibition
is checked; later colon contexts remain unverified rather than inventing a removal boundary.
Mounting one volume at different paths remains valid.

Duplicate env merge keys remain safe source-projection ambiguity refusals. They do not imply
universal native API invalidity. The external projection assertion is P-ENV-AMBIGUITY, not a new
native code. Service normalized port merge ambiguity retains `MergeConflict/Error/Generation`
at `/spec/ports`; native container/volume/port uniqueness remains a separate rule.

ConfigMap keys `.`, `..` and leading `..` receive `NativeContextRequired/Warning/Validation` at
the exact data/binaryData key. Source values stay retained and graph key domains stay Unknown.
Ordinary `.UPPER` keys and the existing 253-byte grammar, disjoint text/binary keys and inclusive
1MiB value/decoded-binary body limit remain unchanged. This decision adds no Secret filesystem rule.

## Finding and authority boundaries

Finite target records carry code, severity, phase, actual input-local ResourceId, exact FieldPath
and existing wrapper associations. Validation positions are null; immutable source coordinates
remain separate source evidence. Root invalid name/namespace uses `InvalidIdentity`; every member
of a duplicate identity group receives `DuplicateIdentity/Error/Validation` at `/metadata`, once.
Retained unadmitted boundaries, including empty objects, receive Validation warnings. Where the
generic maximal-boundary traversal runs, it owns those reports; native Access validation does not
also emit its coarser holder scopes. Standalone native validation retains its holder reports, and
distinct contextual warnings remain independent. Ordering is
source slot, original document, wrapper path, exact pointer, code, phase and severity. Distinct
resource/context records survive; base and each varied mapping remain separate validations.
Projection-conflict fallback still checks finite root metadata and capability fields. A target
unadmitted-access-mode warning never authorizes copied, reordered or edited occurrences: failed
source-preservation proof adds a separate `UnadmittedField/Error/Generation` refusal while retaining
the original Validation warning. Output refusal preserves the actual resource/path and has no
invented source position.
Target warnings also do not authorize unselected Service relaxed names/prefixes or traffic
distribution values. These retain their target record and receive an exact
`UnadmittedField/Error/Generation` refusal. Stable EndpointSlice topology may be emitted only
as unchanged supplied evidence under the explicit preservation policies; edited/authored values
or failed proof receive the same output-boundary refusal. AuthoredIntent may still remove the
observed topology with its removal finding.

Unknown-field preservation warnings remain separate Generation records with actual source proof,
fully qualified nested List paths and the innermost wrapper association. Deduplication is confined
to the same operation phase. Invalid retained List metadata has a separate Generation refusal with
its actual immutable node position; target validation continues to have no source position.
Unresolved inline cron time zones remain syntax errors, independently of contextual warnings for
an unsupported separate timeZone field. Cumulative-budget tests locate their threshold within the
unchanged default production ceiling; a former fixed test search bound grants no product capacity.

Graph Analysis, decoder positions and existing collection preservation contracts stay distinct.

Source and artifact opt-in tokens remain different in-process roles. ProtectedOutput::Include is
an output policy, and ReviewedBlob/digests/JSON assertions confer no private-access or review
authority. A separately implemented host bridge must authenticate opaque handles, caller opt-in,
exact role/type, scope, operation lifetime, independent reviewer/accepted packet and an independent
decoder tree plus actual native resource/source-coordinate cohort. Native code does not self-issue
this external trust. Missing genuine authority is external `missing-independent-authority`.

Ordinary static projections never require runtime proof. Only a separately explicit supplemental
runnability demand lacking genuine authorized evidence/result yields external
`unsupported-runtime-context`. Neither external assertion is a native FindingCode or an original
successful semantic-negative result. No runtime-demand field is added to Request/GenerationOptions;
no cluster, filesystem probe, renderer preparation, apply or publication is authorized.

## Migration and evidence limits

Consumers may retain their i64 carrier but must handle fallible int32 acceptance, corrected complete
finding facets, concrete gate pointers and contextual warnings. Generation refuses native errors
and budget exhaustion without partial artifacts. Opaque/protected policies still govern output;
a warning is never positive native admission or runtime success.

The original CNPG 200m request with unchanged 100m limit is a negative Validation result at the
varied requests/cpu leaf. Retain it and the full positive CNPG obligation; use a separately reviewed
valid positive case rather than repairing the frozen negative into success. All original 22
requests, 180 tuples/90 cells, three graphs, full 30-source/29-edge/26-root CNPG evidence and 32
source closures remain pending. Local regressions, later complete repository gates and this
product correction cannot close those native/official-tool/whole-program obligations.
