# Configuration and storage resources

The configuration/storage cohort decodes the Kubernetes 1.20–1.37 `v1` ConfigMap, Secret,
PersistentVolumeClaim and PersistentVolume resources, and `storage.k8s.io/v1` StorageClass. The
typed values retain explicit presence, nulls, unknown descendants and source evidence through the
shared native codec. This is offline source handling; it does not query clusters, provision storage,
assert installed drivers, copy volume data, or prove API-server conformance.

ConfigMap text and binary maps remain distinct and protected. Text values use `Protected<String>`;
explicit `ExplicitSourceAccess` is required to inspect their contents. Ordinary typed Debug and
diagnostics redact text, and default generation refuses both protected maps. Secret `data` remains protected decoded bytes and
`stringData` remains a separate protected text map. String-data values take precedence for equal
keys in Kubernetes write semantics, while both authored members are retained for faithful
source-preserving generation. ConfigMap and Secret values stay redacted in ordinary Debug and diagnostics, and
generation requires explicit protected-output authorization.

PVC claims use the shared claim-spec helper. PVs use a distinct persistent-volume source shape,
including a CSI source that is not the Pod inline CSI shape. CSI `controllerExpandSecretRef` is
admitted only when `ExpandCSIVolumes` is stable (1.24 onward); the earlier beta default does not
meet the frozen stable-only predicate. Storage references are emitted only
from explicit authored names and are resolved against the supplied resource set. A named external
provisioner or CSI driver is represented as an external prerequisite; it is not evidence that the
driver is installed or operational.

Portworx PV fields remain unadmitted while their gate/context subset is unresolved. They are kept
only as supplied source evidence; source-free Portworx generation is unsupported.

PV and PVC `access_modes` use the opaque shared `AccessModes` holder. Source-free construction
accepts only finite `EstablishedVolumeAccessMode` values, preserving caller order and duplicates.
Copied partial supplied holders cannot authorize source-free authoring; explicit preservation
requires the unchanged sequence at its original supplied destination. Unsupported-mode findings
remain distinct from malformed field-shape errors.

Access-mode admission is bounded to `ReadWriteOnce`, `ReadOnlyMany`, and `ReadWriteMany` under the
separate shared access-mode contract. Unsupported source values remain source-backed evidence and
cannot establish typed graph semantics. StatefulSet claim templates remain workload-owned; their
shared claim fields do not register standalone PVC resources.

The exact field/profile inventory remains in the frozen compatibility ledger. Native runtime and
API-server evidence cells remain pending until the repository completion gate executes them.

Persistent-volume node affinity uses the native `nodeAffinity.required.nodeSelectorTerms`
shape, including `matchExpressions` and `matchFields`; the Pod affinity spelling is not
substituted. Supplied and authored output checks reparse deterministic JSON-compatible
YAML and compare the typed selectors and generation fixed point at both target endpoints.
Secret-identity relationships and external CSI driver prerequisites are asserted separately:
rejecting a malformed Secret reference does not erase the explicitly declared driver.
These regression checks are offline library evidence, not storage or API-server conformance.

Storage roots capture unknown fields through the inherited `FieldDecodeContext` operation.
Production validation streams unknown scopes through `UnknownScopeVisitor`, with no eager
collection or standalone fallback; work/payload exhaustion and callback refusal stop traversal.
Private tests compare all five roots and partial PV/PVC descendants with independently expected
scopes. Public finite-authoring and supplied-preservation tests inspect typed access modes and
reparse generation at both 1.20 and 1.37, including deterministic output fixed points.

These checks cover the selected offline cohort only. The original #11 completion scope and
the machine capability/native evidence obligations remain subject to independent review and
the primary complete gate; no driver, binding, provisioning or native acceptance is established.

The static validator now checks ConfigMap key syntax and the 253-byte limit, exact text/binary
key overlap, and the combined UTF-8 text plus decoded binary body size. Exactly 1 MiB is allowed.
Secret checks use the effective `stringData` overlay without changing either authored map: each
key contributes once to the same size ceiling. Basic-auth requires at least one username/password
key (present-empty passes); TLS requires both keys (present-empty passes); SSH requires nonempty
private-key bytes. Service-account-token Secrets require the nonempty service-account annotation,
without requiring controller-produced token data. Custom, Opaque and bootstrap types receive no
invented required-key checks.

Docker Secret checks interpret the effective private bytes as JSON: object and null roots pass;
other roots, malformed input, missing keys and empty input fail. Work and conservative scratch
charges precede decoding, and findings contain no private JSON or decoder error text. This is a
bounded shape check using the repository JSON decoder. Go decoder parity for extreme numbers,
duplicate keys, recursion and other decoder details remains unestablished; registry access and
credential validity are not checked.

PVC checks require explicit `NativeValidationIntent::Create`. They require selected nonempty
access modes and positive `requests.storage`, validate supplied class names and selected label
selectors, and require data-source name/kind. An absent or empty data-source API group requires
`PersistentVolumeClaim`; grouped custom kinds remain allowed. Nonempty data-source API-group
syntax is checked beginning at 1.29. Positive fractional storage passes this sign check; native
rounding/capping, byte-size interpretation and actual provisioned size remain unresolved. Extra
resource keys and request/limit ordering do not acquire Pod rules. `Unspecified` intent receives
`NativeContextRequired` at `/spec` instead of guessed Create or update-baseline results. The local
intent API has no Update variant, and immutable update comparisons remain unresolved.

StorageClass provisioners are checked as qualified names after lowercase conversion for checking
only; supplied spelling is retained. Parameters permit arbitrary nonempty keys, at most 512
entries and at most 262,144 UTF-8 key-plus-value bytes. Topology checks reject absent/empty values,
duplicate values or keys, and semantically duplicate terms independent of expression/value order.
They accept arbitrary unique topology value strings and an empty outer list. A single empty term
is rejected under the source-composed StorageClass wrapper behavior. Borrowed scratch maps and
ordered signatures avoid a quadratic pair-comparison loop. All scans, private decoding, lookup
comparisons and normalization share the operation budget; exhaustion remains a pathless
`LimitExceeded`, separate from field invalidity.

Independent offline fixtures cover these boundaries, source-free and supplied generation refusal,
protected-value redaction, direct static-check budget exhaustion, and output reparse/fixed points
at 1.20 and 1.37. Unknown descendants retain source evidence and do not bypass other known invalid
fields. These checks do not establish native acceptance, immutable updates, live binding,
controllers, installed drivers or provisioning.

The expectations were researched against immutable Kubernetes implementation witnesses, including
[v1.20.15 core validation](https://github.com/kubernetes/kubernetes/blob/8f1e5bf0b9729a899b8df86249b56e2c74aebc55/pkg/apis/core/validation/validation.go),
[v1.37.0 core validation](https://github.com/kubernetes/kubernetes/blob/f54c212e3a2f75d674b717a9b29052b20b60aefc/pkg/apis/core/validation/validation.go),
[v1.37.0 storage validation](https://github.com/kubernetes/kubernetes/blob/f54c212e3a2f75d674b717a9b29052b20b60aefc/pkg/apis/storage/validation/validation.go)
and the [1.29 boundary](https://github.com/kubernetes/kubernetes/blob/3f7a50f38688eb332e2a1b013678c6435d539ae6/pkg/apis/core/validation/validation.go).
The Apache-2.0 witnesses were inspected as local research, not executed, copied, mechanically
translated or redistributed as fixtures. The authenticated 66-record source receipt and the
bounded specification contract are retained in the primary handoff evidence; no native command
was run for these static expectations. Implementation and test evidence remains subject to
independent review and the primary complete gate.

## Corrected graph, selector and profile boundaries

ConfigMap facts establish text-only keys for environment references and the disjoint text/binary
union for mounts. Each supplies the exact original map/key path; no payload appears in graph facts.
Absent valid maps are known empty, while malformed keys, invalid map shapes and text/binary overlap
cannot establish positive membership. Both domains share the inherited projection budget.

PVC selector validation checks known label grammar and operator/cardinality constraints before
reporting retained unknown descendants. Unknown evidence never suppresses known-invalid fields.

ConfigMap and Secret `immutable` remain source evidence outside the stable-only selected profile at
1.20, including authored false, true and null and an explicitly enabled beta control. Generation
refuses that target selection. Typed admission begins at 1.21; documented defaults preserve supplied
values through 1.37. Explicit toggles of the removed control from 1.25 remain invalid profiles.
No immutable update, stored-object baseline or controller semantics are inferred.

## PersistentVolume static Create checks

PV validation requires explicit Create intent and a spec with nonempty selected access modes,
exactly one positive storage capacity and exactly one supplied volume source. The source union
counts preservation-only Portworx evidence. Its exactly-one rule deliberately rejects a
HostPath/FlexVolume pair even though the researched native helper has a union-counting exception;
this product boundary is stronger than that observed helper behavior.

The 21 selected source shapes have bounded required-field, path, integer-range, exclusive-member,
identifier, options and reference checks from the independent PV specification. These checks
retain authored scalar omissions and nulls; they do not invent native default values. Relative
HostPath/local paths are permitted, NFS requires a POSIX absolute path, and selected POSIX parent
segments are rejected. Backslash path semantics and adversarial Quobyte transport addresses retain
explicit context findings. CSI driver spelling is preserved while checking its lowercase domain.
Checked CSI references use DNS-label names through 1.24, a conservative label subset at 1.25–1.26
with dotted-name context findings, and DNS-subdomain names from 1.27. The retained native helper
does not check nodeStageSecretRef; the library does not invent that native restriction.

Supplied node affinity requires nonempty required terms, permits an empty individual term, and
checks expression keys/operator arity and metadata.name field selectors. Local sources require
node affinity. Invalid expression label values from 1.33 retain an option-context finding rather
than an assumed native verdict; the researched PV strategy options were not authenticated.
Update baselines, plugin availability, driver installation, binding, scheduling, native quantity
rounding/overflow and full server acceptance remain outside these static Create checks.

Secret key facts use the same exact-map admission boundary as ConfigMap key facts. A repeated key
uses its explicit `stringData` occurrence; other keys retain their `data` occurrence. Independently
expected env and mount references resolve at both target endpoints. Missing keys remain MissingKey;
malformed suppliers remain unsupported, and graph Debug reveals no protected payload.

PVC `volumeName` and `storageClassName` retain absent versus explicitly empty values in typed
input and generated output. Empty names express unbound or classless intent and do not create
object references; nonempty names retain supplied/missing object resolution.
