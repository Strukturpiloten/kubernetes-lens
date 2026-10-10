# ADR 0013: Native naming and exact source identity

Status: Accepted

Refines ADRs 0003–0005 and 0009 with the remaining shared naming contract from #9/#12,
implemented under #36. The accepted versionless collision key and all frozen kind/API/field
boundaries remain unchanged. ADR 0012 belongs to the independently integrated renderer work.

## Decision

Acquire exact bounded `String`/`Presence<String>` metadata without imposing a universal DNS
name grammar. Keep one live Metadata authority, original source evidence, explicit namespace
absence, and exact case/Unicode spelling. Invalid naming does not replace a built-in root with
an unsupported-kind document. Wrong field shapes remain fallible with fixed field findings.
Public native fields remain directly inspectable; Debug, automatic findings and graph summaries
remain redacted. Broader names and owner names require explicit protected output when their
spelling lies outside the previous DNS-subdomain envelope; raw artifacts still require their
separate artifact access token. No source normalization or generated name is stored.

Use one private shared checker selected by exact admitted GVK, target minor and caller intent.
Ordinary roots use DNS1123 subdomains. Namespace uses DNS1123 labels. Service uses the frozen
DNS1035 label selection; the upstream relaxed variant remains unadmitted. StatefulSet changes
from subdomain through 1.26 to label from 1.27. RBAC uses full path segments; PDB's generated
prefix uses the distinct path-prefix rule. CRD names and prefixes also require exact supplied
plural/group equality. No name rule admits an unknown field or removed API.

CronJob's 52-byte concrete-name bound applies under explicit Create. Unspecified operation
retains a NativeContextRequired warning; a prefix supplies no final concrete length. Historical
batch/v1beta1 remains available through 1.24. ReplicationController from 1.35 does not receive
the legacy direct-prefix callback. DNS prefixes use comparison-only native specification facts,
including the terminal two-byte operation; authored values remain intact. The historical lone
ASCII dash is handled safely, without reproducing an upstream slicing hazard or claiming native
validity.

Add the public FindingCode variant NativeNamingUnverified for that compatibility hazard. Its
fixed remediation explains that Create does not establish compatibility and identifies an
explicit concrete name without the hazardous prefix or a reviewed safe profile as alternatives.
The Finding struct and public identity fields keep their existing shape. Consumers with exhaustive
FindingCode matches add this variant. NativeContextRequired remains reserved for genuine missing
operation/defaulting/generation context.

Target graph projection uses the same checker with Unspecified intent. Invalid or unverified
selected naming enters the existing failed-projection path and cannot supply native facts or
positive target resolution. No-profile graph equality remains supplied spelling evidence, not
native naming validation. Collision keys exclude served API version, retain established explicit
namespace and concrete name, and never derive an identity from generateName. Owner names keep
their native nonempty constraint without a universal DNS prefilter; target-specific, UID, scope
and ownership checks remain separate.

## Evidence and limits

Repository-owned native-naming contract, independent cases and source witness manifests under
schemas/capabilities record all 35 kinds/48 API profiles/18 minors and immutable source provenance.
They derive from the previously independently reviewed research, including the primary correction
to PDB versionless collisions and CronJob beta removal at 1.25. Original research hashes and old
ledger anchors are retained as historical records. Oracle source is not bundled or translated;
Apache-2.0 source inspection establishes specification facts only.

Independent code regressions cover 125 corrected cases and all 35-kind/profile dispatch, source
acquisition, authoring, edits, generation privacy, exact identities and target reprojection. These
are offline library obligations. API-server/defaulting, old-object Update validation, native name
generation, controllers, storage/backend limits and runtime conformance remain pending under #2.
No field, gate, kind or supported Kubernetes minor is added by this decision.

Undeclared GVK naming is explicitly unverified. The shared validator emits fixed
NativeNamingUnverified evidence at the retained metadata name or generated prefix; it neither
infers a built-in grammar nor declares custom names universally invalid. Selected generation
retains this warning and existing privacy/opaque authorization rules. Ordinary target Owner,
Exact and native fact relationships from or to such identities cannot establish positive evidence.
Standalone CustomDocumentCheck::Checked and graph Bound remain schema-only outcomes and do not
admit naming. Only the sealed SuppliedCustomResourceVersion relationship, after the existing
current descriptor recheck, and the exact External Operator prerequisite retain their narrow
semantics. Missing, ambiguous, stale or invalid descriptor suppliers gain no exemption. No-profile
supplied equality and public custom enum/String/Presence contracts remain unchanged.
