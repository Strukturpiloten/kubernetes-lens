# Native access, scaling and policy checkpoint

This cohort supplies original native declarations for 13 kinds and 18 exact served APIs. The
frozen schema selection contains 176 root-pointer occurrences and 64 helper definitions with
202 selected member occurrences. Fifty-five helpers belong to this cohort; nine remain shared
foundation/common dependencies. Native server, controller, permission, scale and enforcement
conformance are not established by these offline checks.

The selected closure comes from the issue 12 inventory projection of the authenticated
Kubernetes 1.20–1.37 ledger. Its inventory SHA-256 is
`79e103afebe93cae395d266336d5e64a88a0c10e68002b84777dcd834e9fd7a1`; the source ledger SHA-256 is
`747adc51d5646a1977fd1a6fa0d022414cdab72520d31470696aaf4e5b0d2c08`. Declarations and semantic
checks were implemented originally from that selection, without copying oracle implementation
source. Existing repository compatibility provenance remains canonical. A narrow independent
source verification for historical HPA beta1 conversion/types at immutable Kubernetes 1.20 and
1.24 commits is recorded in [the beta1 evidence receipt](evidence/access-beta1-conversion.json),
including exact host `gh` acquisition commands, source hashes, licenses and inspection limits.
It establishes source facts only, not native conformance.

The active ledger is `f071be3cb41aaee879ba0f4b693850c0609d45f872b2439f236b6acb1cd7875f`.
Its networking-only correction leaves this cohort's field selection unchanged. Shared admission
evaluates canonical root/helper gate predicates, including finite gated values and presence;
binding variants remain evidence samples. Ordinary HPA metrics are unconditional, container
metrics require their admitted stable stage, and either unhealthy-Pod eviction policy value
requires the field's stable stage. Native union/enum validity and API/field availability are
independent checks. Numeric HPA zero and Job `FailIndex` retain their distinct gate predicates.

| Resource family                                      | Served APIs                  | API range |
| ---------------------------------------------------- | ---------------------------- | --------- |
| Namespace, ServiceAccount, ResourceQuota, LimitRange | v1                           | 1.20–1.37 |
| Role, RoleBinding, ClusterRole, ClusterRoleBinding   | rbac.authorization.k8s.io/v1 | 1.20–1.37 |
| HorizontalPodAutoscaler                              | autoscaling/v1               | 1.20–1.37 |
| HorizontalPodAutoscaler                              | autoscaling/v2               | 1.23–1.37 |
| HorizontalPodAutoscaler                              | autoscaling/v2beta1          | 1.20–1.24 |
| HorizontalPodAutoscaler                              | autoscaling/v2beta2          | 1.20–1.25 |
| PodDisruptionBudget                                  | policy/v1                    | 1.21–1.37 |
| PodDisruptionBudget                                  | policy/v1beta1               | 1.20–1.24 |
| PriorityClass                                        | scheduling.k8s.io/v1         | 1.20–1.37 |
| RuntimeClass                                         | node.k8s.io/v1               | 1.20–1.37 |
| RuntimeClass                                         | node.k8s.io/v1beta1          | 1.20–1.24 |
| PodSecurityPolicy                                    | policy/v1beta1               | 1.20–1.24 |

## Native values and preservation

Every concrete root converts into the sealed `AuthoredResource` factory. Public native fields
use `Presence`, including absence and explicit null; String access remains explicit native-data
inspection. Complete private snapshots use the shared authoring limits and generated provenance.
Default Debug and findings omit private values. Unknown root/helper/selector descendants are
retained with findings and require explicit protected artifact inclusion. An admitted object
never admits an unknown child by prefix.

Separate versioned HPA, PDB and RuntimeClass roots retain their actual API spelling. APIs are
never relabeled as a conversion. API removal takes precedence over field/gate checks, including
historical PSP removal in 1.25. Finite field capability paths follow only selected helper members;
source-supported but unselected descendants remain preserved/unadmitted.

## Supplied relationships and selected checks

Namespace labels remain declarations, and explicit namespace fields produce supplied membership
references. Recognized Pod Security Admission labels are checked as declared values within the
finite profile; they never prove enforcement, defaults or admission by a server. Unreviewed
label/version semantics produce unadmitted findings. Namespace lifecycle fields remain retained.

ServiceAccount automount and secret/image-pull references remain explicit. No tokens or remote
credentials are obtained. RBAC rules distinguish namespaced/cluster non-resource URL restrictions.
Role references, ServiceAccount subjects and aggregation selectors use supplied resources and
exact paths. User/Group subjects are external identities. Aggregated ClusterRole rules remain
source/desired data; selector membership is not effective permission or controller reconciliation.

HPA checks preserve version-specific metric unions, required members, replica bounds and scaling
behavior. Desired quantities retain selected sign/zero checks without measurements or conversion.
Target kind/name use native path-segment rules. From 1.34, explicit Create validates target APIs
using the native permissive group/version split: grouped targets may have an empty version, and
ReplicationController permits the core group. Unspecified operation context retains an actionable
finding where old-object grandfathering could matter. Scale-subresource and controller availability
remain external prerequisites, not invented admission rules.

PDB values retain exact integers/percentages. Both budgets together are invalid; omitting both
remains legal. Null and absence stay separate. An explicitly empty policy/v1beta1 selector selects
no Pods; an explicitly empty policy/v1 selector selects supplied Pod objects. Controller templates
are excluded. Missing/malformed candidate evidence remains partial, never a positive completeness
claim. Gates and versions still control unhealthy Pod eviction policy.

ResourceQuota desired hard quantities/scopes stay separate from observed status. Scope checks
cover the finite native names, independent conflicts within each collection, selector cardinality and
standard hard-resource applicability. Custom and count keys bypass the scope-resource helper.
CrossNamespacePodAffinity follows the reviewed PodAffinityNamespaceSelector gate in 1.21–1.23 and
is unconditional from 1.24; VolumeAttributesClass quota scope starts at 1.33. Population, aggregation
and enforcement remain external prerequisites.

LimitRange checks supplied min/max/default/defaultRequest order, non-overcommit default equality,
ratio lower bounds, Pod forbidden defaults and PVC storage bounds. Native comparisons are restricted
to nonnegative integral values no larger than i64::MAX; fractional, negative and capped quantities
remain preserved with explicit unresolved-semantics findings. Native ratio ceilings use rounded
int64 and floating arithmetic and remain unadmitted. Missing Container defaults are not synthesized.
These findings distinguish exact supplied intent from native rounding/defaulting and Pod admission;
no quota or LimitRange enforcement is inferred.
PriorityClass accepts signed priorities, checks reserved names/values and keeps preemption policy
independent. RuntimeClass validates its handler separately from metadata identity, retains overhead
and scheduling, and emits an external runtime prerequisite instead of availability proof.
Historical PSP retains selected strategies, ranges, path prefixes, flags, capabilities and volume
strings. Reviewed rule literals and supplied ID ranges are checked: zero is legal, and ranges must
remain ordered within signed 64-bit bounds. Only runAsGroup imposes rule-dependent range presence;
SELinux MustRunAs does not itself require options. Capability names have no whitelist: conflicts use
case-sensitive literal equality, and allowed `*` requires an empty required-drop list. `ALL` is not
expanded. Volume/sysctl/proc-mount strings remain explicitly unadmitted. No PSA conversion or
enforcement equivalence exists.

These finite PSP expectations use the authenticated Kubernetes v1.20.0 inspection commit
`af46c47ce925f4c4ad5cc8d1fca46c7b77d13b38`, `pkg/apis/policy/validation/validation.go`,
SHA-256 `e62f41e7d469872ce944c9f7b0c4eb00d79757dc866959b339e129e59d058ce4`, read from the
primary's source manifest. An independently retrieved official validator at the exact 1.20.15 floor
commit `8f1e5bf0b9729a899b8df86249b56e2c74aebc55` is byte-identical, including that SHA-256;
the primary recorded this static comparison in its authenticated receipt. This is source inspection
evidence only: no native runtime ran, and it does not resolve the ephemeral volume type inconsistency.
Kubernetes source is Apache-2.0; no oracle implementation is copied or redistributed. The checks and
independent expectations are implemented originally.

## Integration and evidence limits

Access validation, label facts, references and protected-field scans share the caller's inherited
processing session. Work and retained payload for copied labels, identities, native diagnostic
scopes, privacy patterns and paths are admitted before traversal or allocation. Exhaustion is
sticky: later fields cannot reset the counters or emit positive facts or references. Unknown-field
diagnostics stream the native containing scopes and stop when the report or processing budget is
exhausted; no complete intermediate scope set is built. Shared metadata and selector diagnostic
semantics remain unchanged.
Reference sink exhaustion is checked before resource-specific dispatch, including eager PSP
runtime-class path enumeration, so a terminal namespace reference permits no later reservation.

If a protected-field scan cannot finish, an empty protected path conservatively protects the whole
resource. This privacy sentinel is separate from the single fixed, pathless processing-limit
finding. These limits account for conservative native work and payload, not process RSS or every
allocator operation, and establish no server permission, scaling or enforcement equivalence.

The primary owns naming corrections, source/effective identity, root observation roles, supplying
provenance, graph completeness and cumulative budgets. Root status is reviewed only for Namespace,
HPA, PDB and ResourceQuota. Arbitrary status, Namespace lifecycle data and aggregated ClusterRole
rules are not universally removable observations.

The initial dependency snapshot remains historical evidence. The current candidate integrates the
merged shared-processing foundation; historical source/schema projections and observation receipts
remain immutable independently of current source/ledger bindings. Independent access tests exercise
real roots/Lists, source-free authoring, round trips, versions/gates, unions, selector distinctions,
negative cases, effective edits, privacy and attribution. Focused checks never replace the complete
local gate; native API/runtime acceptance remains separately required by #2 and #7.

## Immutable native witnesses

The finite HPA, quota, LimitRange and empty-toleration rules use authenticated official Kubernetes
sources for every frozen minor and the exact 1.20.15 floor. Their compact provenance receipt is
[evidence](evidence/access-native-specification.json). The machine-readable
[code ledger](../schemas/capabilities/access-code-evidence.json) links concrete roots, selected fields,
checks, independent test names and remaining context/arithmetic boundaries. These are static source
and local-code obligations; API-server, renderer and runtime evidence remain pending in #2.

Selectors with unknown neighbors retain `UnadmittedField` and an explicit unsupported graph
relationship. Explicit opaque and protected-output policies can preserve their original values.
Foreign-group ServiceAccount subjects and invalid role references cannot resolve to same-name core
identities. RuntimeClass toleration uniqueness compares the raw key, operator, value and effect;
`tolerationSeconds` does not distinguish duplicates. Absent and empty operators collide; explicit
`Equal` remains distinct without a defaulting witness.

Quota and overhead integer quantities are checked only when exact nonnegative milli-units fit
`i64::MAX`. Finer fractions, rounded/capped arithmetic and overflow retain unadmitted semantics.
RuntimeClass hugepage sizes, divisibility and companion CPU/memory rules remain unadmitted.
Qualified extension LimitRange types survive with a finding; malformed and unqualified unknown
types are invalid. Copying duplicate-type bookkeeping reserves inherited payload first.

Historical PSP checks include escalation conflicts, raw runtime-class name and wildcard rules,
nonempty FlexVolume drivers, and CSI names under the native lowercase DNS envelope and 63-byte
limit. Accepted uppercase CSI spelling remains unchanged in typed source. The frozen stable-only CSI
policy does not admit historical PSP CSI output: CSIInlineVolume becomes stable at 1.25, when PSP
is removed. An explicitly enabled beta gate does not override that field-selection boundary.
