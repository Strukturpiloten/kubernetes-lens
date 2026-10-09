# Workload helpers, validation intent and observations

The workload module owns concrete Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
ReplicationController, Job and both served CronJob wrappers, their registration, validation,
capabilities, gates and supplied facts. The common module owns the passive helper declarations
and sealed codecs. Its private children hold the 89 relocated helpers, seven passive specification
DTOs and `NativeTime`; the existing 22 common helpers keep their original definitions. Workload
public paths reexport the same types, so consumers can use shared helpers through
`resources::common` without importing a peer workload resource or defining duplicate DTOs.
Foundation metadata, quantities, selectors, presence and protection keep their existing owners.

The inline Pod CSI helper and flattened Pod volume shape do not authorize reusing them as a
persistent-volume CSI definition. Existing exact field, API and feature-gate admission remains
unchanged. Relocation adds no registration, whitelist member, renderer or runtime capability.
Unknown storage, explicit null/absence, protected values and source-free authoring use the same
single codecs and type identity through both public paths.

CronJob validation uses the caller-selected `NativeValidationIntent`. A syntactically valid inline
`TZ=` or `CRON_TZ=` schedule at the frozen 1.37 create boundary yields `NativeFieldInvalid` under
`Create`. `Unspecified` yields a `NativeContextRequired` warning at `/spec/schedule`, which also
survives generation. Imported old schedules, unchanged output, typed edits and explicit patches
cannot establish a server operation. No Update mode or old-state conformance is claimed. Complete
inline-zone and schedule syntax is checked before that context rule; malformed input and the
independent inline-zone plus `timeZone` restriction remain errors. Timezone recognition uses only
the reviewed embedded database, never host timezone state.

Environment names and nonempty prefixes use the witnessed legacy character grammar at the
1.20 floor. Legacy forms are accepted across the frozen range. Forms rejected by both witnessed
legacy and relaxed grammars are invalid. Relaxed-only printable ASCII forms receive a
`NativeContextRequired` finding at later targets because their default-policy evidence is not
admitted; generation retains that warning. No relaxed-validation gate or unseen minor default
is inferred. Optional absent/empty prefixes remain valid.

Declared empty container-port names remain unnamed; string probe ports require a valid nonempty
native name. Known contradictory volume sources are rejected even beside retained unknown
members. AzureFile volumes contribute an explicit required Secret reference in the established
namespace. Malformed label strings remain unavailable selector evidence rather than positive
membership facts.

Observation descriptors borrow the exact bounded object tree supplied by core for the original
or effective projection. They do not reencode a known-only view. Exact controller/Job PodTemplate,
CronJob JobTemplate/nested PodTemplate, full StatefulSet PVC-template and generic ephemeral-volume
claim-template metadata paths are described independently. Only the full StatefulSet claim carries
nested status observation. Standalone Pod `ephemeralContainers` has a separate subresource role;
core checks the reviewed stable 1.25 boundary and leaves earlier input unadmitted/opaque.
Unsupported template status and template ephemeral containers are preserved, never silently
stripped. Core checks descriptor budgets, GVK/path/version admission, provenance and output policy.

Default authored-intent generation removes only reviewed observations with exact findings.
Explicit observation preservation retains them under the same opaque/private-output checks.
Reordered lists and explicit patches use effective coordinates; original evidence and source bytes
remain immutable. Source-preserving output and successful offline library tests do not prove API
acceptance, controller behavior or Kubernetes runtime conformance. The primary owns integration,
public API documentation, remaining core corrections and the complete gate.
