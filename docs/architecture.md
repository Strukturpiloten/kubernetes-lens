# Architecture

KubernetesLens owns native Kubernetes formats and cannot depend on BoxFerry product crates or
other Lens libraries. BoxFerry owns orchestration, neutral types and semantic adapters. Native
implementation is original; external source facts retain provenance, integrity and licenses.
Shared development tools remain separately pinned infrastructure, not application dependencies.

The offline foundation separates bounded syntax/source evidence (`parser`, `syntax`, `source`),
identities/metadata/collections (`model`), reviewed target facts (`capability`), sealed native
codecs (`registry`, `resources`), supplied-only resolution (`graph`), explicit read-only input
acquisition (`acquisition`), and private in-memory generation (`generation`). `value` contains
exact quantity, presence, protected-value and selector primitives; `diagnostic` exposes only
fixed safe outcomes and private source paths.

Every resource keeps immutable original source/arena/evidence independently of live typed values
and explicit edits. Current identity is computed rather than duplicated in a mutable snapshot.
Generation applies structural deltas to original values and refuses unknown-data loss, unavailable
target fields/APIs, API relabeling, and unauthorized private output. There is no filesystem output,
renderer execution, live cluster acquisition, mutation, or ambient namespace discovery.

The workload cohort registers nine API roots for eight kinds; shared native helpers live in
`resources::common`. Typed workload validation, facts, observations and generation use the
same sealed registry and bounded core projection. The other cohorts and custom documents
remain preservation-only with structured findings. The frozen compatibility ledger and all
named native conformance cells remain pending; focused code tests are separate evidence. See
[ADR 0003](decisions/0003-offline-native-foundation.md) and the
[foundation integration contract](foundation-api.md), supplemented by
[ADR 0004](decisions/0004-native-authoring-facts-observations.md) and [workload limits](workloads.md).
