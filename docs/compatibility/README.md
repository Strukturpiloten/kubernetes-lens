# Frozen Kubernetes compatibility contract

Issue #8 freezes expected native behavior for Kubernetes **1.20 through 1.37 inclusive**.
The checked-in contract is executable specification evidence. No Kubernetes minor, tool profile,
field or command has passed native implementation or runtime conformance yet. The public supported
minor list is empty. Issues #1–#4 and #9–#15 implement and execute these expectations.

The machine contract is authoritative:

- [Capability ledger](../../schemas/capabilities/kubernetes-1.20-1.37.json): exact GVK serving ranges,
  root pointers, finite helper-member lists, schema forms, native predicates, tool/runtime profiles,
  commands and pending evidence obligations.
- [Independent schema witnesses](../../schemas/capabilities/kubernetes-schema-witnesses.json):
  per-profile property shape hashes and separate defined/served GVK inventories.
- [Frozen contract anchors](../../schemas/capabilities/kubernetes-contract-anchors.json): exact reviewed
  command classes/argv, tool provenance and required graph relationships; operational updates cannot
  mutate these compatibility expectations.
- [Native scenarios](../../schemas/capabilities/kubernetes-native-scenarios.json): repository-authored
  positive artifacts and concrete invalid mutations for every required kind, including versioned
  PodDisruptionBudget selector expectations.
- [Feature cases](../../schemas/capabilities/kubernetes-feature-gate-cases.json): exact target minor,
  documented default, explicit enable/disable, value and context cells with pending native execution.

[ADR 0002](../decisions/0002-frozen-native-compatibility-contract.md) records the decision.

## Typed boundary and versions

There are 35 required built-in kinds, divided into the workload, networking, storage/configuration,
policy and extension cohorts in #9–#13. Each admitted API profile names its own serving range.
A definition in an OpenAPI document does not prove the API is served. Removal of an old API does
not authorize an apiVersion-only relabel. In particular, stable and beta PDB empty selectors have
different meanings. An absent selector remains different from an explicitly empty selector.

A selected root pointer admits only that field's source-backed shape and explicitly listed helper
members. It never admits an arbitrary prefix or every descendant of a shared helper. Unknown
kinds, members and future enum values retain source evidence and receive structured findings.
The ledger's explicit exclusions remain PreserveOnly. No future review obligation overrides an
exclusion. Every field/profile cell has its own evidence obligation; a successful generic resource
case cannot prove all its optional fields.

`TargetProfile` requires a numeric minor in the frozen interval and one explicit setting for each
finite gate name: documented default, enabled or disabled. Documentation defaults are expectations,
not observations of a cluster. Unknown/missing settings are invalid. Explicit settings for gates
that are not introduced or are stable/removed are invalid; stable feature availability continues
after gate configuration is removed.

Most optional gated fields use stable-only typed selection. Pre-stable values remain source-preserved
with unadmitted findings even when the caller enables their gate. Sidecars and StatefulSet PVC
retention explicitly select enabled alpha/beta profiles. Sidecar `restartPolicy` admits `Always`
only in init containers; regular containers cannot gain it. PodSpec restrictions apply to Pod and
all seven workload template paths, including CronJob's nested Job and Pod templates. JobSpec
restrictions likewise propagate into CronJob.

HPA ordinary metric types and positive minimum replicas remain selected independently of optional
ContainerResource and zero-replica branches. ProcMount `Default` remains selected; `Unmasked` is
excluded where its hostUsers context cannot be represented in this frozen field subset. Pod
runtime overhead and status/server metadata retain their observed origin; they are not inferred
from authored absence or materialized as desired-state defaults.

## Native processing and protected data

The networking contract corrects the previously missing `Service v1 /spec/loadBalancerClass`
feature binding using its already frozen official `ServiceLoadBalancerClass` source. Typed
selection begins at stable Kubernetes 1.24; schema presence in 1.21–1.23 does not admit it,
including with an explicitly enabled gate. Gate-control removal in 1.26 leaves the stable field
available. Its 54 exact version/default/on/off cases remain pending native evidence. No field,
value or API whitelist was expanded; Service type and update-context validation remain separate.

Inputs include individual YAML/JSON resources, YAML streams, generic Lists and registered typed
Lists. Preserve collection metadata/order, raw syntax evidence, source positions and explicit
null/absence distinctions. Malformed, duplicate, ambiguous and truncated inputs have actionable
findings; strings, numbers, quantities and IntOrString values never silently coerce.

The shared foundation contract uses immutable source evidence and a separate typed view. Native
edits apply only changed field/list paths, retain unknown descendants, and recompute identities,
references and graph caches after identity changes. Keyed lists preserve matching-item evidence;
atomic replacements that would discard unknown data require an explicit conflict resolution.
Generation is deterministic and reaches a parse/generate fixed point without replacing absence
with documented defaults.

Secret bodies, credentials, sensitive values and raw source bytes are private by default, including
Debug, diagnostics, JSON reports and subprocess stderr. Ordinary output must deny protected payload
serialization unless the caller explicitly selects private output access. Privacy tests use named
protected fixture values and verify their absence from all ordinary presentation paths.

Graph checks use only explicitly supplied identities and source-backed references. Missing or
ambiguous references remain findings. Storage provisioners, controller behavior, webhook trust,
runtime handlers and installed extension prerequisites cannot be inferred from offline schemas.

## Commands and external evidence

Offline chart/project rendering is caller-selected and bounded by explicit timeout, output and
memory limits. The command catalogue separates user-only exports, explicit offline renderers and
external disposable harness operations. KubernetesLens owns no live acquisition, apply, deployment,
registry publication or ambient cluster discovery.

Command evidence distinguishes every exact tool profile, source/generated artifact and relevant
install/upgrade mode. Helm cases cover explicit kubeVersion, repeated apiVersions, CRDs, hooks,
strict lint, local package/unpack/render/reparse and independent expected resources. Renderers
cannot download dependencies, use remote bases, enable plugins/post-renderers, invoke server
validation or inherit ambient kubeconfig. Lookup-dependent and nondeterministic output has named
findings rather than being claimed complete.

Standalone and kubectl-bundled Kustomize are separate profiles; the historical kubectl 1.20.15
bundle is 2.0.3 and the modern kubectl 1.37.0 bundle is 5.8.1. Native output acceptance uses matching
historical/modern kubectl flags only against explicitly owned, pinned disposable clusters. Kind
create/delete belongs solely to that external harness with explicit Podman provider, API readiness,
resource/time budgets and verified cleanup. None of these commands has been executed as native
conformance by this change.

Modern operational installers and checksums have one immutable BoxFerry owner. Historical tool,
node-image, schema and feature-documentation anchors are frozen inputs excluded from Renovate.
Updating operational dependencies cannot expand the Kubernetes ceiling or automatically advance
a conformance fixture. [Dependency policy](../dependency-policy.md) defines ownership and review.

## Custom resources and provenance

CRD definitions and admission webhook configurations are built-in native kinds. Their typed
support does not imply operator/controller behavior. Supplied CRDs establish custom-resource
identity, scope, served versions and schema links. The finite offline schema subset covers type,
required, properties, items, enum, basic scalar bounds, additionalProperties, nullable and
preserve-unknown-fields. Unsupported CEL, defaulting, conversion, admission callbacks and operator
reconciliation receive explicit findings. No callbacks or network discovery run.

The later official custom corpus must include CloudNativePG Cluster, Pooler, Backup and
ScheduledBackup and GrafanaOperator Grafana, GrafanaDashboard and GrafanaDatasource. Exact official
revisions, GVKs and licenses are pending #14; these names do not invent served versions or passing
operator evidence.

Schema shape and description excerpts derive from immutable Kubernetes source commits under
Apache-2.0 with [the upstream license](licenses/kubernetes-Apache-2.0.txt) and attribution retained.
Feature documentation is unchanged Kubernetes Authors source at an immutable website commit under
CC-BY-4.0; each record retains source URL, license, attribution, full bytes and SHA-256. Tool records
retain official version/commit, distribution/license, integrity and authenticity limitations.
Sources are schema/documentation evidence; native code must be independently authored, never
copied or mechanically translated from an oracle implementation.

## Checking the specification

The documentation phase runs the offline checker and its mutation/boundary regressions. Normal
checks use only repository files, not a network connection or a temporary research cache.

```console
python3 scripts/compatibility-ledger.py
python3 scripts/test-compatibility-ledger.py
```

An optional independent rederivation checks full upstream bytes before comparing property shapes
and description excerpts. Supply the exact cache filenames recorded in each schema profile:

```console
python3 scripts/compatibility-ledger.py --schema-cache /path/to/verified-schemas
```

These checks prove specification consistency and immutable source facts only. The future completion
gate requires every pending native cell to pass with exact tool/fixture/source/target provenance,
independent expected outcomes, privacy evidence and applicable runtime prerequisites. Pending,
unavailable, skipped and failed outcomes cannot count as supported behavior.
