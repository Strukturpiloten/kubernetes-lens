# Official-corpus native acceptance

Issue #14's native driver consumes the reviewed official receipt and the local unpublished library.
It does not discover input, invoke renderers, read a cluster, discover credentials, apply output or
execute generated commands. It launches only our explicitly supplied, hash-authenticated original
`official_native_probe` executable. The executable receives one explicit bounded JSON request and
returns counts, fixed outcomes and finding-code histograms. Neither source values, resource names,
field paths, generated resources nor child logs appear in its public receipt.

The source candidate manifest, binary and official inventory have separate expected SHA-256
arguments. The driver verifies each against its supplied file, authenticates every inventory asset
(including retained license companions), and binds each request to those identities, the selected
target, explicit namespace/preservation/protected-output choices, source hashes, a fresh per-invocation nonce and independent
expectations. An identical response for a different target or candidate fails binding checks.
The candidate/binary arguments do not prove that compilation used that source: the primary agent
must separately retain authenticated build provenance against the exact reviewed source snapshot.
The complete gate and independent review remain required. The Cargo integration target also runs
the original Python `--self-test` entrypoint with an explicit interpreter path and sanitized environment
on Linux, so `--all-targets` enforces both sets of pure contracts. Other platforms lack this Linux
fixture-harness evidence; that limitation is not a skipped compatibility success.

## Cases and evidence boundaries

| Case                                  | Independent selected checks                                                                                                                | Remaining evidence                                                        |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| Grafana documentation YAML            | PVC access/size, Deployment labels/fsGroup/mount, Service port/selector/type; exact supplied PVC and selected template/named-port subjects | Mutable sample image; API/runtime                                         |
| Immich official local PVC             | Typed PVC, exact claim name, ReadWriteOnce and 10Gi                                                                                        | Rendered workload relationship, storage/runtime                           |
| Immich official CNPG inputs           | Exact Cluster/Database fields and database-to-cluster source spelling preserved                                                            | Extension schema/explicit-reference evidence, controller/database/runtime |
| CloudNativePG official secret example | Exact CR references; typed Secret type and protected base64 values retained                                                                | Extension schema/explicit-reference evidence, controller/runtime          |
| Grafana Operator credentials example  | Typed namespaced Secret and protected values; exact Grafana configuration and Secret-key reference source spellings                        | Extension schema/explicit-reference evidence, controller/runtime          |
| CloudNativePG release manifest        | Supplied ServiceAccount, ClusterRoleBinding role and subject, Deployment service account; exact selected CRD identity fields retained      | Typed CRD/webhook acceptance, API/runtime                                 |
| Grafana Operator release manifest     | Supplied ServiceAccount, ClusterRoleBinding role and subject, Deployment service account; selected CRD kind retained                       | Typed CRD acceptance, API/runtime                                         |
| Forgejo official chart                | Explicit pending cell; selected inventory has no official raw manifest form                                                                | Official rendering and subsequent native/API/runtime acceptance           |
| Nextcloud AIO official chart          | Explicit pending cell; selected inventory has no official raw manifest form                                                                | Official rendering and subsequent native/API/runtime acceptance           |

Expectations are authored in `scripts/fixtures/native_acceptance.py` from the pinned source
observations in `fixtures/official/expected.json`, supplemented by direct inspection of the exact
selected source bytes. No expectation is harvested from KubernetesLens generated output. Source
resource indices identify immutable source order; output identity reconciliation handles deterministic
sorting independently. Graph checks name exact original supplying resource indices and object or
template subject classes, rather than accepting any resolved edge of the same cardinality.

The built-in codec count measures only the delivered workloads/networking/configuration/storage/
access roots that the probe explicitly downcasts. It does not establish admitted fields or target
compatibility for every such object; findings remain authoritative. Extension/custom documents are
never counted as understood merely because their values survive generation.

Native JSON and YAML generation are repeated and reparsed. Independent assertions check selected
fields; source List wrappers are retained and separately assertable. Reprojection comparisons match
original identities, while YAML regeneration additionally checks preserved wrapper structure. These
are deterministic preservation checks, separate from independent semantic expectations. Unknown
fields require selected preservation and retain actionable findings. Historical driver receipts predate
the #33 correction, when selected preservation could omit a native finding for an unadmitted root
member. Current native generation reports these top-level members with actionable findings. The
driver retains the actual default refusal and exposes `selected-unadmitted-source` as separate source
evidence; it does not fabricate a native `unadmitted-field` result or admission. Protected output requires its
own consent, even for known public example credentials. The default generation result is recorded
separately. An unavailable API, exhausted operation, parse/decode error or failed assertion is a
refusal/failure, never a skip that counts as success.

## Explicit invocation

Build the local example only in the coordinated validation slot:

```sh
cargo build --locked --release --example official_native_probe
cargo test --locked --test official_native_probe
python3 scripts/fixtures/native_acceptance.py --self-test
```

Use the optimized example for the large operator manifests. A debug build may reach the unchanged
per-invocation deadline; that outcome is a refusal, not completed corpus acceptance. Authenticate the
binary from `target/release/examples/official_native_probe` and retain its exact source/build binding.

The actual corpus invocation requires all inputs and consent options; substitute the independently
verified digest values and paths from the primary agent's retained receipts:

```sh
python3 scripts/fixtures/native_acceptance.py \
  --definitions /private/reviewed-definitions \
  --inventory-sha256 VERIFIED_INVENTORY_SHA256 \
  --corpus /private/materialized-official-corpus \
  --probe /private/authenticated-official-native-probe \
  --binary-sha256 VERIFIED_BINARY_SHA256 \
  --candidate-manifest /private/reviewed-source-manifest.json \
  --candidate-sha256 VERIFIED_SOURCE_MANIFEST_SHA256 \
  --target-minor 37 --namespace fixture-native \
  --documented-gate-defaults --preserve-unknown yes --protected-output include
```

The supplied definitions directory contains `inventory.json`; its digest is the canonical reviewed
`fixtures/official/inventory.sha256` value. Materialization uses the reviewed receipt/materializer
first and retains source/license/provenance notices. The driver neither fetches nor redistributes
assets. Keep the corpus, candidate/build receipts and captured machine receipt private. Selected
AGPL documentation-derived YAML and fetch-only fixtures remain excluded from the crate package;
this harness does not establish redistribution permission or change upstream license/provenance.

The Python runner is Linux-only: directory-descriptor no-follow reads, procfs execution of an immutable sealed
binary snapshot, independent pipe caps, a private child process group and resource ceilings are
required. There is no shell, inherited environment, executable PATH search or subprocess selected
by corpus content. Bounds are 4 MiB inventory/candidate metadata, 8 MiB per asset, 32 MiB aggregate
source, 12 MiB request, 1,024 resources/wrappers, 128 MiB binary, 256 KiB response, 4 KiB stderr, 60 seconds CPU, 1 GiB address
space and 64 descriptors. A caller-selected wall deadline must be positive and at most 90 seconds.
Timeout/output overflow kills and reaps the owned process group; stderr is never published.

A zero driver exit status means that its selected static cases passed. Its overall receipt still
says `static-driver-executed-programme-incomplete`: renderer, API and runtime cells remain pending.
The separate [custom-document acceptance](custom-acceptance.md) completed its seven selected
CloudNativePG/Grafana kinds at targets 1.20 and 1.37 against reviewed local source. Those runs
verified supplied CRD bindings, supported-subset checks, explicit unsupported-schema outcomes,
external operator prerequisites and generation/rechecking; they establish neither server admission
nor controller behavior. Missing corpus assets or profiles are errors. This driver cannot close issues #14, #2, #15 or #7 by itself and does not grant publication authority. Run it again against the exact
integrated source after relevant native behavior changes and expand pending renderer/API/runtime cells with reviewed, separately bound
acceptance evidence before claiming the complete programme.
