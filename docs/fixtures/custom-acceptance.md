# Official custom-document acceptance

Issues #13/#14 require original native document handling and exact supplied CRD linkage for seven
selected CloudNativePG/Grafana kinds. This driver consumes immutable official assets and the local
unpublished library. It has no renderer, credential discovery, live cluster, webhook callback,
apply/deploy or controller invocation. The original native probe and Python authentication/process
helpers are shared read-only prerequisites; the custom layer supplies independent cases and its own
strict private receipt contract. It does not copy an external oracle.

## Source contracts

| Selected kind                 | Official example                                       | Independent checks                                                                                         |
| ----------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| CloudNativePG Cluster         | `docs/src/samples/cluster-example.yaml`                | Instances, exact storage quantity and supplied Cluster declaration                                         |
| CloudNativePG Pooler          | `docs/src/samples/pooler-example-explicit-image.yaml`  | Both supplied Cluster/Pooler declarations; explicit images, instance count, pool mode and cluster spelling |
| CloudNativePG Backup          | `docs/src/samples/backup-example.yaml`                 | Supplied Backup declaration and original cluster spelling                                                  |
| CloudNativePG ScheduledBackup | `docs/src/samples/scheduled-backup-example.yaml`       | Schedule, owner reference and original cluster spelling                                                    |
| Grafana                       | `examples/grafana/credential_secret/resources.yaml`    | Supplied Grafana declaration, protected Secret fields and original environment/Secret-key spellings        |
| GrafanaDashboard              | `examples/dashboard/configmap/resources.yaml`          | Both Grafana/Dashboard declarations; selector, protected Grafana configuration and ConfigMap/key spellings |
| GrafanaDatasource             | `examples/datasource/datasource_types/prometheus.yaml` | Supplied Datasource declaration, selector, datasource configuration and JSON data                          |

The five CRD assets are the four CloudNativePG `config/crd/bases/` definitions and the full Grafana
`deploy/kustomize/base/crds.yaml` source bundle. Preserve the complete source bundle. Grafana CRD
document indices 2, 3 and 11 supply Dashboard, Datasource and Grafana respectively; the bundle has
13 documents. All selected CNPG custom GVKs use `postgresql.cnpg.io/v1`, Grafana uses
`grafana.integreatly.org/v1beta1`. Their selected declarations use stable CRD API v1, Namespaced
scope, version index 0 and explicit served/storage flags. Independent output assertions also check
the exact CRD name/group/kind/scope/version/flags. Expectations were authored from authenticated
official bytes, never from KubernetesLens output.

Seven source groups contain nine actual custom documents: the Pooler source also contains Cluster,
and the Dashboard source also contains Grafana. Every custom document is checked; unasserted
documents, missing assets or incomplete work cannot count as acceptance. Identity/source matching
uses original resource indices and document coordinates, independently of generated ordering.

## Schema, graph and preservation boundaries

Every selected upstream schema contains behavior outside the current local schema evaluator:
defaulting, CEL and format handling, plus regex, combinators, topology or unknown-field transforms
in some kinds. Intact official schemas must produce explicit `UnsupportedSchema` findings and the
independently observed category witnesses. The result may retain a source-bound descriptor, while
its graph record remains nonpositive, has no positive descriptor and creates no positive supplied
CRD-version dependency. Do not simplify the schema to manufacture a positive admission result.

The probe verifies exact CRD resource/source/document, selected group/kind/version/scope,
served/storage facts and version/schema pointers. It records the supported-subset result, violation
count and numeric uncertainty separately from unsupported categories. A satisfied supported subset
does not mean Kubernetes admission succeeds. Unsupported behavior does not erase supported local
violations. Every recognized custom document must retain one external, unverified Operator
prerequisite. This does not identify, install or prove a controller.

Native YAML/JSON generation requires separate explicit preservation and protected-output choices.
The shared native probe records actual default generation refusal, checks independent output fields,
repeated byte determinism and semantic preservation. The custom probe additionally reparses each
output and reruns native custom checking and graph resolution against fresh supplied CRDs. It never
replays an original descriptor into another resource set. Reparsed coordinates are fresh evidence,
not a replacement claim about original source provenance.

Controller-specific Secret/ConfigMap/selector/cluster spellings are checked as source values only.
No controller-reference edge is invented without an admitted profile. Local synthetic supported
schema controls separately test successful positive graph dependencies and exact version/schema
evidence. Synthetic List controls test original wrapper, CRD/custom and nested schema pointers;
the selected upstream examples themselves are YAML streams. These controls are not described as
official List examples or full operator support.

## Explicit invocation and privacy

Use the coordinated validation slot and authenticate the optimized binary against the exact reviewed
source/build candidate. Large original schemas can exceed the unchanged 60-second deadline with a
debug build; a timeout remains a refusal.

```sh
cargo build --locked --release --example official_custom_probe
cargo test --locked --test official_custom_probe
python3 scripts/fixtures/custom_acceptance.py --self-test
```

Run only with verified paths, actual digests and explicit policies:

```sh
python3 scripts/fixtures/custom_acceptance.py \
  --definitions /private/reviewed-official-definitions \
  --inventory-sha256 VERIFIED_INVENTORY_SHA256 \
  --corpus /private/materialized-official-corpus \
  --probe /private/authenticated-official-custom-probe \
  --binary-sha256 VERIFIED_BINARY_SHA256 \
  --candidate-manifest /private/reviewed-source-manifest.json \
  --candidate-sha256 VERIFIED_SOURCE_MANIFEST_SHA256 \
  --target-minor 37 --namespace fixture-native \
  --documented-gate-defaults --preserve-unknown yes --protected-output include
```

The runner inherits the native harness's Linux-only no-follow bounded reads, authentication of every
inventory asset/license companion, sealed immutable binary snapshot, sanitized environment, fixed
argument execution, nonce/request/candidate/binary/target/source/expectation bindings, pipe/CPU/
memory/wall caps and private process-group cleanup. The wall cap is not increased for custom cases.
Its receipt contains only fixed states, booleans, counts, category/finding histograms and authenticated
bindings. Original identities, pointers, source/schema values, artifacts and child logs stay private.
Source/build binding still requires the primary's separately retained immutable build evidence.

The same explicit target catalogue covers Kubernetes 1.20 through 1.37. Test both endpoints, retaining
any actual unavailable modern-source findings/refusals at the floor. An explicit historical native
profile does not make these modern operator revisions Kubernetes 1.20 runtime-compatible. Synthetic
supported-subset controls check the floor independently.

The Cargo integration target executes the original custom Python pure tests on Linux with an explicit
interpreter/script and cleared environment; no renderer/API/runtime tool runs in those tests. A zero
driver exit means the selected static contract assertions passed. Its programme receipt remains
`official-custom-document-contract-executed-programme-incomplete`: API/runtime/controller evidence,
rendered fixtures, independent integrated review and the final complete gate remain separate.
No crate release, publication or BoxFerry implementation is a prerequisite or authorized side effect.
