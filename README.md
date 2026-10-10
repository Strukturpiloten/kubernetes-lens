# KubernetesLens

KubernetesLens is an independent Rust library repository for native Kubernetes configuration.
This **unpublished foundation** provides bounded strict YAML/JSON parsing, private source evidence,
identities and Lists, explicit Kubernetes 1.20–1.37 target facts, supplied-only references,
merge-safe edits, deterministic private in-memory output and explicit bounded Linux input reads.
Typed workload support covers Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
ReplicationController, Job and historical/current CronJob APIs, with validation, supplied facts
and native generation. Typed access, RBAC, scaling and policy resources and six networking kinds
use the same bounded native contracts. Networking covers Service, Endpoints, EndpointSlice,
Ingress, IngressClass and NetworkPolicy across ten served roots, with finite validation and
supplied-only graph evidence. Typed configuration and storage support adds ConfigMap, Secret, PersistentVolumeClaim,
PersistentVolume and StorageClass; see [storage support and limits](docs/storage.md).
Extension definitions remain preservation-only. No Kubernetes
minor, renderer or runtime conformance is claimed. Renderer execution and live cluster operations
are not delivered. See [workload support and limits](docs/workloads.md),
[access support and limits](docs/access.md) and [networking support and limits](docs/networking.md).
See the [foundation API and integration contract](docs/foundation-api.md).
Shared native-processing limits now cover cumulative charged payload/work and diagnostic reports.
Protected binary values and exact supplied-quantity ordering are available without claiming native
rounding, storage provisioning or controller behavior.

Rust edition 2024, minimum supported Rust 1.85.0, MPL-2.0. The existing license is preserved.
The `0.1.0` manifest version is a local package identity, not a published release.

## Development

Use the existing [shared BoxFerry development environment](docs/development-environment.md).
Run `./scripts/format-lint.sh --fix`, then `./scripts/check-all.sh --check`.
Formatting and linting alone are not validation evidence. The complete gate packages locally;
it does not publish, apply configuration, contact a cluster or create resources.

## Project documents

- [Architecture](docs/architecture.md) and [decisions](docs/decisions/README.md)
- [API stability](docs/api-stability.md), [testing](docs/testing.md), [dependencies](docs/dependency-policy.md)
- [Release boundaries](docs/releasing.md) and [platform support](docs/platform-support.md)
- [Bootstrap parity and immutable baselines](docs/bootstrap-parity.md)
- [Contributing](CONTRIBUTING.md), [security](SECURITY.md), [documentation index](docs/README.md)

Native work follows [KubernetesLens #7](https://github.com/Strukturpiloten/kubernetes-lens/issues/7),
after [bootstrap #6](https://github.com/Strukturpiloten/kubernetes-lens/issues/6).
External repository administration is tracked in [#16](https://github.com/Strukturpiloten/kubernetes-lens/issues/16).
