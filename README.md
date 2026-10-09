# KubernetesLens

KubernetesLens is an independent Rust library repository for native Kubernetes configuration.
This **unpublished foundation** provides bounded strict YAML/JSON parsing, private source evidence,
identities and Lists, explicit Kubernetes 1.20–1.37 target facts, supplied-only references,
merge-safe edits, deterministic private in-memory output and explicit bounded Linux input reads.
The five native resource cohorts remain preservation-only; no Kubernetes minor, renderer or
runtime conformance is claimed. Renderer execution and live cluster operations are not delivered.
See the [foundation API and integration contract](docs/foundation-api.md).

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
