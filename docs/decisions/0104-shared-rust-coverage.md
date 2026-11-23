# ADR 0104 Shared Rust coverage

- Status: Proposed source contract
- Amends: [ADR 0103](0103-direct-api-jobs-and-trusted-policy-transition.md) for coverage selection and proof

The complete local gate and hosted CI run the canonical coverage task with the exact
candidate-owned Cargo tool and Rust compiler. The trusted policy controls the coverage commands
and the region, function and line thresholds. Pure prose selects the existing documentation
and dependency-admission jobs. Main, manual dispatch and reusable release CI require coverage
as part of complete validation.

`scripts/cargo-llvm-cov.version` contains the exact version followed by one LF.
One shared Renovate crate extractor owns that file. The shared implementation supplies the
SemVer tool and the development container.

The exact five- and six-job policy snapshots predate coverage. Their PR and merge-group runs
require a planned coverage skip and pass only the original needs into the canonical gate after
proof validation. The five-job snapshot still requires API proof when Rust quality is
selected. The seven-job policy passes its complete needs to the canonical gate and requires
same-candidate coverage proof for a selected job. A change to the version file selects coverage even
when the same change set includes prose. The gate checks the original plan against
the event base. A candidate's policy edit takes effect as trusted policy once it is on the base.

Update the adapter's trusted policy digests alongside a reviewed ratchet adjustment so both
base revisions can pass the transition. Source coverage measures Rust test execution. Native
qualification follows the independent compatibility contract, and release validation follows
the unpublished [release policy](../releasing.md).
