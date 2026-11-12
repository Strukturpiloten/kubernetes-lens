# ADR 0103: Direct API jobs and exact trusted-policy transition

- Status: Accepted source contract; hosted exact-candidate acceptance remains required.
- Date: 2026-11-07
- Amends: ADR 0102 only for its local Rust/API wrapper and job inventory.

## Decision

Call the existing canonical quality and API workflows directly. Preserve all eight
quality commands, the unfiltered positive foundation contract, explicit package and
purpose, child budgets and read-only permissions. KubernetesLens remains unpublished;
release validation requires actual published-purpose API proof for the tested SHA.

The old trusted five-job policy meant both quality and API inside `rust`. Its first
PR/queue transition therefore runs both children and validates both successful
candidate receipts before passing only the exact six original dependencies into
the unchanged canonical gate. The original serialized plan and every original
outcome remain unchanged. The new six-job policy passes all seven dependencies
normally, including complete main/manual/reusable-release validation.

The consumer-only stdlib adapter binds the event-base checkout and tracked policy
blob to exactly the P5/P6 hashes in `scripts/ci-api-transition.py`. Unknown policy,
repository, schema, inventory, identity, purpose or selected proof fails without
aggregate outputs. Prose permits only the planned quality/API skips. Dependency
admission still executes the exact trusted-base authority; no candidate-policy
fallback or canonical API/parser enhancement is introduced.

Joint checks retain a five-minute step inside the existing ten-minute aggregate.
Publication policy, native suites and fixed FCOS qualification remain unchanged.
Remove the exact P5 branch separately after outstanding old-base runs have advanced.
