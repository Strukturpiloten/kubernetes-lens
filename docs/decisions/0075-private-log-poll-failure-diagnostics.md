# ADR0075: Private cached log-poll failure facts

Status: Accepted source contract; pacing and clock order partly superseded by [ADR0076](0076-bounded-existing-log-poll-pacing.md); final validation and native qualification pending (#62). Current role/ownership/wait contract partly superseded by [ADR0077](0077-kind-owned-log-process.md).

## Context

[ADR0073](0073-versioned-postcreate-guard-reason.md) leaves a `pg1.g` or `pg1.p` failure
without a specific role or cached state. The actual V12 result is v2 `pg1.g`: its
role and state remain unavailable. Diagnostic improvements must preserve the original
poll, clock and identity predicates and their order, the 4096 per-role bound,
success/readiness requirements and independent whole-target retirement.

## Decision

Use explicit RootfulResult v3 with the same wire and log keys. Preserve strict v1/v2
decoding and the v3 plain states and `pg1.a` through `pg1.p` aliases. Only the first
actual `g` or `p` false branch within the existing log-role poll can record
`pg2.<g|p>.<role>.<state|u>.<q>.<pid>.<start>`.

Use only the current role, expected PID/start, loop index and already-read,
same-identity proc-stat state. Reset the cache per role. Report the finite subset
`R S D Z T t X I`; unsupported state text or no sample becomes `u`, meaning
unavailable. `g` reports 4096 completed samples, with the existing clock comparison
having passed before the last sample. `p` reports the existing failed work-clock
comparison before the next sample, with zero through 4095 earlier completed
samples. A zero count requires `u`.

Strict offline decoding requires canonical ASCII components, PID 1 through 32767,
start 1 through 9223372036854775806, and a non-null exact match to the selected
existing `logs.identities` member. Rich tokens require failed/create-int-0/not-reached/
startup-false context and matching explicit v3 schema, including standalone private
prefix evidence decoding. They never establish liveness, elapsed time, a signal
cause, EOF, readiness, success or retirement, including when the cached state is `Z`.

Keep the same private evidence roles, raw/durable path and public projection. The
frozen `LogPollFailure` DATA helper derives primitive facts without adding a
serialized summary or receipt member. Other codes and untagged, skipped or
interrupted paths retain existing meanings. First assignment survives cleanup.

## Consequences

No new observations, helper processes, commands, signals, queues, retries, files or
budget allowances are introduced. The original end and utility/native/output/raw/
metadata/source caps remain unchanged. Finite builtin bookkeeping consumes actual
time within that end; no zero-cost claim is made. Require a final canonical
receiver at most 65536 bytes, exact current enrollment and a strict new inverse to
immutable v2 bytes before older history. Preserve old endpoints, patterns and Rust
bodies.

Projected source, parser, worker, parent and durability controls remain separate
from final complete validation and any later explicitly adopted native run. No
underlying cause or behavioral correction follows from this diagnostic policy.

## Refinement by ADR0076

[ADR0076](0076-bounded-existing-log-poll-pacing.md) supersedes this decision's
no-new-wait and unchanged-clock-order statements only for the current eight-role
poll. It adds one bounded builtin pacing read after the first sample when the
original work allowance exceeds one second, an additional clock check after an
accepted wake, and a final clock check after descriptor closure. One extra receiver
FD/open-file description references the same inherited pipe; no actor, utility or
inode is created. Exact status 142 plus an empty buffer is a policy wake event,
without a timer/signal/retirement causal claim. All original sample, identity,
collector EOF/status, marker, poison, budget and whole-target retirement conditions
remain mandatory. Historical diagnostic-only v3 source is retained by an exact
inverse before the unchanged v2/v1 history. Selected-image and native qualification
remain pending.

## Current ownership refinement

[ADR0077](0077-kind-owned-log-process.md) versions the current source as v4,
with a same-PID native log client and six collector roles, no separate child or
PDEATHSIG dependency, and always-unavailable receiver-owned log wait. Historical
v1–v3 roles/statuses remain exact. Original pacing, caps, clocks, privacy and
independent whole-target retirement requirements remain; native qualification
is pending.
