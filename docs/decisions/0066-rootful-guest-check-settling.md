# ADR 0066: Fixed scheduling interval before the rootful guest check

Status: proposed source contract for issue #62; native qualification remains pending.

## Context

The consumed V21 attempt refused at the initial authenticated guest check with the
source-bound `inv-drift` label. Both inventory scans completed, but their strings
differed. Neither snapshot nor its differing fields were retained. Independent
review established retirement of the owned VM and recorded processes. This result
does not establish which process, task, limit or FD changed, or why.

The existing console boot marker permits one authenticated check; it does not
establish quiescence or guest readiness. Starting the check immediately after that
marker can overlap ongoing guest activity. A scheduling change is an experiment,
not a diagnosis of the earlier refusal.

## Decision

For the explicitly selected rootful phase only, wait one fixed 30-second interval
after the first existing boot marker and before the single authenticated check.
The endpoint is calculated once. Later markers cannot extend it. Refuse before
the interval if its endpoint does not precede the original work deadline.

During the interval, continue draining the same QEMU stdout/stderr pipes through
the existing selector, charging every byte to the original output allowance.
Retain no new console buffer. Check the original work deadline, cancellation and
QEMU exit; a closed stream or exhausted allowance still refuses. No readiness
poll, guest command, observation source or additional child is introduced.

This narrowly refines ADR 0062's immediate marker-to-check scheduling. The original
absolute work/cleanup deadlines, CPU, memory, PID, storage, output, command and
cleanup reservations are unchanged. No retry, fallback, deadline renewal or new
attempt follows from refusal. Non-rootful phases retain their original behavior.

The receiver bytes, all 314 historical diagnostic patterns, 49 original utility
query sites, 24 prepaid record guards and exact two-inventory equality remain
unchanged. A pair that differs still refuses immediately. The interval neither
repairs a task nor asserts that a later inventory will be stable.

## Verification and limits

Mocked-clock controls cover the one fixed interval, repeated console markers,
both streams and byte charges, unchanged command/deadline state, insufficient
time, cancellation, expiry, QEMU exit, EOF and output exhaustion. Worker controls
cover one check after the interval and retirement when settling fails before any
SSH producer starts. Historical source checks reverse only the exact hashed
scheduling helper and its single rootful call before applying their original
hash assertions.

These are source controls. The final complete gate, independent source review,
fresh one-attempt runtime admission and independent retirement remain required.
No Kubernetes readiness, scenario, controller or native conformance is established
by this decision. No software pin, Renovate owner, publication or BoxFerry product
behavior changes.

[ADR0085](0085-phase-specific-guest-census.md) later refines only post-create census
equality. The30-second initial scheduling interval and all three earlier stable
checks remain; no extra post-kind settling, retry or quiescence claim follows.
Statements here about unchanged receiver equality describe this historical source
step, rather than requiring byte-identical live node topology forever.
