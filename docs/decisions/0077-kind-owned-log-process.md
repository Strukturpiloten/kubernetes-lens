# ADR0077: Kind-owned direct log-client process

Status: Accepted source contract; independent final source review, complete validation and native qualification pending (#62).

## Context

The independently reviewed V17 result is failed-retired. Create and delete returned0,
but the v3 child role exhausted4096 identity samples with last cached stateS.
The collector records had genuine EOF and actual dd0/tee0; the marker predicate
was not reached. Neither the token nor those facts identify a parent-death-signal
cause or prove continuous child state. V17 remains a failure, not native acceptance.

Official frozen kind0.14.0/0.33.0 sources start a context-bound provider logs command
and cancel it after the startup-regexp return. Previous source placed a Bash wrapper
in that kind-owned PID and depended on setpriv/PDEATHSIG propagation to a separate
Podman child. Remove that additional lifecycle dependency without diagnosing V17.

## Decision

For the one exact admitted rootful logs route, preserve the source-owned launcher's
ordinary exec into the receiver, record that same PID/start as `native`, prepare the
two existing bounded collectors, then ordinary exec the fixed Podman logs command
in the same kind-owned process. There is no separate log child, setpriv launch,
logs-child route, PID-directed signal, helper, observer or fallback. Keep existing
prerequisite package/executable/capability observations unchanged.

Require Bash's `BASH_SUBSHELL` to equal0 before the provider makes native/output
reservations, and again before the logs claim or collectors. Enable execfail with
an explicit failure branch. Guard each descriptor setup operation. Close spare
writers and FD3 before the fixed final exec. Disable errexit only at that final
handoff: successful exec never returns; every returned path writes poison with a
Bash builtin and exits nonzero, preserving an available nonzero exec status.

This narrow errexit handling is supported by actual pure Bash regressions: with
noninteractive errexit enabled, failed exec exited before its guarded handler on
the admitted validation Bash; execfail alone did not publish poison. A late EXIT
trap did not provide the needed backstop. No EXIT trap is added. Preparation and
descriptor setup retain ordinary guarded failure handling. The dedicated poison
path does not use generic fail's FD3 diagnostic, which may already be closed.
Poison-write failure remains nonzero and cannot publish success or trigger retry.
Selected-image behavior still requires separately admitted qualification.

## Explicit v4 evidence

Use `kubernetes-lens-owned-rootful-result-v4` with seven unique roles: `native`,
`out`, `err`, `out-dd`, `out-tee`, `err-dd`, `err-tee`. The native role records the
same provider PID/start before ordinary exec. This is trusted source-chain custody,
not a newly observed parent-process attestation. No wrapper/child alias is allowed.

Keep the existing log member keys. In v4 the legacy-named
`wrapper_observed_child_wait_status` is always null, as is signal cause. Reject
`direct-wait-zero` and pg1.n, the removed wrapper-wait guard. The only positive
log state is `retired-wait-and-signal-cause-unavailable`, after every seven-role
retirement, collector, marker and poison predicate. Neither kind's top-level status
nor the outer receiver invents a native-client or collector wait.

Each collector still owns and really waits its actual dd and tee children. Their
actual statuses, byte bounds and genuine EOF records remain mandatory. Collectors
may outlive kind's cancellation target, so all six collector identities still must
retire. Broken downstream readers, successful kind create or a startup marker alone
cannot replace any retirement predicate. Independent whole-target retirement,
quarantine and final publication remain separate requirements on success and failure.

Keep the exact142-empty pacing policy, existing clock comparisons, per-role4096
sample ceiling and close-before-native/finish ordering. Seven roles reduce the
maximum to28672 samples and28665 possible pacing reads; no cap grows. Preserve
70/5 native actions,680/24/64 utility/guard/cleanup partition, historical stage256,
all original work/cleanup ends, CPU/PID/memory/storage, private stream/prefix,
raw/wire/metadata/source caps and public redaction. Omitting the absent setpriv
invocation does not refund any issued credit. Actual counters remain ledger-derived.

## History and qualification

This decision supersedes only ADR0075/0076's current eight-role and wrapper-child
ownership/wait contract. Their pacing and diagnostic meanings otherwise remain.
V1/v2/v3 decode in their own unchanged roles and states, including genuine historical
wrapper wait evidence. An exact current-to-frozen65362-byte v3 inverse precedes the
unchanged pacing/v3/v2/v1 inverses; historical hashes and all314 literal prerequisite
patterns stay fixed. Current enrollment and independent test literals bind the new
canonical receiver bytes; there is no historical-source acceptance fallback.

Pure local controls cover same-PID ordinary exec, direct owned-PID cancellation,
actual collector child waits/EOF, final exec/setup/poison-write/subshell failures,
v4 role/status/version refusal, clocks/pacing/FD lifetime, private durability and
historical decoding. They launch no native Podman, kind, VM or cluster and establish
no failure cause or native conformance. No package pin, installer or new probe is
introduced. Final complete validation and a separately reviewed/adopted native run
remain required; this source decision authorizes neither a retry nor publication.

## Narrow v5 extension

[ADR0078](0078-private-postlog-failure-code.md) supersedes only the current outer
result version and inverse entry seam. V5 adds a nullable private post-log first
explicit-fail scalar; this ADR's exact seven-role logs object, null native wait,
collector proof, ownership, caps and historical v1–v4 meanings remain unchanged.
A strict v5-to-frozen63399-byte v4 inverse now precedes the existing v4-to-v3 chain.
