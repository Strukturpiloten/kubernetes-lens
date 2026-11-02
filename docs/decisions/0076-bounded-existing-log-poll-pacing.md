# ADR0076: Bounded pacing inside the existing log-role poll

Status: Accepted source contract; final validation and selected-image/native qualification pending (#62). Current role/ownership/wait contract partly superseded by [ADR0077](0077-kind-owned-log-process.md).

## Context

[ADR0075](0075-private-log-poll-failure-diagnostics.md) adds cached facts to the
existing eight-role log-retirement poll. Its no-new-wait and unchanged-clock-order
statements describe the historical diagnostic-only v3 source. A finite tight
4096-sample loop can consume its sample allowance without useful scheduling space.
No retained failure establishes that this was its cause, and pacing cannot establish
that an original process has retired.

## Decision

Refine ADR0075 only for this existing poll. Preserve its eight roles, identity/state
predicates, 4096 samples per role, private v3 vocabulary and original absolute work
and cleanup ends. Before polling, require fd0 to be a pipe/FIFO according to the
existing procfs descriptor view. Reopen `/proc/self/fd/0` read/write into one Bash
brace descriptor and require `-ef` equality with fd0. Unsupported types, failed open
or failed equality refuse. This adds exactly one receiver FD and one open-file
description referencing the same inherited pipe inode. It creates no inode,
producer, utility, helper, observer, queue or independent protocol channel.

For each role, the first sample retains the original clock check and has no pacing
read. Before each later sample, retain that check. Only when the integer remaining
work allowance is greater than one second, perform the fixed builtin read
`IFS= read -rd '' -n 1 -t 0.01 -u "$pace_fd" line`. Accept only an exact status 142
with an empty buffer as a policy wake event, then check the original clock again
before examining proc state. Success (including the empty successful NUL-delimited
read), EOF/status 1, nonempty data, every other status and failed/malformed clock
reads refuse. This policy deliberately does not classify status 142 as evidence of
a timer expiration, a particular signal or process retirement. No minimum elapsed
interval or scheduler progress is inferred. The NUL delimiter plus one-byte bound
prevents an unexpected NUL from disappearing into accepted empty data.

The read/write endpoint retains a writer for its own lifetime. A closed original
producer therefore does not turn its pacing read into immediate pipe EOF. That is
an intentional lifetime change limited to this descriptor; it is not EOF evidence
for the separate log collectors. Selected Bash/Linux/procfs behavior remains a
trusted primitive requiring separate qualification on the selected guest image.
The nominal read timeout is neither a fresh work allowance nor a hard real-time
scheduling guarantee. Its actual time and all additional builtin work consume the
original end. There are at most 4095 pacing reads per role and 32760 across eight
roles, without increasing the 4096-sample bound. With one second or less remaining,
no pacing read is attempted; original clock/sample limits still apply.

A failed pre-read or post-wake work check uses the same current iteration count
and last sampled state in `pg2.p`; the wake supplies neither a sample nor a new
state. Unsupported state glyphs remain unavailable. Persistent `Z` still exhausts
the sample cap: no state glyph or wake authorizes retirement. PID disappearance or
identity reuse, collector successful statuses and real EOF, capture bounds and
paths, the existing startup marker, available wrapper wait-zero status, and poison
absence retain their independent predicates. Create status zero remains necessary
and insufficient for success.

Close and unset the descriptor after all those predicates and before publishing
`logs-retirement`. Clear local poll attribution and perform one final original
clock check before publication. A final false clock comparison therefore has plain
`pg1.p`, not a stale role/sample attribution. The next normal native action cannot
inherit the descriptor. On every admitted failure, the real `finish` trap clears
its traps and closes the descriptor before optional diagnosis, mandatory cleanup
native launch or evidence emission. Closure is idempotent when no descriptor was
acquired; a failed close exits fail-closed before launching a later child.

## Consequences and historical evidence

This decision explicitly supersedes ADR0075's no-new-wait and unchanged-clock-order
claims for the current poll only. Diagnostic meanings, old endpoints and immutable
historical v1/v2/v3 domains remain intact. A strict exact inverse reconstructs the
65431-byte historical v3 source before its retained v3-to-v2 and v2-to-v1 inverses.
The reviewed current receiver is 65362 bytes, below the unchanged 65536-byte source
ceiling; only ordinary comments were recovered to fit the new behavior. The current
source-enrollment hash changes with those bytes. This is no new third-party tool,
installer, version pin or Renovate ownership change.

No extra native/utility credit, capture, source, metadata, output, CPU, PID, memory,
storage, guard allowance, cleanup reserve or absolute deadline is granted. The
680/24/64 rootful partition and historical stage reservation remain unchanged.
Poison, private redaction, genuinely observed statuses, marker semantics and
independent whole-target retirement retain their requirements. The receiver FD is
not a new authority and is not inherited by a new actor.

Current-source pure controls use owned local Bash pipes and private proc-shaped
files, including actual byte/NUL reads and descriptor lifetime checks. Separate
projected controls cover exact wake policy, deadlines, sample counts and cleanup;
explicit historical controls retain the older read/invocation comparisons. These
controls, source inverses and static checks establish no selected-image primitive,
SSH/VM behavior, kind/API readiness, underlying failure cause, native success or
whole-target retirement. Final complete validation and separately admitted exact
selected-image primitive/native qualification remain pending. No retry or native
execution authority follows from adopting this source contract.

## Current ownership refinement

[ADR0077](0077-kind-owned-log-process.md) versions the current source as v4,
with a same-PID native log client and six collector roles, no separate child or
PDEATHSIG dependency, and always-unavailable receiver-owned log wait. Historical
v1–v3 roles/statuses remain exact. Original pacing, caps, clocks, privacy and
independent whole-target retirement requirements remain; native qualification
is pending.
