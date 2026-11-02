# ADR 0063: separate whole-guest hard NOFILE metadata profile

Status: accepted source contract; runtime qualification pending. Supersedes only the
whole-guest hard-NOFILE ceiling and future numeric-slot theorem of
[ADR 0062](0062-owned-qemu-prerequisite.md). Its other resource and custody
requirements remain unchanged.

## Context and historical evidence

The first profile required current `nr_open`, every current task's finite hard
NOFILE and every occupied numeric FD index to satisfy the same `1073741816`
ceiling. Under its trusted-kernel/global/program premises it claimed at most
`32767 × 1073741816` future user FD slots. The V16 admission refused with
`inv-nf-range`. That fixed source-bound frame establishes only that a parsed
finite numeric hard limit exceeded the old hard ceiling; it identifies neither
a task nor the value, and supplies no successful resource or native qualification.
The failed-retired receipt remains historical evidence, not a v2 admission.

Current `nr_open` limits raises of hard NOFILE; it does not retroactively lower
inherited hard limits or revoke already occupied descriptors. Host QEMU/SSH
NOFILE limits do not constrain the separate guest kernel. Receiver-only limits
and service defaults cannot establish an all-task limit including PID1.

## Decision: whole-owned-guest-trusted-programs-v2

Use the fixed hard metadata ceiling `H = 9999999999`, the maximum of the
already accepted one-to-ten ASCII decimal digit grammar. This value is derived
from the source contract, never from a failed guest's observed limit. It is not
a claim that the guest supports or physically fits that many descriptors.

Keep these independently checked admission facts:

- Actual guest `pid_max` is `32768`; every current PID/TID and the strict total
  task bound remain below it, including PID1 and early/manager/SSH tasks.
- Actual `nr_open` is positive and at most `1073741816`.
- Every current task's hard NOFILE has the unchanged finite decimal grammar and
  is at most `H`. Neither infinity nor eleven-digit values are admitted.
- Every currently occupied numeric FD index is strictly below `1073741816`,
  including retained descriptors whose task limit has since been lowered.
- Both complete PID/start/limits/FD inventories are equal. Missing, unreadable,
  changed, malformed, truncated or over-budget evidence still refuses.

Only the receiver's fixed hard-domain constant/predicate changes; the controller
enrolls the new receiver source identity. It does not repair any current task,
raise or lower a task limit, adapt to observations, or add a guest observation.
The Ignition request for `nr_open=1073741816` remains unchanged and requires
actual admission evidence. `H+1` is eleven digits and therefore refuses as
`inv-nf-form` before the range comparison. No in-grammar number exceeds `H`;
the explicit hard-range guard and its historical fixed label remain enrolled.

## Revised proof and limits

Under the existing trusted selected-kernel/global/program premise, initially
occupied indices are below the old ceiling and every admitted current hard limit
is at most `H`. Fork inheritance and exec preservation retain that bound. With
`nr_open` preserved at or below the old ceiling, subsequent hard-limit raises
cannot exceed it, including privileged raises. A new occupied descriptor index
is below its task's soft limit, which is at most its hard limit. Lowering a limit
may retain existing descriptors; those were already below `H`. Consequently,
future occupied numeric indices remain below `max(H, 1073741816)`.

The unchanged guest-initial PID-space premise bounds PID-bearing tasks by `32767`.
The v2 future user FD-slot bound is therefore
`32767 × max(H, 1073741816) = 327669999967233`. Both `H` and this product fit
signed 64-bit arithmetic. This deliberately replaces, and does not preserve,
the smaller v1 future bound. The unchanged scan of current indices establishes
only current occupation, not a future allocation clamp from `nr_open`.

Neither theorem bounds allocated FD-table array capacity, all kernel open-file
descriptions, in-flight SCM_RIGHTS references or other kernel memory. Existing
physical guest RAM and backing storage bound those separately. This is not
protection against hostile transient guest root changing the trusted globals,
and no continuous observer or stronger atomic-snapshot claim is introduced.

The reviewed Linux manual evidence is documentary source evidence, not proof
that the selected guest applied this profile:

| Local reference  | SHA256 of reviewed compressed manual                               | Relevant formatted text                                                                                                               |
| ---------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `getrlimit(2)`   | `263a639ba6e03bf8fdf6537551e4ba9202b3f6c24fc60b0ebdba1d7635d489da` | Lines 56–64 soft/hard; 279–288 descriptor numbers; 496–502 `nr_open` raise denial; 569–581 inheritance, exec and retained descriptors |
| `proc_sys_fs(5)` | `1f12a4af5e082afdf488c6568fcf10cd879a6fa65420a44b048ab2d503847aa3` | Lines 237–244 hard-limit raise ceiling                                                                                                |

These are `/usr/share/man/man2/getrlimit.2.gz` and
`/usr/share/man/man5/proc_sys_fs.5.gz`. No upstream implementation is copied or
translated; no manual text is redistributed. Selected-kernel application and
native fit still require a separately reviewed fresh candidate run.

## Unchanged accounting and verification

The fixed decimal field remains at most ten characters in each existing SNAP
record. Both 32-MiB snapshot caps, task counts, PID/start checks, mode/EOF/privacy,
314 closed diagnostic patterns (296 historical plus 18 inventory labels),
original 49 utility query sites and the separate existing stage-flock site keep
their exact source/argv/order. The 24 prepaid record guards, 680/24/64 rootful
partition, separate stage-256 reservation, utility/native/output/capture limits,
2-vCPU/4-GiB guest, 8-GiB host memory, 256 host tasks, 24-GiB storage,
1800-second total and original 120-second cleanup reservation remain unchanged.
A larger admitted numeric limit grants no additional enumeration work, memory,
records, time, queries or native commands; exceeding an original cap still refuses.

Pure private proc-shaped tests cover old/new hard boundaries, PID1 and another
TID, nonfinite/malformed/H+1 refusal, independently unchanged FD/`nr_open`
boundaries, healthy ten-character snapshots, limit drift and protected refusal
output. Reverse normalization binds the entire receiver and controller to V16
except the two intended hard-domain edits and source enrollment, proving exact
query/control/budget preservation. All historical classifiers remain exercised;
stale V16 source cannot authenticate the new enrollment.

No Rust, product API, tool/software pin, workflow or Renovate owner changes.
These numeric contract constants and fixture source identities are intentional
reviewed evidence, not updateable software versions. Focused controls do not
replace the primary's final complete gate or independent review. This source
change authorizes no guest observation, runtime retry, deployment, publication
or native conformance claim.

[ADR0085](0085-phase-specific-guest-census.md) refines admission fact40 only for the
post-create live phase: both complete individually bounded inventories remain, but
changing topology/FD sets no longer require byte equality. Provider pre-node, initial
prerequisite and execution-before-runtime retain exact stable equality. The numeric
profile, initial-admission/inheritance/global-preservation theorem and its stated
limits remain unchanged; neither census mode is atomic or continuous observation.
