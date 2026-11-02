# ADR0085: Phase-specific guest resource census

Status: Accepted source correction; final independent source review, complete
validation and separately adopted native qualification pending (#62).

## Context

V23n reports failed-retired, create0/delete0, positive seven-role log retirement,
source Deployment not-reached and V8 pl1.r with reason inv-drift. This source has
one inv-drift branch: two complete censuses returned and their SNAP strings differed.
Every observed per-record guard passed; neither differing census was retained.
No PID, task, FD, limit, underlying cause or native success is inferred. The failed
run and its spent adoption remain historical evidence, without retry authority.

SNAP includes process/task identity, hard NOFILE and occupied FD-index lists. Ordinary
bounded FD open/close or task/process birth/exit between completed scans can change
those bytes. Retiring the seven owned log roles does not quiesce the whole guest or
its node programs. Exact post-create topology equality therefore asks for a fact
that the owned lifecycle and resource contract do not require or establish.

## Decision

resource_check accepts zero arguments for stable admission, or the one exact
internal literal live for a live census. Unknown, empty and extra arguments fail
before resource observations. This is not a public CLI, input-record or environment
selector. Preserve zero-argument stable calls at provider run before node start,
initial prerequisite and execution before runtime effects. Only the call after
successful kind create and owned log retirement uses live.

Both modes retain every global/resource predicate and both complete inventory
scans in their original order. Stable still requires byte-for-byte SNAP equality.
Live accepts changes between two completed, individually bound-valid scans. This
intentionally replaces the post-create quiescence predicate; it does not claim
that all predicates remain unchanged. Unreadable/disappeared entries during a scan,
incomplete or malformed records and original cap failures still refuse. No retry,
wait, queue, recovery scan, observer or suppressed record is introduced.

Retain the second scan's global INVENTORY_START map. Each scan clears and rebuilds
it, so no first-scan, prerequisite or provider cache can supply a missing key. Keep
the subsequent genuine node inspection, PID grammar/range, cache-presence/decimal,
first stat PID/start, cgroup and second stat start predicates unchanged. A missing
selected PID from the second scan or later PID/start/cgroup drift still fails.
Neither cached identity nor a census supplies signal or retirement authority.

## Resource theorem and observation limits

Keep actual pid_max32768; all positive PID/TID and strict task-count bounds; positive
nr_open<=1073741816; occupied FD indices<1073741816; finite ten-digit hard NOFILE
<=9999999999; both32MiB census caps; and every existing namespace, mount, mapper,
device, memory and filesystem predicate. No task limit is repaired and no numeric
resource profile is widened.

ADR0063's conditional future user FD-slot bound remains
32767*max(9999999999,1073741816)=327669999967233. Its premises are initial all-task
admission, fork/exec inheritance and preservation of the selected trusted kernel,
globals and guest programs. That theorem does not require static future FD sets.
Current occupied-index observations and this conditional future bound are separate.
Actual host/VM containment, physical guest RAM/backing storage, original deadlines
and independent whole-target retirement retain their own authority; host QEMU/SSH
PID limits do not become guest-task limits.

Two completed scans are sampled, non-atomic censuses. They prove no continuous
all-task census or absence of transient/ABA changes. Earlier byte equality was not
an atomic proof either. Hostile guest root changing trusted globals remains outside
the accepted premise. Within-scan races remain conservative refusals: this finite
correction resolves the demonstrated between-completed-scans seam, without promising
native fit or eliminating every possible race.

This supersedes only the post-create universal-equality requirement in ADR0063's
admission facts and ADR0062's inventory description, and clarifies ADR0066/docs
wording that described all receiver equality as unchanged. All three earlier stable
checks and the existing initial30-second scheduling interval remain unchanged.

## Accounting, history and verification

The exact reviewed receiver is65354 bytes, SHA-256
`19c958a58fbfdd42085f6a2380807de5d23649d5aa7f1d9e9150ee5617a28983`.
Shortening only the inventory comment makes space for the internal phase guard.
The65408-byte integration envelope and65536-byte hard cap remain. The inventory
body and downstream node corridor are unchanged. There are zero added proc reads,
utility/native launches, processes, helpers, scan passes, raw roles or wire fields.
Native70/5/75 action counts, rootful680+24+64 utility partition, stage256 reservation,
all capture/input/output/resource caps and actual1800/1680/120 timing remain unchanged.
First failure, poison, incoming exit capture, early site clear, real delete failure,
private durability/public redaction and outside retirement retain their contracts.

V8 wire members/code meanings and all historical schemas/evidence remain exact.
Keep old inv-drift decoding, including failed historical V8 results. Advance only
the receiver source epoch/enrollment, with a strict current-source-to-frozen
65408-byte d265f883 V8 inverse before unchanged earlier source inverses. Preserve
all564 predecessor test IDs/assertion inventories,314 literal patterns and immutable
fixtures. Historical first-V8 inverse controls name their frozen domain explicitly.
No new diagnostic schema, code layer, default normalization, dependency, pin,
manifest, API or Renovate ownership is introduced.

Pure controls use two prepared private proc-shaped trees to model benign FD/task/
valid-limit changes between scans. They preserve stable refusal, all live malformed/
access/bounds/count/cap/incomplete failures, final-map replacement and selected-node
cache/start/cgroup refusal. No actual proc or runtime is queried. Exact current and
historical source seals, final pinned formatting, focused checks, independent review
and the complete primary-owned gate remain necessary before later native adoption.
These controls do not establish native success, readiness, conformance or a new run.

[ADR0086](0086-owned-node-cgroup-membership.md) later refines only the g predicate
from leaf/root equality to canonical owned-subtree membership. The unchanged-corridor
claims above describe this phase source step; the selected PID/cache/stat reads,
phase behavior, resources and history remain. No new namespace/framing claim follows.
