# ADR0080: Private post-log native status snapshot

Status: Accepted source contract; independent final source review, pinned formatting,
complete validation and separately adopted native qualification pending (#62).

## Context

V19n remains failed-retired under v5 with pl1.n, create0/delete0, accepted log proof
and source Deployment not reached. This code identifies the fixed native inspect
action or its wrapper guards, not the particular predicate or a Podman cause. The
packet has no inspect result/capture statuses. Existing transient last_* statuses
are overwritten by cleanup before emission. Do not retroactively classify V19n.

## Decision

Explicit kubernetes-lens-owned-rootful-result-v6 retains v5 fields and adds required
private postlog_native. It is null unless postlog_failure is pl1.n, which requires
an object with exactly return_status, command_status, stdout_capture_status and
stderr_capture_status. A known return is a strict integer1–255; other known statuses
are strict integers0–255. Null denotes unavailable observation from this action.

Return status is the existing native false return captured before its original fail.
Command status is the existing command-call subshell rc, including possible exec or
descriptor failure, not proof of a Podman process exit or launch. Capture statuses
are the existing actual waits for the two owned capture helpers. No new observation,
query, wait, process, capture, catalogue role, raw body or output size is introduced.

Current explicit parent fails admit exactly three forms:

- Four nulls when no command result was obtained before the guard failure.
- Null return, a known command and two zero captures when the final clock guard fails.
- Four known statuses after native returns nonzero. Any nonzero capture requires
  return125; with captures0 the nonzero return must equal command status.

Reject partial triples, bools, out-of-range/wrong types, impossible relationships,
missing/extra keys and wrong scopes. Non-null requires failed/create strict integer0,
not-reached, complete seven-role positive log proof, null native-log wait/signal,
and no ordinary node-inspect catalogue member. Other/null codes and positive
results require null. Preserve the six-site pl1 contract and exact v4/v5 log rules.

Reset and unexport four caches and the snapshot at startup. Clear all four caches
immediately before the one fixed n invocation; never populate from prior last_*
values at failure or finish. Copy only at original result/wait assignment points
while the active site is n. Keep native on the same left side of its existing OR
context; its false handler saves the existing nonzero status before the same fail.
Freeze JSON only in the existing FIRST admitted parent fail assignment, only for n.
Later native updates cannot change this immutable snapshot. Child/subshell fail,
ERR or signal without an actual parent fail never invents a code or object.

Finish MUST keep its FIRST original local status=$? capture, then clear active site
before traps, pace, diagnosis, cleanup and evidence. Cleanup may overwrite transient
last_* values but cannot fill null or replace the first snapshot. Preserve original
failure/poison/status propagation, successful logs, public redaction and durability.

This narrowly supersedes ADR0078's current outer schema/member set and inverse entry
seam. V1–v5 keep exact schemas and source/evidence domains, without new default fields.
A separate sealed v6-to-frozen63958-byte19bd89 v5 inverse precedes all unchanged earlier
seams and constants. Preserve every519 existing test ID and314 prerequisite pattern.

## Verification and limits

Pure fixed-DATA native projections exercise original guards, command/capture result
points, actual owned capture waits, old/new call order and returns, fresh pre-action
availability, inherited reset/unexport and immutable first failure through finish.
Codec controls cover finite forms/endpoints, partial/type/range/scope/history refusal,
futurev7, private durability, real mocked worker/parent budgets, producer/VM retirement,
public redaction and genuine delete failure. They launch no target tooling.

Raw receiver size is64608 bytes,650 above the frozen v5 source. The authorized added
budget is at most1200 and the formatted target at most65158 within hard65536. Exact
pinned formatting/size, independent source review and final complete validation remain
primary responsibilities. Keep all native70/5, utility680/24/64, output/raw/wire/source,
clock/deadline and retry limits. No cap increase, new observer, native attempt or
publication is authorized. Obtained statuses establish neither cause nor conformance.

## Narrow v7 extension

[ADR0081](0081-private-postlog-resource-reason.md) adds a private first-existing-reason
scalar only for pl1.r and supersedes only the current outer member/version and
inverse entry seam. V6 native status availability, finite relationships and historical
source/evidence meanings remain unchanged. A strict V7-to-frozen64608-byte V6 inverse
precedes the existing chain. V6's measured size/allocation remains historical evidence;
the successor fits its separately authorized addition within the unchanged65536 cap.
