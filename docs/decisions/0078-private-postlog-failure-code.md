# ADR0078: Private post-log first explicit-fail code

Status: Accepted source contract; independent final source review, complete validation
and separately adopted native qualification pending (#62).

## Context

The independently reviewed V18n outcome is failed-retired: create0/delete0, accepted
seven-role logs with genuine collector EOF and marker, source Deployment not reached.
No retained node-inspect body/status/code identifies the failing action. Do not infer
or retroactively assign a cause. A bounded private discriminator may distinguish an
actually entered existing fail from a last-entered stage without new observations.

## Decision

Explicit `kubernetes-lens-owned-rootful-result-v5` adds required nullable
`postlog_failure`. The only non-null strings are `pl1.r` (post-log resource check
and helpers), `pl1.i` (owned node-id read), `pl1.f` (64-hex node-id predicate),
`pl1.n` (fixed native container inspect and guards), `pl1.j` (existing inspect jq
action/result guard), and `pl1.e` (node-inspect role/path enrollment guard).

Set a closed active label immediately before each original action, without changing
its invocation context or errexit. Record only inside actual existing `fail()` in
parent `BASH_SUBSHELL == 0`, authenticated execution intent/admission and work mode,
with first assignment immutable. Reset and unexport both variables at startup.
Clear the active site after successful remember. Site entry, skipped calls, child
or subshell fail, ERR, signals and direct IO errors bypassing fail produce no code.
Null is absence of that observation, never proof of success or a runtime cause.

Finish MUST retain its existing FIRST `local status=$? ...` capture, THEN clear
the active site, before trap changes, pace closure, diagnosis, cleanup and evidence.
Keep the recorded first code. Clearing before capture would destroy original failure
status; cleanup fail must neither fill null nor replace a code. Preserve original
ERR/HUP/INT/TERM traps, poison and cleanup semantics.

Decode non-null only in v5 failed/create0/not-reached records with strict integer
create status, complete seven-role positive v4 logs, marker true, genuine EOF and
collector statuses, null native wait/signal and no ordinary node-inspect catalogue
member. Positive v5 results require null. Preserve normal catalogue and node-inspect
semantic checks. V5 uses exact v4 logs rules, including rejection of direct-wait-zero
and pg1.n. Never place these codes in logs.state or alter successful logs.

V1–v4 retain exact old key sets and historical source/evidence domains. No default
null or global normalization applies to old records. A separate sealed v5-to-v4
inverse restores the exact63399-byte C334 source before the unchanged strict v4-to-v3,
v3 pacing/diagnostic, v2 and v1 inverses. Keep all314 prerequisite patterns and
all507 original test IDs. Current enrollment seals bind only the current source.

This adds no actor, query, capture, role, catalogue member, tool, credit, cap, clock,
deadline or retry. Keep receiver at most65536 bytes and all existing native, utility,
output, source and wire limits. The scalar uses only existing private durability
and receipt paths; no public code, raw value or new attribution message is added.

## Verification and limits

Pure local Bash/Python projections retain original statement order and helper call
contexts. Focused controls exercise all six actual fail sites, helper guards,
parent-only assignment, inherited reset/unexport, null success/skipped/ERR/signal/
subshell paths, immutable first code and real finish status capture/cleanup order.
Decoder tests cover codes/types/context/log facts/catalogue refusal, strict history,
future-version refusal, private persistence, genuine delete failure and existing
worker/parent retirement and public-redaction paths. They launch no target tooling.

This narrowly supersedes ADR0077's current outer version/inverse entry seam only.
Final independent review and complete validation remain the primary's responsibility;
native qualification needs separately adopted authority. Source evidence establishes
neither V18n's failure cause nor native success, readiness, publication or a new attempt.

## Narrow v6 extension

[ADR0080](0080-private-postlog-native-status.md) supersedes only the current outer
result version/member set and inverse entry seam. It retains this ADR's exact v5
six-site meaning and adds a private snapshot of four already-obtained statuses for
pl1.n. V5 objects and evidence remain unchanged; a separate strict v6-to-frozen-v5
inverse precedes the unchanged v5-to-v4 chain. No historical normalization applies.
