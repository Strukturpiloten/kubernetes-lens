# ADR 0072: Conditional prepaid post-create private prefix

Status: Proposed for issue #62; complete validation and native qualification remain pending.

## Context and narrow refinement

The retained legacy attempt returned failed with kind-create and kind-delete statuses
both 0 and source deployment not reached. Its log/startup retirement gate was not
established. Final collector metadata reported 7826 stdout bytes, but their body was
not retained. This neither establishes absent startup text nor identifies the failed
gate predicate or underlying cause. The original failure remains authoritative.

This decision refines ADR 0065 only by admitting actual create status 0 in the same
failed, pre-readiness private-prefix scope and by requiring conditional four-ticket
prepayment. It does not change historical attempts, fixtures or ADR 0068's separate
work-paid kind-create stderr/attribution mechanism.

## Decision

The existing fixed `node-init-stdout-prefix` role may retain already-collected node
initialization stdout when create status is an actual integer from 0 through 255,
source application submission was not reached, and the existing startup/log
retirement gate was not established. The host still requires a failed result,
`complete=False`, `logs.state=not-established`, `startup_marker=False`, exact owner,
plan and source-spec bindings, collector metadata, length, canonical base64 and hash.
Unattempted create (-1), successful results, established log retirement and
post-application results remain ineligible. No native status or unknown value is
rewritten to make evidence eligible.

Mandatory kind deletion and its actual native collector waits finish before the
optional prefix operation. The existing six ordinary catalogue roles are paid and
encoded first; the optional prefix is admitted only at the fixed final role slot.
Short prefix credit therefore cannot starve already-affordable ordinary evidence.
Only cleanup mode may fund it. Before destination
redirection, prefix copying or publication, acquire four actual source-bound
single-use utility tickets from the existing 64 cleanup slots. The four tickets
pay exactly the existing `dd`, `stat`, `sha256sum` and `base64` invocations; catalogue
emission consumes the last three prepaid tickets without another debit. Ordinary
catalogue roles retain their existing utility charging. No utility is free.

Attempt admission once per execution. If fewer than four credits remain, preserve
unavailability: no prefix destination, copy or catalogue pointer is created, and
the original failure and completed mandatory cleanup survive. Every partial grant
remains spent; no reset, refund, retry, reissue or transfer from the 680 work slots
is admitted. The existing execution claim prevents a fresh execution epoch, and
persistent ticket/used-ticket records prevent reuse. An unused reserved ticket is
spent allowance, not proof that its program executed. Copy or catalogue failure
still refuses; prepaid allowance cannot establish successful capture or emission.

This is a conditional admission proof, not universal diagnostic availability.
The ordinary outer delete plus exactly four successful cleanup provider calls
costs 36 utilities; six ordinary catalogue roles cost 18; prefix handling costs 4,
for 58. Provider authentication spends two utilities before native-action admission,
and repeated cleanup verbs are not single-use. Consequently 58 is not a complete
all-branch bound, and aggregate ledger/utility observations cannot prove remaining
cleanup credit. The persistent 64-slot limit and four actual grants govern admission.
Other final evidence checks and caps may still refuse a fully prepaid prefix.

The original 680 work / 24 prepaid guards / 64 cleanup partition, native/output
partitions, absolute work/cleanup ends, 49 original queries, 314 fixed diagnostic
patterns and all retirement rules remain unchanged. The receiver remains within
65536 source bytes by shortening comments without changing their executable
neighbors. Current receiver enrollment follows the new bytes; immutable historical
source fixtures and expectations retain their original identities through exact
test-only inversions and explicit historical enrollment constants.

The role remains protected, `pre-readiness-node-init-only` and
`diagnostic-prefix-only`, capped at 16384 bytes within the existing 128 KiB raw
aggregate and 256 KiB private wire. No new observer, query, provider call, general
application logs, caller path, role, schema, helper software, dependency or quota
is introduced. Private artifacts remain exclusive 0600 files under a 0700 parent.
Public receipts contain only protected role/size/hash/reference metadata.

## Validation and limits

Pure controls exercise actual create0/delete0 failed wire, binary preservation,
0/1/2/3-credit denial without destination creation, exact four-credit success,
all six ordinary roles surviving the same prefix-credit shortages,
sticky partial admission and unused-ticket conservation, repeat/single-use refusal,
copy/catalogue faults, work-pool separation and mandatory-cleanup-before-prefix
ordering with the original nonzero exit retained. Existing scope, integrity,
redaction, cap, historical source, query and pattern controls remain required.
These controls establish neither the old missing body or cause nor fresh native
success, readiness, retirement or conformance. The primary owns independent review,
the final complete repository gate and any separately adopted fresh native attempt.
