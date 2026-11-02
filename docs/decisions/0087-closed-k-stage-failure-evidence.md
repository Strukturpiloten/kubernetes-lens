# ADR0087: Closed private k-stage failure evidence

Status: Accepted bounded source contract; pinned formatting, independent final review,
complete validation and separately adopted native qualification pending (#62).

## Context

V26 remains failed-retired/spent: V8 pl2.k, create0/delete0, native69, utility627,
positive seven-role logs and ordinary node-inspect. Its native/reason fields are
null and no downstream k command capture/status was retained. Aggregate counts
and expected server patch do not establish the exact cause or observed API version.
The source Deployment not-reached marker means the final scenario was not accepted;
it does not prove each downstream command was skipped. V24's g cause remains unknown.

## Decision

Adopt explicit kubernetes-lens-owned-rootful-result-v9 with exactly the V8 members.
Keep postlog_failure=pl2.k and all existing first admitted explicit parent-fail rules.
Only at V9 pl2.k, reuse private postlog_reason as one closed k1 scalar:

| Scalar | Active existing action/helper/guard group  | Native object |
| ------ | ------------------------------------------ | ------------- |
| k1.a   | Config-view native call                    | Required      |
| k1.b   | Config-view jq/utility checks              | null          |
| k1.c   | Version native call                        | Required      |
| k1.d   | Server-version jq/utility checks           | null          |
| k1.e   | Current readyz native call                 | Required      |
| k1.f   | Existing captured-readyz read_file         | null          |
| k1.g   | Consumed readyz REPLY equality             | null          |
| k1.h   | Current get-nodes native call              | Required      |
| k1.i   | Owned-node/version/Ready jq/utility checks | null          |
| k1.j   | Namespace-create native call               | Required      |
| k1.k   | Existing fixture hash utility/substitution | null          |
| k1.l   | Existing fixture hash/path equality        | null          |
| k1.m   | Server-dry-run native call                 | Required      |
| k1.n   | Returned Deployment jq/utility checks      | null          |

A prearmed label identifies the active group when an existing explicit parent fail
commits. It proves neither tool launch, predicate evaluation/falsehood nor Kubernetes
cause. An existing helper may refuse before jq, or a native clock/poison/resource
guard before kubectl. Do not promote the label into an unevaluated predicate result.
ERR/HUP/INT/TERM still exit through original traps, without calling fail: an interrupt
between label and statement supplies no code/reason/status. Child failure alone,
unadmitted/skipped/cleanup actions and unclassified exits likewise supply no claim.

Keep both original readiness rounds and every existing continue. A rejected first
round followed by success commits no diagnostic. Ordinary exhaustion commits only
at the existing final ready guard: the scalar describes the last rejected check in
the second round (e/g/h/i), not first-sample history or a timeline. An existing
explicit helper refusal commits immediately instead. A poisoned next native entry
may refuse before launch, and its fresh unavailable status does not describe the
preceding round. Preserve every command, argv, check, read, wait, OR/if/continue
context, count, order, loop, deadline, retry and resource reservation.

## Status availability and immutable first failure

Reset/unexport k_site at startup. Reuse the four existing private status caches,
resetting all four at each k native entry before its first guard. Copy only at the
original command-call result and two actual owned collector wait assignments while
site n/k is active. Preserve the n reset/caller semantics. At six k call sites save
the existing nonzero return before the same fail/continue. Never obtain statuses
from last_* at fail or finish. Freeze JSON only at the original FIRST admitted
parent fail; later action/round/cleanup cache mutations cannot change it.

Native groups require the same exact four-key object as ADR0080: four nulls before
observations; null return plus known command and zero capture waits on the final
clock-check group; or four known statuses after nonzero return. Return is strict
integer1–255; command/waits strict integers0–255. Partial observations, bools,
return0 and impossible relationships refuse. Capture failure requires return125;
otherwise return equals command. Command status is the command-call subshell result,
including possible descriptor/exec failure, not proof of kubectl process launch or
exit. Final-clock form does not prove numerical deadline exhaustion rather than a
clock helper refusal. Validation/helper groups require native null even after a
successful earlier native call.

Retain parent BASH_SUBSHELL0, admitted execution intent, work mode and empty first
code. Retain original poison/exit propagation. Finish's first statement captures
incoming status, then clears postlog_site before trap changes, pace, diagnosis,
cleanup and emission. Still-set k_site has no authority after this clear. Neither
finish nor deletion fills/overwrites evidence; actual delete failure is independent.
Invalid/unset stages are never repaired or inferred: V9 k without a valid scalar
refuses strict decoding.

## Codec, history and privacy

V9 k requires failed, actual integer create0, source not-reached, original positive
complete seven-role log proof and ordinary node-inspect. All original owned node,
image/network/args/PID/cgroup and raw/catalogue integrity checks remain. Require
exactly k1.a–n and a native object iff the scalar is a/c/e/h/j/m. Type-check reason
before set lookup; malformed lists/dicts must refuse through structured validation.
Other V9 codes keep V8 semantics, including resource reason only pl1.r and native
status only pl1.n outside k. Positive/null-code results require null new meanings.
V1–V8 retain their exact schemas/key/code/evidence domains; V8 k still requires
native/reason null. Do not add defaults or reinterpret old receipts. V26 stays failed.

Private wire/durable equality and repeated decoding revalidate these fields. Public
CLI/descriptors gain no code, reason, status or raw output. No new field/catalogue
role, kubeconfig, body, path, arbitrary message, observer or acquisition is added.
The new strict V9-to-frozen65359-byte237b5a10 V8 inverse precedes the unchanged
owned-cgroup and older inverses/constants/seals. Historical inverse/V8-emitter
controls explicitly select that frozen source; current V9 receives separate controls.
Preserve all580 predecessor IDs/assertion inventories and314 prerequisite patterns.
Only current future-version negative boundaries advance from V9 to V10.

## Envelope and original safety contracts

The reviewed raw receiver is65309 bytes, SHA256
6fd1d3d0f4f314968c54146e6bb2553c0eeb0188ce3a9747c52dd2b60b2d5886.
Canonical formatting yields current65331 bytes, SHA256
7fb07aa0ffbf0f62968a6355ad02bccd6034e9496d424820806064329694c2d4.
It fits unchanged65408 integration/65536 hard caps; exact current source enrollment
and the V9-to-frozen V8 inverse bind these formatted bytes. Eight ordinary comment
lines reclaim597 bytes without changing these original rules:

- RPM diagnostics run only after the original exact tuple predicate fails; captured
  values stay private and the bounded builtin loop chooses only fixed codes.
- Atomic O_EXCL tickets remain permanent, including denied/unused prepayment.
- Two fixed normal-I/O capture helpers have no polling service. The actual receiver
  owns both process-substitution PIDs and waits each. Each dd reads at most max+1;
  the extra byte is a pre-reserved overflow sentinel, never truncation proof.
- Kernel process identities never grant signal authority.
- The bounded private collector requires original dd EOF/size proof of source closure.

No installed tool/version/pin/dependency, operational definition or Renovate owner
changes. The receiver digest is source enrollment, not an operational tool pin.
Retain all original native70/5/75 action counts, utility/work/guard/cleanup/stage
partitions, input/output/capture/wire bounds, FD/PID/resource limits and original
1800/1680/120 timing. No new read/query/wait/process/loop/retry/budget is introduced.

Pure controls cover actual finite recorder scope/interruption/reset/first snapshot,
fixed-DATA complete k traces and readiness continuations, original native command
and collector waits, cache freshness/poisoned next entry/final clock forms, real
finish with delete0/19, strict schemas/history/private durability/revalidation and
public redaction. Every apparent runtime/proc helper is projected before execution.
These controls establish no runtime cause, readiness or native conformance. Primary
owns pinned formatting, final source review and complete validation; any future
native attempt requires separate exact-candidate adoption and fresh budgets.

This refines ADR0084's broad k attribution and only the current outer version/source
epoch of ADR0086. Membership, namespaces, capture closure and whole-target retirement
remain independent and unchanged.

[ADR0088](0088-node-readiness-conjunct-evidence.md) proposes V10-only refinement of i
with finite first-false atom, pre-dispatch and obtained-error/round tokens. This V9
contract/raw evidence remains exact: old k1.i still proves no jq execution/falsehood.
Other groups, readiness acceptance, budgets and retirement remain unchanged.
