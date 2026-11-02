# ADR0090: Closed Ready-condition text-class evidence

Status: Proposed V11 source contract; scratch controls passed. Independent candidate review,
canonical formatting/final seals, complete gate and any fresh native attempt remain pending.

## Decision and evidence boundary

V28 remains a failed/retired V10 run. Its k2.i.2.r is source-bound return67, meaning no Ready=True
on the decisive second-round classifier root after count/name/kubeletVersion checks. It proves
neither a specifically False condition, CNI/preload cause, kernel exec nor future compatibility.
No NodeList/condition body or exported log body was retained. This successor does not rewrite it.

Use the SAME existing bounded NodeList and SAME one jq invocation/input. Only after the original
Ready predicate returns false, distinguish no Ready-type condition and a Ready-type condition
whose supplied string message contains the fixed literal NetworkPluginNotReady. All remaining
no-Ready-True cases keep the generic Ready class. A marker means supplied-text classification,
never proof of CNI cause, missing preload, runtime failure, kernel exec or independent process exit.
No raw NodeList, reason/message, host/user data, credentials, log body or extra output role is added.

Explicit V11 retains the same outer fields/pl2.k/native-null i contract. Its namespace is k3.i.R:

| Token suffix | Obtained source-bound fact                                                             |
| ------------ | -------------------------------------------------------------------------------------- |
| p            | Existing explicit utility refusal before dispatch, fresh round1/2                      |
| c / n / v    | Original first false count/name/kubeletVersion return64/65/66                          |
| r            | Return67: generic no Ready=True after the ordered checks                               |
| x.68         | Return68: no condition with type exactly Ready                                         |
| x.69         | Return69: a Ready-type condition supplied a string message containing the fixed marker |
| x.N, other N | Obtained other canonical nonzero1–255 excluding64–67; opaque error/exit, no atom cause |

The two new x codes have meaning ONLY for V11 under the exact helper/program/source/invocation
binding and existing admitted-return premises. V10 k2.i.R.e.68/e.69 remain old opaque exits.
Foreign/cross-version namespaces, leading zeros, bools, out-of-range returns, missing context or
contradictory caches refuse or retain the original broad unavailable witness. No e.N aliases are
accepted in k3. i never gains native status. Other k/native/resource meanings remain unchanged.

## Exact acceptance, stream and privacy contracts

Count/name/version priority stays exact. Factor the selected node only after the count check;
project its conditions only after the original name and version checks. The original any of
Ready=True runs FIRST, retaining its short circuit: any True succeeds even with duplicate Ready
entries, marker-bearing other entries, malformed messages or unreached later condition faults.
A condition fault reached by that original any still returns the original evaluation error;
new message matching cannot hide it or override it with an earlier marker.

Only the original false branch inspects metadata. No Ready-type wins even when a non-Ready entry
has the marker. Message matching accepts strings only; absent/null/bool/number/array/object fields
cannot become marker evidence or introduce a new filter error. Duplicate Ready entries without
any True can supply the marker. No inference that status was False follows from the text class.
Empty conditions can mean no Ready type; malformed/missing/null iteration retains the original
error behavior rather than being coerced to an empty list.

Retain the constant-state last-root reducer, original per-root error5/later-root replacement,
empty4 and parse/error behavior. Success0 remains exact; false return67 is deliberately refined
into67/68/69. Counts/name/version false64/65/66 stay unchanged. halt_error receives an EMPTY
constant, not the input/error/message; false codes emit no stdout/stderr. Do not slurp, halt on
the first root, evaluate metadata before Ready acceptance, or add an output channel/helper.

Admission/reset/round/first-parent-failure custody is unchanged. First reject then success records
none; later refusal cannot borrow a prior marker; cleanup/signal/child-only behavior cannot invent
an i snapshot. Earlier immutable failure survives later return and delete0/19. No command/query,
wait/pacing/retry, counter, deadline, capture, catalogue role or public-output expansion occurs.

## Source specification, history and limits

The input source-spec constructor/request/resource contracts remain rootful-v1, byte/AST unchanged;
receiver/checksum/source binding still authenticates the current receiver and spec. No new input
keys, default, operational version/pin or budget is invented. Only the explicit result/decoder V11
and private k3 vocabulary are new. Old V1–V10 raw records/decoders remain exact.

A strict current-to-frozen V10 inverse restores65233 bytes /SHA256
9cd7ada881b04eef1283cd02dde3989a3a493dfb4a977d7c610d9316694d1d5b,
then unchanged V10-to-V9 and earlier inverses continue. Every609 predecessor method/assertion body
and historical function/constant is preserved under explicit source selectors/current-seal/future-
negative adaptations.314 stderr patterns stay unchanged. New successor controls use current V11;
old current-source controls explicitly choose frozen V10 before older inverses. Current enrollment
uses the exact new receiver. No old captured return68/69 is reinterpreted as this classifier.

Raw scratch receiver:65369 bytes, SHA256
b13c5b4b3f2782296c7764fb20475ac387bae803bde4075c7f3e1a137bec2283.
Growth136 leaves39 under integration65408 and167 under hard65536. There is no comment reclamation,
minification, lint suppression, cap increase or native policy change. Canonical formatted fit and
all final seals remain unqualified until primary integration. Native70/5/75, utility/record/output/
FD/PID/storage partitions and1800/1680/120 ends remain exact; kind still receives --wait0s.

## Controls and remaining qualification

The existing pinned official jq1.8.1 fixture oracle checks V10 vs V11 on synthetic JSON, including
independently expected two-class cases, private canaries, malformed fields, duplicates/True,
late faults, first-false priority, empty/parse errors, ordered multi-root recovery and16KiB input.
The sealed program hash binds that proof to the candidate. It is not a guest-RPM binary match or
native qualification; no new tool is installed/distributed. Original jq provenance/license limits
from ADR0088 remain. Default gates use mandatory fixed dispatch DATA and do not run a host jq.

New receiver/decoder/parent controls cover exact traces, refusal/freshness/interruption, immutable
snapshots, explicit new/old version domains, source-spec/resources, private durability/redaction,
real worker shared budgets/reaping and success/delete failure. All predecessor AST/history and
current-source aliases are audited. These controls do not substitute for the main's independent
review, formatting/final-byte seals, full complete check-only gate after the final edit and any
separately adopted fresh owned attempt. No automatic retry, CNI/pacing fix or native claim follows.

## Current V12 policy successor

[ADR0091](0091-owned-node-ready-wait.md) proposes one fixed owned kubectl Ready wait
before the unchanged strict classifier, with hard refusal after wait entry. V11/k3
and V29 remain frozen; supplied marker text grants no readiness or cause claim.
The successor is source-only and authorizes no native adoption or retry.
