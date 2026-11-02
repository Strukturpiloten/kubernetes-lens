# ADR0088: Closed node-readiness conjunct evidence

Status: Proposed bounded source contract; scratch controls passed, independent
candidate review, canonical formatting, complete gate and native qualification pending (#62).

## Evidence and decision

V27 remains failed/spent: V9 pl2.k/k1.i, create0/delete0, no retained NodeList,
utility return or predicate atom. k1.i proves an active parent-failure group only;
utility admission can refuse before jq, or the final ready guard can fail with i
last active. The corrected independent review does not prove jq ran or any specific
conjunct evaluated false. Neither expected patch nor counters repair that gap.
No wait/pacing/readiness behavior change or retry is justified by this evidence.

Explicit V10 retains the V9 outer fields/pl2.k. It adds only finite private i reasons:

| Token      | Source-bound observation                                                                        |
| ---------- | ----------------------------------------------------------------------------------------------- |
| k2.i.R.p   | Fresh round R1/2; existing parent utility refusal before dispatch admission; return unavailable |
| k2.i.R.c   | Admitted classifier call returned64: first false check is sole-item count                       |
| k2.i.R.n   | Returned65: first false check is owned node name                                                |
| k2.i.R.v   | Returned66: first false check is expected kubeletVersion                                        |
| k2.i.R.r   | Returned67: first false check is Ready=True existence                                           |
| k2.i.R.e.N | Other obtained nonzero N1–255; no failed atom inferred                                          |
| k1.i       | Active i without a complete new witness; no stronger claim                                      |

R is exactly1/2; error N excludes64–67,0,leading zeros and values above255. First
false means first in original short-circuit order, not the only false atom. Unreached
checks are not evaluated or assigned outcomes. Missing/empty/malformed fields retain
the existing predicate's truth/error behavior, without coercion/default-empty fixes.
These are command-call observations, never proof of kernel exec/process exit or a
particular API/controller cause. postlog_native remains null for i.

## One existing jq invocation and original acceptance

The same already-budgeted jq call reads the same already-captured NodeList file.
It uses a constant-state reducer over its existing input stream: per root, evaluate
exactly the original ordered count/name/version/Ready checks, retain a fixed code,
then use the last outcome. Empty input remains4. Per-root evaluation error is5 and
later inputs can replace it, matching the actual jq1.8.1 CLI; malformed input aborts5.
Do not halt at the first root or slurp/reorder inputs. This preserves last-output
truth, including false-to-true and error-to-true streams accepted by the original.

Success still returns0. Ordinary false numeric1 deliberately becomes its classifier
code64–67; zero/nonzero acceptance is unchanged. Non-false errors retain observed
codes in the fixed conformance cases. halt_error receives only an empty constant,
so reserved false codes emit no stdout/stderr/body. Errors are opaque numeric returns;
no NodeList, name, version value, condition message, kubeconfig or credential is
retained in a new role. No scratch output file/channel, reader, pipe or wait is added.

## Admission, round and first-failure custody

Reset/unexport i_admitted/i_return/i_round at startup; reset each reached i entry,
copying only the existing two-value round variable. The dispatch marker is set only
for the existing parent i jq call, after all allowed-command/ticket/read/binding/
single-use guards and immediately before dispatch. It is source-control admission,
not OS launch proof. The first statement of the original if false branch saves its
existing return before any assignment can overwrite status. The utility command,
conditional context and original loop/continue policy are unchanged.

Only the original first admitted explicit parent fail freezes a token. Prearmed
labels, child failures, ERR/signals and incomplete/contradictory caches supply no
new claim. First-round rejection followed by success commits none. Ordinary exhaustion
retains only last rejected second-round DATA. A second-round helper refusal cannot
borrow a prior atom/status. Other groups ignore stale i caches; earlier failure stays
immutable. Finish captures incoming status first, clears active site before cleanup,
and never invents an i failure from successful caches. Success plus delete19 retains
cleanup failure independently; no first i failure is manufactured. Whole-VM retirement
retains separate authority.

## Strict schemas, source history and limits

V10-only tokens require failed, strict integer create0, source not-reached, genuine
complete seven-role logs and ordinary integrity-checked node-inspect proof. Require
native null for i. Old pl1/resource/native and other k meanings remain. Exact key,
finite token/type/range/round/scope, revalidation/private wire equality and public
redaction remain mandatory. V1–V9 schemas/raw bodies stay exact; old V9 k1.i is not
retroactively assigned an atom. No default insertion or historical normalization.

A strict current-to-frozen65331-byte7fb07aa0 V9 inverse precedes unchanged history.
All596 prior IDs/assertion inventories,314 literal patterns and Rust remain. Existing
source-based controls explicitly choose frozen V9; new V10 controls use actual new
source. Current enrollment checks follow the new exact receiver. Audit aliased/shared
source readers, not only direct SCRIPT calls. Current future negatives advance only
toV11; genuine older fixtures stay unchanged.

Scratch raw receiver is65233 bytes, SHA256
9cd7ada881b04eef1283cd02dde3989a3a493dfb4a977d7c610d9316694d1d5b.
Before the same comment reclamation it is66303. Exactly1070 ordinary comment bytes are
reclaimed; shebang, ShellCheck and pure-control seam stay. The source remains within
unchanged65408 integration/65536 hard caps; canonical formatted final bytes and
current seals still need primary integration review. Removed prose contracts remain:

- Failed exec returns to poison/exit handling even with errexit; successful exec never returns.
- Original work/cleanup capture partitions reserve1MiB including4KiB for at most150 one-byte sentinels.
- Inherited writers close; owned collector waits require genuine source EOF.
- Census remains builtin and fail closed.
- Raw input uses one fixed exclusive file; Bash NUL removal still requires exact canonical cmp.
- Fresh official boot/authenticated constructor supplies initial namespace authority; live proc checks do not replace it.
- Owned network name/routes do not prove bridge absence; live/dangling links still refuse.
- Compare argv arrays, never joined shell strings; jq variables use --arg, not interpolation.
- The fixed private prefix role accepts no caller path or arbitrary application log.

Every runtime/resource/deadline/counter remains: native70/5/75, original utility/
record-guard/cleanup/stage partitions, input/output/raw/wire/storage/FD/PID caps and
1800/1680/120 timing. No extra query, external utility, process, wait, sample, retry,
pacing, controller or operational pin. Current code remains fail closed when budgets
or owned file operations refuse.

## Focused evidence and qualification boundary

A temporary official jq1.8.1 static fixture oracle (not an installed tool or a guest
RPM equivalence claim) is SHA256
020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d.
Primary verified its official release digest and published checksum list. Scratch
469-case/940-invocation original-versus-classifier controls cover four atoms, types,
short-circuit/unreached errors, all ordered variant pairs, multi-root/error recovery,
empty/malformed/trailing input and16KiB boundary; zero/nonzero and non-false codes
match. Controlled file/usage/compile errors also match. Reserved codes emit no body.
This artifact is temporary conformance tooling, no operational inventory/Renovate
owner change, no binary/source redistribution or upstream implementation translation.
Official artifact provenance is the jq1.8.1 release at
<https://github.com/jqlang/jq/releases/tag/jq-1.8.1>; the source notice at commit
4467af7068b1bcd7f882defff6e7ea674c5357f4 has COPYING SHA256
ad2b4a266b2268939c1446979759706077421cf906a203aa188c6f396e8cfd74.
That notice includes jq MIT, documentation CC-BY3.0 and bundled-component terms;
it does not attest every linked component in the release binary. Oracle invocations
compare the original -e and proposed -en programs with identical --arg node/patch
bindings and private fixed input files; only the reviewed program/options differ.

ReadinessAtomReceiver/Decoder/Parent controls exercise original admission guards,
caller/round/interrupt/first-snapshot/finish behavior with mandatory fixed DATA,
all512 token forms, strict old/new schemas, shared budgets, private durability and
redaction. Default gates invoke no official jq/runtime through these model controls.
Oracle/source facts remain distinct from native kernel/API/controller qualification.
Main owns final formatting, independent review, full gate and any later separately
adopted exact-candidate native attempt. No V27 root cause or automatic retry is claimed.

## Proposed successor

[ADR0090](0090-ready-condition-text-class-evidence.md) adds explicit V11/k3 same-input diagnostic
classes only. This V10 contract, including opaque k2.i.R.e.68/e.69, stays exact; old evidence is
not relabelled. It adds no wait/query/pacing change or CNI-cause/native claim.

## Current V12 policy successor

[ADR0091](0091-owned-node-ready-wait.md) proposes a separately versioned source-only
wait gate and hard refusal after it. The V10 diagnostic-only two-round/continue
contract above remains frozen; its outcomes and exact source history are unchanged.
