# ADR0091: One owned-node Ready wait before strict validation

Status: Proposed V12 source-only prototype. Focused offline controls and canonical
formatting are evidence about this source candidate, not native qualification.
Primary review/integration, final complete gate and any separately adopted attempt
remain pending. No execution or retry authority follows from this document.

## Decision and history

Keep kind `--wait 0s`. After the first successful existing `/readyz` response,
invoke the already pinned kubectl with the private owned kubeconfig and fixed
`wait --for=condition=Ready nodes --all --timeout=30s` arguments. Successful
command and capture completion are necessary to proceed, never sufficient for
acceptance. Nonzero wait is a hard refusal at the new private native site `k4.o`.
After this invocation starts, no readiness-round transition remains: NodeList
native failure and every rejected classifier return refuse immediately. Only the
original pre-wait readyz failure/non-ok transition can reach round2.

Retain the original sole-node, exact owned name, kubeletVersion and AnyReadyTrue
checks in their original order, using exactly the same classifier program and
constant-state last-root/error semantics. Namespace creation, fixture-integrity
check, server dry-run and response validation remain mandatory. A successful wait,
create0 or text output cannot override a rejected strict predicate or cleanup.
The additional wait gate may conservatively reject a case the old predicate alone
would accept; it does not change that predicate's AnyReadyTrue short circuit.

V29 remains failed/retired V11 with `pl2.k / k3.i.2.x.69`: supplied Ready-type string
message classification after no Ready=True, not proof of a CNI cause or status
specifically False. No old failed trace is changed or assigned this new policy.
ADR0088/0090 unchanged-round/continue statements describe their frozen diagnostic
changes; this successor deliberately refines current orchestration only.

## Explicit V12 source, spec and failure domains

Current result and constructor spec use explicit V12. The existing guest spec-field jq invocation now first selects the explicit V12
schema, refusing a mismatched spec before native effects without a new utility.
The strict decoder requires
V12 results to bind a V12 constructor spec. Trusted source checksums and existing
request digest bind the actual spec. Input keys, forced SSH intents, request framing,
resource declarations and source-proof construction otherwise remain unchanged.

All current k stages use the closed `k4` namespace. Existing a–n sites retain their
corresponding operation groups; `k4.o` is only the new wait invocation. Native
snapshot scopes are a/c/e/h/j/m/o. `k4.i.R` retains the same classifier admission,
first-false atom and opaque return interpretation as frozen V11, now after the
wait gate; R is the actual original pre-wait round1 or2, never a retry count.
The historical repeated-classifier-rejection trace no longer exists in V12:
a first-round classifier rejection is now final. An R2 classifier can occur only
when round1 never entered the wait. Source-bound k3/V11 meanings,
V10 opaque codes and every older serialized domain stay exact and separate.

The first explicit parent failure, unavailable/fresh admission caches, interruptions,
signals, poison, privacy and independent cleanup status retain their existing rules.
Wait failure preserves only the existing obtained native-wrapper/command/capture
status tuple. It establishes no process-launch, permission-denial, timeout-cause,
readiness or CNI claim. No raw NodeList, condition/message, log body or new public
payload/capture role is added.

## Pinned CLI semantics and time boundary

The official kubectl1.20.15 implementation already supports this command. It
enumerates selected resources, lists by node name, checks condition strings and
uses a watch when needed; watch closure can cause relist/rewatch. This is one
native invocation, not one HTTP request or a new server-side wait verb. It performs
read-only API operations in the explicitly owned guest cluster, not live product
acquisition. No ambient context or backend fallback is introduced.

At this floor, condition type/status comparisons are case-insensitive and the first
matching condition decides. This differs from the strict exact AnyReadyTrue check
with duplicates. No-match, ordinary API/setup failure and wait timeout return
nonzero; watch error events can print an error and continue. This command is not a
new malformed-input validator or a permission-denial classifier.

The30s value is nominal, not a hard global or transport bound. This floor uses
unbounded-context initial list/watch setup, a timeout per resource, and a fresh
full timeout for a restarted watch rather than its computed remaining duration.
Multiple nodes or reconnects may therefore exceed30s. The existing original host
and guest absolute work/cleanup ends remain authoritative while the command blocks.
No new readiness deadline, timer, retry pool or promised successful fit is granted.

Official specification provenance: Kubernetes release source v1.20.15,
`staging/src/k8s.io/kubectl/pkg/cmd/wait/wait.go` (15411 bytes), options at88/136,
condition parsing at179, visit/error behavior at231, list/watch at362 and string
comparison at427. Source was read only through official GitHub raw documentation
GET; Apache-2.0, no implementation copied or mechanically translated, no source
redistributed and no tool executed as an oracle. Current Context7 CLI documentation
was consulted separately; newer observedGeneration behavior is not assumed here.
Operational binary/image/tool pins and their canonical BoxFerry ownership remain
unchanged, so no new software inventory or Renovate extraction is introduced.

## Independent call accounting and space recovery

Worst current readiness trace is2 readyz +1 wait +1 NodeList +1 classifier:
4 native work actions,11 output-work slots,8 sentinels and17 capture/classifier
utilities. The old two-full-round maximum was4/14/8/18. Each readyz and wait uses
stdout4096/stderr4096; NodeList remains16384/4096. Four capture utilities are
pregranted per native call; classifier uses one. Partial failures do not refund.
API discovery/list/watch/reconnect requests inside kubectl remain transparent
additional profile operations; native credits count actual native invocations.

All original aggregate limits remain: native70 work/5 cleanup/75 total;
utility680 work/64 cleanup plus24 guards; output245 work slots/10 cleanup slots,
150 sentinels and1MiB; original1800 total/1680 work/120 cleanup ends. Namespace,
dry-run, cleanup, storage, input, metadata, CPU/PID/memory/FD and outside retirement
bounds stay intact. No cleanup credit borrowing or successful residual-fit claim.
The log-retirement pacing FD still closes before native children; no helper,
channel, observer, role, provider query or FD lifetime extension is introduced.

The canonical receiver is65408 bytes, SHA256
`e5d4870bc9d3994f9c73d54cbeeb5abe322c9511a973f3f1d8870dd05b16a0b5`:
at integration65408 and128 below hard65536. The behavior delta adds222 bytes;
readable status/phase renames recover183, giving net growth39. Rename cached
`last_tool_status` to `tool_status` and the two `last_*_capture_status` variables to
`stdout_status`/`stderr_status`, consistently through native snapshots, kind and
finish. Rename the active prerequisite flag `initial_prerequisite` to
`prerequisite_mode` (18 bytes recovered) without changing its phase semantics.
The new names have no conflicting binding. No guard, comment, ShellCheck
rule, cap or validation was deleted or weakened; every wire key remains unchanged.

An exact current-to-frozen inverse restores65369-byte V11 with SHA256
`b13c5b4b3f2782296c7764fb20475ac387bae803bde4075c7f3e1a137bec2283`, then invokes
the unchanged predecessor inverse chain. Existing source controls explicitly
select frozen V11; new V12 controls explicitly read current source. Current-only
enrollment expectations migrate independently; old fixtures and assertions remain.

## Qualification boundary

Focused fixed-DATA controls cover success, pre-wait round transition, once-only
wait, every rejection class, hard native/capture/clock/utility refusal, independent
accounting, strict result/spec domains, private status custody, history and source
fit. They use the existing offline fake/injected facilities and qualify no actual
kubectl/server, selected guest primitive or native readiness. Main must review and
integrate latest main, run the serialized complete gate after the final edit and
separately choose any fresh exact-source attempt. V29 retirement sealing and all
failed/retired history remain independent; no automatic retry follows.

## Source-only capture diagnostic successor

[ADR0093](0093-capture-size-helper-status.md) refines only the existing ordinary
capture helper's checked-over-cap exit status under a new exact source hash.
The V12 wire/spec/k4 contracts and policy above remain unchanged; the byte/hash
section above identifies the frozen accepted V30 base, preserved by an exact inverse.
