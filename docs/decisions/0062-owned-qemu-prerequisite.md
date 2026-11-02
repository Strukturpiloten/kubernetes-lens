# ADR 0062: Explicitly owned QEMU prerequisite for rootful conformance

Status: Accepted source contract; native qualification pending (#62)

## Context

The existing rootless kind provider refuses when its complete helper lifetime cannot be bounded.
Historical kind 0.14.0 also refuses rootless Kubernetes before 1.22. Neither refusal can be removed
to obtain the required Kubernetes 1.20 evidence. A disposable guest provides a separate kernel for
rootful Podman while preserving the workstation's runtime stores, managers and workloads.

## Decision

Add an explicitly selected external `--owned-vm --phase qualify-vm` route. Its first component
qualifies only one disposable Fedora CoreOS QEMU guest and one authenticated rootful/local
Podman-info operation. It establishes no kind, Kubernetes API, resource or controller conformance.
The library and ordinary validation gates never boot a guest or acquire product input from it.

Use the official stable x86_64 QEMU archive selected by the single operational
`scripts/kind-vm-image.json` record. The harness accepts a previously acquired archive, verifies
the committed compressed digest before bounded decoding, and derives the official immutable URL.
Publisher-signature and license/provenance review remain explicit preparation obligations. Do not
build a replacement image, layer guest packages or create another shared Kubernetes tool inventory.

The outside owner and the target service have different resource contracts. The owner has finite
process/control-command limits and the original deadline. Before giving the worker permission to
start QEMU, it verifies the exact transient service invocation, peer process, cgroup inode and actual
finite CPU, memory, swap and PID limits. The target contains the worker, QEMU and SSH children.
Read-only host paths, a private writable directory, fixed argument grammars, no restart producers,
bounded streams and one cleanup reservation constrain the operation. This is a VM-specific barrier;
it does not satisfy the existing Podman object/proxy/client barrier by relabeling its states.

QEMU exposes no host share, runtime socket or external network helper. Restricted user networking
allows one host-loopback SSH forward. Ignition masks automatic OS updates and supplies per-run
client and host keys. The SSH client ignores ambient configuration and credentials, pins the host
key, and can request only the fixed guest command. A possibly executed guest command is never retried.
Installed host executables require an independently reviewed eight-role identity manifest; observing
new hashes is not automatic admission. The root-managed OS, loader and libraries remain trusted.

Success requires a genuine worker producer-stop barrier and independent outside observation of
manager inactivity, no new invocation or start job, recorded PID-start retirement and an empty or
removed complete cgroup subtree. Uncertainty preserves private evidence and cannot become a pass.
Earlier failures survive successful cleanup. All phases share the original monotonic end.

## Consequences

The existing rootless guards and product boundaries remain intact. Pure controls run in ordinary
repository validation; runtime qualification is explicit and separate. Official image updates have
one Renovate owner, coupled version/digest replacements, Dashboard approval and no automerge.
Missing publication timestamps hold updates under the existing minimum-age policy.

Full #62 acceptance still requires the rootful kind route, historical and modern node profiles,
independent native scenarios and a concrete hosted qualification lane. A VM prerequisite receipt,
an eventual runner disposal or a passing source test is insufficient for any of those claims.

The [lifecycle contract](../fixtures/owned-qemu.md) specifies command, resource, trust and retirement
details. The [dependency policy](../dependency-policy.md) owns pin and update obligations.

## Refinement: exact parent authority under a trusted constructor

The source profile keeps strict host-root tool authority in the outside parent
and separately checks the worker's exact mapped presentation of those same
objects. It selects systemd's finite `PrivateUsers=self`/`PrivateMounts=yes`
profile, requires an independently proved immediate-child user namespace, and
refuses same/nested/managed alternatives. Typed constructor readback, zero
capabilities, no privilege gain, native-only syscall ABI, deny-all namespace
creation/switching and explicit mount/new-mount/root-switch/`clone3` denial are
mandatory before GO. The actual readonly cgroup2 descriptor and bounded
unchanged mount topology replace the earlier unsupported implication that
`ProtectControlGroups=` establishes readonly cgroups in a user manager.

The installed systemd 261.4 manager, kernel, loader and libraries remain an
explicit trusted OS boundary. Exact requested policy installation and ordinary
mount construction are trusted constructor premises. Status/filter counts and
mountinfo are independent consistency/drift observations; they are not claims
of dumped BPF, universal idmap detection or protection from hostile outside
administrators. Actual manager version/kernel metadata and safe host-view
bindings are retained. Selected typed normalization remains unqualified until
an actual owned run matches it and independent review accepts that evidence;
unknown values fail normally before GO rather than being self-approved.

Source loading, authenticated GO and every native-child boundary use the same
source/manifest/identity bindings and original finite budget. This refinement
adds no product live-cluster behavior, runtime fallback, custom observer or
qualification probe. The [lifecycle contract](../fixtures/owned-qemu.md) records
the exact observations, refusal behavior and remaining runtime obligations.

## Refinement: explicit source-bound input staging

A separate `--phase stage-inputs` route uses a fresh guest, an additional per-run
forced receiver key, and exactly three admitted binary-stdin transfers. It retains
the original info-only key/command and requires rootful/local Podman-info evidence
before staging. The existing ledger/canonical tool owner and complete unchanged
parent/amd64/config/layer/diffID/archive chain authorize inputs; a caller plan digest
alone does not. Exact legacy Docker schema2 media bytes may be preserved in a local
OCI selection envelope without claiming importer compatibility or source-parent
index identity. The receiver publishes no executable bytes before exact header,
length, hash and EOF checks; boot-bound cursor/inflight/poison state forbids retries.

All transfers share one actual worker Budget/Session and authenticated host-view
callback. Private source/plan/Ignition bindings, finite externally admitted SSH
producer identities, genuine reaps and outside whole-target retirement remain
mandatory. Storage reservations reduce the existing overlay allowance rather than
expand the original envelope. This source refinement and pure protocol tests prove
no guest runtime, image import, kind, Kubernetes API or controller conformance.
The [staging contract](../fixtures/owned-guest-staging.md) records explicit command,
provenance, byte protocol, budgets, retirement and unqualified assumptions.

The receiver's fixed command now uses `/var/lib/kubernetes-lens-stage/receiver`.
This supersedes the earlier design's `/usr/libexec/kubernetes-lens-stage-receiver`
placement: the harness must not rely on writable FCOS `/usr`. Ignition installs
source-authenticated receiver bytes inside the same root-only staging directory;
root ownership, exact file mode and checksum/forced-command bindings remain
mandatory. This placement decision is source contract, not a claimed guest run.

Fresh outside source/boot/tool readback is mandatory immediately before parent
key generation, manager-environment inspection and normal worker start. This
pre-child guard does not require not-yet-generated private inputs. Staging
reserves the full immutable compressed-archive ceiling for the external source,
not a preliminary stat; the original aggregate envelope never increases. Final
private receipts retain only the newly constructed strictly controller-validated
guest summary, never raw guest-info JSON or producer frames in its place.

## First rootful kind phase (source contract; runtime evidence pending)

`--owned-vm --phase run-rootful-kind` is a separate, genuinely dispatched route.
It retains the original parent 128 and worker 128 native counters. The actual worker
irrevocably reserves75 guest native actions and1 MiB guest captures from its own
original Budget before guest effects; its fixed host schedule has8 actions,
including QEMU start. No fresh nested 128, refunds or output allowance are created.
The fifth SSH producer carries at most4096 source-bound bytes, pre-reserved inside
the unchanged total input ceiling. The actual stdin writes, all five producers,
reaps, original absolute ends and outside whole-VM retirement remain mandatory.

The source-owned Bash receiver uses the pinned official guest's jq, never guest
Python. Native actions (including top-level kind and its lower Podman invocations)
predebit persistent atomic credit files; utilities have a separate768-token
predebit ledger. The unchanged three staging calls retain their static 256 utility
reservation, so the full source-bound utility ceiling is1024. Atomic Bash
noclobber claims require no uncharged flock or mv bootstrap. Unknown argv,
missing credit, drift, expiry, partial/extra input or failed acknowledgement cannot
renew a cursor. Raw outputs remain genuine private files; returned summaries
cannot turn failed kind deletion into success. Whole-VM retirement retires the
private network/store; no network-rm success is claimed.

The only first profile is rootful overlay on XFS, one owned guest virtio disk,
strict guest-only mapper control closure, one IPv4 network172.30.0.0/16,
pod10.244.0.0/16 and service10.96.0.0/16. Requested limits are2 vCPU,
4 GiB guest RAM,8 GiB host memory ceiling,256 host tasks and24 GiB aggregate
host storage. Actual guest pid_max must be32768; nr_open, every current hard
NOFILE and existing numeric FD indices must satisfy the reviewed1073741816
ceiling. Receiver namespace/proc and consistent PID/start inventories are required.
Trusted whole-guest OS/runtime/node programs must preserve these globals; this is
not a claim against hostile transient guest root or a bound on all kernel open-file
descriptions. No current guest task limits are repaired. Mismatched storage,
mapper, package, namespace, PID/FD, import or runtime facts refuse.

Each fresh legacy1.20.15/kind0.14.0 or modern1.37.0/kind0.33.0 run currently
plans only real bootstrap, exact owned readiness and one original Deployment
source server dry-run. Both native provider argv grammars are separate. Fixed
preserve import must retain publisher child/config identities; no conversion,
load or pull fallback exists. `--wait 0s` requires the receiver's genuine readiness
checks and establishes no nonzero native wait compatibility. Discovery, remaining
positive/invalid/generated cases, all 35 kinds, controller/application behavior,
other admitted profiles and hosted execution need separately budgeted fresh runs.
No source test, successful prerequisite or first smoke closes#62,#2 or#7.

The preceding shared hard-NOFILE/FD ceiling describes the historical v1
profile. [ADR 0063](0063-whole-guest-hard-nofile-v2.md) supersedes its hard
metadata ceiling and future user FD-slot theorem; the original current FD-index
and `nr_open` checks and every other resource limit remain unchanged. The v1
text and failed evidence are retained for comparison.

## Refinement: requested guest PID/FD boot profile

The rootful-only existing mode-0600 `/etc/sysctl.d/99-kubernetes-lens.conf`
requests `fs.nr_open=1073741816` alongside `kernel.pid_max=32768` during normal
owned-guest boot. This keeps the same file, metadata cap and existing admission
bounds. It does not alter host settings or repair already-created guest tasks'
hard NOFILE limits. Requested configuration is not proof of application: the
existing live reads, `0 < nr_open <= fd_max` predicate and task/FD inventory
checks remain mandatory and refuse mismatches.

The three existing PID/FD guards select distinct fixed initial-only refusal
codes (`pid-max`, `nr-open-form`, `nr-open-range`) without new observations or raw
value capture. Historical `pid-limits` and all prior whole-stream patterns remain
recognized; three additional patterns retain the original frame/stream bounds.
Queries, parsing, predicates, credit/capture pools, deadlines, poison and final
exit status remain unchanged. This refinement identifies no earlier failure
cause, proves no sysctl application or runtime/task-limit compliance, and grants
no runtime retry. See the [rootful contract](../fixtures/owned-rootful-kind.md).

## Refinement: rootful boot profile and same-boot transitions

Only the source-bound `run-rootful-kind` Ignition requests
`kernelArguments.shouldExist=["ostree.prepare-root.composefs=0"]`. The publisher
sources describe disabling Composefs and Ignition's internal reboot when kernel
arguments change. Only that QEMU phase omits `-no-reboot`. Normal internal resets
remain inside the same QEMU process, original PID/start/cgroup/overlay, absolute
work and cleanup deadlines, cumulative streams and existing resource budgets.
Exit remains failure; no host relaunch, retry, renewed deadline or refunded credit
is introduced. Reset count and cause are unobserved. Qualify and standalone-stage
arguments and serialized Ignition remain unchanged.

The rootful key dispatches only two literal host intents to the existing receiver's
prerequisite/execution roles. Caller command text is comparison data before the
existing `env -i`, never executable text. The prerequisite claims genuinely pristine
same-boot state once, publishes inflight before preflight and seeds the stage cursor
once under the existing stage lock. Complete ready0 and deadline/mode/claim bindings
are required before publishing `staged-required` last. Missing, partial, duplicate,
foreign or rebooted state never becomes a fresh fallback. Guest checks precede
subsequent payload/state/runtime effects; they do not precede the already-budgeted
host SSH producer spawn. Early refusals leave state untouched; admitted failures
retain poison and the outside whole-target retirement obligation.

The standalone stage receiver source stays byte-exact. Rootful staging uses a
bounded deterministic host-side transformation with exact unique disjoint literal
anchors. Its generated bytes, modes, checksum list, plan and Ignition entries bind
through the existing source/config evidence and unchanged 64 KiB metadata ceiling.
This preserves historical standalone output while selecting an explicit rootful
mode without initialization fallback.

[Immutable boot/QEMU facts](../../scripts/fixtures/owned-boot-profile-source-facts.json)
record commits, blobs, content hashes, licenses and source limitations. They support
a publisher-expected profile, not selected-image mount attestation or a diagnosis of
an earlier refusal. No new software inventory, operational pin, installation,
runtime acceptance or execution authority follows from this source refinement.

The exact-record refinement uses fixed, prepaid read-only `cmp` comparisons with
command-local here-strings and accepts only status zero. Deadline candidates must
also have a successful bounded LF-delimited read before complete comparison;
nonzero reads are not EOF evidence. The unchanged rootful utility allowance is
680 ordinary work plus 24 prepaid guards plus 64 cleanup. The 24 guards are
10 prerequisite, 5 execution and 3 per stage; the separate historical stage 256
reservation is retained without double charging. One nonblocking stage flock uses
an ordinary work credit. The original worker consumes each purpose before its
single producer's pre-child/launch boundary, with no replay/refund/reconstruction.
Guest fuel stays in memory before admission. Receipts distinguish reserved fuel,
unknown attempts on early failure, and authenticated completed comparison counts.
The existing execution claim is atomic after all five early predicates and before
ordinary preflight debits, so a duplicate loser cannot poison or debit the owner.
This relies on the explicitly trusted serial host and source-owned private records;
it introduces no new helper, observer, metadata/version query or total allowance.

[ADR0085](0085-phase-specific-guest-census.md) supersedes only universal post-create
inventory byte equality: the three earlier stable admissions retain it, while the
post-kind live phase keeps both complete per-record bounded scans and the final-map/
selected-node identity corridor. Numeric limits, containment, history and budgets
remain; sampled censuses establish no atomic or continuous all-task observation.
