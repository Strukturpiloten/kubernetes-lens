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
