# Explicit owned QEMU prerequisite lifecycle

Issue #62 adds an opt-in **VM prerequisite check**, independent of Kubernetes
readiness or native conformance. The existing rootless helper refusal stays in
force. No QEMU image, container, kind cluster or custom guest image is built by
this harness. The first phase cannot stage node images, access a registry, run
kind, tunnel a Kubernetes API, or execute arbitrary guest commands.

## Explicit inputs

Invoke the existing entry point with `--owned-vm` as its first argument:

```sh
python3 scripts/fixtures/kind_runtime.py --owned-vm \
  --phase qualify-vm \
  --image /absolute/path/to/reviewed-fedora-coreos.qcow2.xz \
  --host-tools /absolute/path/to/reviewed-host-tools.json \
  --host-tools-sha256 REVIEWED_MANIFEST_SHA256 \
  --output-parent /absolute/path/to/private-owned-directory \
  --cpus 2 --memory-mib 8192 --guest-memory-mib 4096 \
  --pids 256 --disk-gib 16 --ssh-port 22222 \
  --deadline-seconds 1800 --cleanup-seconds 60
```

Every option shown is required. The parent directory must already be owned by
the invoking non-root user, mode `0700`, without symlink ancestors. The selected
parent must also leave the complete private control-socket path within Linux's
107-byte pathname limit; an overlong parent refuses before image preparation.
The selected
port must be unoccupied. Only Linux x86-64 with usable `/dev/kvm`, a delegated
cgroup-v2 user manager, and the admitted host programs is supported by this
component. These are prerequisites, not claims of successful runtime evidence.

`scripts/kind-vm-image.json` is the sole operational image pin: its closed schema
has exactly `schema` (`kubernetes-lens-owned-vm-image-v1`), `release`, and
`archive_sha256`. The harness derives the official stable-stream immutable FCOS
x86-64 QEMU archive URL from that release. It performs **no download** and accepts
no caller checksum override. The source archive is copied privately while
hashing; both file identity and the committed compressed digest must match
before XZ decoding. A single XZ stream, at most 2 GiB compressed and 4 GiB
expanded, is accepted. Decoder memory is capped at 128 MiB. Trailing streams,
external QCOW2 backing/encryption/incompatible features and virtual disks over
32 GiB refuse. The base becomes read-only; only a fresh private overlay is used.
The compressed digest authenticates expanded bytes; the expanded digest is
recorded, not a second operational pin. Acquisition/signature/provenance review
is external; no signature check or download is silently implied here.

The reviewed tool manifest has this shape (all eight roles are mandatory):

```json
{
  "schema": "kubernetes-lens-owned-vm-tools-v1",
  "tools": {
    "qemu": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "qemu_img": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "ssh": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "ssh_keygen": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "systemctl": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "systemd_run": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "busctl": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    },
    "python": {
      "path": "/absolute/ordinary/ELF",
      "bytes": 123,
      "sha256": "64-lowercase-hex",
      "owner": 0,
      "mode": "0755",
      "version": "reviewed installed version"
    }
  }
}
```

The example contains placeholders and is not an admission record. Every binary
must be a non-symlink, root-owned ordinary ELF with root-owned non-writable
ancestors, no set-ID bits or file capabilities, and the reviewed bytes/mode/hash.
The Python role must identify the actual executing interpreter. `version` is
reviewed provenance bound by the manifest hash, not an inferred runtime probe.
The manifest is an explicit installed-tool identity receipt, not a second
installer, automatic self-approval mechanism or shared version inventory.
Root-managed loader/shared libraries remain part of the trusted installed OS;
ELF hashing alone is not whole-machine attestation.

## Boundaries and the single guest operation

The outside owner starts exactly one uniquely named transient **user** service.
Its worker first waits on a private authenticated Unix channel. The owner checks
the peer PID/start/group/session, host boot, exact unit invocation, kernel cgroup
identity and finite actual CPU/memory/PID/swap limits before sending `go`.
QEMU and SSH cannot start before that barrier. The unit has no restart, trigger,
upholder, failure/success follow-up or stop-command producer. A pending start
job, mismatched invocation or runtime timer extending beyond the original
execution end refuses. No ambient/global parent limits are changed.

The target service contains the worker, foreground QEMU, qemu-img and every SSH
child. It has CPUQuota, MemoryMax, zero MemorySwapMax, TasksMax, finite file/FD/CPU
limits, read-only host paths except the private run directory, and read-only
cgroup access. Guest RAM must leave at least 1 GiB inside the memory ceiling for
QEMU and worker overhead. This headroom is an explicit admission bound, not a
promise about actual memory pressure. Unit runtime/stop guards supplement the
observed retirement proof.

The outside owner is **outside** this target. Its own address space, CPU, core,
FD and file-size limits are separate, and every control subprocess has bounded
output, duration and resources. Each domain has at most 128 commands and 2 MiB
subprocess/channel output. Target limits never claim to cover the outside
owner. This VM-specific boundary does not coerce the older kind controller's
outer-slice or rootless producer-gate contracts.

Outside control commands use only the reviewed installed `systemctl`, `systemd-run`, `busctl` and
ordinary Ed25519 `ssh-keygen` modes, with a clean environment and no shell. Manager inspection,
stop and cancellation disable pagers and password prompting. This boundary trusts those exact
non-daemon control modes not to leave persistent helpers outside the target; it does not prove
a cgroup quota or generic descendant closure for arbitrary replacement control programs.

Loaded-service stop-command absence is checked through typed D-Bus properties,
not inferred from properties omitted by `systemctl show`. The reviewed `busctl`
role performs one read-only `get-property` for the exact owned unit object path,
interface `org.freedesktop.systemd1.Service`, properties `ExecStop` and `ExecStopPost`.
The command uses `--json=short`, no pager, the private manager environment, and a
built-in timeout of at most five seconds inside the original deadline. Exactly two
JSON objects must each have only `type` and `data`, with the exact systemd signature
`a(sasbttttuii)` and an empty array. Unknown or unsupported properties, command
failure, missing/extra/truncated/duplicate JSON, wrong types and nonempty arrays
refuse. The requested systemctl text inventory excludes these two complex fields;
semantic empty values are added only after successful typed proof. These interfaces
are documented in systemd's `busctl(1)` and `org.freedesktop.systemd1(5)`.
Simple unit/invocation/producer-policy observations before and after the typed
read must agree; replacement or disappearance cannot inherit an earlier proof.
The startup health-poll chain has one shorter absolute cutoff propagated through
both simple reads and the typed read. It charges the original Budget counters;
no call renews that cutoff or grants new output, commands or total time. A timed
out control child is killed/reaped inside the original cleanup reservation.

A stopped service may subsequently be unloaded. A simple readback of
`LoadState=not-found` is accepted only with the exact unit name, inactive state,
zero MainPID, no pending job, no invocation and no cgroup. This is a terminal
not-found observation, **not** proof that omitted complex properties are supported
or empty; those fields remain absent. Retirement still requires the previously
authenticated loaded invocation, genuine producer barrier, PID-start retirement
and two external kernel subtree observations. Arbitrary missing fields never
become empty values.

Private disk writes have a finite sum: expanded base at most 4 GiB, at most
2 GiB temporary compressed copy, overlay file size at most the selected total
minus those reservations and 4 MiB metadata headroom; metadata/key files have
individual 64 KiB limits and a fixed catalogue. RLIMIT_FSIZE bounds native
overlay growth. This is a fixed-file size bound, **not a filesystem quota** or
an assertion about arbitrary compromised-host writes. The base, keys and
Ignition inputs are rebound to private file hashes before native execution.

QEMU disables user configuration, default devices, monitor, display, reboot and
external process helpers. No QMP endpoint, host socket, filesystem share, tap,
bridge, external network helper or daemon mode is configured. The only network
is built-in user networking with `restrict=on` and one explicit
`127.0.0.1:PORT -> guest:22` forward. There is no registry/WAN access or host
service reachability granted by this mode.

Ignition masks Zincati before boot and installs per-run host/client Ed25519
keys. The client authorized key is restricted to the one forced command;
password authentication, agents, forwarding, TTYs and tunnels are disabled.
The host key is injected privately and pinned in the client's private known-hosts
file. SSH ignores ambient config, agents, proxies, multiplex sockets and global
known-hosts. A boot marker only schedules the one SSH attempt; it is not trusted
guest identity. The authenticated session executes exactly:

```sh
/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin /usr/bin/podman --remote=false info --format=json
```

The structured response must establish Podman `5.8.7`, rootful operation, local
service, Linux amd64 and cgroup v2. No guest Python, installer, package layering,
Podman API endpoint or arbitrary command interface exists. A disconnect after
the command may have executed is failure; the command is never retried.

## Deadline, retirement and receipts

One boot-bound monotonic end covers admission, copying, decoding, keys, unit
startup, QEMU, SSH, cancellation, outside retirement and artifact removal. Final public receipt
output uses bounded nonblocking writes under the same end, with no buffered print or
interpreter-exit output flush. A full undrained output pipe cannot extend the operation or
turn incomplete publication into a successful exit. The
cleanup reservation is subtracted once and cannot renew the end. SIGINT/SIGTERM
cancel the exact recorded worker; its child processes are reaped before a
provisional producer-stop message. The external owner then stops only the
authenticated unique service invocation, verifies no manager respawn/start job,
worker/QEMU/SSH PID-start retirement, and observes the same cgroup subtree empty
(or removed) twice. Direct `cgroup.procs` emptiness alone is insufficient;
`cgroup.events populated=0` must cover descendants.

Only this conjunction, plus the genuine worker producer barrier and successful
private-artifact removal, permits **`vm-qualified-retired`** and exit 0. SSH
success, QEMU exit, unit stop request and a worker-supplied boolean cannot
individually promote success. Earliest prerequisite failure is retained
separately from cleanup failure. Identity drift, subtree repopulation, PID
reuse, missing producer proof, deadline exhaustion or unknown retirement
produces `failed-quarantined`; its private directory is retained and must not
be deleted until external ownership/retirement review. No automatic recovery
or unowned stop path is provided. Other safely retired failures exit nonzero.

The public JSON contains fixed state/error codes, owner identifier and receipt
digest. The mode-0600 private receipt retains unit/boot/PID/cgroup/tool/source
identities and timings, never keys, raw guest info, console logs or ambient
credentials. It always records Kubernetes readiness and runtime conformance as
**not performed**. Abrupt owner death supplies no positive outside receipt;
the supplementary unit runtime guard is not retirement evidence.

## Official image provenance

The initially reviewed input is Fedora CoreOS stable x86_64 QEMU release
`44.20260928.3.2`, directly from the official
[immutable archive](https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.2/x86_64/fedora-coreos-44.20260928.3.2-qemu.x86_64.qcow2.xz).
The [release metadata](https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.2/x86_64/meta.json)
and [component manifest](https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.2/x86_64/commitmeta.json)
record source provenance and guest packages. Acquire it separately, compare the committed archive
checksum, and verify its detached signature against the Fedora 44 fingerprint published by
[Fedora Security](https://fedoraproject.org/security/). Use a task-private keyring; never change the
maintainer's keyring or infer trust from the signature's own issuer hint.

Fedora's compilation license is MIT; individual components retain their respective licenses
and source/notice obligations. See the official [license policy](https://docs.fedoraproject.org/en-US/legal/fedora-linux-license/).
This route downloads no image itself and bundles or republishes no image or upstream implementation.
An archive/signature receipt proves acquired bytes, not a successful boot or controller behavior.

Pure tests run with:

```sh
python3 scripts/fixtures/kind_runtime.py --owned-vm --self-test
```

The ordinary `--self-test` also includes these controls and the unchanged
rootless tests. Fake subprocess/kernel/SSH peers establish source behavior only.
Real boot, installed systemd sandbox behavior, SSH/tool compatibility,
cancellation/crash/resource limits and repeated exact retirement require the
main agent's independently reviewed native runs before runtime claims.

## Parent authority and the worker's projected host view

The finite source profile selects `PrivateUsers=self`, `PrivateMounts=yes`,
`DynamicUser=no`, `RestrictNamespaces=yes`, native-only syscall architecture,
empty bounding/ambient capability sets and `NoNewPrivileges=yes`. It explicitly
denies `chroot`, `clone3`, `fsconfig`, `fsmount`, `fsopen`, `fspick`, `mount`,
`mount_setattr`, `move_mount`, `open_tree`, `pivot_root`, `setns`, `umount2` and
`unshare`, with `ENOSYS`. Denying `clone3` closes its pointer-argument namespace
flag path; ordinary `clone` remains subject to the manager's namespace filter.
There is no weaker retry if this policy prevents a required operation.

The actual selected policy must match a closed typed D-Bus contract before GO.
That contract includes empty mount/image/extension/bind/directory constructors,
no managed/dynamic user, no namespace-path overrides, the selected readonly and
private-write paths, and no unreviewed private-device/tmp/proc/hostname mounts.
Unknown, missing, differently typed or differently normalized properties refuse.
The fixed constructor profile is systemd 261.4 on Linux x86-64. Its normalization
requires the exact typed `SystemCallArchitectures` value `as ["native"]`, matching
the requested `SystemCallArchitectures=native` policy and the admitted native
host ABI. The explicit `x86-64` spelling, additional ABI entries and unknown
spellings are refused; there is no alternate normalization or runtime fallback.
The failed attempt's typed readback established this serialization, not guest
execution or the remaining host-view checks. The complete profile normalization
is a proposed source contract until an actual owned run and independent review
qualify it. Initial default-property observations do not qualify the selected
restrictive policy. The harness reads `Manager.Version` through the admitted
client and records the actual kernel release/machine; client ELF hashes do not
authenticate the running manager. The installed manager remains part of the
explicitly trusted installed OS.

The outside parent's tool admission remains unchanged: root-owned, non-writable
ancestors and reviewed ordinary ELF files, hashes, identities, modes and absent
file capabilities. It retains namespace handles and binds the exact worker
PID/start/group/session, boot, unit invocation and cgroup. Through the bound
`/proc/<pid>/root` descriptor it opens fixed tool paths component by component
with no-follow semantics. Every ancestor and executable must be the same
kernel object admitted from the parent's host view. The running worker
interpreter must also match its admitted executable.

Only a proved immediate-child user namespace with a single self-mapping for the
invoking UID/GID is accepted by this selected profile. `NS_GET_PARENT` must prove
the parent namespace; denied inspection, same namespace despite `PrivateUsers=self`,
nested/multirange mappings, wrong credentials or a mutable/unknown mapping refuse.
The worker's mapped owner is derived from this exact map and the observed kernel
overflow values for the same parent-admitted objects. An overflow owner, matching
bytes, or a user-owned copy never independently grants authority.

Before GO the parent checks all five capability sets are zero, `NoNewPrivs=1`,
`Seccomp=2` and a positive filter count. Filter counts are consistency evidence,
not a BPF dump or proof of filter contents. It checks bounded mountinfo, the
actual readonly flags of root-view tool descriptors and the effective cgroup2
descriptor, its exact outside-root inode/device identity, and unchanged
namespace/map/status/topology across the barrier.
`ProtectControlGroups=` is unsupported for this user-manager profile and is
required to remain off. `ReadOnlyPaths=/sys/fs/cgroup` plus actual descriptor and
mount observations supply the cgroup readonly requirement instead.

The authenticated GO contains the digest-bound host-view frame with original
ends, source and manifest bindings. The worker repeats source, manifest, exact
projected-object, namespace/map/status and readonly-view checks before each
native child. The helper is loaded only from its authenticated bounded source
bytes, without ambient module-path discovery; direct `-I` worker execution
shares its owning exception/cancellation state with that helper. The host-view
module is included in the owning source digest set. These checks use the same
original deadline and counters. They create no new observer or native probe.
The private receipt retains the safe host-view frame, or clearly marked partial
observations on a before-GO refusal; partial observations are never admission proof.
It contains no key bytes,
raw guest JSON or subprocess logs.

This contract trusts the installed manager to install the selected sandbox
before exec and the kernel to enforce it. It trusts the closed manager options
to construct ordinary mounts without unreviewed ID mapping. It does not dump
BPF, universally detect ID-mapped mounts, authenticate the whole OS, or prevent
host root/administrators or other outside namespace actors from changing mounts.
Mount propagation and namespace inode identity do not freeze the mount table;
any observed drift refuses. These explicit trust premises do not replace the
mandatory object, status, namespace or effective-readonly observations. Every
refusal preserves the earlier failure and follows the existing outside
retirement/quarantine path, without restarting a deadline or selecting another
backend. Pure tests establish source behavior only; they establish no VM, kind,
API or controller conformance.

## Separate staging phase

The [explicit guest staging contract](owned-guest-staging.md) adds
`--phase stage-inputs` for a fresh guest, with three independently admitted input
roles and a separate fixed receiver key. It preserves `qualify-vm` unchanged and
requires its rootful/local info result before transfers. Staging retains original
budgets and source/host-view authority, extends outside retirement to every actual
SSH producer, and claims only `stage-inputs-retired`. Kind/image import/API/runtime
qualification remains pending. Ordinary validation still runs only pure controls.

The outside owner freshly rechecks its source/boot and strict tool admission
immediately before each key-generation, manager-environment and worker-start
child, including before generated private inputs exist. The original budget is
retained. A closed sanitized `guest_info` receipt field is populated only after
the controller validates the exact expected summary and boolean types; raw guest
JSON and producer frames are not copied into that field. Without that validation
the field is `null`.
