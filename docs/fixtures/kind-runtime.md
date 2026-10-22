# External kind-on-Podman readiness

`scripts/fixtures/kind_runtime.py` is an explicit external harness for KubernetesLens #2.
It prepares one disposable cluster's prerequisites, creates one control-plane node, checks
its exact selected server patch and readiness, and removes its recorded runtime resources.
It does not import the library, acquire product input, apply manifests, run generated commands,
or deploy any application. It complements the existing official fixture and renderer drivers;
it does not repeat them. API acceptance, workload/controller behavior and all machine-ledger
native evidence cells remain **pending** until separately executed and independently reviewed.
A `readiness-passed` receipt establishes only this harness's selected readiness checks.

The Linux Rust integration target `official_native_probe` invokes only `--self-test`, with
an empty inherited environment and an explicit Python path. Ordinary tests and complete gates
never prepare images or clusters. The pure controls use fake subprocesses, bounded stdlib pipe/thread peers and synthetic runtime
metadata; their success cannot establish actual host compatibility or Kubernetes support.

## Execution evidence boundaries

The helper and interrupted-creation controls below are implemented source contracts. Real legacy
and modern profile execution remains pending. Pure controls cannot supply delegated CPU/memory
controllers or prove actual kind/Podman compatibility. A host exposing only the `pids` controller
to its user manager is unavailable for this harness; there is no disabled-cgroup or process-limit
substitute for actual cluster execution. Request an explicitly authorized host prerequisite change
or select a suitable host. This script never changes global delegation or host configuration.

## Existing owners and authenticated inputs

The sole runtime and tool selector is
`schemas/capabilities/kubernetes-1.20-1.37.json`, specifically `runtime_profiles`,
`tool_profiles` and `canonical_tool_owner`. Select an exact profile ID, currently
`legacy-1.20.15` or `modern-1.37.0`. There is no implicit default, existing-cluster route,
current-context selection, supported-version discovery or automatic profile advancement.
The profile's node-image digest is mandatory, including during preparation.

Supply explicit regular, non-symlink Linux amd64 ELF paths for kind, kubectl and Podman.
Historical kind/kubectl integrity comes directly from their ledger records. Modern integrity
is extracted only after authenticating the supplied canonical BoxFerry
`scripts/install-kubernetes-tools.sh` against the ledger's **existing** whole-file SHA-256;
the selected version variable and amd64 checksum must match. An arbitrary caller checksum
file cannot replace that owner. `--canonical-owner` is required for modern selection.
Podman's caller-supplied `--podman-sha256` identifies the independently reviewed local executor;
it does not establish authenticity or add an installer/version pin. The harness snapshots
all three authenticated executables into its private directory before executing any of them,
and rechecks snapshot hashes before each invocation. No tool installation or download occurs.
The host dynamic loader, shared libraries, kernel, system Python and package administration remain
trusted execution prerequisites. The explicitly authenticated helper catalogue below covers selected
external programs; it does not authenticate that entire operating-system/software closure.

### Explicit host helper closure

Supply `--helper-manifest` and an independently reviewed `--helper-manifest-sha256`. This is an
invocation-specific host identity receipt, not a new tool installer, frozen version list or authority
to update operational pins. Its exact JSON schema is `podman-host-helper-closure-v1`, with only a
`schema` string and `helpers` object. The required helper keys are `newuidmap`, `newgidmap`, `crun`,
`conmon`, `netavark`, `aardvark-dns`, `pasta` and `rootlessport`. The only optional keys are
`catatonit`, `iptables`, `ip6tables` and `nft`, when the selected host implementation needs them.
Unknown helpers, missing required roles and arbitrary shell launchers refuse. This finite provider
contract selects documented rootless pasta/netavark behavior and an explicit crun runtime; it does
not infer compatibility with every Podman release.

Every helper record has exactly `path`, `sha256`, `bytes`, `uid`, `gid`, `mode` and
`capability_sha256`. For example, one member has this shape; the full object must contain all
required keys, with actual independently reviewed values:

```json
{
  "schema": "podman-host-helper-closure-v1",
  "helpers": {
    "newuidmap": {
      "path": "/usr/bin/newuidmap",
      "sha256": "VERIFIED_FILE_SHA256",
      "bytes": 12345,
      "uid": 0,
      "gid": 0,
      "mode": "0755",
      "capability_sha256": "VERIFIED_RAW_SECURITY_CAPABILITY_XATTR_SHA256"
    }
  }
}
```

Use the SHA-256 of the raw `security.capability` xattr, or SHA-256 of empty bytes when that xattr
is absent. Missing xattr and unsupported xattrs both require the empty-byte digest. Preserve the
actual mode: mapping helpers may use mode 0755 with file capabilities rather than setuid. Do not
invent privileged bits or replace capability metadata with a null field. The harness hashes each
ELF file, checks bytes/mode/uid/gid/capabilities and captures its device/inode. Every path and
ancestor must be canonical, root-owned and not group/world writable. Resolve distribution
symlinks to their canonical real paths during the independent host inventory; the harness does
not silently resolve a changed input path.

Private `bin` and `helpers` entries are symlinks to those authenticated host files. The target's
native setuid/capability metadata therefore stays intact; privileged mapping helpers are never
copied into a user-owned executable. Before every tool call, the target identity and private link
are rechecked. Podman receives explicit `--runtime` and `--conmon` paths and a single private
`helper_binaries_dir`; its reported runtime/backend/DNS/pasta paths must match the selected
closure. PATH contains only the private directory. Missing helpers never trigger an ambient
PATH fallback. Private empty hook/CDI directories prevent those default execution paths; nonempty
system default bind-mount files refuse to prevent implicit host credential mounts. Helper or
configuration drift stops the operation and makes unproved cleanup quarantine explicit.

Only explicit `prepare-image --allow-public-image-pull` may retrieve an image. It requests
`docker.io/kindest/node@<the selected ledger digest>` with an explicit empty auth file.
The resulting local image must retain that exact repository digest and Linux amd64 platform.
No arbitrary image, mutable tag, registry credentials, automatic fallback or archive-derived
digest assertion is accepted. Preparation retains the exact image ID in the ownership manifest.
The later `run` uses only that same authenticated private store and `--pull=never`.

No operational pin is added, moved or removed: modern tools remain BoxFerry-owned, historical
profiles remain fixed compatibility anchors, and the existing capability-ledger exclusions
remain applicable. No duplicate Renovate manager is needed. Updating an operational owner
without renewing its frozen source/profile association deliberately makes this harness refuse;
copying a fresh checksum into a second inventory would weaken that rule. Manifest/workflow,
installer and Renovate files are unchanged by this harness.

## Host preparation and explicit limits

Use a rootless Linux amd64 host with Podman, cgroup v2, systemd user service access and the
`cpu`, `memory` and `pids` controllers. Missing prerequisites are `unavailable`, never passed
or silently skipped. The harness never changes systemd, GRUB, mounts, host configuration or
global installs. It requires an already bounded **task-owned user slice** whose final name
starts `kubernetes-lens-issue2-` and ends `.slice`. The caller must already be inside that
slice. Each node gets that exact slice via Podman's documented `--cgroup-parent`; the harness
also injects `--memory`, `--memory-swap`, `--cpus` and `--pids-limit` before creation.
`--cgroups=no-conmon` keeps conmon in its inherited bounded caller scope while leaving node
cgroups and every node resource cap enabled; container cgroups are never disabled.
After creation, actual node inspection and its live host PID cgroup must agree with those caps
and placement before readiness can pass. Kind's rootless privileged node remains within the
unprivileged user runtime and this bounded task slice.

A concrete external preparation route is a **new transient user slice**, followed by a delegated
scope within it. An operator can use the existing systemd D-Bus `StartTransientUnit` method;
this creates no persistent unit file and must use `fail`, never replace an existing unit.
The following is an example for a fresh, operator-recorded unique name, four GiB, two CPUs,
zero swap and 4096 tasks. These commands are operator preparation, not commands the harness
executes. Authenticate the locally supplied systemd tools and select a new unique name first.

```sh
issue2_slice='kubernetes-lens-issue2-REPLACE_WITH_UNIQUE_TOKEN.slice'
/usr/bin/busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
  org.freedesktop.systemd1.Manager StartTransientUnit 'ssa(sv)a(sa(sv))' \
  "$issue2_slice" fail 4 \
  MemoryMax t 4294967296 MemorySwapMax t 0 \
  TasksMax t 4096 CPUQuotaPerSecUSec t 2000000 0
/usr/bin/systemd-run --user --scope --slice="$issue2_slice" -p Delegate=yes \
  /usr/bin/bash --noprofile --norc
```

Inside that scope, obtain this exact slice's `ControlGroup` from the user manager and verify
its `memory.max`, `memory.swap.max`, `cpu.max` and `pids.max` before supplying its absolute
`/sys/fs/cgroup/...` path. If the user manager cannot create the bounded slice or delegate the
scope, request that explicit host prerequisite; do not weaken the checks or alter global host
settings. Stop only the uniquely recorded task slice after all its owned resources and scope
are retired. Never stop an ambient slice or a unit selected by name-prefix enumeration.
The harness itself owns no systemd unit and never stops one.

Supply a fresh absolute mode-0700 empty directory, owned by the invoking uid, as `--store`.
Its graph/run roots, HOME, XDG directories, auth file, Kubernetes config and container configs
are private. There is no inherited kubeconfig, registry login, service connection, SSH key,
proxy environment or command search outside the private provider launcher. The only shared
service endpoint is the explicit current uid's systemd bus, verified to be an owned socket.
Podman's graph/run roots and rootless/cgroup mode are checked before any node creation;
pre-existing containers, volumes or kind network refuse rather than being reused or deleted.
Do not place the store under a symlink or allow concurrent writers with the same uid.

Every invocation must explicitly supply every limit:

| Argument            | Accepted contract                                                                    |
| ------------------- | ------------------------------------------------------------------------------------ |
| `--seconds`         | Original total wall lifetime, 300–1800 seconds, including setup and cleanup          |
| `--cleanup-seconds` | Reserved final 60–300 seconds, strictly less than half the lifetime                  |
| `--cpus`            | 1–8 CPUs; aggregate slice quota must be finite and no greater                        |
| `--memory-bytes`    | 2–16 GiB; aggregate slice memory must be finite and no greater; swap zero            |
| `--pids`            | 1024–65536 tasks; aggregate slice task count must be finite and no greater           |
| `--nodes`           | Exactly 1; a second node creation attempt refuses                                    |
| `--store-bytes`     | 8–32 GiB measured allocated-store budget, with at least one GiB free before commands |
| `--output-bytes`    | 64 KiB–16 MiB aggregate operation stdout plus stderr                                 |
| `--commands`        | 16–512 total commands; an additional 32 commands are reserved solely for cleanup     |

Each pipe pair is capped at one MiB, within the aggregate allowance. Cleanup has its own
one-MiB aggregate output allowance. Node logs are limited to one MiB; individual child-written
files are capped at eight GiB; open descriptors initially at soft 256 with hard ceiling 524288; core dumps are disabled.
The admitted node nofile limits may raise that soft value within the inherited hard ceiling; an
inadequate inherited ceiling refuses before its one-shot node creation attempt. The private
store has at most 250000 scanned entries. Before/after allocated-byte counts and entry counts
are recorded. **The disk budget is a measurement/preflight refusal, not a filesystem quota**:
image unpacking and a node can consume space between measurements. Use an independently
provisioned quota/tmpfs if a hard disk ceiling is required. The harness neither creates such
mounts nor claims a hard physical-disk theorem. CPU/memory/PID limits are kernel-enforced.

## Explicit invocation

Run pure controls without access to Podman or a cluster:

```sh
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py --self-test
```

Within the prepared task scope, choose reviewed immutable inputs and limits. Values below
are placeholders; they are not discovered from PATH, global tools, current-context or a cache.
The private store must be empty on the first phase. A separate `preflight` phase is available
with the same arguments; it contacts no Kubernetes server and returns a non-pass receipt.
Use a new empty store after a standalone preflight rather than attempting to adopt its state.

```sh
issue2_args=(
  --profile modern-1.37.0
  --kind /private/reviewed-kind
  --kubectl /private/reviewed-kubectl
  --podman /private/reviewed-podman
  --podman-sha256 VERIFIED_PODMAN_SHA256
  --helper-manifest /private/reviewed-host-helper-closure.json
  --helper-manifest-sha256 VERIFIED_HELPER_CLOSURE_SHA256
  --canonical-owner /private/authenticated-install-kubernetes-tools.sh
  --cgroup /sys/fs/cgroup/EXACT_TASK_SLICE_PATH
  --store /private/new-issue2-store
  --seconds 900 --cleanup-seconds 180
  --cpus 2 --memory-bytes 4294967296 --pids 4096 --nodes 1
  --store-bytes 17179869184 --output-bytes 8388608 --commands 256
)
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py "${issue2_args[@]}" \
  --phase prepare-image --allow-public-image-pull
```

Retain and review the `image-prepared-only` receipt and its `policy_sha256`. Preparation
returns status **2**, deliberately distinguishing it from completed readiness. It leaves the
private prepared image, policy, snapshots and ownership record for the explicit next phase.
No Kubernetes server or node has been started. Use its exact reviewed policy digest once:

```sh
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py "${issue2_args[@]}" \
  --phase run --prepared-policy-sha256 VERIFIED_PREPARED_POLICY_SHA256 \
  --execute-owned-cluster
```

Run authenticates the original source, ledger, limits, task slice, store inode, tool snapshots,
helper closure, owner and unused prepared state before creating anything. It cannot adopt an existing cluster
or reuse a prior run. A generated private provider launcher forwards only the finite kind
command catalogue; unsupported upstream command forms refuse and require reviewed adaptation.
It injects a unique ownership label, exact node name/image, a named owned `/var` volume,
resource caps, capped logs and offline image selection. `--image-volume=ignore` suppresses
implicit image-declared anonymous volumes; the explicit recorded `/var` volume remains selected. The one-node kind configuration has
no extra ports, mounts, workers, feature-gate patches or addon installation.

### Frozen kind provider protocol and byte transport

The finite provider catalogue covers the existing kind 0.14.0 and 0.33.0 clients. Their official
interfaces require exact global `-v`/`--version` probes, a labelled `volume create` returning its
name, and that returned volume mounted at `/var:suid,exec,dev`. The provider supplies its unique
recorded volume name and owner label at creation; it never replaces an anonymous mount after launch.
Node options admit the exact `-e container=podman`, snapshotter-variable and control-plane kubeconfig
forms, the random loopback `--publish=127.0.0.1::6443/tcp` form, and only `/dev/fuse` as an explicit
device. The fuse path must already be the expected readable/writable character device before node
creation. Conditional `/dev/mapper` host mounts remain unavailable rather than exposing additional
host devices. Kind's normalized `docker.io/kindest/node@sha256:...` reference is checked against the
selected ledger digest and forwarded without a mutable tag. Existing resource caps remain injected.

Owned `logs -f` output is delivered while the process is running. Owned `exec --privileged -i`
commands receive their original stdin bytes, including binary data and a real EOF after all pending
input drains. This includes kind's `cp /dev/stdin /kind/kubeadm.conf` interface; command arguments
alone cannot deliver that file. Output is never replayed after live delivery. Each direction uses
nonblocking polling, handles partial writes, interrupted/would-block operations and downstream closure,
and applies backpressure with 64 KiB pending queues per stdin/stdout/stderr channel. Each actual
command has a combined stdout/stderr ceiling and an independent stdin ceiling of at most 1 MiB.
Input and output also consume separate aggregate invocation budgets, each bounded by `--output-bytes`;
cleanup output retains its separate 1 MiB reserve. Input bodies/hashes are never persisted.
All forwarding remains inside the original monotonic end; a stalled peer cannot renew it.

Kind can SIGKILL its direct log-provider process after observing readiness. Each generated provider
front therefore starts a separate backend session with an inherited control pipe. The front must
record the backend PID/start-time/group/session lease before sending its one-byte start gate. The
backend authenticates that lease before running tools. Front death closes the sole control writer;
control EOF or controller cancellation stops the backend, which retires each actual child session
before acknowledging retirement. The front never kills a backend that may still own native clients.
The controller requests cancellation and waits within the original end, for at most five seconds,
for all lease acknowledgements before resource cleanup. Missing, changed or unacknowledged leases
quarantine; a front exit, reused PID or empty label listing proves no retirement.

These command facts were independently read from official kind sources at
[`v0.14.0` / `7a5ce5b16f36ffd8bbb05961f580aae91c58ef95`](https://github.com/kubernetes-sigs/kind/tree/7a5ce5b16f36ffd8bbb05961f580aae91c58ef95)
and [`v0.33.0` / `407a9675e6d9af1200b5f57f9ca52ec6cdacce74`](https://github.com/kubernetes-sigs/kind/tree/407a9675e6d9af1200b5f57f9ca52ec6cdacce74),
using authenticated Git-blob catalogues for Podman `util.go`, `provision.go`, `node.go`, `images.go`,
nodeutils `util.go` and create/config actions. The read-only catalogue receipts bind paths, bytes,
Git blob IDs and SHA-256 values. The oracle license is Apache-2.0 (both LICENSE files have SHA-256
`b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1`). Only interface facts were
used; this harness is original and no upstream implementation or source catalogue is redistributed
in this change. The source consultation is distinct from execution of the selected kind command
shown above, which remains pending for both profiles.

The generated kubeconfig must contain exactly this owned cluster/context/user, inline CA and
client certificate/key material, and the node's inspected loopback API port. Credential plugins,
external files, ambient auth and external endpoints refuse. Explicit-context, TLS-verified
kubectl requests check `/version`, `/readyz` and the sole node's name, kubelet patch and Ready
condition. Server evidence retains exact `gitVersion`, major/minor, git commit and platform.
There is no current-context command, global apply, workload submission or application behavior
claim. The harness does not validate feature-gate boundaries or all issue #2 conformance cases.

## Cleanup, results and evidence

Creation intents precede effects. A node attempt consumes exactly one intent and records its
private CID-file path without creating that file: Podman requires `--cidfile` to be absent at
launch. The provider injects that fixed path and records when the operation starts. Authority
requires a naturally returned nonnegative result, the exact file CID, matching successful stdout
when status is zero, and an inspection proving that full container ID's exact name/profile owner.
The private CID file's contents, device/inode and metadata must still match before cleanup.
A nonzero natural result remains failure evidence even when its exact owned CID permits cleanup.

An interrupted call, missing result, missing CID, mismatched result or unproved process retirement
cannot be repaired by a late file or labelled resource. Such states quarantine before any destructive
cleanup. A late CID is recorded only as non-authoritative recovery evidence. No label enumeration
can mint a resource identity. Network and volume identities likewise require their recorded
one-shot create result and exact expected object inspection; an unknown result quarantines.
The named volume's creation timestamp and mountpoint fingerprint are rechecked to detect replacement.

The manifest records exact created container/network IDs, the owned named volume and prepared
image ID. Cleanup re-inspects identity and owner label before each destructive operation; container
deletion uses the recorded full ID, never a name query, wildcard, latest/all selector, prune,
kind-delete or force-network removal. Volume and network removal are non-force. Kind's own
destructive cleanup is refused by the provider; the parent cleans after its command group has
retired. Foreign resources are preserved. Unknown/late creation retains all recovery evidence
and reports incomplete cleanup, rather than claiming an empty resource listing proves retirement.

One original monotonic deadline includes all commands and readiness retries; no command renews
it. SIGINT/SIGTERM are sticky and route to cleanup. Every actual tool child owns a private process
group, including calls issued by leased streaming backends, with default SIGCHLD required, bounded pipe capture and forced retirement, retaining its
unreaped leader until
Linux procfs checks every thread, including threads whose group leader is a zombie, and proves
no live group member remains. Unproved retirement or ownership drift leaves
quarantine and never races destructive cleanup. SIGKILL, host loss and an OOM killing the entire
slice cannot be handled in-process; retain the private manifest for separately authorized,
identity-verified operator recovery rather than running broad cleanup commands.

This cleanup proof is deliberately limited to recorded runtime objects and leased client process
groups. Rootless Podman can detach helpers, namespace/pause processes or network services outside
those client groups. Whole-host, pause, netavark/aardvark and detached-helper retirement are **not
established** by the present harness. The receipt states
`cleanup_scope=recorded-runtime-objects-and-leased-client-groups` and
`detached-helper-retirement=not-established`; it does not authorize killing broad helper/PID
catalogues. Any stronger whole-runtime cleanup claim needs a separately authenticated ownership
and retirement mechanism, reviewed and actually executed on a suitable host.

Status 0 means selected readiness checks **and** cleanup completed. Status 2 means unavailable,
preflight-only or image-prepared-only; status 1 means failure, and cancellation retains the
conventional signal status. No unavailable/skip/preparation result counts as pass. Cleanup failure
makes the result failed and retains the original error code/status. Private ownership/result
records include command statuses, stdin byte counts and output sizes/hashes, not input bodies or raw child logs. Provider diagnostics retain only fixed codes/states; command arguments and exception bodies are not recorded. Public receipts
contain fixed codes, counts and bounded server/profile identities, never kubeconfig credentials.
The private directory, snapshots and credential files remain for audit and must be protected;
cleanup removes owned runtime resources, not the retained evidence tree.

Main must execute/review both historical and modern profiles on the exact final source, retain
source/tool/host/resource/server/cleanup receipts, and update machine evidence separately.
The source-only implementation and pure controls do not close #2, #14, #15 or #7. New commands,
resource scenarios, architecture/root modes and server semantics need independent evidence.
No runtime profile's pending state is changed by this patch.

Official CLI/reference sources consulted through Context7 on 2026-10-21:
[kind rootless](https://kind.sigs.k8s.io/docs/user/rootless/),
[kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/),
[Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html),
[Podman global options](https://docs.podman.io/en/latest/markdown/podman.1.html),
[containers configuration](https://github.com/containers/container-libs/blob/main/common/docs/containers.conf.5.md),
[Podman image inspection](https://docs.podman.io/en/latest/markdown/podman-image-inspect.1.html),
[Podman network creation](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html),
[systemd control-group interface](https://systemd.io/CONTROL_GROUP_INTERFACE/), and
[systemd delegation](https://systemd.io/CGROUP_DELEGATION/).
These are documentation references, not copied implementations or runtime evidence. Installed
Podman/containers configuration manual text was also read to verify helper directory, hooks, CDI,
network selection and default-mount behavior; no upstream implementation was copied or executed.
Upstream tools/images are acquired only externally under their existing profile provenance,
license and redistribution records; no upstream executable, image or source is vendored here.
