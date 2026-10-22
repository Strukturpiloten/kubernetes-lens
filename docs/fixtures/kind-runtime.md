# External kind-on-Podman readiness

`scripts/fixtures/kind_runtime.py` is an explicit external harness for KubernetesLens #2.
It prepares one disposable cluster's prerequisites, creates one control-plane node, checks
its exact selected server patch and readiness, and removes its recorded runtime resources.
It does not import the library, acquire product input, apply manifests, run generated commands,
or deploy any application. It complements the existing official fixture and renderer drivers;
it does not repeat them. API acceptance, workload/controller behavior and all machine-ledger
native evidence cells remain **pending** until separately executed and independently reviewed.
Successful API checks produce `readiness-observed-pending-retirement`. No current public phase
completion emits `readiness-passed` or exit 0: complete detached-helper containment is not established.

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
and placement before readiness can be observed. Kind's rootless privileged node remains within the
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
mounts nor claims a hard physical-disk theorem. CPU/memory/PID limits are kernel-enforced for the explicit outer envelope and its entire
subtree, including the controller and target slice. The target slice also retains its own caps.
This requires the pre-existing outer envelope described below; it is never inferred or created.

## Explicit invocation and outside finalization

Pure controls remain isolated from Podman and clusters:

```sh
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py --self-test
```

Runtime phases now require two explicit invocations of this same script. External operator
preparation must place both under one already bounded, uniquely owned outer task slice:

- The full target slice is a strict descendant of that outer envelope. The worker and its
  launching shell live inside the target slice, along with node and inherited conmon scopes.
- The controller lives in a different descendant of the outer envelope, outside the entire
  target slice. It never creates a process, service, unit or cgroup, or moves itself or the worker.
- The outer envelope's finite CPU, memory, zero-swap and PID caps must be no greater than the
  supplied invocation limits. They cover both stages and other processes in that subtree from
  their first read. They provide no resource or accounting claim for helpers launched elsewhere
  by the shared user manager or migrated out of the envelope.
  A bounded target slice alone is insufficient. Missing topology or caps refuse before any
  native command; the harness never changes a parent/global unit or weakens an aggregate claim.

Prepare a separate fresh absolute mode-0700 handoff directory owned by the invoking uid,
outside the private store and without symlink ancestors. Put an operator-reviewed mode-0600
single-link contract there and authenticate its exact SHA-256. Do not reuse a handoff directory,
even after failure. The contract has this shape; replace all identity placeholders with actual
independently captured values, not guesses or invented manager identities:

```json
{
  "schema": 1,
  "owner": "32_LOWERCASE_HEX_NONCE",
  "phase": "prepare-image",
  "boot_id": "ACTUAL_KERNEL_BOOT_UUID",
  "source_sha256": "ACTUAL_FINAL_SCRIPT_SHA256",
  "cgroup": "/sys/fs/cgroup/EXACT_OUTER_SLICE.slice/EXACT_TARGET_SLICE.slice",
  "cgroup_identity": [123, 456],
  "unit": {
    "name": "EXACT_TARGET_SLICE.slice",
    "transient": true,
    "invocation_id": "ACTUAL_32_HEX_MANAGER_INVOCATION_ID"
  },
  "launch_shell": { "pid": 1234, "group": 1234, "session": 1234, "start": 12345 },
  "store": "/private/new-issue2-store",
  "store_identity": [123, 789],
  "envelope": {
    "cgroup": "/sys/fs/cgroup/EXACT_OUTER_SLICE.slice",
    "cgroup_identity": [123, 455],
    "cpu": [200000, 100000],
    "memory": 4294967296,
    "swap": 0,
    "pids": 4096
  },
  "controller_reservation": { "output_bytes": 4194304, "store_bytes": 1048576 },
  "limits": {
    "seconds": 900,
    "cleanup_seconds": 180,
    "cpus": 2,
    "memory_bytes": 4294967296,
    "pids": 4096,
    "nodes": 1,
    "store_bytes": 17179869184,
    "output_bytes": 8388608,
    "commands": 256
  }
}
```

Both actual slice basenames must start `kubernetes-lens-issue2-` and end `.slice`;
the example paths are schematic. Device/inode pairs come from the exact live kernel paths.
The unit record is the operator's attestation of the unique transient unit and its recorded
InvocationID, bound to that boot/path/inode; the script does not query the manager to independently
authenticate it. If the selected host cannot provide that identity, refuse this topology rather
than invent one. This record grants no unit-stop or kill authority. Exact source, policy digest,
selected tool/profile/helper/configuration identities, store inode, shell PID/start identity,
controller and worker identities all join the same handoff. There is no helper-coverage boolean,
provider selector or caller-ready override.

First start the controller from the outer envelope's separate controller scope:

```sh
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py \
  --retirement-controller /private/fresh-handoff/contract.json VERIFIED_CONTRACT_SHA256 \
  --controller-envelope /sys/fs/cgroup/EXACT_OUTER_SLICE.slice \
  --seconds 900 --output-bytes 8388608 --store-bytes 17179869184 \
  --controller-output-bytes 4194304 --controller-store-bytes 1048576
```

The controller starts the one original monotonic budget on entry, verifies its pre-existing
outer kernel limits before reading policy/store/contract contents, and holds the outer directory
identity. Before `armed.json`, it opens the exact target slice directory and `cgroup.events`
with no-follow component traversal. It retains those descriptors throughout worker activity.
No late finalize invocation can reopen a path and claim the same lifecycle evidence.

After `armed.json` exists, invoke the worker from the recorded launching shell inside the target:

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
  --cgroup /sys/fs/cgroup/EXACT_OUTER_SLICE.slice/EXACT_TARGET_SLICE.slice
  --store /private/new-issue2-store
  --seconds 900 --cleanup-seconds 180
  --cpus 2 --memory-bytes 4294967296 --pids 4096 --nodes 1
  --store-bytes 17179869184 --output-bytes 8388608 --commands 256
  --retirement-contract /private/fresh-handoff/contract.json
  --retirement-contract-sha256 VERIFIED_CONTRACT_SHA256
  --controller-output-bytes 4194304 --controller-store-bytes 1048576
  --retirement-original-start EXACT_ARM_START --retirement-original-end EXACT_ARM_END
)
/usr/bin/python3 -B scripts/fixtures/kind_runtime.py "${issue2_args[@]}" \
  --phase prepare-image --allow-public-image-pull
issue2_worker_status=$?
exit "$issue2_worker_status"
```

Do not `exec` the worker over the recorded shell: the protocol requires distinct producer
identities and both must exit. No task may be launched into the target after the barrier.
An interactive shell left alive prevents the full-slice zero witness. If the manager removes
the slice before the held identity yields a zero witness, ENOENT quarantines; absence is not proof.

The worker consumes the controller's exact original start/end, partition and contract owner
before policy creation. **The currently selected installed helper profile is unsupported and
refuses here, before policy/bootstrap creation, `execute`, Podman/provider commands or native
cleanup.** It writes only a prepaid bounded `worker.json` refusal; the controller may publish a
bounded failure receipt while original time and credit remain. The public proxy/front entries
also refuse before policy reads or provider/process launch. No supplied boolean can admit this
profile. Pure decision/accounting primitives and the scoped metadata controller remain testable;
they do not establish current native conformance or permission for another real run.

For any future independently reviewed native profile, the policy handshake additionally requires
`worker.json` with the exact policy hash and a matching `gate.json` before native work. The
controller verifies actual ownership counters (`output=R_output`, `input=0`, `commands=0`) and
the reduced private-store bound before releasing that gate. A missing or incompatible gate has
no native fallback. The existing image-pull consent and prepared-state rules remain prerequisites,
not an admission route for the current unsupported profile.

Operations retain the existing cleanup reserve. The final `min(30, cleanup_seconds / 2)` whole
seconds of that reserve belong to outside finalization. Worker cleanup and proxy retirement must
finish before this interval; neither stage starts a new timeout. The controller's original end
includes bootstrap reads, setup, worker waiting, cleanup, final construction, serialization,
file write/fsync, stdout and return. Deadline/cancellation checks bracket each admitted stage;
expiry or exhausted credit permits no fresh diagnostic receipt or success return. Poll waits are
at most 50 ms and share that end.

The CLI supplies the original duration/output/store limits **before contract acquisition**.
The authenticated contract's `controller_reservation` contains numeric `output_bytes=R_output`
and `store_bytes=R_store`, with `0 < R_output <= O` and `0 < R_store < S`. These exact values
are bound again in `armed.json`, the worker CLI and its policy. Controller metadata consumes
one cumulative `R_output` partition; reads, missing-record polls, conservative serialization
bounds and stdout are charged without refunds. Worker `state.output` begins at `R_output`, so
native output can use at most `O-R_output`; independent native input still begins at zero with
its original `O` cap. The private worker store is measured against `S-R_store`; the separate
handoff and controller metadata allocations consume `R_store`. This is a partition of the
original invocation allowances, never another full allowance or a renewed clock.

Before claim/arm, the controller precharges one closed worker subshare and binds its entire
`worker_io` map in `armed.json` and policy. Content windows remain: contract/arm/gate reads
16,386 each; source length plus two; boot and own-stat 4,097 each; two controller identity checks
24,582; shell and own checks 12,291 each; policy/final-policy/ownership reads 65,538 each; worker
record 16,384; controller gate check 12,291; private/provisional receipts 65,536 each; and 512
for absent-gate content framing. This includes the existing two record-framing units per
regular read, independently of the metadata-event debit. Store subshare remains 393,216 bytes.

The same role additionally reserves **1,323 metadata operations**, or **338,688 surface
accounting bytes**, inside that original output subshare:

| Worker metadata category | Maximum operations | Derivation                                                                           |
| ------------------------ | -----------------: | ------------------------------------------------------------------------------------ |
| Source size              |                  1 | One stat, already debited before downward share narrowing                            |
| Seven regular reads      |                469 | Seven times (64 ancestry lstat probes + outer stat/open/fstat)                       |
| Contract extras          |                 70 | Path/parent stats plus at most 68 store/ancestor probes                              |
| Seventeen kernel windows |                 34 | One open and one lseek per path window                                               |
| Replay probes            |                  4 | Four exists/stat attempts                                                            |
| Store lease              |                  2 | Open and nonblocking flock                                                           |
| Three writes             |                231 | Each: two handoff measurements of at most35 operations, statvfs, six file operations |
| Final worker store walk  |                256 | Explicit ceiling before operation257                                                 |
| Missing-gate stats       |                256 | At most257 total gate attempts, including its one regular-read window                |

The worker's source stat consumes the existing original partition before it narrows to this
controller-prepaid share; usage is retained and cannot reset or increase its original allowance.
Read-only identity bootstrap precedes the store lease so the original worker meter owns both
lease effects. The lease still precedes any worker refusal publication or possible policy/native
effect. The selected unsupported helper profile remains refused before those native effects.
Only absence at the read's initial charged outer stat is a retryable missing-record poll.
Once that stat succeeds, any later ancestor/open/read-stage disappearance is a fixed pathless
`retirement-input-disappeared` refusal, with its original partial/full read debit retained and
no sleep/retry. Suppressing the original exception chain keeps the input path out of the
reported error. This preserves the finite derivation: the gate has one complete regular-read
window plus at most256 single-stat absent polls, rather than257 nearly complete read windows.
The same original deadline,257-attempt cap,1,323 metadata effects and all byte/store limits
remain unchanged. Ordinary initial absence may still wait for a bounded publisher under that
same cumulative credit.

A final store walk or gate wait that exceeds its finite role window refuses even if another
window has unused credit. The controller's own operations consume the remainder of the same
`R_output/R_store`; no failed attempt refunds credit or grants a new diagnostic allowance.

Every admitted filesystem metadata operation uses the same precharged primitive: stat/lstat
(including exists/is-dir/is-symlink), open/create and each no-follow component open, scandir and
each next/termination attempt, statvfs, lseek, replace, unlink, file/directory fsync and the
existing nonblocking store flock. Each costs 256 **surface accounting bytes** from original
output credit and checks the original deadline/cancellation before and after, including failure.
Generic `stage` remains time-only for pure computations and content operations. Helpers own
their internal metadata debits; their callers do not charge the same event again. Raw read/write
and stdout content retain their separately prepaid byte/serialization windows. Descriptor
wrapping/fileno and release/close add no metadata event or publication credit.

Regular/kernel/nofollow/store helpers accept optional accounting callbacks, preserving their
no-controller calling form. An absolute ancestry of at most64 components is checked before
traversal, including recursive store descendants; the admitted source reader uses its literal
absolute source path and authenticates no-follow ancestry, without a hidden `resolve` walk.
The known helper profile cannot be admitted through a default helper call or supplied boolean.
These fixed interface debits are not measurements or bounds on physical filesystem I/O, kernel
metadata representation, CPU, Python heap or native source Work. Too-small reservations refuse;
sufficient original budgets still support bounded scoped metadata results.

| Record                                            | Maximum raw bytes |
| ------------------------------------------------- | ----------------: |
| Contract, arm, worker and gate                    |            16,384 |
| Policy, ownership, provisional and final receipts |            65,536 |
| Kernel/proc record                                |             4,096 |
| Each outer-envelope cap                           |               128 |

JSON is preflighted before decoding: depth at most 12, at most 4,096 structural tokens/nodes,
512 list elements, 128 object members, 4,096 characters per string, finite numbers and bounded
integers. Duplicate fields refuse. Receipt fields and nested diagnostic/store/server/barrier
fields use closed schemas; arbitrary extra fields are not copied into final receipts. A
conservative ASCII serialization upper bound charges 12 bytes per Unicode character plus
punctuation before allocating the serialized body. Larger/deeper records fail before copying,
serialization or handoff write. These format maxima never add budget credit.

Store accounting remains **measured, not a filesystem quota**. The handoff has at most 16
regular entries; allocated blocks are measured and atomic replacement precharges overlapping
old/new rounded payload backing. These software admissions and the existing kernel envelope
cannot preempt a synchronous kernel/filesystem call, stop scheduling delay, revoke a write
that physically completes after expiry, or prove exact CPU/memory/physical-storage use.
The external launcher must enforce the **same original hard stop**, including bootstrap and
final publication; Python checks alone are not a hard real-time boundary. No new observer,
helper service, deadline or post-expiry cleanup allowance is introduced. On detected expiry,
no later publication or successful status is admitted; an already-started blocking write can
leave a quarantined artifact. Native execution remains refused under the current profile.

In the independently testable scoped protocol, after exact resource cleanup and all
proxy/client-group prerequisites, the worker atomically
writes a provisional `store/control/receipt.json` and `handoff/provisional.json`. This producer
barrier binds the final policy hash and original end; no owned runtime command follows it. The
controller requires the recorded worker and shell to disappear without PID/start identity drift,
checks the full-slice identity again, then reads `populated=0` directly twice. Reappearance,
surviving population, cancellation, deadline expiry, unreadable/over-budget/malformed events,
unit/contract/boot/inode drift or missing producer gates quarantine. The strict parser currently
accepts only the documented `populated` and optional `frozen` keys, each once and valued 0 or 1;
unknown future keys refuse until reviewed.

The controller's stdout and `handoff/final.json` are the final receipt. A valid witness records
`scoped_retirement.state=subtree-empty-observed`, the exact boundary/identity and ordered barrier
and observation timestamps. This proves no live process remained in that subtree at that instant,
including detached sessions and grandchildren that stayed inside it. It is not a historical
helper census, containment proof for migrated/shared-manager helpers, or whole-host retirement.
`detached-helper-retirement` remains `not-established` on every current path. Successful API
checks remain `readiness-observed-pending-retirement`, exit 1. Preflight and image-only stay
non-readiness states, exit 2, when their own scoped finalization succeeds; finalization failure
quarantines them, exit 1. SIGINT/SIGTERM retain the conventional signal status.

The selected installed Podman 6.1.2/common 0.69.2 contract has concrete source counterexamples
to complete containment, rather than only missing positive evidence. At immutable Podman commit
`04f3aa430e6df81bea059978bc5bafbc846ba3e7`, pause setup reaches
[MovePauseProcessToScope](https://github.com/podman-container-tools/podman/blob/04f3aa430e6df81bea059978bc5bafbc846ba3e7/vendor/go.podman.io/common/pkg/systemd/systemd_linux.go#L74),
which requests a random pause scope in the shared manager's `user.slice`. Selected rootless
bridge pasta setup also
[moves the helper](https://github.com/podman-container-tools/podman/blob/04f3aa430e6df81bea059978bc5bafbc846ba3e7/vendor/go.podman.io/common/libnetwork/internal/rootlessnetns/netns_linux.go#L203)
through the hardcoded
[rootless-netns scope route](https://github.com/podman-container-tools/podman/blob/04f3aa430e6df81bea059978bc5bafbc846ba3e7/vendor/go.podman.io/common/pkg/systemd/systemd_linux.go#L61).
These manager-mediated migrations can leave both the target and outer envelope; neither
`--cgroup-parent` nor `--cgroups=no-conmon` constrains these paths. Changing only to cgroupfs
does not close them. The documented no-pause option has fallback paths and does not close the
bridge-pasta move. This source successor does not change runtime/profile/configuration choices,
manage those outside scopes, or authorize another real run. Complete resource bounds and
retirement of the selected helper cone remain unsupported. Its receipt reports
`helper_containment.reason=unsupported-selected-helper-containment`.

This is version-specific upstream implementation evidence: Podman 6.1.2 pins common 0.69.2 in
[go.mod](https://github.com/podman-container-tools/podman/blob/04f3aa430e6df81bea059978bc5bafbc846ba3e7/go.mod#L68).
The installed binary's recorded version/build information corresponds to that source, but no
reproducible-build or distributor-patchset proof is claimed. Introduction/removal boundaries
for these move paths and full placement of every other helper remain unestablished. The kernel
population contract is documented behavior; these paths are observed upstream source behavior,
not a portable theorem about every Podman version or a native execution result from this change.

The examples specify the protocol; the current public native entries refuse the known
unsupported installed helper cone before commands, even when every example argument is supplied. A later real run needs separate authorization and a genuine complete
helper/resource contract beyond this change. Its prepared-state rules additionally require
review of the completed image-preparation `final.json` and its
`policy_sha256`. Reuse only its exact prepared store/source/tools/profile/owner and cgroup path,
with a fresh per-phase handoff and controller, a current operator-recorded shell, and exact live
boundary/envelope identities. The prior image phase must have a valid scoped zero witness and
complete cleanup; an unfinished or quarantined prior phase cannot be replayed. This is a new
explicit phase budget, not renewal of the earlier phase or finalizer. Then pass the reviewed
prepared digest and `--execute-owned-cluster` to the worker with `--phase run`. An image-only
receipt never supplies runtime conformance, API acceptance or complete helper-retirement evidence.

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

No current public phase completion returns status 0: the complete helper-containment gate is unresolved.
Status 2 means unavailable, preflight-only or image-prepared-only; status 1 means failed or
readiness-observed-pending-retirement, and cancellation retains the conventional signal status. No unavailable/skip/preparation result counts as pass. Cleanup failure
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

The scoped-retirement successor additionally consulted the official
[Linux cgroup v2 populated interface](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#un-populated-notification)
and systemd v255 [delegation](https://github.com/systemd/systemd/blob/v255/docs/CGROUP_DELEGATION.md),
[transient settings](https://github.com/systemd/systemd/blob/v255/docs/TRANSIENT-SETTINGS.md) and
[invocation identity discussion](https://github.com/systemd/systemd/blob/v255/docs/RANDOM_SEEDS.md)
through Context7 on 2026-10-22. Kernel documentation defines recursive live-process population;
it does not establish this host's held-descriptor lifecycle or helper placement. The selected
systemd material documents transient slices and service invocation UUIDs but does not establish
a version introduction boundary or exact installed slice InvocationID behavior. Those remain
explicit native evidence gaps; v255 is documentation evidence, not a new operational pin or a
claim that every v255 host supports this contract. No source or external implementation was copied.
