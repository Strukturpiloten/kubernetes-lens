# Explicit owned guest input staging

The external `--owned-vm --phase stage-inputs` route selects a **fresh VM** and
stages three authenticated inputs. It does not run kind, load an image, contact
a registry, expose a Kubernetes API, or establish native conformance. Ordinary
validation runs pure controls only. VM execution and guest utility assumptions
still require separately recorded runtime qualification.

The existing `qualify-vm` route remains info-only. Its authorized key and fixed
Podman-info command remain unchanged. Staging uses a separate per-run key with
one source-owned forced command; it cannot select arbitrary shell text or paths.
The same per-run pinned host key protects both client keys.

## Explicit invocation and input authority

Supply all the existing owned-VM arguments from [the lifecycle contract](owned-qemu.md),
with `--phase stage-inputs`, and these additional arguments:

```text
--profile modern-1.37.0
--kind /absolute/path/to/prepared-kind
--kubectl /absolute/path/to/prepared-kubectl
--canonical-owner /absolute/path/to/authenticated-install-kubernetes-tools.sh
--node-parent /absolute/path/to/original-parent-index.json
--node-manifest /absolute/path/to/original-amd64-manifest.json
--node-config /absolute/path/to/original-config.json
--node-archive /absolute/path/to/closed-node.oci.tar
```

The other admitted profile is `legacy-1.20.15`; its frozen binary checksums come
from the existing capability ledger. Modern checksums come only from the ledger's
exact canonical BoxFerry tool-owner source. The existing `kind_runtime.select_profile`
function verifies that source and selects both tools; there is no second installer,
version catalogue or caller checksum override. Binaries are hashed as bounded
regular files and checked for ELF magic, without execution during preparation.
No network, download, runtime acquisition or installation occurs in this route.

The caller independently verifies the complete node-input chain before boot:

- The ledger's exact parent image digest authenticates original raw parent bytes.
- Exactly one unchanged linux/amd64 child descriptor selects raw child digest,
  size and media type; variants, ambiguous selections and metadata overrides refuse.
- Original config bytes must match the child descriptor and declare linux/amd64.
- Every compressed layer matches its exact descriptor digest/size. Bounded streaming
  gzip decoding checks its config diffID without extracting or executing any member.
- The archive is a closed regular USTAR catalogue containing only the selected
  child/config/layers, `oci-layout`, and one local OCI selection index. Duplicate,
  absent, linked, special, extended-header, unexpected, trailing or corrupt entries
  refuse. Metadata, total compressed bytes, layer inflation and cumulative inflation
  have fixed caps and use the original deadline.

OCI media types and the frozen legacy Docker schema2 child/config/gzip-layer media
combination are admitted exactly. Original raw manifests are preserved byte-for-byte;
no media-type conversion is performed. The archive's OCI index is a new local
selection envelope, **not the original upstream parent index**. The archive digest
is a locally derived transport identity, not a fabricated upstream publisher digest.
A source-preserved Docker-manifest transport proves only stored bytes: importer,
RepoDigest, local alias and actual node-run identities remain unavailable. Neither
profile's archive admission proves Skopeo/Podman import interoperability.

The generated closed plan has schema `kubernetes-lens-owned-guest-stage-plan-v1`
and exactly `schema`, `owner`, `profile`, `files`. Its fresh 32-hex VM owner and
profile bind exactly three role records (`path`, positive integer `bytes`,
SHA-256). The plan's raw-byte digest is retained. Plan identity alone grants no
permission; admission above establishes the independent provenance.

## Closed receiver protocol

The root-owned original receiver, exact raw plan, derived table, fixed expected
header files and checksum list are embedded into the same bounded Ignition input.
The table derives directly from the parsed plan; input cannot supply another
owner, profile, role, filename, size, digest, command or environment assignment.
The root-only fixed directory is `/var/lib/kubernetes-lens-stage`. The receiver
lives there too; this supersedes the earlier `/usr/libexec` design and avoids
relying on writable FCOS `/usr`. No guest runtime observation is implied.

| Cursor | Exact header bytes                  | Role     | Published basename | Maximum bytes | Mode |
| ------ | ----------------------------------- | -------- | ------------------ | ------------- | ---- |
| 0      | `stage-kind` plus LF (11 bytes)     | kind     | kind               | 128 MiB       | 0700 |
| 1      | `stage-kubectl` plus LF (14 bytes)  | kubectl  | kubectl            | 128 MiB       | 0700 |
| 2      | `stage-node-oci` plus LF (15 bytes) | node-oci | node.oci.tar       | 2 GiB         | 0600 |

The forced command is fixed:

```text
/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin /var/lib/kubernetes-lens-stage/receiver
```

Before reading stdin, the receiver checks the pinned whole-image Bash/coreutils/
util-linux profile and root-only directory/file ancestry, source/table/plan/header
hashes, exclusive nonblocking lock, and boot-bound persistent state. The image
owns these utility versions; this route installs no packages and adds no pin owner.
These utility-version literals are closed qualification facts for the reviewed whole
image, not independent installation pins; an image update requires requalification
and review of their consumers. Unavailable tools or unsupported presentation refuse.
Pure tests do not establish
that these guest prerequisites actually hold.

A pristine first use binds the guest boot ID. Each exchange persists `inflight`
before reading its header. The header is copied to a fixed file and checked by
exact byte count and `cmp`; Bash `read` never interprets received header bytes.
Then exactly the table-selected byte count is copied to a retained regular payload
FD, whose identity, size and SHA-256 must match. A separate one-byte read must
observe EOF. Embedded NUL, CRLF, truncation, changed content or any trailing byte
refuse. Only then is executable mode set and the fixed basename published.

All receiver invocations share the same retained lock FD. Contention refuses
without poisoning an active owner. A command failure, signal or uncertain
publication leaves poisoned/inflight state. SIGKILL cannot be trapped, so the
persistent inflight marker itself refuses reuse. Cursor advancement follows
publication and precedes the reply. Reboot, replay, inflight state, poisoned state
and completed state cannot resume the operation. No recovery/reset is provided.
A lost acknowledgment poisons the **same** host session; the caller never retries,
skips a role, or constructs another session for the same VM.

The root-only directory and single-lock rule provide the no-competing-writer
premise for publication. Shell does not provide an `openat2` security boundary
against an adversary already holding guest root. This remains an explicit trusted
whole-guest boundary, including any future privileged kind node.

A successful receiver writes exactly one strict LF-terminated JSON reply with
schema `kubernetes-lens-owned-guest-stage-reply-v1`, owner, raw-plan digest, phase,
role, integer byte count, digest and `state=staged`. The host rejects duplicate or
extra fields, malformed framing, wrong identity, boolean counts, nonzero exit and
missing acknowledgment. Fixed diagnostic codes never include payload bytes,
credentials, private input paths or raw subprocess stderr.

## Original budgets, source authority and retirement

One actual worker `Budget` and one `Session` serve all three transfers. The exact
transport input ceiling is the admitted payload sum plus 40 header bytes. Actual
writes, including headers, charge that ceiling. Every SSH launch and stdout,
stderr, console and control byte uses the existing command/output counters;
work/cleanup ends are never reset. Guest coreutils are a fixed finite receiver
schedule inside the VM, not separately metered host control-plane commands.

The sender opens every source via no-follow directory FDs, prehashes the retained
regular FD, and hashes actual successful payload writes. FD/name identity, exact
size and EOF are checked again. Nonblocking writes/reads multiplex bounded SSH
and QEMU streams. The authenticated worker host-view callback replaces the
inapplicable parent-root presentation check inside the mapped worker. New helper
bytes are authenticated before loading, share the one owning module identity,
and join the source binding. Private plan/key/Ignition hashes and base-image
identity are rechecked at each staging child boundary.

The outside parent admits an ordered append-only list: info SSH, kind transfer,
kubectl transfer, archive transfer. Every actual process is retained before a
callback can fail. PID/start/group/session and exact target cgroup must be read
back externally before a transfer receives permission to write payload. The worker
actually reaps all recorded producers and QEMU; a boolean without that path does
not establish retirement. The finite producer list is also checked by the outside
retirement path, which still requires manager inactivity/no respawn, exact process
retirement, and two empty/removed complete-cgroup observations. Earlier transfer
failures survive later cleanup success or failure. Cancellation authorizes no
further payload. No existing workstation workload or cluster is targeted.

Before every parent key-generation, manager-environment or worker-start child,
the outside owner freshly rechecks source/boot bindings and its original strict
root-owned tool identities. This guard does not require private inputs before
they have been generated, and it shares the original deadline.

For staging, the existing disk envelope additionally reserves selected external
payload sizes and the full immutable 2 GiB compressed VM-input ceiling. A
preliminary stat cannot shrink that reservation or authorize a replacement input. It already reserves a private
compressed copy, expanded base, metadata and one capped overlay; the overlay cap
is reduced, never the total budget increased. Guest staging creates only fixed
files on that overlay. Temporary payload publication is a rename, not a second
payload copy. Guest virtual size does not override the host overlay cap. Ordinary
outside source owners and the installed OS remain trusted; concurrent unrelated
disk use may cause honest storage failure. No kind image store or node writable
storage is created, so future import/runtime stages need their own aggregate
storage and guest helper/PID admission.

The private receipt retains a new closed `guest_info` summary only after exact
controller validation of its fields, values and boolean types. Unvalidated frames
and raw guest JSON are not copied into that summary. If validation has not
completed, the field is `null`.

A successful final receipt is only `stage-inputs-retired`. Intermediate replies
are `stage-reply-observed`, with VM retirement `not-established` and runtime
conformance `not-performed`. Actual native execution, historical/modern API and
resource scenarios, controller behavior, image lookup/import/run identities and
hosted conformance remain pending. This phase cannot close #62, #2 or #7.

## Focused pure validation

`python3 -B scripts/fixtures/owned_qemu.py --self-test` and the existing
`kind_runtime.py --self-test` include transport, OCI catalogue, finite producer
and receiver controls. Receiver tests run an explicit task-private path/UID/package
projection of the actual Bash protocol with tiny fake payloads. They preserve the
byte framing/state/publication logic but do not qualify installed guest utilities,
privilege boundaries, VM runtime or container tools. Binary all-byte payloads
above 64 KiB, withheld EOF, killed inflight process groups, existing destinations,
publication/crash/lost-ack windows and NUL corruption at every header offset are
covered by the same explicit private projection. The complete repository gate
and independent native evidence remain separate obligations.

The asynchronous private-projection test helper uses ordinary `waitid(WNOWAIT)`
to observe its actual Popen leader without reaping it. Cleanup signals that
still-owned private process group even when the leader has already exited, then
performs the final leader wait and closes every pipe in a finally path. It never
uses a reaped leader's numeric PGID as authority. Missing groups still allow the
owned final wait; unexpected signal failures close pipes while retaining the
unreaped handle for a bounded cleanup retry under the original test deadline.
Idempotent completed cleanup does not signal again. A finite descendant fixture
proves EOF after complete-group signaling before its own fixed alarm, alongside
absent-group, signal/wait/close-error and detected ownership-loss regressions.
These are ordinary task-private child lifecycle tests, not product observers,
native guest retirement evidence or a general defense against fixture programs
that deliberately escape their private group.
