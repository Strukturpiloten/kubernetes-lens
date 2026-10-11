# ADR 0015: Root-selected native wait observation

Status: accepted source contract; native conformance remains pending.

This refines ADR 0014 for operations explicitly selected by the root broker configuration.
The default remains absent. The closed `wait_observer` object contains only `profile` and
`tool_sha256`; the only accepted profile is `strace-7.2-supervisor-wait-v1`, with
`/usr/bin/strace` SHA-256
`508698af314d3fad6bed553d0dcb59e5002732339ea205ebcce1c617dd368b92`.
The canonical fixed profile is recorded in
[`native-wait-observer-profile.json`](../../schemas/capabilities/native-wait-observer-profile.json).
It is an excluded historical conformance anchor, with checked Rust consumers, rather than a
second operational tool installer; its executable digest does not seal the loader/library closure.
Selection is restricted to Linux x86_64. Clients cannot choose a PID, command, tool path,
trace flags, status, evidence path or additional budget. A selected refusal has no retry,
late attach, fallback to the unobserved route, or extension of either original end.

The capability-free leased launcher holds and hashes the helper and tool images before
FD-based execution. It requires the initial user namespace before executing the observer;
full identity UID/GID maps do not prove that boundary. Root separately authenticates the
actual held tracer and supervisor credentials, namespaces, images, cgroup membership and
process identities before opening the existing native permission gate. The separately reviewed
initial-namespace clarification v2 (SHA-256
`277eb6d4fd6117e8a06704e2a8062e4e2c3cc94befc9018fd7ae47f1177210b9`),
which preserves clarification v1 (SHA-256
`ad2091087e913f5ba3c3ebe204ae0d9b3aaf6d6aabcece2f10a040a5eca4f6dc`)
retains the immutable parent contract (SHA-256
`eff0e36afb0a3bb233342349016dacf5ab1eefc63ce6a1753b104673029bc256`). Root holds
its authenticated initial namespace before work creation. Fixed systemd `PrivateUsers=no`
and `StandardInput=file:/proc/1/ns/user` hand off a root-opened witness on existing FD0.
PrivateUsers is ancestry policy, not proof: any automatic systemd namespace fallback still
fails the actual namespace comparison. Launcher compares that held FD0 with its own held
namespace, replaces FD0 with verified `/dev/null` and closes temporary witness descriptors
before tool execution. Observed supervisor authenticates its own initial namespace again
before control/native effects. Root readiness independently compares its retained witness
against held actual supervisor/tracer namespace objects.

A separately source-reviewed safe type check avoids unsafe ioctl code or new dependencies:
fstatfs on the same held namespace FD must be NSFS_MAGIC, fstat inode must be reserved initial
user inode 4026531837, and numeric readlinkat from an authenticated PROC_SUPER_MAGIC directory
must return exactly `user:[4026531837]`. The kernel nsfs dentry name derives from namespace
operations, whose `user` class is CLONE_NEWUSER; it is not a caller-supplied filename label.
Before/after descriptor identity must agree, and own/handed-off/root-retained dev/inode matches
are mandatory. No trimming, aliases, ordinary symlinks, pathname fallback or identity maps
substitute for this witness. All missing/changed/unsupported evidence refuses before tool/native
permission. This is source-backed admission, not evidence that installed runtime handoff passed.

Official systemd 261.3 commit `3255daee1572366b74fe92f002a3d60ecbb27103`,
`src/core/exec-invoke.c` 272–283, 420–433, 5536, 6018–6030 and 6376 establish
root-opened stdin before UID dropping and possible automatic PrivateUsers fallback.
Official Linux 7.2.8 commit `9a66fdc0d7fd55f54235524a73435af99051e46f`,
`include/uapi/linux/nsfs.h` 50, `fs/nsfs.c` 43–54, 239–240 and 428,
`kernel/user_namespace.c` 1400–1406, `include/linux/ns/ns_common_types.h` 185/205,
`fs/proc/fd.c` 174–186, `fs/proc/base.c` 1815–1824 and `fs/d_path.c` 281–283
establish the reserved inode, namespace type, held FD path and kernel-generated name.
The installed host reports 7.2.8-1-default; upstream source does not authenticate distribution
patches or replace actual host/runtime evidence. These source facts are independently authored
here; no upstream implementation is redistributed.

Stock strace starts as the supervisor's parent with fixed `-D --trace=wait4 --signal=all
--interruptible=2 --decode-pids=none --quiet=none --color=never
--const-print-style=abbrev` arguments. This observer neither follows forks nor performs
injection, late `-p` attachment or EXITKILL. The independent existing gate observer is unchanged.
The helper descriptor and trace writer are removed before the supervisor creates the ordinary
control/Bubblewrap/gate/renderer path. The parser admits a finite ASCII vocabulary: exact
supervisor attachment, startup nonproof, the held child's zero-result WNOHANG poll, a matching
consuming exit/signal/core wait, bounded auxiliary signals and one natural supervisor terminal.
Disappearance, a startup reap, a signal-delivery record or forced stream closure never proves
native child reap. The ACK must agree with the consuming wait including the core flag. Every
contributing recvmsg fragment independently carries exactly the original supervisor's
SCM_CREDENTIALS; missing, wrong, extra or truncated ancillary evidence refuses admission.
A bounded nonblocking no-ancillary peek precedes recvmsg on the sole owning reader. It detects
zero-byte EOF without decoding Linux's zero-PID EOF credential sentinel through rustix's
nonzero Pid type. Positive peek leaves bytes queued for the actual credential-bearing recvmsg;
EOF itself proves no sender or process status. Reader races refuse, never authorize retirement.
The private accepted stream has one owning ACK reader, no concurrent local shutdown/close,
no PEEK_OFF changes (kernel default -1), and ordinary in-band writes. Root's same-PID-namespace
readiness precedes positive credential decoding. These fixed ownership assumptions cannot be
relaxed to arbitrary sockets. Linux 7.2.8 `net/unix/af_unix.c` 2377–2445, 2945,
2989–2990, 3024–3031, 3056–3085 and 3105–3114 plus `net/core/scm.c` 513–521
establish buffered-data, peek, rights and EOF-sentinel behavior. The existing rustix 1.1.5
crate checksum is `891efababe418670775f199f0d233d84843c227a0949a883ce15b37c78d6629d`;
its typed UCred embeds nonzero Pid and ancillary drain/drop must not decode EOF's zero PID.
The local socket regression exercises this receiver path; it is not an official-tool fixture.
The shared native descriptor handoff has the same zero-PID EOF guard before ancillary receiver
construction. Its plain peek retains the original blocking read timeout; remaining time is derived
again from the same original end before recvmsg. This prevents early root-peer closure from
constructing an invalid typed credential while retaining delayed handoff, partial-message
refusal, descriptor counts, credential checks and rights cleanup.

Original received request bytes are hashed at admission; descriptor, journal and origin retain
that hash rather than reconstructing a canonical request. Origin is appended once before
native permission; retirement is appended once after authenticated ACK EOF, consuming wait,
natural trace EOF, held tracer death and zero remaining writers. Pumping stays on the existing
controller and owning tracer threads with at most sixteen 4096-byte reads per quantum.
Manager, setup, accept, receive, digest, output, audit and cleanup loops use the same original
execution/total ends. Failure is sticky; exact-owned cleanup can continue, but cannot manufacture
positive observation or release the identity lease.

An observed operation reserves one root:root 0700 `archive/<nonce>.json` directory inside the
existing 256-entry archive cap. It contains only root:root 0600 single-link `trace.fifo`,
`trace.bin` (4 MiB), `ack.bin` (65536-byte body plus one newline), `origin.json` and
`retirement.json` (65536 bytes each), and finalized `record.json` (32768 bytes). The original
16-active cap and original input/output/resource ends remain unchanged. Final publication adds
`record.json` inside that reserved entry; no top-level sidecars increase scanner admission.
Per-operation retirement rereads and hashes its own complete evidence before lease release.
Cold scanning reads only the original bounded record plus the six finite child metadata
entries, never all retained trace/ACK/origin/retirement bodies. Missing proof, partial publication,
orphan reservations, live/archive overlap, different-boot observed records or format downgrade
remain quarantined. Legacy regular-file archives retain their original format.

The source-derived signal vocabulary is authenticated against official strace 7.2 commit
`195ac8ddbf6fad16ff1ff125b0feb725b6c46dcf`: `src/signal.c`,
`src/linux/generic/signalent.h`, `src/wait.c` and `src/strace.c`. Canonical Linux signals 1–31,
`SIGRTMIN` (32) and `SIGRT_1` through `SIGRT_32` (33–64) are accepted; aliases and alternate
realtime spellings are refused. Upstream is LGPL-2.1-or-later, with individual source notices;
no upstream implementation is copied or mechanically translated and no upstream source/binary
is redistributed by this change. Consulted source is behavioral provenance only. The fixed
executable digest does not authenticate the dynamic loader or shared libraries; reviewed host
closure remains an independent runtime obligation.

Focused grammar, local socket and recovery-model tests are source evidence, not native fixtures.
All ninety renderer cells, three graph cases, both target patches and the full unchanged CNPG
30-second/4-MiB default render remain mandatory and unfulfilled by this ADR. No provisioning,
installation, grant, renderer execution, cluster effect or publication is authorized here.
