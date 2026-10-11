# ADR 0016: Pre-permit input-view rendezvous

Status: Accepted source contract; native acceptance pending

This refines ADR 0015 with an optional private rendezvous after authenticated readiness and
publication of `origin.json`, before the original `RootPermit::send_once`. The root controller
remains the only permit owner. No public API, extra journal phase, archive child, external
witness path, FD transfer, thread, process, signal, service or resource allowance is added.
The implementation is original product code; no external harness implementation is included.

The reviewed source specification v2 has SHA256
`d38c3954e837249fd5e187a73820f218ea4d7c59ba2c09b2e54f7e8d6377db0b`.
The reviewed product-boundary clarification v1 has SHA256
`aaf9537210b78e734195e20c013fffc4c2649069cfa65ea6f80fbb5db64ff32a`.
These identify source contracts, not native evidence or authority to launch an environment.

## Selection and authority

The existing outer root `Config` remains schema 1. Its optional `input_view_witness` and the
corresponding private descriptor field default to absent; null also means absent. Selection
requires controlled request schema 2 and selected wait observation. Schema 1 and missing wait
observation refuse before creating transport-owned effects. There is no passive fallback.

The closed selection contains exactly `schema: 1`,
`profile: "root-pre-permit-input-view-witness-v1"`, `socket`, `boot`, `grant_nonce` and `observer`.
The observer contains exactly `pid`, `start`, `uid: 0`, `gid: 0`, `image_sha256` and
`cmdline_sha256`. PID must exceed 1, start must be nonzero, SHAs are 64 lowercase hex
characters, and the grant nonce is 32 lowercase hex characters distinct from the request nonce.
Boot uses the original canonical operation spelling. The absolute, non-abstract socket path
rejects NUL, traversal, redundant components and the actual Unix-address length overflow.

The socket has root-owned 0600 permissions in a root-owned 0700 parent. Every ancestry object
and socket node is held and rechecked; symlink ancestry, replacement and writable ancestry
refuse. A single nonblocking Unix stream connect is attempted. Unavailable, backlog-full,
pending or interrupted connection attempts refuse without retry or reconnect.

Kernel peer credentials, held pidfd/start/liveness, held proc identity, exact four UID/GID
slots, empty supplementary groups, single-thread identity, executable and command-line hashes,
original boot, admitted initial user namespace, retained controller PID namespace equality and
held cgroup identity authenticate the selected actor. Root UID alone is insufficient. These
bindings are rechecked throughout the exchange and executable bytes are rehashed afterward.
The gate retains its separately audited child namespaces; root namespace rules do not apply
to it. Retained PID namespace equality does not establish an initial PID namespace.

## Wire and ordering

Each direction has exactly one eight-byte big-endian u64 length and compact UTF-8 JSON body.
Offer is at most 4096 bytes; Ack is at most 2048 bytes, excluding their respective prefixes.
Root sends Offer then closes its write half. The observer must verify actual receive EOF before
capture. It sends Ack then closes its write half; root requires actual receive EOF afterward.
Every positive recvmsg fragment, including prefix bytes, has exactly one matching original
SCM_CREDENTIALS. Missing, extra, wrong or truncated credentials, ancillary rights, truncated,
empty, oversized, incomplete or additional frames refuse.

The sole owning reader first makes a plain non-consuming one-byte PEEK, before constructing a
typed ancillary buffer. Zero PEEK is actual EOF; EAGAIN and EINTR remain pending and yield to
same-thread deadline/cancellation/pumping. A positive PEEK requires credentialed recvmsg. A
zero receive after a positive PEEK refuses as a reader race and never decodes a zero-PID
credential sentinel. This freezes sole-reader ownership, no concurrent local close/shutdown,
default SO_PEEK_OFF=-1 and ordinary in-band stream assumptions. EOF is not status evidence.

Offer has exactly `schema`, `profile`, `grant_nonce`, `request_nonce`, `request_sha256`, `boot`,
`execution_ns`, `total_ns`, `controller`, `supervisor`, `bwrap`, `gate`, `tracer`, `leased_uid`,
`leased_gid`, `work_invocation`, `ready_ns`, `descriptor_object`, `origin_object`,
`stage_input_object`, `input_object`, `mount_namespace_object`, `cgroup_object` and
`origin_sha256`. Five role-distinct process identities contain exactly `{pid,start}`; wire
object identities contain exactly `{dev,ino}` with type/owner/mode checked on actual objects.
The request digest covers the original first JSON frame payload, excluding its prefix and
later file frames. Origin digest covers the exact held published body.

Ack has exactly `schema`, `profile`, `grant_nonce`, `request_nonce`, `request_sha256`,
`offer_sha256`, `witness_sha256`, `capture_started_ns` and `capture_finished_ns`. It binds the
actual Offer bytes and requires
`ready_ns <= capture_started_ns <= capture_finished_ns <= current_ns < execution_ns`.
Unknown, duplicate, missing or wrong types refuse; integers exclude booleans, floats,
negatives and overflow. SHA syntax permits all-zero hex, which alone proves no witness.

The product never reads or parses the external witness body or gains authority over its
location. The observer independently verifies and persists it; the external harness later
binds and interprets it. The product authenticates the peer, frame, correlations, digest syntax
and original capture interval. Before permitting, it rechecks its retained descriptor/body,
origin/body, five processes, gate root/cwd, staged and mounted input roots, mount namespace,
cgroup, manager invocation, pinned gate image/argv, wait readiness and audited namespace/mount
setup. Replacement after Ack refuses. Handles remain local until the original permit decision.
Existing trace-armed persistence, permit, native wait/core proof, natural observer retirement,
cleanup, lease release and six-child archive publication remain mandatory.

## Original bounds and outstanding evidence

Capture consumes the original execution interval and total end. Full CNPG remains at most
30 seconds aggregate, at most 20 seconds execution plus the original 10-second cleanup
reserve; all 90 cells, three graph cases and both target patches remain required. There is no
new clock, budget extension or resource-fit claim. Same-thread work pumps trace and checks
cancellation and deadlines. Finite checked open/read/hash/persist/recheck work cannot hard-cancel
a stalled kernel open/read/fsync. Installed-environment watchdog and cleanup evidence remain
necessary. Focused source controls never establish final native acceptance.

The external witness ceiling remains 32768 bytes; product bodies and both prefixes add at most
6160 bytes per operation before separately charged evidence. Original aggregate traffic,
retained evidence, memory, FD, CPU, process and trace envelopes still apply. Independent
external admission remains blocked on:

- B1: exact independent mounted golden closures for all cells, companions, repeats and graph
  cases, including sealed values paths, bytes and provenance.
- B2: exact operation count and actual remaining aggregate evidence and traffic fit.
- B3: actual root actor RSS/Python objects, FD lifetime and double-read amplification fit.
- B4: original-grant-authorized per-run actor and immutable configuration sealing before
  original broker activation, without shared/global rewrites or replacement grants.
- B5: actual installed-kernel stall, watchdog and original cleanup evidence.
- B6: independently implemented, reviewed and sealed external metadata projection for the
  full 19158976-byte ledger under the original 4-MiB Python retained parse cap. Preserve the
  full ledger hash, Rust embedding, all semantic oracles and original bounds.

No B1–B6 blocker is solved by an Ack digest, product reports, focused tests or this ADR.
