# ADR0086: Owned node cgroup membership

Status: Accepted source correction; independent final source review, complete
validation and separately adopted native qualification pending (#62).

## Context and selected source facts

V24n remains failed-retired/spent: create0/delete0, V8 pl2.g, positive seven-role
logs and ordinary node-inspect, with source Deployment not-reached. The g group
includes the existing proc-file helper and predicate. No proc-cgroup text was
retained, so neither an equality mismatch nor init.scope or any actual cause is
established. Previous guards succeeding and cleanup do not become native success.

Pinned Podman5.8.7 commit c593b672bf3db1173aebea565ebf1a724ea196dc reads the selected
PID's cgroup, then deliberately trims a cgroupfs descendant after /libpod-ID/ to
report the container root. Inspect uses that normalized root. Thus the inspected
container root need not equal the literal process leaf:

- [cGroupPath](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/libpod/container.go#L1139)
  reads membership; lines1197–1200 trim descendants for cgroupfs.
- [Inspect](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/libpod/container_inspect.go#L110)
  uses cGroupPath and assigns State.CgroupPath at139.
- [crun1.28](https://github.com/containers/crun/blob/54f16ffbefcd022bf032af768b5c5ce075c18bfc/src/libcrun/cgroup-cgroupfs.c#L107)
  retains the supplied container root. Its annotated1.28 tag resolves to that commit.
- [Approved systemdv257](https://github.com/systemd/systemd/blob/70bae7648f2c18010187c9cf20093155eaa26029/src/core/cgroup.c#L4270)
  creates/attaches init.scope under the manager root.

The already approved legacy image config SHA256
6b1578e8b4e934319a18ea47cd133ce820ac74f63255c5a739fe32b4b79bcc8e declares
/usr/local/bin/entrypoint followed by /sbin/init. Config/upstream facts do not attest
the installed node executable/build, downstream RPM equivalence or V24n's path.
The existing monochrome facts retain that limitation. Podman's intentional root
normalization supports this correction independently of a guessed runtime cause.

## Decision

Refine only the g assertion on the existing consumed REPLY. Accept exactly a
unified-v2 0:: header followed by the already validated literal owned root, with
zero or more slash-delimited, nonempty canonical descendant components. Components
contain no slash/control character and are not exactly dot or dotdot. Quote the
trusted root literally in the anchored builtin predicate. Keep fixed LC_ALL=C.

Exact root, init.scope, deeper system.slice/service paths and ordinary dotted names
such as .hidden/a..b are valid. Reject sibling/foreign/ancestor roots, container-ID
prefix lookalikes, relative or namespace-local paths, empty components, repeated/
trailing slash, dot/dotdot anywhere, controls and nonempty additional records.
There is no path decoding, realpath, traversal, normalization or root substitution.
Preserve actual successful REPLY unchanged in the existing private process file.

Keep guest and host exact inspect-root checks, owned ID/image/name/running/network
binding, PID grammar/range, second-inventory start cache, first stat PID/start,
existing cgroup read and second stat/start. Missing cache, failed read or either
identity mismatch still refuses before later work. No earlier cache fallback,
extra read/query/helper/process/loop/retry or new raw evidence role is introduced.
Earlier failure, poison, original exit capture, independent delete failure, private
durability/public redaction and outside whole-VM retirement retain their contracts.

## Namespace, framing and authority limits

[Selected upstream Linux7.2.7 documentation](https://github.com/gregkh/linux/blob/f42acb3678424d1e08f6ed27c0d8ba8a125e14d6/Documentation/admin-guide/cgroup-v2.rst#L3125)
defines proc paths relative to the reader's cgroup namespace. A payload's private
view does not authorize interpreting its slash as the guest reader's full owned
root. Retain the existing trusted kernel/proc/initial-guest-reader/source premise.
PID namespace checks and path strings alone do not authenticate cgroup namespaces;
this change adds no such attestation or namespace probe. Reject visible relative/
escape/foreign forms without repairing them. Unknown reader provenance is not
silently supplied by a successful match.

Membership is sampled at g. Two stat samples do not freeze migration or establish
continuous membership/liveness. Whole-VM physical/resource/lifecycle boundaries and
independent outside retirement remain separate authorities; a path grants no signal
authority. Hostile guest root remains outside the accepted trusted-program premise.

Existing read_file strips trailing newlines. The assertion concerns consumed REPLY,
not a new exact raw-byte framing theorem. Nonempty embedded records and controls
refuse, while arbitrary trailing empty records were not newly distinguished. Do not
add an unbudgeted raw reader or manufacture evidence by replacing a descendant with
its root. The actual V24n failure remains unexplained.

## Source history, accounting and checks

The reviewed literal-root receiver is65359 bytes, SHA256
237b5a10e1d767fa05588ff5dfc6d73cfa2959409bece5cc758b0f374d104829.
One ordinary comment is consolidated to keep unchanged65408 integration/65536 hard
caps; the raw delta is5 bytes. Every numeric profile, PID/FD/NOFILE/storage/resource
cap, native70/5/75 action count, rootful680+24+64 and stage256 utility reservation,
input/output/capture budget and actual1800/1680/120 timing remains. No installed
software/image/tool/pin/API/default/schema or Renovate owner changes.

V8 fields/code meanings, exact host inspect-root validation, old g failures and all
earlier evidence/schema domains stay unchanged. Advance only exact receiver source
enrollment; prepend strict current-to-frozen65354-byte19c958 phase-source inversion
before unchanged history. Preserve all574 predecessor IDs/assert inventories,314
literal patterns and immutable fixtures. Older phase-corridor controls explicitly
use their frozen source domain; current membership gets separate controls.

This supersedes only proc-leaf-equals-container-root in ADR0084's g contract and
ADR0085's historical unchanged-corridor description. Other phase, cache, namespace,
resource and lifecycle requirements remain. Controls execute the original corridor
with private proc-shaped/fixed helpers, root/descendant/dotted positives and canonical/
foreign/helper/cache/start negatives. Actual successful descendant text stays private;
g failure cannot reach the write/native boundary, and real helper failures remain
separately tested. First failures and actual delete0/19 are independent under real
finish. Final pinned formatting, review, full validation and fresh native adoption
remain primary responsibilities; tests establish no native qualification.

Context7 preceded pinned-source research. Public read-only GET identities, hashes,
line windows and licenses are retained in the local review packet. Podman reference
is Apache2; systemd/libcrun source is LGPL2.1-or-later; Linux's selected COPYING states
GPL2 with Linux-syscall-note without inventing a doc-specific SPDX header. Temporary
public quotations support review only: no upstream implementation is copied,
mechanically translated or vendored into this repository, and no publication occurs.
