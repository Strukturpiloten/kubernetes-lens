# ADR0101: Kernel-bounded owned-VM LIVE resource envelope

Status: Accepted source contract for issue #62. Scoped upstream/downstream source
qualification has independent review. Final exact-byte implementation review,
complete validation, separate fresh native adoption and full conformance remain pending.

## Problem and precise supersession

An active guest does not provide an atomic complete proc census through finite shell
enumeration. Missing entries cannot safely become zero, and equal completed lists do
not prove completeness. V35 remains failed, spent and independently known retired under
its original finite model; its pl1.r/inv-proc-task PID, failed conjunct and cause remain
unknown. Create/delete status zero is not Deployment or conformance success.

Introduce the closed internal resource profile owned-vm-live-v1 and spec/result V13.
This supersedes only the LIVE universal census/PID-count/hard-metadata and cache
premises in [ADR0063](0063-whole-guest-hard-nofile-v2.md),
[ADR0085](0085-phase-specific-guest-census.md) and
[ADR0086](0086-owned-node-cgroup-membership.md), and corresponding LIVE descriptions
in [ADR0062](0062-owned-qemu-prerequisite.md) and
[ADR0066](0066-rootful-guest-check-settling.md).
Historical source, records, codes and temporal claims keep their original meaning.

The three original provider/prerequisite/execution stable admissions retain every
PID/TID/start/limits/FD/count/SNAP predicate, two scans and exact equality. They are
strict finite sampled guards, with no new atomic or exhaustive-membership claim.
Only obsolete start-cache bookkeeping is removed from current source, since no
current consumer uses it. The exact predecessor inverse restores that bookkeeping
and all other source339 bytes for historical controls.

## Explicit numeric theorem and remaining trust

The [closed compatibility record](../../scripts/fixtures/owned-live-resource-envelope-source-facts-v1.json)
and [exact schema](../../scripts/fixtures/owned-live-resource-envelope-source-facts-v1.schema.json)
bind the canonical FCOS image identity, admitted local KVM/QEMU domain, component
versions, source qualification and residual premises. They are reviewed compatibility
anchors. They introduce no installer, competing software inventory or operational pin
owner. A canonical image update fails admission until a newly reviewed matching
compatibility record is enrolled.

The selected normal native x86_64 standard VFS initial/allocated/duplicated FD tables
have at most 268435392 slots; use the conservative F=2^28. Every counted simultaneous
LIVE normal-lifecycle user/helper FD owner retains at least one unique resident 4096-byte
page from coherent managed system RAM. Under the existing exact configured 4GiB
managed-RAM ceiling, T<=2^20 and U<=T*F<=2^48=281474976710656, strictly below the old
32767*9999999999=327669999967233 ceiling. F also preserves occupied indices below
the original 1073741816 ceiling. The loose UINT_MAX bound does not suffice:
2^20*(2^32-1)=4503599626321920. The distinct 16KiB task-count product is
1125899906580480; the frozen-v2 factor-four error is not carried forward.

U is instantaneous logical user-FD slot occupancy summed per LIVE normal owner;
shared tables may be conservatively counted per owner. This does not prove global
PID/TID<32768, total task count<=32767, finite current hard-NOFILE metadata, complete
membership/cache, continuous or future absence, or cumulative births/opens/work.

Recursive PF_EXITING fault/dead-leak paths can bypass normal exit_files ordering.
Dead/leaked files pointers, detached/in-flight references, allocated/RCU table backing,
kernel-owned resources and unjustified worker-lifecycle extensions are outside U.
Their cost is not zero: unchanged physical RAM/backing storage and complete independent
per-run whole-VM retirement retain their separate authority.

Signed Fedora kernel7.2.7-200.fc44.x86_64 source and openSUSE
qemu-x86-11.1.2-1.1.x86_64 source have scoped relevant equivalence to Linux7.2.7
f42acb3678424d1e08f6ed27c0d8ba8a125e14d6 and QEMU11.1.2
4fc49f46dc95d4a27de2509e7fceb2931e91faeb. The record binds the independent
qualification review and primary acceptance of that facet. It does not attest the
running binary/configuration, prove reproducibility, audit all writers/extensions,
or establish module/livepatch absence.

Official distribution-build provenance, coherent kernel/allocator/firmware hardware-map,
trusted OS/module/livepatch/program/global state and fixed-command QEMU semantics remain
explicit premises. QEMU can have reserved ROM/device RAM-backed mappings; these are
not Linux buddy managed stack RAM. No extra memory device/backend or hotplug capacity
is supplied by the fixed no-user-config/nodefaults, -m4096, omitted slots/maxmem/QMP
construction. Host8GiB/TasksMax256 and a MemTotal sample are distinct facts.

## Closed source, spec and result domains

The sole existing post-kind/log-retirement call selects the literal vm-live-v1.
Zero arguments still select stable admission. Empty, old live and unknown/extra modes
refuse before resource observations. No environment/public-input/rootless/fallback
selector is introduced.

All existing scalar pid_max32768/nr_open, namespace, mounts, memory/no-swap,
device/mapper and filesystem checks remain. LIVE constructs no SNAP or process/task/FD
member list and cannot silently omit an unknown member. It has no inventory cache.

Before guest effects, the existing host source-custody route validates bounded exact
fact/schema hashes, the canonical FCOS owner and exact admitted host-QEMU record.
V13 spec includes resource_profile and resource_facts_sha256; guest selection requires
both exact values and V13 schema. V13 results require the exact profile and V13 spec.
Old V12 cannot satisfy new meaning even if owner/plan/evidence are rebound. Historical
V12 and earlier decoder domains remain. Inventory failure reasons cannot masquerade
as a V13 LIVE observation.

These fixed metadata reads use source-custody plumbing, not a new runtime/kernel
observer. No native helper, process observer, census retry or kernel probe is added.

## Direct selected-node interval

Retain exact owned node CID/image/name/running/network/inspect-root binding and actual
small PID grammar/range checks. Use the existing three reads only: first stat,
canonical exact owned-CID root-or-descendant cgroup, second stat. First stat validates
literal PID/comm framing, at least20 fields and decimal start. The second must have
literal same PID and start. Keep genuine private sampled stat/cgroup evidence.

Missing, malformed, unreadable, wrong/reused PID/start, foreign/noncanonical cgroup or
inspect drift refuses before later API/scenario work. There is no stale cache/default.
The interval starts at the direct first stat. This replaces the earlier pre-inspect
census-cache anchor explicitly; it proves no original creation, inspect-to-first-sample,
continuous/ABA identity or membership, cgroup-namespace authentication or signal authority.

## Unchanged resources, effects and acceptance

Retain CPU2; host8GiB/swap0/Tasks256; guest4GiB/no-swap; aggregate disk24GiB;
native70/5/75; utility680+24 prepaid+64 within768 plus separate stage256;
output1MiB/work245/cleanup10/sentinels150; all input/FD/capture/source limits;
receiver integration65408 and outer65536; and original1800/1680/120 ends.
No new reservation, credit refund/reset, cleanup borrowing, observer, retry, native
grammar or runtime fallback is authorized.

Capture prepayment, genuine EOF/waits/FD closure, one-shot owner/plan/boot/source claims,
sticky first failure/poison, saved incoming status, independent genuine delete failure,
private durability/public redaction and outside complete target retirement remain.
Eventual disposal or this theorem cannot substitute for per-run retirement or native work.

Current source uses only reviewed comment shortening and obsolete cache removal for
space; no source/accounting relocation, lint waiver or hidden compression is used.
A strict new-to-source339 inverse restores full predecessor bytes, then every previous
inverse remains exact. Final pinned-formatted byte fit and independent source review
are necessary; source fit is no successful runtime budget fit.

Current source-body controls cover stable/LIVE selection, scalar guards, direct target
samples, actual finish/credit/capture behavior, closed metadata/spec/result/history,
ownership failures and public redaction. Source/kernel reasoning and test fixtures
remain different evidence. Required complete validation runs after final integration.

All35 kinds, exact official tools/fixtures, positive/invalid/unsupported/version
boundaries, API/runtime/controller semantics, legacy/modern and each claimed local/hosted
domain remain required. First Deployment smoke success does not close #62/#2/#7.
No BoxFerry Kubernetes product acquisition/adapter, release, publication or deployment
is supplied or authorized by this source proposal.
