# ADR 0073: Versioned private post-create guard reason

Status: Accepted source contract; final validation and native qualification pending (#62)

Refines ADR 0071's private failure evidence and ADR 0072's prefix scope. It does not
change any retained attempt, retire an owned target or authorize another attempt.

## Contract

Emit `kubernetes-lens-owned-rootful-result-v2` with the existing top-level members.
The decoder explicitly accepts legacy v1 with its three original log states and
v2 with those states plus the fixed private `pg1.a` through `pg1.p` vocabulary.
Unknown versions, unknown codes and wrong types refuse; no state is normalized.
The evidence catalogue and private/public receipt schemas and roles stay unchanged.

A code is valid only in a v2 failed result with actual integer kind-create status
0, source deployment not reached and startup flag false. Coded logs are incomplete:
nullable identities/collectors, failed collectors and the original overflow sentinel
allowance retain their failure meaning. They cannot satisfy complete EOF, positive
retirement, readiness, success or acknowledgement requirements. The same version-aware
incomplete-state classification governs the existing protected prefix; owner,
plan, source-spec, raw/base64/hash/length and private-only checks remain mandatory.
Standalone decoder calls must supply v2 and the matching failed context for codes.
The worker still requires the actual successful native status and positive proof;
the parent revalidates exact raw bytes before its existing durable write.

Initialize one private, unexported reason empty at receiver entry. Only an already
existing false predicate in the original direct `logs_retirement` call selects a
fixed code. Assign only while empty; the first evaluated failure survives cleanup.
Preserve the original predicates, order, short circuiting, 4096 bound, reads and
invocations. Untagged helper failure, skipped evaluation or interruption leaves
`not-established`, which means the reason is unavailable. No enclosing-stage guess
is assigned. The existing clock call supplies fixed context only to its existing
final UPTIME/limit false comparison; clock read/parse/helper failures stay untagged.
A genuine established retirement record keeps its original handling.

| State   | Existing false predicate only                       |
| ------- | --------------------------------------------------- |
| `pg1.a` | Initial no-poison predicate                         |
| `pg1.b` | PID/start lexical shape                             |
| `pg1.c` | PID ceiling                                         |
| `pg1.d` | Existing proc-stat read failed                      |
| `pg1.e` | Returned proc-stat PID equality                     |
| `pg1.f` | Stat-field count/start lexical shape                |
| `pg1.g` | Identity not retired within the existing fixed loop |
| `pg1.h` | Collector status/count/EOF closure tuple            |
| `pg1.i` | Stdout byte ceiling                                 |
| `pg1.j` | Stderr byte ceiling                                 |
| `pg1.k` | Source-owned capture-path pair                      |
| `pg1.l` | Regular, non-symlink capture files                  |
| `pg1.m` | Existing startup-marker accumulator                 |
| `pg1.n` | Available direct wrapper status equals zero         |
| `pg1.o` | Final no-poison predicate                           |
| `pg1.p` | Existing original work-clock comparison             |

These aliases identify only a false evaluated branch. In particular a stat-read
failure does not prove persistence, loop exhaustion does not identify its cause,
and the marker accumulator describes only bytes scanned at that evaluation. Later
captures containing a marker cannot identify an earlier failed guard or repair
its result. The retained V10 failure and its exact cause remain unchanged/unknown.

## Costs, privacy and source evidence

There is no new read, query, wait, sleep, tool, observer, retry, helper process,
reason file or wire member. Selection uses constants and already returned facts.
Only `logs.state` carries the private alias; genuine captured stdout is unchanged.
Public diagnostics retain ordinary failure/status/descriptors, with no code appended
to the prefix and no PID, path, tick, signal, raw state, key, token or log body.

Keep all 49 query sites, 314 historical prerequisite patterns, 680 work/24 guard/64
cleanup utility partition, native/storage/output/raw/metadata/wire caps, original
absolute ends, four prepaid prefix tickets and independent retirement rules.
The canonical receiver must fit the unchanged 65536-byte source cap. Shorten only
comments in touched helpers to fund this seam; exact inversion restores the prior
source anchor. Current enrollment follows current bytes; old recordings, source
assets, historical hunk tuples, expected patterns and source facts stay sealed.

## Focused evidence and remaining obligations

Pure controls compare all sixteen actual false branches against the prior receiver
using projected files, including read order/counts, compound branches and fixed-loop
boundaries. They cover true/skipped/interrupted/untagged paths, first assignment,
unexported initialization, legacy v1 behavior, strict v2 scope/types, incomplete
collector/null/sentinel cases, genuine prefix/privacy/credit conservation, exact raw
durability and the actual mocked worker failure path without positive promotion.

Canonical format, syntax, source inventory and focused controls are implementation
evidence only. Final independent source review and the primary's complete gate must
pass after final source changes before any separately adopted native attempt. No
runtime qualification, repaired cause, rootless support or universal quota headroom
follows from this contract.
