# ADR0098: Modern default-storage capture allocation

Status: Proposed. Refines ADR0097's provider source boundary and retains every earlier
source/history contract.

At proposal creation, subject controls, independent review, the complete gate and any
separately adopted attempt were pending. This is an immutable creation-time validation
snapshot. Later formatting, test, complete-gate and adoption results live in separate
records and must never be inferred from this snapshot; successful checks require no
source update.

## One explicit role allocation change

Only the exact owned-node storage retrieval under modern-1.37.0/kind 0.33.0 receives
stdout 8192 instead of 4096. Stderr stays 4096. This is an explicit 4096-byte per-role
increase; legacy storage and every other role remain unchanged. Storage-install
continues 4096/4096 output despite its complete 4567-byte stdin. No grammar, command,
bootstrap option, owner/source/phase admission, status or error acceptance changes.

The original native allocator is byte-exact. Its existing combined-cap arithmetic
charges three output-work slots for 8192+4096 instead of two. All three slots, both
original sentinel credits and all original action/utility credits are taken before
collectors and exec; denial cannot borrow cleanup capacity, reset/refund credits or
launch a command. Aggregate 1MiB, 245 work/10 cleanup slots, 150 sentinels, 70/5/75 native
actions, 680/64 utilities, 24 prepaid guards and 1800/1680/120 total/work/cleanup seconds
remain unchanged, as do CPU/memory/PID/storage/FD and all other limits.

## Complete transport and refusal

The authenticated frozen storage file is 4567 bytes/SHA256
`dc16a44e6a49a1f26fc39f341c361e7939993bd68431efc3a49d216e5914e903`.
Every byte, resource, field and final newline must pass the existing capture/forward/
kind Reader/shim/provider/native FD0 chain once. No truncation, filtering, conversion,
image mutation, source shrinking, fallback-as-success or new stdin framing is supplied.
The main 4096 execution request parser does not consume provider apply stdin.

Over 8192 follows the original maximum+1 helper23/wrapper125/work-poison behavior;
legacy over 4096 remains the original refusal. Other failures stay raw/opaque.
Subsequent work and fallback cannot clear first poison; original deadlines,
cancellation, cleanup and independent whole-target retirement remain mandatory.
A complete file transfer alone does not prove apply/defaultSC/API or remaining-route fit.

## Source, privacy and history

[Portable source facts](../../scripts/fixtures/owned-modern-storage-capture-source-facts.json)
retain exact public revision/URL/hash/license references. No upstream implementation
or private archive body is copied into product/test source. Portable transport controls
use original independent 4567-byte DATA; a separately held authenticated-payload control
requires explicit private execution and is not part of public source. At proposal creation, neither the portable controls nor the private
authenticated-payload control had been executed. Historical V34 inner child/wrapper/predicate remain unobserved;
static incompatibility is not a retrospective collector23/wrapper125 attribution.
Failed/spent source337 records and the original retirement review stay intact.

A strict new-current inverse restores 65361/35035 logging source before the unchanged
65388/491078, 65378/5bc and older domains. Existing operational enrollment aliases
advance separately from frozen constants. Three named test methods change only source
inputs through explicit inverses; assertion/expected/counterexample text is preserved.
The old logging helper selects its frozen epoch so original role expectations remain
historical; new storage controls select current. No accept-either source selector.

One classifier line adds 56 bytes. Four ordinary jq--arg comments retain their meaning
while recovering 20 bytes; licenses and every ShellCheck directive remain exact.
Pinned canonical source is 65397 bytes/SHA256
`0a512e1f5d2a9463e17fd5d10319b4a989129eb1149a5c4f4fbfc84b688424ad`, 11 below 65408
integration and 139 below 65536 hard. At proposal creation, targeted formatting/ShellCheck passed; this
creation-time snapshot supplies no subject-test or complete-gate evidence. No operational pin/installer/version inventory
changes; existing fixtures Renovate exclusions remain, with static no-change evidence
only. Primary owns final review/source custody/integration, the complete gate and any
fresh exact-source adoption; no automatic V34 rerun or new approval tier is created.
