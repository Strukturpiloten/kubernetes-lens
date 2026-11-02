# ADR 0067: Fixed presentation setting for the owned kind node

Status: Proposed source contract for issue #62; native qualification remains pending.

## Context

The independently retired V22 attempt reported kind-create status 1, delete 0 and
source deployment not reached. Its followed stdout collector recorded16385 bytes
against the existing16384-byte ceiling, source EOF false and no post-create
logs-retirement receipt. The authenticated private diagnostic prefix contains the
existing marker pattern, but does not establish its delivery to kind, readiness,
the exact create failure stage or an underlying node fault. Cap overflow remains
failure. A missing retirement receipt is not evidence that marker text never existed.

The prefix carries substantial SGR decoration. Its unknown tail prevents a claim
that removing ordinary colors will make the complete stream fit. The selected log
identifies systemd major 257; existing guest 259.9 version-query facts do not attest
that node. Retained immutable official v257 facts independently support the narrow
presentation choice below.

## Decision

After the unchanged closed provider classifies the incoming owned node run, append
exactly the fixed `-e SYSTEMD_COLORS=0` pair to the already translated executed argv,
immediately before the same content-addressed image. Preserve the existing
`--pull=never` selection and every incoming argument. This is explicit node container
environment, not forwarding arbitrary host settings or selecting a global guest/host
export. Extra incoming environment arguments remain outside the closed grammar.

The setting selects false/COLOR_OFF in official systemd v257 and initializes normal
PID 1/job-status color accordingly. The retained official kind entrypoint preserves
that supplied environment and execs its command. No log level, severity, message
filter, status suppression, second variable or environment-clearing wrapper is added.
Existing ellipsization and ephemeral display behavior remain. TERM-driven cursor/erase
CSI, palette-reset OSC, selected raw emergency SGR and explicit later color/URLIFY
configuration can remain; this is not an all-ANSI or lossless-output guarantee.
Upstream facts do not attest the installed image build or entrypoint bytes.

ADRs 0062, 0063, 0065 and 0066 remain otherwise unchanged. Preserve every capture cap,
private diagnostic prefix 16384, outer 2 MiB and delegated guest 1 MiB output allowance,
CPU/memory/PID/disk limits, original absolute work/cleanup deadlines, query/native
credits, all 314 diagnostic patterns, poison, genuine EOF and independent retirement.
No marker scanner is added or copied. Prefix text is never an acceptance source.
No retry, old admission reuse or new runtime authorization follows this proposal.

The receiver's source fingerprint changes because the exact argv changes. Refresh
only its existing source enrollment and derived current-test data. Reverse this
one exact argv delta before checking immutable historical receiver checksums;
do not update historical expected bytes or diagnostic transcript hashes.

## Verification and limits

Pure controls cover both existing profile argv forms, exact fixed placement,
unchanged incoming arguments and credit accounting, hostile/ambient values,
extra environment aliases and invalid image refusal. Exact reversal proves the
rest of the receiver, collectors, private prefix, poison, EOF, retirement, query
sites and credit ledgers unchanged. The host result/command contract needs no
widening; its existing supplied image identity and no-pull checks still apply.
All existing Rust files and protected test bodies remain unchanged.

Source/license/provenance facts are metadata only in
`owned-node-monochrome-source-facts.json`; no upstream implementation is copied or
executed. These are historical fixture anchors under the existing Renovate fixture
exclusion, with no operational pin or tool change. Final formatting/complete gate,
independent review, fresh runtime admission and independent retirement remain
main-owned obligations. A successful future stream fit or native conformance is
not claimed by these source controls.
