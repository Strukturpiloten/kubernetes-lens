# Testing

The complete gate is `./scripts/check-all.sh --check`; `--fix` performs the same checks with formatting
first. `format-lint.sh` runs no tests. Lightweight contracts cover trusted-base PR planning, aggregate
failure/skip propagation, repository/release boundaries, and real Renovate extraction and policy.
Renovate tests import the locked tool itself and require its RE2 engine to be available.

The explicit [owned-QEMU prerequisite](fixtures/owned-qemu.md) has pure lifecycle controls in
`scripts/fixtures/test_owned_qemu.py`, discovered by the existing policy runner and included in
`python3 -B scripts/fixtures/kind_runtime.py --self-test`. Ordinary gates run these controls without
starting systemd units, VMs, SSH or Podman. A separate opt-in runtime receipt must establish the
actual VM prerequisite and retirement; it cannot satisfy the pending kind/API/resource scenarios.
Command-runner controls require every acquired pipe to be closed after selector
acquisition/close failures, unavailable child retirement and earlier pipe-close failures,
including interrupted unwinding. They retain the first cleanup failure and original deadlines.
The same owned-QEMU controls cover the bounded retirement codec, actual
producer prefixes, observation chronology and scope, shared fuel/output/storage
limits, partial evidence, cancellation and publication custody. The historical
host-view inverse tests use an immutable project-owned source fixture; they do
not repin their historical target to current production. Prepared private files
are non-authorizing: commit acknowledgement and successful controller exit are
separate obligations. See [ADR 0071](decisions/0071-bounded-owned-retirement-evidence.md).

The documentation phase also runs actual Prettier against the production file-check script
with conflicting workspace configurations and fail-closed owning-config controls.

Rust check, Clippy, test, doctest, Rustdoc, MSRV, cargo-deny, and local package validation run against
the locked package. Offline native unit/integration tests and doctests verify the delivered
foundation and typed resource cohorts. A separate Cargo integration harness executes the Python
policy suite. These tests do not establish API-server or runtime conformance.
There is no native coverage ratchet or conformance gate yet; do not fabricate passing fixture,
coverage, version or cluster evidence. Native suites and meaningful thresholds belong to #7.

PR prose changes may select documentation and lockfile age checks only. Executable examples and all
other changes select every job. Main, manual dispatch and release validation always select every
job. Unknown paths, invalid comparison, changed policy, and first rollout fail full. Missing, failed,
cancelled or unexpectedly skipped selected jobs make the PR gate fail. Test the inline bootstrap
fallback as executed Python, not only as YAML strings.

At most one complete or heavy workspace gate may run at a time. Use worktree-local target storage;
never reuse another checkout's fixture-path-sensitive artifacts. Native runtime evidence is future work.

The documentation phase checks the [frozen compatibility specification](compatibility/README.md),
independent schema witnesses, concrete native-kind scenarios and exact gate/command evidence cells.
Its regressions cover numeric version bounds, removed APIs, gate defaults/settings, template
contexts, per-field/profile obligations and mutated source facts. All native outcomes remain pending.
Compatibility documentation always selects the full validation plan.

## Offline foundation

Run focused development checks with `cargo test --locked --lib --test foundation` and
`cargo clippy --locked --lib --tests -- -D warnings`. Public tests cover strict source syntax,
Unicode source positions, each parser budget, aliases, identities, Lists, target versions/gates,
privacy, deterministic generation, explicit edits, supplied references and Linux acquisition.
Genuine test-only codec tests independently exercise downcast edits, known-leaf deltas, keyed
item reordering, retained unknown descendants, unchanged null/absence, atomic conflicts, and
registry/identity divergence. Independent review regressions cover read-only provenance,
cluster collision identity, owner scope and malformed-source evidence, empty opaque containers,
and retained/flattened wrapper admission, privacy, observations and API removal boundaries.
Wrapper-subject regressions distinguish equal-position sources, multiple documents, nested Lists
and failed decode attempts without disclosing source values. They are not fake production codecs or runtime conformance.

Foundation fixture provenance is in `fixtures/foundation/README.md`. All named compatibility
cells remain pending. Focused checks never replace the primary agent's final complete gate.

JSON primitive checks are `cargo test --locked --test exact_json_number --test protected_json`.
Internal snapshot cases cover raw numeric magnitude, duplicate keys, malformed numbers and private
budget failures. These tests establish neither CRD evaluation nor API-server numeric parity.

Access/policy development checks use `cargo test --locked --lib --test access`. Independent cases
cover all eighteen roots, generated fixed points, source-free validation, API removals, feature gates,
RBAC/selector resolution and protected evidence. Quota scopes, HPA Create context and LimitRange
relationships use authenticated native source expectations. Cumulative work/payload and report tests
retain one pathless terminal finding. Local code checks do not establish native runtime conformance.

Configuration/storage development checks use `cargo test --locked --lib --test configuration_storage
--test access_modes`. Independent cases cover all five roots, protected configuration/secret
values, supplied key domains, known-invalid selectors with unknown descendants, immutable
version boundaries and finite PV Create/source/affinity checks. Processing exhaustion stays
pathless and sticky. Static witness and code evidence do not establish API-server, controller,
binding or provisioning conformance; those domains remain pending.

## Official fixture preparation and admission

The [official fixture corpus](fixtures/official-corpus.md) has 97 source-only Python regressions
for receipt integrity, private offline preparation, companion notices, closure, budgets and
renderer admission expectations. Run `python3 scripts/test-repository-policy.py` for the existing
repository policies and both fixture modules, or
`python3 -m unittest discover -s scripts/fixtures -p 'test_*.py'` for fixture-only feedback.

The policy runner discovers each fixture test once and requires the source-receipt and renderer
expectation witness IDs from their respective modules. Missing modules, absent witness tests,
discovery/import errors and assertion failures make policy validation fail. The existing Cargo
`repository_policy` harness (`cargo ci-policy`, including MSRV) and documentation phase both
invoke that runner, so the complete gate includes these tests without an optional fixture switch.
Gate regressions execute the real policy hook with synthetic fixtures and fake build/tool commands;
they prove independent assertion, missing-module and wrong-test-ID failures stop validation.

These tests neither acquire official sources nor execute Helm/Kustomize, native corpus acceptance,
API validation or runtime commands. Corpus bytes remain in caller-owned public caches and private
destinations; metadata and scripts remain excluded from the Cargo package. Actual package-list
verification and the final complete gate remain required during primary integration. Passing
preparation/admission tests does not satisfy the pending #14 native acceptance or #2 runtime cells.

Extension development checks use `cargo test --locked --lib --test extensions
--test extensions_final_corrections`. Tests independently cover typed stable/beta roots,
source-free generation, schema subset outcomes, descriptor replay/staleness, target mismatch,
exact private keyword/List paths and terminal budget exhaustion. Current source/profile guards
are in `schemas/capabilities/extensions-code-evidence.json`; the complete policy gate rejects
stale/omitted source bindings and fabricated native claims. Official custom corpus, server
admission, webhook/controller and native-profile conformance remain pending.

Native naming regressions replay 125 independently frozen, primary-corrected specification cases
and cover all 35 kinds/48 API profiles across admitted minors and removal boundaries. Tests use
actual native source, authoring, edits, protected output and supplied graph projection. The naming
source/contract/code evidence remains distinct from API-server, generated-name and runtime
acceptance. Historical research hashes are immutable; current source guards bind candidate code.

Renderer integration tests in `tests/formats.rs` exercise supplied snapshots, finite command/profile
admission, cumulative generation and resource association, private artifact access, explicit
variations, lifecycle findings, and bounded local v1beta1 `vars`. They invoke no official tools.
`tests/supervised_renderer.rs` is enabled only with the optional Linux `supervised-renderer` feature;
its source-level refusal tests do not establish live isolation or cold-cache resource fit.
Run the complete repository gate after integration; focused tests do not replace it.

The renderer/naming bridge regression checks private native RBAC names and unverified custom
workload names through both artifact generators: denied output, explicit exact-name preservation,
retained redacted native warnings, and refusal of inferred typed parameters. Existing reordered-root,
List association and cumulative overlay-budget regressions remain required after integration.

Renderer #38 focused validation is `cargo test --locked --features supervised-renderer
--lib --test supervised_renderer`. Pure controls cover conservative absolute-end
conversion, ten-second cleanup reservation inside total, cap/expiry/overflow/version
refusal, clone cancellation, write-half-only cancellation with retained read-half,
late cancellation after available output, immutable journal/descriptor boundaries,
owned unreaped child kill decisions, exact wait acknowledgement and missing/wrong
reap refusal, cancellation between output chunks and after native acknowledgement,
unchanged recovery expiry, tracer terminal-before-parent ordering, and fixed creation
guard/activation-lag/complete STOP and FINAL waits, 250ms per timer accuracy and
activation rounding arithmetic. Recovery also tests persisted 15s cleanup expiry
at 15s and refusal at 16s under an unchanged 30s total, including a complete
interrupted pending write while live cleanup is unset. Complete/partial/malformed/
foreign pending admission, repeated promotion, widening refusal and validated-live
fallback preserve the earliest deadline and authority. Local
socket-pair tests and modeled parent/kernel outcomes invoke no official renderer,
broker service, runtime provisioning or cluster. They do not establish actual kernel
containment, native parent reap, cold-cache behavior, installed-manager timer effects
or interrupted recovery. All original 90 renderer cells, three graph cases, two target
patches and full unchanged CNPG default-render obligations remain required. Run the
complete repository gate only under the primary's shared-slot authorization after the
final source edit; focused source/model checks never replace it.

Renderer #39 focused source controls live in private `wait_observer` tests and cold recovery
models. They cover literal stock wait/signal/core vocabulary, startup/zero/signal nonproof,
wrong child/attach/status, partial/duplicate/trailing records, 4-MiB trace and 65536-byte record
limits, actual local Unix socket recvmsg credentials and EOF, finite FIFO pumping, closed
selection/argv, immutable original request/Origin/Proof, archive kinds/child metadata/caps and
crash/downgrade/overlap quarantine. These tests launch no helper, observer, broker, renderer,
manager or cluster. Official source expectations are not runtime fixtures. Native wait, actual
initial namespace, tracer lifetime/writer ownership, crash durability and unchanged full CNPG
default execution remain independent obligations; see ADR 0015.

Renderer #41 focused source controls cover closed/default-none selection and descriptor fields,
controlled-schema refusal, independent literal Offer/Ack hashes, original capture intervals,
credentialed length-prefix fragments, caps, truncation, extra bytes, actual socket EOF, missing
credentials and injected rights. Cancellation with a complete body but no EOF refuses; retained
root replacement, symlink substitution and same-inode content mutation refuse. Tests launch no
helper, broker, renderer, systemd service or cluster. Native input-view equality, every independent
closure, per-run actor/config sealing and original aggregate resource fit remain pending under
B1–B6 in ADR 0016. The primary owns complete validation and independently authorized native work.

Issue #62's [ADR 0072](decisions/0072-postcreate-private-prefix-prepayment.md) pure
controls in `test_owned_guest_rootful.py` cover already-collected binary prefixes on
failed create 0/delete 0 post-create log-gate results, exact four-ticket cleanup
admission, no prefix file/copy/publication at 0/1/2/3 available credits, sticky partial
grants, unused-ticket conservation, single-use emission, copy/catalogue failures
and mandatory cleanup plus ordinary catalogue emission before optional diagnosis
with the original exit preserved.
The same protected role, scope, redaction, raw/wire/source caps and work/guard/cleanup
partitions remain covered. Current receiver enrollment tests are separated from the
immutable historical controller fixture's enrollment; the fixture, its exact fold
and all 314 historical patterns remain unchanged. Focused pure Python controls and
Bash syntax checks do not replace final complete validation or establish native
success, old missing log contents, underlying cause or whole-target retirement.

Issue #62's [ADR 0073](decisions/0073-versioned-postcreate-guard-reason.md) focused
`GuardReasonReceiverControls` and `GuardReasonDecoderControls` project all sixteen
original false branches, true/reused/skipped/interrupted paths and clock/helper
failures without target observation. Old/new read sequences and the 4096 boundary
remain equal. Tests cover first private assignment, v1/v2 dispatch and scope,
null/failed/overflow evidence, unchanged genuine prefix bytes/credits/privacy, exact
raw persistence and failure propagation through the mocked worker. Existing v1
fixtures, 314 patterns and historical source inversions remain exact. These pure
controls do not replace independent final source review, the complete gate or a
separately adopted native attempt.

Private v3 log-poll controls compare the original projected read/invocation traces
with the preserved v2 source, exercise all eight role bounds and cached-state/deadline
attribution, and reject malformed or mismatched private tokens. Frozen v1/v2 fixtures
remain explicit source domains. Durable-wire/private-prefix controls preserve public
redaction and independent whole-target retirement; passing these source tests does
not establish a native cause, readiness, runtime conformance or a new attempt.

Issue #62's [ADR0084](decisions/0084-post-node-first-parent-failure.md) adds bounded
`PostnodeReceiverControls`, `PostnodeDecoderControls` and `PostnodeParentControls`.
Original post-node statements run only with builtin fake utility/native/read
helpers and fixed inventory/process DATA: no runtime executable or actual proc
read runs. Controls compare frozen V7/current query and read traces, return and
poison behavior; exercise each group, helper and parent-after-child failures,
skipped entry, child-only/ERR/signal nonproof, first-code immutability and finish's
original status capture and early site clear. Actual Bash clauses are checked with
255 distinct non-NUL single-byte values and closed prefixed/malformed tokens.

Synthetic wire controls require V8-only pl2, complete genuine seven-role logs and
ordinary integrity-checked node evidence, preserve old pl1 exclusion/native/reason
semantics, and reject type/scope/catalogue/meta/node/version errors. Strict new
V8-to-C6 V7 inversion precedes unchanged historical seals; all 550 original IDs and
314 literal patterns remain. The registered future-V8 refusal fixture moves only
its future version to V9; genuine V8 and frozen V7 domains are tested separately.
Private exact-byte durability, summary mismatch, public redaction, independent
delete failure and original worker/parent budgets remain covered. Focused checks
establish source behavior only. Final independent source review, the complete gate
and separately adopted native qualification remain the primary's responsibilities.

Issue #62's [ADR0085](decisions/0085-phase-specific-guest-census.md) adds
PhaseSpecificCensusControls. Two prepared private proc-shaped trees model FD open/
close, task birth/exit and finite-limit changes between original complete scans,
without a host proc read or runtime call. Live accepts only individually valid
censuses; stable still refuses drift. Negative controls retain malformed/access/
range/count/empty/incomplete/cap failures in either pass. The original exact32MiB/+1
boundary controls remain unchanged; a lowered private cap projection additionally
checks that live cannot bypass that fail route. Second-map replacement and selected
node cache/PID/start/cgroup/stat drift use the original guarded corridor with fixed
helpers. Exact topology/inverse controls require three stable calls and one live,
unchanged inventory and node bodies, caps and314 literal patterns. All564 original
IDs/assertion inventories remain; current enrollment is separate from frozen first-V8
history. Pure checks do not establish atomic/continuous observation, native fit,
readiness or conformance, and do not replace independent review or the complete gate.

Issue #62's [ADR0086](decisions/0086-owned-node-cgroup-membership.md) adds
OwnedCgroupMembershipControls on the original selected-node corridor. Prepared private
censuses and fixed read/utility doubles exercise exact root, descendants and dotted
names with actual consumed descendant text preserved in the private write. Foreign/
sibling/prefix/relative/header/dot/slash/control/multirecord failures prove no write or
later native reach. Existing real read_file is separately directed only at owned
private missing/directory/symlink and regular files; its inherited trailing-LF stripping
is tested honestly. Guest/host exact inspect-root, missing final cache, first PID/start
and second-start failures remain; real finish keeps earlier failures and delete0/19
independent. No live proc/runtime executes. Strict source inversion/current enrollment
and all574 old IDs/assert inventories/314 patterns remain. Historical phase and seven-group byte-equivalence
controls use frozen19c958 source; current membership has its own original-corridor tests.
These pure controls replace no pinned final checks, independent review, complete gate
or separately adopted native qualification.

Issue #62 [ADR0087](decisions/0087-closed-k-stage-failure-evidence.md) V9 controls
in KStageReceiverControls/KStageNativeControls/KStageDecoderControls and
KStageParentControls cover all14 active groups, six existing native status scopes,
original complete fixed-DATA k traces/counts/continues, both readiness rounds,
last rejected group, successful later round, prearmed interruptions, helpers before
predicate/launch, poisoned next entry with fresh nulls, actual command/capture waits,
final clock-helper availability, first immutable snapshot and delete0/19. Strict
old/new schemas, closed types/ranges/relationships, missing/extra fields, private
durability/double-decode/public redaction and sealed inverse/caps remain covered.
All580 predecessor IDs/assertion inventories and314 literal prerequisite patterns
are preserved. Historical exact-source/V8-emitter controls explicitly select frozen
65359-byte V8 through the new strict inverse; independent V9 controls exercise current
source. Every apparent runtime/proc helper uses mandatory fixed DATA; these are not
native qualification, exact V26 diagnosis or authorization to retry. Primary owns
pinned formatting, final independent review and the complete gate after the last edit.

Proposed [ADR0088](decisions/0088-node-readiness-conjunct-evidence.md) adds13 focused
ReadinessAtomReceiver/Decoder/Parent controls, retaining all596 predecessor IDs and
assertion inventories (609 rootful/QEMU total). Actual V10 source guards/callers/finish
run only with mandatory fixed tool/runtime DATA. Cases cover four atoms, opaque
returns, pre-dispatch grant/ticket/read/binding/use refusal, both rounds, recovery,
stale/incomplete caches, interrupt/first-failure/cleanup0/19, all512 tokens, strict
old/new wire scopes, original shared budgets and private durability/redaction.
Historical source-based controls explicitly select frozen V9 before unchanged older
inverses; aliased/shared readers and actual-current enrollment checks remain distinct.

The task's separately authorized official jq1.8.1 fixture oracle compares original
and classified truth/error/stream outcomes on469 cases plus controlled file/usage/
compile failures, with exact checksum/provenance and no guest-binary equivalence
claim. Default repository policy uses pure model/source controls, not that external
oracle or any runtime. These focused results do not replace final canonical source
review, complete gate or separately adopted native qualification.

The proposed [ADR0090 V11 controls](decisions/0090-ready-condition-text-class-evidence.md) append
current-source receiver/decoder/parent cases while preserving every609 predecessor method and
all historical V1–V10 domains through a strict V11-to-V10 inverse. Fixed command DATA tests cover
new class/opaque exits, source-spec/budgets, refusals/freshness/interruptions, late cleanup, private
wire durability/redaction, success and delete failure. Separate temporary pinned jq1.8.1 synthetic
controls prove exact acceptance/order/stream/error/privacy, including malformed messages and
duplicate True; default gates do not invoke a host jq or native runtime. Full canonical validation
and any exact fresh owned attempt remain independent main-owned gates after the final edit.

The proposed [ADR0091 V12 controls](decisions/0091-owned-node-ready-wait.md) select
actual current source independently of historical readers. Fixed/injected DATA
covers exactly one wait, only pre-wait round transitions, hard post-wait failures,
wait-success/strict-predicate rejection, current native debits/status/clock refusal,
independent4/11/8/17 accounting, strict V12 spec/result/k4 domains, old V11/k3 isolation,
source inverses, enrollment, private failure custody and canonical source caps.
Historical controls explicitly recover frozen V11 before their existing inverses;
current enrollment expectations migrate separately. Existing tools/pins/314 stderr
patterns stay unchanged. These focused offline controls and formatting do not run
kubectl, a VM or a host runtime and do not replace independent review, main integration,
the serialized complete gate or a separately reviewed fresh native adoption.

## Hosted prerequisite observation controls

The manual-only [hosted prerequisite lane](fixtures/hosted-native-prerequisites.md) has pure
controls in `scripts/fixtures/test_hosted_native_prerequisites.py`, discovered by the existing
policy runner in local, PR, main, manual and release gates. Focused feedback is
`python3 -B -m unittest discover -s scripts/fixtures -p test_hosted_native_prerequisites.py`.
They cover exact source/workflow/run binding, pre-checkout shell refusal, missing/denied/unknown
indicators, no-autostart D-Bus grammar, KVM API-only ioctl, tool authority/version privacy,
streaming/hash/output/time bounds and FD/child/private-scratch cleanup failures. No host
observation or native qualification occurs in normal gates. The existing actual Renovate suite
also checks the new workflow consumer's extraction, SHA/tag replacement and effective pin policy.

The proposed [ADR0093 capture-size controls](decisions/0093-capture-size-helper-status.md)
read current source explicitly while predecessor controls select exact accepted V12
before old inverses. Fixed dd/stat DATA covers below/equal/over-cap, malformed and
arithmetic-error forms, tool23/error normalization, utility/refusal and noclobber
paths without a real tool. Inert extracted native() helper tests preserve the
inherited ERR policy and original process substitutions, proving raw23 propagation,
wrapper/command/earlier-failure precedence and no added read. Mock worker/parent
controls preserve raw POSIX fields, old opaque statuses, shared budgets and privacy.
Static history/assertion/call/trap/byte proofs and scoped canonical formatting are
not a complete gate, host/cluster query, constructor/renderer, native qualification
or authorization for another attempt.

The proposed [ADR0094 compact-root controls](decisions/0094-compact-root-dry-run-json.md)
add exact fixed argv/sequencing, mandatory unchanged response admission, injected
native/capture/validation refusal, strict source inverse, receiver cap and frozen
official-source provenance controls. Existing test-method bodies/assertions and
314 diagnostic patterns stay intact; source selectors recover exact ADR0093
before predecessor inverses. Current source enrollment migrates separately.
The controls use fixed fake tools/status DATA only; they are not kubectl printer
execution, modern native acceptance, a 4096-byte fit guarantee, an actual Renovate
engine pass, a complete gate or authority for another native attempt.

[ADR0098 storage allocation controls](decisions/0098-modern-default-storage-capture.md)
author current-source modern 8192/8193, legacy 4096/4097, exact-role/argv preservation,
one-slot-short and global credit exhaustion, child/helper/raw status, poison fallback
and deadline/cleanup refusals. Original independent 4567-byte DATA traverses real
receiver capture/forward/apply FD0 with fixed fake tools; apply outputs stay 4096/4096.
Source/history controls preserve full entry/admission and native allocator bytes.
The authenticated image payload remains private and is not redistributed; a private
control proposal binds its fixed hash separately. No subject test runs in this source
proposal wave; formatting/static checks are not complete-gate or native evidence.

## V13 owned-VM LIVE envelope source controls

ADR0101 adds current source-body controls for strict stable/LIVE selection, unchanged
scalar/resource prefixes, genuine first-stat/cgroup/second-stat identity and owner
refusals, first failure/real delete independence, closed V13 spec/result/source facts,
canonical-image/host-domain mismatch and exact predecessor inversion. Current provider,
capture/credit, log-role and output controls continue to execute current source bodies;
historical comparisons explicitly recover their original immutable source domain.
All predecessor test IDs and assertions remain accounted for.

Proof arithmetic and source qualification do not establish native/kernel application.
Pure proc-shaped or mocked wire data cannot supply complete census, running-binary
attestation or runtime success. Run focused source controls and the complete required
gate after final integration. These proposed controls have not been executed as part
of the inert implementation proposal. Full native35-kind/tool/fixture/API/controller/
domain evidence and independently observed per-run retirement remain separate.
