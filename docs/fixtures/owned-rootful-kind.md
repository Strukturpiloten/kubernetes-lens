# Owned rootful kind smoke contract

> The current selected rootful spec and results use V13 and the
> `owned-vm-live-v1` resource profile under
> [ADR0101](../decisions/0101-kernel-bounded-live-resource-envelope.md). The V4
> seven-role log layout remains unchanged under
> [ADR0077](../decisions/0077-kind-owned-log-process.md).
>
> Earlier sections retain their historical version/source contracts and are
> superseded only as stated by later refinements. Use ADR0101 and the final V13
> section for current LIVE resource and selected-node identity claims; historical
> universal LIVE census/cache claims do not apply to V13. The three strict stable
> admission checks remain required.

This opt-in external harness route is implemented as source only. It has no
runtime qualification yet. Ordinary product/CI work does not boot a guest.

Use the existing owned-VM command and staging inputs, selecting
`--phase run-rootful-kind`, `--cpus 2`, `--memory-mib 8192`,
`--guest-memory-mib 4096`, `--pids 256`, `--disk-gib 24`,
`--deadline-seconds 1800` and `--cleanup-seconds 120` (each CLI option and
number are separate arguments). Supply the exact independently selected
`legacy-1.20.15` or `modern-1.37.0` profile and its already authenticated
kind/kubectl/node parent/manifest/config/archive inputs. There is no download,
image build, installer, ambient credential/cluster acquisition or implicit fallback.
The API remains guest-local; SSH is the only explicitly owned host listener.

`owned_guest_rootful.py` is host-only source/admission/receipt code. Its actual
caller in `owned_qemu.py` installs the checksummed Bash receiver and finite
provider wrapper through Ignition, selects the forced client command, reserves
one actual worker's75 native credits and1 MiB of its original 2 MiB output, stages
all three admitted inputs, and starts exactly one fifth registered SSH producer.
The receiver's finite stdin record binds owner, Plan and complete source spec.
Its at-most4096 bytes are reserved before boot inside the unchanged aggregate
input ceiling; actual writes are retained even on partial failure. No text is
evaluated as shell, path, argv or SSH_ORIGINAL_COMMAND. Existing qualify/stage
modes retain their original forced commands and controls.
Only the new rootful receiver uses deterministic gzip in Ignition3.4's file
contents representation. Its decoded bytes are bounded by the existing64KiB
metadata ceiling; Ignition restores the exact enrolled source, and all source
and guest checksum bindings use those uncompressed bytes. The complete encoded
Ignition object still must fit the unchanged64KiB limit. Existing stage files
and old modes retain their original plain data URLs. The official Ignition3.4
file-contents specification permits gzip (documentation Git blob
`94e1b0df98665d39fe6c8900276f5e074c6759dc` in `coreos/ignition`,
`docs/configuration-v3_4.md`). The host compares the
exact supplied receiver bytes and the helper's digest of its actual consumed
scenario bytes with the enrolled source before image preparation or any child.

Guest uptime cutoffs only supplement the host's authoritative original absolute
work/cleanup ends. Relative guest time does not authenticate a host-clock offset
or renew the operation. Missing/late intervals refuse. All host pumping,
cancellation, cumulative output and outside retirement checks remain active.

All guest native actions debit the same persistent work 70/cleanup 5 partition,
including actual lower Podman calls. These are hard attempted-action limits,
not a guaranteed successful fit for either profile. Retries consume the same
credits; unknown or excess work refuses before further effects. A separate
persistent 768-token utility catalogue plus the unchanged
stage 256 static reservation bounds bookkeeping by 1024 utility invocations. Each
actual utility is predebited; tokens survive crashes, command failures and lost
ACKs. Shell builtin finite bookkeeping is distinct from arbitrary subprocesses.
Output maxima are pre-reserved in4 KiB units within the same1 MiB guest allowance;
raw stdout/stderr are separately captured with per-file limits and never rewritten.
A cap failure is a failed run, not permission to omit evidence or increase caps.

The only storage variant is private overlay-on-XFS with strict guest mapper
control and the expected sole-vda block closure. The selected Linux bridge must
be absent (including dangling links), and the route table must be readable
immediately before exclusive network creation. Actual store, disk, kernel,
manager, package, network, namespace, PID/start, hard-NOFILE and existing FD-index
observations must pass in the real receiver before effects. The trusted whole
VM boundary covers helpers and privileged node descendants; host process limits
cover QEMU/SSH, not guest tasks. No workstation device, runtime store or existing
cluster is a target. The24 GiB aggregate ceiling includes immutable image/base,
staging inputs, metadata and remaining capped physical overlay. Node storage,
import temporary files and logs share that overlay; no per-directory quota is
claimed. Source capture still needs independent unchanged-cap admission.

The fixed reference-free OCI-archive preserve import authenticates the publisher
parent/child/config/layers/diffIDs/archive and then genuine same-store raw manifest,
raw config and real image ID. Skopeo `inspect --raw --config` is required: ordinary
`--config` formats JSON. Alias substitution is permitted only at the final native
run boundary, after a fresh genuine same-store identity check. The legacy media
transport may fail; no conversion or podman-load fallback may hide that result.

The first cohort creates one owned cluster and namespace, checks actual server
and node readiness, and submits the original authenticated Deployment fixture
with server dry-run. It retains genuine kind-delete status and requires outside
whole-VM retirement. No native network-rm command runs; network/store retirement
is solely whole-VM retirement. Failure before or during deletion remains failure
even if outside retirement succeeds. Remaining discovery, source-invalid,
generated, resource-cohort, semantic, official-application and hosted cases remain
pending and must receive separately frozen fresh-run budgets. First smoke does
not satisfy the complete native resource or version goal.

Official configuration documentation was retrieved through Context7 from Podman
and Skopeo. Public provider argv facts come from the previously frozen official
kind0.14.0 commit7a5ce5b16f36ffd8bbb05961f580aae91c58ef95 and kind0.33.0
commit407a9675e6d9af1200b5f57f9ca52ec6cdacce74. The original executor does not
copy or mechanically translate their provider implementation. Versions embedded
here are frozen historical acceptance anchors tied to the existing admitted image
and capability ledger, not new operational tool/update inventories. Shared tooling
and the official VM image keep their existing sole Renovate owners.

Every attempted native command reserves its requested capture bytes before
launch, including every nested provider command. Hard pools are
980 KiB work and 40 KiB cleanup, with at most 150 one-byte overflow sentinels
inside the remaining 4 KiB of the same 1 MiB allowance. Two normal-I/O dd helpers
per native action are pre-admitted before that action. Each helper consumes
single-use source-bound dd/stat utility tickets, closes inherited write ends,
reads at most its stream maximum plus one, and is explicitly waited by its owner.
An overflow or missing genuine EOF fails; truncation is never positive evidence.
The utility allowance preserves 680 ordinary work, 24 prepaid record guards and
64 cleanup tickets inside its original 768 limit, including all 150 possible dd captures. All known, failed,
retried and cleanup paths remain bounded by persistent partitions. No static
estimate of kind call multiplicities guarantees a successful fit: unexpected
argv, insufficient credit or larger output refuses before further effects.
Successful acceptance needs authenticated actual action/capture/retirement
evidence, never an assumed successful-path count.

Only the exact admitted `podman logs -f` call uses immediate streaming: each
stream has predebited dd/tee/stat tickets. A single-byte bounded dd forwards
short startup markers promptly through tee while retaining private raw bytes.
The two replaced final provider cats keep the tee multiplicity neutral; one
setpriv and four executable metadata/capability observations in each of the two
receivers account for the nine additional utility launches. Reaching max+1,
nonzero dd/tee, missing completion or lack of genuine source EOF poisons the run.
tee's ignored broken reader does not establish receipt or EOF. Actual kind
success and authenticated private startup markers have separate evidence roles.

Kind's genuine context cancellation SIGKILLs its logs wrapper. The guest-only
exception arms official-image `setpriv --pdeathsig KILL`, then directly executes
the fixed source gate in the same PID. The gate checks actual kernel PPID and
the original parent's start identity, root effective/filesystem credentials,
and performs no fork or credential change before direct Podman exec. Package,
root-owned mode and absent file-capability checks bind Bash, setpriv and Podman
before launch; missing getcap refuses without installing anything. An early
arming race or changed identity refuses. No recorded PID or group is signalled.

Ordinary surviving owners directly wait and preserve real statuses. For the
one context-cancelled helper only, the original receiver checks each retained
wrapper/child/collector/dd/tee PID+start retired, actual collector direct waits,
closed EOF records and markers after genuine kind-create success. Missing wait
status and signal cause remain explicitly unavailable; kernel/PID1 retirement
is never called receiver-owned wait. A bounded 4096-iteration builtin retirement
check still obeys the original work end and refuses late/unreadable identities.
The same bounded private result retains exactly eight fixed role-bound PID/start
records and two collector records, the finite retirement label and marker flag.
`wrapper_observed_child_wait_status` is the actual Podman-child wait performed
by the surviving wrapper; it is null when that wait was not observed. It never
claims an outer receiver wait for the wrapper. Unobserved `signal_cause` remains
null. The parent strictly validates types, role membership, unique identity pairs,
stream byte/status limits and state consistency. These are authenticated reports
from trusted guest source, not host process observations. No raw log bytes,
kubeconfig, keys or paths enter this closed object; outside whole-VM retirement
remains independent final evidence under the unchanged wire and metadata caps.

Operation cancellation, prior failure and poison cannot become success. These
controls have pure source tests only: actual guest setpriv/kernel reaping and
kind startup remain unqualified until separately authorized runtime evidence.

After strict incoming-kind argv validation, the executor substitutes the proven
full image ID and injects exactly `--pull=never` before that ID. Private incoming
and executed argv records are distinct; kind itself emitted no pull flag. Genuine
node inspect must record that executed guard. Existing rootless guards are untouched.

The same fifth SSH stdout can carry a closed durable evidence envelope: raw-byte
sum at most 128 KiB and full wire at most 256 KiB. Only genuine imported raw
manifest/config, image/network/node inspect and private-store Podman-info are
allowed. [ADR 0065](../decisions/0065-private-node-init-failure-prefix.md) proposes
one narrow exception: a protected first-16384-byte `node-init-stdout-prefix` from
the existing captured provider stdout, only on a failed pre-readiness result before
any application submission. [ADR 0072](../decisions/0072-postcreate-private-prefix-prepayment.md)
includes actual create status0 when the post-create log/startup gate is unestablished;
this diagnoses neither the gate predicate nor the old missing startup text. The role
shares the original raw/wire caps and requires four actual cleanup tickets prepaid
after mandatory deletion and the six ordinary catalogue roles, before destination
redirection: dd, then catalogue
stat/SHA256/base64 each consume one ticket once, without double charging. If fewer
than four remain, no prefix destination or pointer is created. Partial grants remain
spent, admission is sticky, and unused grants are not execution proof; no refund,
retry, reissue, work borrowing or quota increase is admitted. The conditional
64-slot admission does not promise fit on every repeated-provider/refusal branch.
It is always prefix-only failure
evidence, never EOF, readiness or success. The source-bound private sidecar may
contain sensitive text; public summaries expose protected role/hash/size references
only. Raw kubeconfig, separately acquired credentials, Secret/application output
and all other logs remain excluded. Admin kubeconfig has an explicit private-only 64 KiB stdout limit;
it never enters that envelope. Exact original base64 bytes, lengths, hashes,
source/owner/Plan and expected native identities are validated before and after
outside retirement. The parent then exclusively creates one fixed owner-derived
0600 no-follow sidecar inside the existing private output parent and 4 MiB metadata
reservation. Only its hash/size/reference enters the receipt. Actual envelope
transport still consumes the original worker's remaining output Budget; there is
no additional allowance. Persistence/validation failure prevents native success.

[ADR 0068](../decisions/0068-private-kind-create-failure-evidence.md) additionally
retains a fixed 4096-byte prefix of existing failed kind-create stderr and a
protected attribution record of at most 1024 bytes before cleanup replaces capture
globals. It records actual captured bytes, including the existing overflow sentinel,
and distinct kind/native-wrapper/collector waits; unsupported provider attribution
and unproved EOF remain unknown. Eight existing work utility credits (four when
stderr is empty) pay preservation and emission before cleanup, without borrowing
its 64-credit reserve or refunding partial predebits. Both roles remain private 0600
and public summaries contain only protected references. Preservation refusal still
allows original cleanup; emission failure remains failure. No underlying cause,
readiness, native qualification, new query or new allowance is established.

All new version literals are historical acceptance anchors inside fixture paths,
which existing Renovate `**/fixtures/**` exclusion covers. No workflow, operational
pin, updater or canonical tool consumer changes in this slice.

The existing first `guest-info` SSH command also reports a closed private mechanical
outcome, bound to its actual first admitted producer PID/group/session/start record.
It contains the observed signed return code (or null), completion classification,
and separate stdout/stderr charged-prefix byte counts, SHA-256 hashes and genuine
EOF flags. Hashes include only bytes whose existing output charge succeeded;
bytes read in a rejected over-budget block are excluded. QEMU console streams
still consume the same shared budget but never enter these command hashes. No
additional raw stderr buffer, raw diagnostic output, stdout copy, command, probe,
input/output allowance, deadline or metadata cap is introduced.

These reports come from the trusted worker; they are not host observation of the
SSH peer or guest receiver. Closing a stream is not EOF. A partial record or null
status means the missing evidence is unavailable. An observed status of 255 alone
proves neither authentication nor receiver execution. Even a complete zero-status
record is only one prerequisite: the existing independent guest-info validation,
all remaining phase checks and whole-VM retirement still apply.

The worker binds the capture before placement/acknowledgment and retains it before
checking command status or parsing guest-info. The parent validates closed fields,
counts, status and exact first-producer binding before handling worker failure,
and retains the validated record in its private receipt even when outside retirement
fails and the run is quarantined. A malformed record is refused without retaining
raw fields or skipping retirement; an earlier worker failure keeps precedence.
Every new real rootful worker barrier includes the field. Actual controller success
requires both genuine EOF flags and an observed zero exit status. Legacy direct
retirement-only controls may omit the field as unavailable; they establish no
native acceptance. No kind or runtime qualification is claimed by these pure controls.

The adjacent parent-derived `guest_info_stderr_pattern` private receipt field is
strictly a source-literal byte-pattern report. It admits only the frozen receiver
content digest enrolled in the actual configuration, the validated first-producer
command outcome with observed status and both genuine EOFs, empty stdout, and the
exact full stderr length/SHA-256 of either the legacy refusal marker alone or that
marker followed by exactly one of the receiver's 34 fixed prerequisite-code frames.
The parent uses only existing counts/digests and its source-bound configuration;
it reads no raw stderr or external classification table and invokes no additional
command. The embedded receiver digest is a fixture-content binding rather than an
operational tool pin. Any differently formatted or modified receiver is unknown
until explicitly reviewed and rebound.

`legacy-refusal-bytes` and `prerequisite-code-bytes` mean those literal whole-stream
bytes matched; they establish neither SSH authentication, receiver execution,
prerequisite observation nor native acceptance. The signed numeric status remains
independent and unchanged, including 255. A complete stream with extra, repeated,
truncated, conflicting, empty or unknown code bytes is `unrecognized`; missing EOF,
missing observed status, missing command evidence or an unrecognized receiver source
is `not-established`. No raw marker, frame, log or secret is retained. The closed
field contains only its schema, enrolled source digest, finite classification and
optional fixed code. It survives worker failure and quarantine under the same
retirement obligations and unchanged resource limits as the mechanical outcome.

Initial package diagnostics refine only the failure destination of the existing
jq-display, exact twelve-package RPM tuple, systemd-display and kernel predicates.
Their acceptance expressions and native queries are unchanged. After the original
RPM aggregate predicate has already failed, a builtin-only helper examines at most
4096 bytes of the already captured private string using one loop of at most 13 rows.
A wrong row count or oversized value yields `rpm-shape`; otherwise the first
mismatching expected row selects one of twelve literal RPM codes. The helper never
returns success, re-queries, repairs values, runs another utility or prints actual
package data. Outside initial mode or during cleanup it refuses generically before
examining that string. The three other predicates use fixed `pkg-jq-ver`,
`pkg-sd-ver` and `pkg-kernel` codes. Existing coarse patterns remain recognized.

These codes label only which source-owned failure predicate or diagnostic row
matched. They prove no actual version, authentication or receiver execution.
A nonzero RPM query now takes an explicit generic refusal before any row
classification, without inferring a package cause. Every optional frame remains at most
44 bytes under the unchanged output allowance; whole-stream count/hash/source and
EOF requirements remain unchanged. Pure tests expand both code catalogues and
tighten the prior guest frame-length assertion from 96 to 44 bytes. No runtime
retry or qualification follows from this source-only diagnostic refinement.

The existing systemd display query now selects `SYSTEMD_COLORS=0` temporarily on
its existing `u` invocation inside the same command substitution. This makes that
single query's presentation independent of inherited color settings. It leaves
its argv, prefix literal, utility credit, invocation count and surrounding environment
unchanged; the color selection adds no global export, env executable, URLIFY
setting, query or capture buffer. Reviewed immutable upstream 259.9 and Fedora recipe facts,
source hashes, licenses and limitations are recorded in
[`owned-systemd-color-source-facts.json`](../../scripts/fixtures/owned-systemd-color-source-facts.json).
These are historical source facts, not operational tool pins. Existing Renovate
`**/fixtures/**` exclusions cover every changed path and the new metadata; tool
owners, managers, extraction paths, approvals and automerge remain unchanged.

This narrow presentation contract does not establish that color caused the observed
`pkg-sd-ver` byte pattern. The text predicate remains unchanged, but an explicit status check now precedes
it: nonzero utilities refuse even when their captured output matches the text.
No independent retained utility-status observation or native acceptance is claimed.
Pure projections retain the original utility dispatch/credit helpers while replacing
only their final external execution, and check inherited absent/0/1/256 settings,
unchanged argv, single charge, isolation from adjacent queries and failure behavior.

The finite utility-status refinement covers the source inventory's 49 static `u`
sites. Fourteen formerly inline queries now capture one value and immediately
refuse nonzero status before the same literal comparison. Thirteen existing
captured assignments and four standalone calls now refuse explicitly rather than
depending on conditional/errexit/ERR-trap context. Those seventeen newly explicit
refusals use the generic marker, poison work state and exit 1 without inventing a
fine cause or retaining the underlying utility's numeric status. The existing
seventeen explicit guards and intentional readiness-jq false branch remain exact.

The three source-hash queries remain lazy: an earlier utility failure or text
mismatch prevents every later query. Captures reuse existing scalar slots where
available, clear new inline values immediately after comparison, and introduce
only one function-local EOF-size scalar. No query wrapper, new command, parallel
raw copy, output buffer, counter refund, cap, deadline or cleanup exception is
introduced. Existing dispatcher/native helpers and the original 34 digest patterns remain
unchanged; the parent source binding follows the exact new receiver. Pure controls
exercise every changed site through actual utility/token logic with only its final
external execution projected, including conditional callers, matching/nonmatching
output, failure before effects and each hash short circuit. These source checks
establish neither an actual failure cause nor runtime acceptance.

The existing systemd query-expression failure argument expands `$?` immediately
into one of `pkg-sd-q1` through `pkg-sd-q255`. The receiver accepts only exact ASCII
decimal status codes 1 through 255; its final refusal exit status remains 1. A
successful query whose output fails the unchanged version-prefix predicate still
uses `pkg-sd-ver`.

These frames describe the shell assignment-expression status. The utility wrapper
may itself refuse before systemd executes. A matching fixed byte pattern does not
independently establish a systemd process status, signal, output, version,
authentication or runtime failure cause. The observed SSH status remains separate
from the status represented by a diagnostic code.

Each new optional frame is 39 through 41 bytes (64 through 66 bytes with the
generic marker), within the existing 44-byte frame and 69-byte transcript bounds.
The original 35 whole-stream patterns, including the legacy `pkg-sd-query` frame,
remain exact; 255 added patterns make 290 unique entries. Source/EOF/count/hash
checks, query argv/order, scoped color setting, single credit and all budgets
remain unchanged. Pure controls cover all 255 codes, malformed codes, suppressed
emission outside the initial prerequisite, and rejection of incomplete, duplicate,
mixed, embedded and nested-refusal transcripts. These controls do not constitute
runtime acceptance.

## Canonical systemd path requirement (source only)

The expected guest profile requires exactly `/usr/lib/systemd/systemd --version`,
with the existing scoped `SYSTEMD_COLORS=0`. The two closed utility allowlists and
that one existing query select this path. There is no alias lookup, PATH search,
fallback, second query, installer or new helper. Failure refuses under the same
single-credit, EOF, capture, status, poison and original deadline contracts. The
version-prefix predicate, 49 query sites, all 290 diagnostic patterns and final
refusal status 1 are unchanged. The enrolled receiver hash changes with its source;
the former V12 hash cannot authenticate a V13 diagnostic pattern.

[Immutable source facts](../../scripts/fixtures/owned-systemd-path-source-facts.json)
record upstream URLs, commits/blobs, content hashes, licenses and relevant lines;
the supplemental selected-build record is explicitly unverified.
Upstream systemd v259.9 resolves to commit
`63c0371fa71ae32ba02f05f90658bc40aaa19168`. Its root Meson lines 137/281 and
core Meson lines 194–211 declare the default libexec executable location;
core lines 297–300 separately declare the init symlink. Fedora dist-git commit
`29f902fb5a9fc3d5a5c1de5cfc1075dac7f309ec` selects that upstream version by
default. The spec's installation and splitter rules support the expected canonical
path, conditional on default build settings and the binary being present in the
buildroot. They do not manufacture or attest RPM/image contents.

This is a publisher-declared expected profile requirement, not an attested file
path in the selected image. Retained supplemental CoreOS metadata reports that
build/package tuple, but its publisher-versus-local origin and the meaning of its
`synthetic: true` flag remain unverified. That record is excluded from the canonical
path justification and does not establish RPM/image membership, authentication or
execution. No absence of `/usr/bin/systemd` is claimed. Neither the installation
sources nor the recorded V12 `q127` byte pattern establish
an actual systemd process status or the failure's cause; the outer SSH status is
separate. Runtime, kind, API and controller acceptance remain pending. This source
change grants no runtime retry or execution authority.

GitHub's tag API reported a valid signature; no independent local tag-signature
verification was performed. Fedora's sources manifest declares the tarball SHA512;
the tarball was not downloaded or independently hashed. Optional external build
macros/configuration remain unattested. The exact Fedora NVR-tag lookup returned
404, so no exact NVR-to-dist-git build attestation is claimed. The facts preserve
upstream LGPL-2.1-or-later source labels and Fedora's aggregate package expression;
separate spec/splitter/manifest licenses were not established. Only provenance
metadata and independent factual summaries are retained, without redistributing
upstream implementation, tarballs, RPMs, binaries or images.

These fixed compatibility facts and receiver-content bindings live beneath the
existing `**/fixtures/**` Renovate exclusion. Existing historical-evidence controls
also cover `docs/evidence/**`. The operational VM image record, shared tool
inventory, workflows, manager definitions, extraction/replacement/grouping and
approval rules are byte-identical to V12; no operational pin or owner is added.
The existing actual-engine regression definitions already test historical fixture
and docs-evidence exclusions. No Renovate configuration change or new inventory
is needed, and this source-only slice does not claim a fresh actual-engine run.

## Requested guest PID/FD profile and fixed refusals

Only the rootful route's existing mode-0600
`/etc/sysctl.d/99-kubernetes-lens.conf` requests `kernel.pid_max=32768` and
`fs.nr_open=1073741816` during normal guest boot. The same file and existing
Ignition metadata ceiling are retained; qualify/stage output remains unchanged.
This configures the disposable guest, with no host setting, new unit, query,
helper or runtime repair. It neither proves the setting was applied nor changes
already-created tasks' hard NOFILE limits. Those tasks and numeric FD indices
still face the existing inventory checks. If boot configuration is not applied
or any later observation mismatches, the unchanged live checks must refuse.

The three existing guards retain their exact reads, parsing, predicates and order.
Their fixed refusal destinations are now `pid-max` for the required PID maximum,
`nr-open-form` for the existing numeric grammar, and `nr-open-range` for
`0 < nr_open <= 1073741816`. No raw value, additional observation or underlying
status is captured. Read failures and other existing generic failure paths remain
unchanged. The original 290 whole-stream patterns, including historical
`pid-limits`, remain exact; three added patterns make 293. New frames are 37, 42
and 43 bytes (62, 67 and 68 with the generic marker), within the existing 44/69
bounds. Source binding, whole EOF, empty stdout, initial-only selection, poison,
final exit 1, all 49 query sites, utility credits, caps, deadlines and retirement
remain unchanged.

These are requested configuration and source-control contracts. They do not
establish the earlier coarse refusal's failing value or cause, successful guest
sysctl application, task-limit compliance, runtime acceptance or retry authority.
Pure tests project existing guard values and test fixed frames without reading
host proc limits or executing sysctl, VMs or Kubernetes tools. The existing
fixture exclusions still cover these source bindings; no operational pin,
Renovate configuration or tool inventory changes.

## Rootful boot profile and one-time stage epoch (source only)

The rootful Ignition alone requests
`kernelArguments.shouldExist=["ostree.prepare-root.composefs=0"]`; its existing
sysctl request is unchanged. Publisher sources describe Composefs defaults and
Ignition's reboot transition when kernel arguments differ. The rootful phase alone
omits QEMU's `-no-reboot`; every other QEMU argument remains unchanged. Internal
resets keep one continuous QEMU PID/start/cgroup/overlay and the original host
absolute ends, output accounting and finite budgets. The harness observes neither
reset count nor cause. QEMU exit still fails; there is no host restart, connection
retry, renewed guest epoch, deadline renewal or credit refund. Requested settings
and upstream source facts do not establish actual selected-image mounts or the
cause of any earlier failure.

The actual rootful authorized key contains a closed dispatcher. Only
`rootful-prerequisite-v1` and `rootful-execution-v1` select literal
`prerequisite-v1` and `execution-v1` arguments to the existing rootful receiver.
Missing, unknown, padded, multiline and extra command text refuse without executing
or logging caller text. Dispatch precedes the existing fixed `sudo`/`env -i` chain;
the receiver gets no ambient SSH command or caller environment. No new producer,
key, helper, observer or attempt is added.

Builtin trusted-prefix checks precede the first claim. Prerequisite requires empty
state/credit/capture directories and only the immutable stage entries; old or
partial claims, cursors, payloads and publications refuse. Its atomic claim and
inflight phase precede preflight. One separately inventoried nonblocking
`u /usr/bin/flock -n 9` action holds the existing stage lock while seeding exact
same-boot ready0. It is precharged from the original 768 utility allowance, with
no extra metadata/version query. The existing whole-image/util-linux and stage
flock inventory remain the software authority. Consistent complete ready0,
prerequisite claim, work mode and original deadlines precede success publication;
`staged-required` is published last. Lost acknowledgments cannot reinitialize.

Rootful staging explicitly selects `rootful-kind-v1`. The host creates its receiver
from the byte-exact standalone base using only trusted literal edits: every anchor
must occur exactly once, intervals must be disjoint, and generated size stays
within the existing 64 KiB bound. Base/generated sizes and hashes, actual Ignition
rows and modes, and the generated checksum file are verified through source/config
bindings. Rootful mode requires the old same-boot successful prerequisite and an
existing valid cursor before inflight/header/payload publication. There is no
standalone initialization fallback. The old zero-argument receiver and historical
971/11689-byte qualify/stage Ignition identities remain exact.

Execution requires the existing same-boot successful prerequisite, work mode,
original deadline record and complete3 cursor before new guest preflight credits,
deadline writes or runtime effects. Missing runtime state after reboot therefore
refuses rather than starting again. Early refusal creates neither poison nor other
state; post-admission failure preserves the existing poison rules. These are guest
refusal boundaries after the already-budgeted SSH producer starts, not a claim of
refusal before host producer creation.

The original mountinfo scan and combined acceptance predicate remain exact. Only
its refusal branch distinguishes `mount-both` (`0:0`), `mount-proc` (`0:1`) and
`mount-root` (`1:0`), with unexpected flags retaining `mount`. The 293 historical
whole-stream patterns remain unchanged; three new 40-byte frames/65-byte
transcripts make 296, within the existing 44/69 bounds. There are no added mount
queries or raw-value diagnostics. Source/status/EOF/empty-stdout/hash/privacy rules,
the original 49 metadata/version query sites, utility/native/output caps,
deadlines and retirement remain unchanged.

[Boot/QEMU provenance](../../scripts/fixtures/owned-boot-profile-source-facts.json)
contains immutable publisher identities, licenses and limitations. Only factual
summaries and provenance metadata are redistributed; no upstream implementation,
image, firmware or binary is copied. Supplemental synthetic build metadata remains
unverified and unused. Pure projected-path controls do not establish guest, kind,
API, controller, reset or hosted-run qualification. Separate exact runtime
admission and independent whole-target retirement remain mandatory.

### Exact record reads and prepaid guard partition

Known records are verified only by fixed `/usr/bin/cmp -s -- "$path" -`
with a command-local here-string containing the bounded expected bytes plus one
LF. Only status zero passes. Differences, I/O errors, signal/launch/open failures
and redirection failures refuse; a nonzero Bash read is never interpreted as EOF.
The dynamic deadline candidate starts empty, requires a successful bounded
LF-delimited builtin read, at most 255 candidate bytes and the existing two-integer
grammar, then undergoes the same complete raw comparison. Missing LF, NUL,
extra LF, suffixes and truncation cannot become complete records. No process
substitution or extra shell helper is introduced, and the here-string leaves the
original stage payload stdin intact.

The unchanged rootful utility allowance is now partitioned as 680 ordinary work,
24 prepaid exact comparisons and 64 cleanup actions. The original worker Budget
irrevocably reserves this partition before any SSH producer. The 24 comparison
ceiling is separately catalogued: prerequisite 10 (inflight 1, seed 3, publication
6), execution 5, and three checks in each of the three stage producers. Each
literal purpose has local in-memory fuel, decremented before every comparison
attempt, including failure. Provider/logs routes have zero guard fuel. No guest
filesystem guard-fuel ledger is written before admission. The existing separately
reserved 256 historical stage operations remain unchanged and are not charged
again for these new comparisons. The separately inventoried single nonblocking
stage flock consumes an ordinary work credit. All 49 original metadata/version
queries and their argv/order remain exact.

The trusted original worker owns an ordered, nonreissued purpose ledger. It
consumes each of the five existing producer purposes before pre-child checks or
launch; failed preflight/spawn, disconnect and lost acknowledgment cannot refund,
replay or reconstruct a purpose. The host stops on failure rather than continuing
the schedule. This is an explicit trusted serial-host/private-record/whole-image
primitive boundary, excluding hostile guest root; it is not a global filesystem
call-closure claim.

After all five healthy execution predicates, the existing atomic execution claim
precedes admission and ordinary debits. A concurrent loser cannot poison the owner,
consume ordinary utility credits or renew deadlines. A successful execution
receipt separates actual ordinary `utility_ledger_actions` from `record_guards`
(`prepaid=24`, `attempted=24`), and `utility_actions` includes both. Reaching that
receipt requires all prerequisite, stage and execution comparisons. Earlier
failures retain host `rootful_record_guards` with prepaid 24 and consumed purposes;
its `comparisons_attempted` remains unknown. Consuming a purpose does not establish
how many guest comparisons launched, and no failure receipt invents 24 executed
commands. All paths retain the original total allowances, deadlines and outside
retirement obligations.

## Inventory predicate diagnostics (source only)

The earlier coarse V15 `inventory` refusal identified no particular predicate or
failure cause. The initial prerequisite now distinguishes the following existing
refusal destinations. These are labels on unchanged conditions, not additional
observations or claims about the failed guest:

| Code             | Existing failed predicate                                          |
| ---------------- | ------------------------------------------------------------------ |
| `inv-pid-range`  | Process ID outside the admitted range                              |
| `inv-proc-task`  | Process task directory lacks required directory/read/search access |
| `inv-proc-read`  | Process stat read fails                                            |
| `inv-proc-pid`   | Process stat ID differs from its path ID                           |
| `inv-proc-form`  | Process stat field count or numeric start-time grammar fails       |
| `inv-task-empty` | No tasks are enumerated for a process                              |
| `inv-tid-count`  | Task ID range or cumulative task-count bound fails                 |
| `inv-task-read`  | Task stat read fails                                               |
| `inv-task-tid`   | Task stat ID differs from its path ID                              |
| `inv-task-form`  | Task stat field count or numeric start-time grammar fails          |
| `inv-nf-form`    | Hard NOFILE value is missing or fails its numeric grammar          |
| `inv-nf-range`   | Hard NOFILE exceeds the existing ceiling                           |
| `inv-fd-access`  | Task FD directory lacks required directory/read/search access      |
| `inv-fd-form`    | An enumerated FD index fails its numeric grammar                   |
| `inv-fd-range`   | An enumerated FD index reaches or exceeds the existing ceiling     |
| `inv-snap-size`  | Accumulated snapshot exceeds the existing size bound               |
| `inv-empty`      | No tasks were counted                                              |
| `inv-drift`      | Two completed snapshots differ                                     |

A compound-condition label does not distinguish its individual operands. A label
inside the shared inventory routine does not identify which snapshot invocation
failed. `inv-drift` establishes only that both scans completed and their recorded
values differed; it does not identify a process, task, FD or limit change. Existing
unlabelled failures are not retrospectively classified.

The active prerequisite calls inventory directly, and the scan starts no child or
external program. Other trusted guest tasks can nevertheless appear, disappear,
change FD indices or alter limits during boot. Such races and a persistent profile
mismatch remain possible explanations until separate evidence distinguishes them.
The original coarse failure establishes neither. No stability retry, wait,
disappeared-task exception, repair or weakened snapshot equality is introduced.
Executable privilege checks precede inventory; inventory does not inspect executable
identity and its labels do not diagnose an executable problem.

All 296 historical whole-stream patterns, including `inventory`, remain exact;
18 new fixed labels make 314. The longest new frame/transcript is 44/69 bytes,
within the original ceilings. Emission remains initial-prerequisite-only, with
ordinary execution/provider/cleanup suppression unchanged. No raw ID, path, stat
record, limit, snapshot or protected value is emitted. Current source enrollment,
independent observed status, complete EOF, exact whole-stream byte count/hash and
empty stdout retain their existing roles; a recognized byte pattern never supplies
an inner process status or cause. Stale V15 source cannot authenticate new enrollment.

The 49 original queries, argv/order, predicates and short-circuit evaluation remain
unchanged, together with state/poison, one-time claims/cursors, original deadlines,
24 prepaid record guards, 680/24/64 rootful partition, separate historical stage
256 reservation, native/storage/output/capture limits and retirement requirements.
Pure private proc-shaped fixtures and scalar boundary projections establish source
behavior only. They authorize no new guest observations, runtime retry or native
conformance claim.

## Versioned whole-guest hard NOFILE profile v2

[ADR 0063](../decisions/0063-whole-guest-hard-nofile-v2.md) supersedes the
historical shared hard-NOFILE ceiling and future FD-slot theorem above. The new
fixed hard metadata ceiling is `9999999999`, derived from the existing ten-digit
grammar, not a failed guest value. Actual `nr_open` remains positive and at most
`1073741816`; currently occupied numeric FD indices remain strictly below
`1073741816`. Every current task, including PID1 and every TID, must satisfy the
new finite hard limit in both equal complete inventories. No task is repaired,
no observation added, no source evidence replayed and no fit inferred.

Under the unchanged trusted-kernel/global/program premise, inheritance and the
hard-limit raise ceiling preserve a future occupied numeric-slot bound of
`32767 × max(9999999999, 1073741816) = 327669999967233`. This replaces the v1
future bound; it does not bound allocated FD-table capacity or all kernel file
references. RAM, backing storage and every original query, snapshot, utility,
native, output and deadline budget remain unchanged. The ten-character field
width is unchanged; `10000000000` refuses as `inv-nf-form`. No in-grammar value
exceeds the new fixed hard ceiling, but `inv-nf-range` and all other historical
closed patterns remain enrolled. The source-bound V16 refusal does not identify
a task or limit and remains a failed-retired v1 record. V2 requires new source
enrollment and separate fresh runtime admission; pure tests establish neither
application nor native conformance.

## Fixed marker-to-check scheduling proposal

[ADR 0066](../decisions/0066-rootful-guest-check-settling.md) proposes one fixed
30-second interval before the single rootful guest check. The existing bounded
QEMU console drain remains active, charging its original allowance, and the
interval consumes the original absolute work deadline. Later console markers
cannot extend it. Insufficient time, cancellation, QEMU exit, EOF or exhausted
output still refuses; failure starts no extra check or retry.

This is a scheduling experiment after the independently retired V21 `inv-drift`
refusal, whose differing inventory fields were not retained. It neither diagnoses
that failure nor establishes quiescence. The receiver, strict inventory equality,
314 historical patterns, 49 queries, 24 guards and all other caps are unchanged.
The proposal requires independent review, the final complete gate and separate
fresh runtime admission; native qualification remains pending.

## Fixed owned-node presentation proposal

[ADR 0067](../decisions/0067-fixed-node-monochrome-presentation.md) proposes exactly
`-e SYSTEMD_COLORS=0` in the source-owned translated node creation argv, immediately
before its content-addressed image. The incoming provider grammar, `--pull=never`,
all other arguments and existing credit accounting remain unchanged. This setting
is delivered to the node, with no arbitrary host environment forwarding or global
host/guest export. Existing guest version-query color selection remains separate.

[Immutable v257 and kind source facts](../../scripts/fixtures/owned-node-monochrome-source-facts.json)
support normal PID 1/log/job-status color reduction. They do not attest the selected
installed binary/script, suppress messages, alter severity/show-status, remove all
CSI/OSC/raw SGR or guarantee lossless presentation. Existing ellipsization remains.
The unknown tail of the V22 private prefix prevents a claim of complete stream fit.

The entire followed stdout ceiling stays16384-bytes, stderr 4096, and the private
failure prefix stays16384. Original total/delegated output, CPU/memory/PID/disk,
work/cleanup deadlines, all 314 diagnostics, credits, poison, EOF and independent
whole-target retirement remain unchanged. No observer, marker acceptance, retry or
new runtime authority is added. Pure source/argv tests and future main-owned gate
results must remain separate from independently admitted native evidence.

## Opt-in host-view mismatch diagnostic (source only)

The legacy/default profile keeps the existing GO and bare `producer-stopped` barrier unchanged and emits no mismatch record. The explicit `host-view-diagnostic-credit-v1` profile predebits 2053 bytes from the existing cumulative output budget before unit start. The worker grant is bound through the existing config digest in GO. The worker sends the unchanged bare barrier first, then makes one nonblocking best-effort send of a separate V3 diagnostic frame on the same private channel. Its body is capped at 2048 bytes and its frame at 2052 bytes; the extra prepaid byte is only a trailing-data sentinel.

The controller begins existing outside retirement from the bare barrier and does not wait for optional data. Only after successful retirement proves the worker exited does it make one nonblocking read of at most 2053 already-queued bytes. Missing, partial, malformed, wrong-site, over-cap, or trailing data is omitted without changing the original failure or cleanup. Credit is never refunded or charged a second time. A valid record contains fixed site/object aliases and sorted unequal scalar details derived from the already-computed comparison, including projected owner/group values. Paths, arbitrary names, object contents, xattr data, and exception text remain excluded. Parent-local details use the private receipt cap independently. Records appear only in private failure receipts; public summaries and stdout/stderr do not expose them. Equality still refuses the mismatch; this diagnostic is neither acceptance nor runtime qualification evidence.

[ADR 0073](../decisions/0073-versioned-postcreate-guard-reason.md) versions the private
rootful result as v2, preserving explicit v1 reads. Sixteen fixed `pg1.a` through
`pg1.p` log-state aliases identify only the first actually evaluated false predicate
in the existing post-create retirement gate. Codes require failed/create-zero/
source-not-reached/startup-false context and retain incomplete null/collector/overflow
semantics, including protected-prefix scope. Untagged, skipped or interrupted
evaluation stays unknown; no new read, query, wait, observer, budget, role or raw
stdout modification supplies a reason. Neither a code nor later startup text proves
the old failed predicate, cause, readiness, native success or retirement.

[ADR 0075](../decisions/0075-private-log-poll-failure-diagnostics.md) adds explicit
rootful result v3 private `pg2.g/p` facts for the existing log poll. The token binds
an existing guest log role and PID/start to its last sampled state and per-role
completed iterations. Unsupported/no state is unavailable; it is never a liveness,
signal, readiness or retirement claim. Original v1/v2 records retain their meanings,
and the retained V12 `pg1.g` cannot be attributed retrospectively. No new read,
process, signal, file, retry or budget is added; builtin bookkeeping uses actual
time within the unchanged original end. The typed DATA projection stays private
and is not another wire/receipt member or native authority.

## Bounded pacing in the existing eight-role poll (source contract)

[ADR0076](../decisions/0076-bounded-existing-log-poll-pacing.md) refines the
ADR0075 diagnostic-only no-new-wait and unchanged-clock-order statements above.
The current poll first requires pipe/FIFO fd0, opens `/proc/self/fd/0` read/write
using one additional Bash receiver descriptor, and verifies `-ef` equality with
fd0. This is one extra FD and one open-file description on the existing inherited
pipe inode, with no new inode, actor, helper, utility, observer or protocol channel.
The read/write endpoint intentionally retains its own pipe writer until closure;
a closed original producer does not supply immediate EOF to this pacing read.
Unsupported fd0 types, open failure and unequal descriptor objects refuse.

Every role still has at most 4096 samples. Its first sample has no pacing read.
Before each later sample, the original work-clock check runs; if integer remaining
work is greater than one second, the fixed builtin
`IFS= read -rd '' -n 1 -t 0.01 -u "$pace_fd" line` runs, followed by another original
clock check before proc examination. Only exact status 142 and an empty buffer are
an accepted policy wake event. No timer, signal, elapsed interval or retirement
cause follows from that event. Success, including empty successful NUL input,
nonempty data, EOF/status 1, other statuses and failed/malformed clocks refuse.
The one-byte/NUL-delimited read detects unexpected bytes including NUL. There are
at most 4095 such reads per role and 32760 across the same eight roles. The nominal
10 ms read timeout supplies no hard real-time or minimum-progress guarantee.
Actual time and extra builtin work consume the original absolute work end; no
read occurs with one second or less remaining and no work/cleanup end is renewed.

The last sampled glyph and completed-sample count remain cached observations.
A failed pre-read or post-wake clock retains the same `pg2.p` count/state. A wake
adds no sample and does not retire persistent `Z` or any other state. Original
identity disappearance/reuse rules, real collector EOF and zero statuses, raw
capture/path/size predicates, startup marker, available genuine wrapper wait-zero,
create status 0 and poison checks remain mandatory. Independent outside whole-target
retirement remains necessary on success and failure.

After those predicates, the receiver closes and unsets the descriptor, disables
poll attribution, and checks the original clock once more before publishing
`logs-retirement`. Final clock failure is plain `pg1.p` and publishes nothing.
The next normal native child therefore cannot inherit the pacing FD. Real
`finish` closes it immediately after clearing traps, before optional diagnosis,
mandatory cleanup native launch or evidence emission, including early refusal
where no FD was acquired. A close error exits before any later child launch.
No receiver descriptor survives into cleanup and no accepted wake supplies an EOF
or wait-status substitute for the separate log collectors.

All original caps, the 680/24/64 rootful utility/guard/cleanup partition, historical
stage reservation, eight roles, 4096 sample cap, native actions, poison, public
redaction and private v3 wire meanings remain unchanged. The reviewed receiver
is 65362 bytes under the unchanged 65536-byte ceiling. Its current enrollment hash
changes with its source bytes; no third-party pin, installer, tool inventory or
Renovate definition changes. Exact inverse controls recover historical diagnostic
v3 bytes before the retained strict v2/v1 inverses. Existing ADR0075 trace controls
explicitly use their historical source domain; `PollPacingReceiverControls` and
general Bash protocol controls exercise actual current source.

Pure controls are local owned Bash/pipe and private proc-file projections. They
cover actual bytes/NUL, empty closed-producer behavior, one-FD lifetime, refusal
on unsupported descriptors/open/equality/status/data, exact 142-empty policy,
original clock expiry and sample/state attribution, collector/marker/poison
refusals, and closure before real finish ordering with projected native launches.
They are not selected-image primitive, SSH, VM, kind, API, scheduler, failure-cause
or whole-target retirement evidence. Final complete validation and separately
scheduled exact selected-image primitive/native qualification remain pending.

## Current v4 kind-owned log process (source contract)

[ADR0077](../decisions/0077-kind-owned-log-process.md) replaces the historical
separate wrapper/child ownership path. The source-owned provider launcher and
receiver keep kind's command PID through ordinary exec into the fixed Podman log
client. Before reservations/claim/collectors, the admitted path requires
`BASH_SUBSHELL`0; it enables execfail, guards descriptor setup and closes all spare
writers plus FD3 before the final exec. Only the final handoff disables errexit,
with every returned path performing a direct builtin poison write and nonzero
exit. No handler depends on the closed diagnostic FD. Failed poison persistence
also remains nonzero. There is no fallback, child/PDEATHSIG launch or EXIT trap.

Explicit result v4 has exactly seven unique roles: native, out, err, out-dd, out-tee,
err-dd, err-tee. Native is the same provider PID/start before and after fixed exec,
under the trusted source/program chain. V4 always reports null for the legacy
wrapper-observed child wait member and signal cause. It rejects direct-wait-zero
and the removed pg1.n guard; older v1–v3 records keep their exact original meanings.

The two collectors still really wait their own dd and tee children, preserve
immediate bounded forwarding and private exact bytes, and require genuine EOF,
zero actual statuses and existing byte limits. All seven process identities must
retire before collector/marker/poison acceptance. EOF, kind create0, cached S/Z or
a marker is never a retirement substitute. Whole-target retirement and original
failure/cleanup/publication requirements remain independent.

All existing action, utility, guard, source, stream, storage and deadline caps are
unchanged. The absent setpriv invocation consumes no ticket; no issued credit is
refunded. Pacing keeps its original policy and4096 per-role bound, now over seven
roles. Current source and enrollment are sealed separately from frozen v3 and
older source inverses and all314 literal prerequisite frames. No pin, installer,
new observer or runtime probe is added. Pure owned local exec/pipe controls and
final complete validation do not establish selected-image or native qualification;
a fresh separately reviewed/adopted run remains necessary.

## Current v5 private post-log failure site (source contract)

[ADR0078](../decisions/0078-private-postlog-failure-code.md) adds required nullable
`postlog_failure` to the private result. It records only the first actual existing
parent receiver `fail()` in the admitted execution/work segment after successful
log retirement and before successful node-inspect enrollment:

| Code    | Existing action or guard                             |
| ------- | ---------------------------------------------------- |
| `pl1.r` | Post-log resource check, including its helper guards |
| `pl1.i` | Owned node-id file read                              |
| `pl1.f` | Canonical 64-hex node-id predicate                   |
| `pl1.n` | Fixed native container-inspect action and guards     |
| `pl1.j` | Existing inspect jq action and result guard          |
| `pl1.e` | Node-inspect role/path enrollment guard              |

A label alone, a skipped call, subshell failure, ERR, signal or direct IO failure
bypassing `fail()` supplies no code. Null means no admitted explicit fail was
recorded; it does not identify a cause or prove the action succeeded. Both variables
reset unexported at startup. Successful enrollment clears the active site. Finish
keeps its original first `local status=$?` capture, then clears the active site
before trap changes, pace closure, diagnosis, cleanup and evidence; an existing
first code survives and cleanup cannot invent one.

A non-null code requires failed/create0/not-reached, all seven genuine positive
log facts (including marker, EOF and collector statuses), null native wait/signal,
and no ordinary node-inspect catalogue member. Successful v5 results require null.
V5 reuses exact v4 logs validation; the logs object and state are unchanged.
V1–v4 retain exact member sets and source/evidence domains; no synthetic null is
added. A separate exact v5-to-frozen-v4 inverse precedes the unchanged historical
inverses. All 314 prerequisite patterns remain fixed.

The scalar travels only through the existing bounded private wire and durable
receipt; public output gains no code, raw value or attribution message. No actor,
query, raw role, credit, cap, deadline, retry or native invocation is added. Pure
local fixtures cover the original action order, fail sites, finish ordering,
version/context refusals, private persistence and worker/parent failure propagation.
They establish no V18n cause or native qualification. Final independent source
review, complete validation and separately adopted native work remain required.

## Current v6 private native status snapshot (source contract)

[ADR0080](../decisions/0080-private-postlog-native-status.md) preserves the v5
six-site code and adds required private `postlog_native`. It is null except for
`postlog_failure: pl1.n`, where it has exactly four nullable status members:

| Member                  | Existing observation                                                              |
| ----------------------- | --------------------------------------------------------------------------------- |
| `return_status`         | Nonzero return from the fixed native action before its original fail              |
| `command_status`        | Existing command-call subshell result, including possible descriptor/exec failure |
| `stdout_capture_status` | Existing wait status for the owned stdout capture helper                          |
| `stderr_capture_status` | Existing wait status for the owned stderr capture helper                          |

Null means that this action had not obtained that status before the first explicit
parent fail. It never means zero or an inferred Podman exit. All four caches reset
unexported at startup and clear immediately before the single fixed n invocation.
Only the original result/wait assignment points populate them; prior network,
create, image and provider observations cannot supply a current value. Freeze JSON
inside the existing first parent fail bookkeeping; cleanup cannot overwrite it.
Finish still captures the original status first, then clears the active site before
trap changes, pace closure, diagnosis, native cleanup and evidence.

V6 accepts only the current source's three forms: four nulls; null return plus a
known command and two zero capture statuses when the final clock guard fails; or
four known statuses after a nonzero native return. A failed capture requires native
return125. With both captures0, the nonzero return must equal command status.
Partial triples, bools, wrong types/ranges/relationships and extra members refuse.
Command/capture statuses range0–255; a known return ranges1–255. The object requires
the same failed/create0/not-reached/positive-seven-role-log/no-node-inspect scope as
pl1.n. All other codes and successful results require null.

These are obtained wrapper statuses, not a Podman launch attestation or an overflow,
resource or runtime cause. The spent V19n packet remains v5 and cannot acquire this
new evidence retroactively. Logs, raw roles/catalogue, public projection, all caps,
credits, clocks/deadlines and cleanup semantics remain unchanged. No new query,
wait, actor, capture or retry is added. V1–v5 keep exact schemas and historical
source/evidence domains; a new strict v6-to-frozen63958-byte v5 inverse precedes the
unchanged earlier seams. Pure fixed-DATA controls do not replace independent source
review, pinned formatting, the final complete gate or separately adopted native work.

## Current v7 private existing resource reason (source contract)

[ADR0081](../decisions/0081-private-postlog-resource-reason.md) adds required private
postlog_reason. Only a first explicit admitted parent fail at site r records one of
the30 existing fixed resource_check/inventory reason labels. Otherwise that site's
first fail records literal unlabelled, meaning no admitted fixed reason was supplied.
Missing, empty or unrecognized arguments never become raw wire content. All other
sites, success and paths without an actual parent fail require null.

The one private scalar resets unexported at startup and freezes in the same first
parent fail bookkeeping as pl1.r. No previous argument or resource value supplies it.
Child/subshell failure cannot directly set it; if the parent later fails, it records
only its own existing label. ERR/signal paths and cleanup cannot invent a reason or
replace the first one. Finish's original first status capture and early active-site
clear remain unchanged.

This preserves existing guard groups, not an underlying cause or a measurement.
Several predicates share labels; unlabelled command/credit failures remain distinct
from named guards without identifying which unlabelled path failed. Current r has
no clock_check call. V20n-v2 remains a spent failed v6 result and cannot acquire a
reason retroactively. Native status snapshots, log proof, catalogue/raw roles,
public redaction, all caps/budgets/clocks and cleanup stay unchanged. No query,
process, observer or retry is added. V1–V6 retain exact schemas and source/evidence
domains; a strict V7-to-frozen64608-byte V6 inverse precedes unchanged earlier seams.
This source contract still requires independent review, the complete gate and
separately adopted native qualification; it establishes no cause or conformance.

## Compact owned node-inspect presentation (source contract)

[ADR0083](../decisions/0083-compact-owned-node-inspect.md) adds only the fixed
--format '[{{json .}}]' argument to the single local n container inspect. The pinned
Podman5.8.7 formatter serializes the complete same report with its standard JSON
encoder without default indentation; brackets preserve the one-element root array.
No field projection, new query/process/helper, alternate mode, target or output role
is added. All existing16384/4096 bounds, reservations, clocks and semantic gates stay.

This applies only to exactly one owned named container. It is not a generic
multi-result template. The official json helper ignores encoder errors, so existing
jq syntax, length1, identity, image, state, args, network and ports checks remain
mandatory; empty[] or malformed output must refuse. No cap is raised if compact data
still fails capture. Raw evidence retains actual native bytes, not a normalized copy.

V21n proved command-call status0/stdout helper1/stderr helper0/native return125, not
an overflow cause. The format is a prospective full-JSON presentation improvement,
not a proven fix or a reinterpretation of that failure. V7 wire/status/reason meanings
are unchanged. Earlier V1–V7 source/byte/evidence domains remain sealed: a separate
strict compact-source-to-frozen65246-byte V7 inverse precedes the unchanged chain.
Current enrollment admits only the new canonical source. Fixed-DATA controls are not
Podman native execution; complete validation and separately adopted qualification
remain pending.

## V8 private first parent failure after node enrollment (source contract)

[ADR0084](../decisions/0084-post-node-first-parent-failure.md) succeeds the frozen
V7 contracts above. It uses the same fields and existing unexported site/first-code
state. Successful node-inspect enrollment now enters a rather than clearing the
site; the existing post-node statements have these closed group boundaries:

| Code    | Existing action or guard group                                            |
| ------- | ------------------------------------------------------------------------- |
| `pl2.a` | Cgroup-equality jq action and parent helper guards                        |
| `pl2.b` | PID extraction and decimal/range guards                                   |
| `pl2.c` | Cached inventory start lookup and decimal guard                           |
| `pl2.d` | First proc stat read and PID/start identity guards                        |
| `pl2.g` | Proc cgroup read and equality guards                                      |
| `pl2.h` | Second proc stat read and start identity guard                            |
| `pl2.k` | Broad downstream config/version/readiness/namespace/fixture/dry-run group |

The k group does not identify a specific kubectl cause. Only the original explicit
parent fail in admitted execution/work with no previous first code records a
value. Entry, skipped actions, children alone, ERR and signals remain null. A
parent fail after child failure records the parent's active group without child
values. The first code is immutable. Finish captures original $? first and clears
the site before trap changes, pace closure, diagnosis, cleanup and evidence.

Every non-null pl2 requires explicit V8, failed, actual integer create0, source
Deployment not-reached, genuine positive seven-role logs and ordinary node-inspect
evidence with all original catalogue/raw-integrity/node semantic checks. Native
snapshot and resource reason are null. Old pl1 codes retain their no-node-inspect
requirement, native snapshot only for pl1.n and reason only for pl1.r. V1–V7 retain
exact schemas, fields, code/source/evidence domains and bytes without inserted
defaults. The strict V8-to-frozen65270-byte C6 V7 seam precedes unchanged earlier
inverses. All 550 predecessor test IDs and 314 prerequisite patterns remain.

The exact receiver is 65408 bytes, SHA-256
`d265f8834fdca00d79f9a4fdd487f3e5574813eeb5337cf10ece9dd5740adecb`,
138 bytes above C6 V7. The 65408-byte integration envelope is enforced inside the hard 65536-byte cap.
No initialization state, command/query/process/wait/observer, role, cap, credit,
deadline, retry, tool or pin changes. Existing compact full-JSON inspection stays.
Current enrollment binds only the new canonical source. Codes stay in the private
bounded wire/durable receipt; public output, outer failure, real delete failure,
original budgets and independent whole-target retirement retain their contracts.

V22n's V7 null fields and retained node-inspect role do not locate the later failure.
Aggregate counters and closed offline checks establish no cached inventory, live
process, helper or downstream cause. No retained native body is decoded for this change.
Projected tests use fixed builtin helpers before executing original statements;
no Podman, kubectl or actual proc query runs. Focused source evidence does not
establish native success/readiness/conformance or authorize a retry. Final source
review, complete validation and separately adopted native qualification remain
primary responsibilities; existing pins and Renovate ownership are unchanged.

## Phase-specific stable and live resource censuses

[ADR0085](../decisions/0085-phase-specific-guest-census.md) corrects the post-kind
quiescence predicate. The internal resource_check function accepts only zero args
(stable) or exact literal live. Provider run/pre-node, prerequisite and execution
before runtime stay stable and require identical snapshots. Only successful kind
create plus owned seven-role log retirement selects live, before node inspection.
Both modes run every original global/resource guard and both complete inventories.
Live permits differing, individually bound-valid topology/FD/finite-limit records.
Missing/unreadable/disappeared or malformed records and every original cap still
fail; there is no retry, wait, extra scan, helper, process or new observation.

Keep PID/TID/count<32768, nr_open<=1073741816, occupied FD indices<1073741816,
finite hard NOFILE<=9999999999, both32MiB snapshot caps and all other resource facts.
The second complete scan clears/rebuilds the final INVENTORY_START map. Subsequent
node PID/range, cache presence/decimal, first stat PID/start, cgroup and second stat
start checks stay unchanged; earlier caches cannot fill a missing selected PID.
Two censuses are sampled and non-atomic, with no continuous all-task claim. Initial
admission/inheritance/trusted-global preservation supports the existing future-slot
theorem; actual whole-VM containment and outside retirement have separate authority.
Within-scan races still refuse conservatively, so no native-fit guarantee is made.

V23n's failed-retired V8 pl1.r/inv-drift means two completed scans differed, without
retained differing fields. It identifies no actual process/FD/cause and grants no
retry. This change intentionally replaces that post-create predicate and preserves
all three earlier stable checks, numeric/resource/utility/native/capture/time caps,
first failure, real deletion failure, privacy and retirement. No code-only diagnosis
layer or new V9 is added. V8 wire/history remain exact; a strict new-source-to-frozen
65408-byte V8 seam precedes the unchanged historical chain. All564 prior IDs and314
literal patterns remain. The reviewed65354-byte source stays within65408 integration
and65536 hard caps; pinned formatting, full validation and separate native adoption
remain primary responsibilities.

## Canonical selected-node owned subtree

[ADR0086](../decisions/0086-owned-node-cgroup-membership.md) refines only the existing
g assertion. Selected Podman5.8.7 deliberately trims a cgroupfs process descendant
to the container root in inspect. Retain that exact root in guest/host inspection;
the subsequent proc record may name that root or a canonical descendant across an
exact slash boundary. Quote the root literally, require unified0::, nonempty non-control
components and no dot/dotdot segments. Reject sibling/prefix-lookalike/foreign/relative
roots, empty/repeated/trailing slash, controls and nonempty multiple records. No
decoding, normalization or descendant-to-root replacement occurs; preserve consumed
REPLY unchanged in the existing private file.

All selected PID/range, final second-map cache, first PID/start, cgroup read and
second start statements remain. Real read-helper failure still fails; earlier
failure/delete failure/privacy/whole-target retirement are independent. Proc paths
are relative to the reader cgroup namespace. Existing initial guest reader/kernel/
source premises remain; strings and PIDns checks do not add cgroupns attestation.
The payload's private slash is not a valid replacement for the full guest-view root.
Membership is sampled, not continuous containment or signal authority. Existing
read_file strips trailing newlines, so logical REPLY validation is not a new raw-file
framing guarantee.

V24n's failed-retired pl2.g includes helper or predicate failure, with no retained
proc text. Neither init.scope nor a mismatch/cause is established. All resource,
read/query/action/utility/capture/time limits stay; no runtime profile, observer,
retry or schema changes. V8/history and all574 predecessor IDs/314 patterns remain,
with strict current-to-frozen19c958 source inversion. The raw65359-byte quoted-root
source stays within65408 integration/65536 hard caps. Final review/full validation
and any separate fresh native adoption remain primary responsibilities.

## Current V9 closed k groups

[ADR0087](../decisions/0087-closed-k-stage-failure-evidence.md) advances only current
private outer result to V9, retaining the V8 member set and pl2.k. Private
postlog_reason selects k1.a–n for the active existing downstream action/helper/guard;
postlog_native is required only at six native groups, using original obtained
command/capture-wait availability. A label may precede helper refusal or interruption;
it proves no predicate evaluation, tool launch or Kubernetes cause. Interruption
without an existing explicit parent fail leaves diagnostic fields null.

Both original readiness rounds/continues remain. Ordinary exhaustion reports the
last rejected second-round group only at the original final ready failure; it is
not first-sample history. Each k native entry clears caches before any guard, so a
poisoned later entry retains unavailable observations instead of earlier statuses.
First snapshot and real delete failure remain independent; public output stays
redacted. V1–V8 domains stay exact, including V8 k native/reason null.

V26's retained V8 pl2.k/create0/delete0 has no exact k cause/status. Source
not-reached means no accepted final Deployment scenario, not that every downstream
command was skipped. Counts and expected server patch prove neither location nor
observed API version. No new query/read/process/wait/retry, raw role or budget;
unchanged65408 integration/65536 hard source caps. Source controls and gate evidence
are distinct from native qualification and fresh-attempt authorization.

## Proposed V10 readiness-conjunct diagnostics

[ADR0088](../decisions/0088-node-readiness-conjunct-evidence.md) uses the same existing
jq invocation/input to preserve original zero/nonzero acceptance while reporting a
fixed first-false count/name/version/Ready code. Fresh scoped admission/return/round
caches distinguish utility refusal before dispatch from an obtained error. No raw
NodeList/error text/credential or extra role/query/helper/wait is introduced. Only
an existing first explicit parent failure freezes DATA; success/recovered rounds,
interruptions and cleanup never manufacture an i failure. Delete outcome stays
independent. V1–V9, old k1.i and all bounds remain exact; no wait/pacing fix is inferred.

The temporary official jq1.8.1 conformance artifact and pure fixed-DATA controls are
not guest-binary equivalence, native qualification or a new operational tool pin.
Canonical final source bytes, independent candidate review and the complete gate
remain pending. V27 stays failed/spent without a retained exact atom; a later native
attempt requires separate exact-candidate adoption and fresh original budgets.

## Proposed V11 Ready-condition evidence

[ADR0090](../decisions/0090-ready-condition-text-class-evidence.md) refines only the same existing
jq call after no Ready=True: V11 k3.i.R.x.68 means no Ready-type condition; x.69 means a Ready-type
condition supplied a string message containing NetworkPluginNotReady. The marker is supplied-text
evidence, not CNI/preload or kernel-exec proof. Other no-Ready-True cases keep r; any Ready=True
still succeeds despite duplicates or malformed other messages. No raw body, query, role, process,
wait or budget change. V1–V10 records and their old k2 opaque e.68/e.69 meanings stay unchanged.
The input rootful-v1 source-spec shape/resources are unchanged; result V11 is explicit. Candidate
review, canonical final-byte fit, complete gate and any fresh native attempt remain main-owned.

## Proposed V12 once-only owned Ready wait

[ADR0091](../decisions/0091-owned-node-ready-wait.md) keeps kind wait0s and introduces
one fixed pinned-kubectl condition wait after the first existing readyz success.
After wait entry, every wait/NodeList/classifier failure is final; only pre-wait
readyz may advance to round2. Wait success alone never bypasses exact sole-node,
name, kubeletVersion, AnyReadyTrue, namespace, fixture hash or server-dry-run checks.

V12 spec/results and k4 private sites distinguish this policy from immutable V11/k3
history. The new native wait failure site is k4.o, with existing obtained status
custody and no cause/readiness claim. Kubectl1.20.15 checks condition strings with
first-match/case-insensitive semantics, so strict independent checks remain necessary.
Its30s timeout is nominal per-resource/watch behavior, not a hard transport/global
bound; original parent/guest absolute ends still govern and no second wait is allowed.

The worst readiness trace is4 native actions/11 output slots/8 sentinels/17 utilities,
versus old4/14/8/18. No aggregate cap, cleanup allowance, helper, output role or FD
lifetime is expanded. Canonical receiver65408 bytes fills the65408 integration envelope;
readable status-variable renames recover space without removing comments or guards.
This is a source-only proposal pending primary review/integration and complete gate;
V29 failed-retired history and any future native adoption stay separate.

## Proposed source-bound capture-size status

[ADR0093](../decisions/0093-capture-size-helper-status.md) keeps V12 wire/spec/raw
status semantics and all native/utility/output/read/actor limits. Only an existing
ordinary capture helper whose already-obtained numeric size exceeds its unchanged
cap explicitly exits23; other failure/refusal remains1 and native still returns125.
Both helper callers remain the existing process substitutions, preserving global
ERR traps and earlier-failure precedence. No failed payload or new role is retained.

Interpret23 only under the exact new receiver/helper/cap binding; it is not a global
label for23 or V12. V30 collector1 and older raw statuses remain opaque. The new
canonical65378-byte source leaves30 integration bytes; two cached-status name
shortenings recover space without removing comments or guards. No cap increase,
dry-run projection, extra query, timer, observer, preflight or retry is introduced.
Focused inert controls and source fit still require independent review, primary
integration and complete gate before any separately adopted source-changed attempt.

## Proposed compact complete-root dry-run response

[ADR0094](../decisions/0094-compact-root-dry-run-json.md) changes only the existing
server dry-run output selector to fixed full-root compact JSONPath for both frozen
kubectl versions. All returned fields and nested JSON types remain available; the
original four strict identity checks, authenticated fixture and 4096/4096 captures
remain mandatory. No field projection, array flattening, profile branch, extra
query, helper, capacity or retry allowance is added.

The [official source facts](../compatibility/kubectl-root-jsonpath-sources.json)
establish source compatibility, not byte equivalence or native/runtime acceptance.
Modern JSON defaults omit managedFields while root JSONPath retains them, so even
compact output may exceed 4096. Overflow still fails the original cap. Canonical
receiver 65388 bytes leaves 20 integration bytes; exact frozen ADR0093 source and all
predecessor test-method/assertion history remain preserved. Independent review,
primary integration, complete validation and fresh admission remain separate.

## Proposed modern kubeadm logging fidelity

[ADR0097](../decisions/0097-modern-kubeadm-logging.md) preserves kind 0.33.0's exact requested
modern init --v=6 classifier, then after existing work/cleanup guards translates only its final
logging value to --v=0. Legacy v6, all bootstrap options, statuses, captures32768/32768 and
deployment4096/4096 remain unchanged. Base returned errors/exit 1 and ungated Info/Warning/Error
logging remain; positive-verbosity debugging and v>4 stacktraces are intentionally reduced.
This is not critical-errors-only output or preservation of every diagnostic byte.

The [fixed official source facts](../../scripts/fixtures/owned-kubeadm-logging-source-facts.json)
are evidence, not a new installer/version inventory or per-run argv observation. The canonical
65361-byte receiver hash plus existing source/profile bindings identify this policy; targeted
shfmt/ShellCheck and exact current enrollment are complete, with independent review pending. Actions 70/5/75 and seconds 1800/1680/120 remain distinct original budgets. No cap,
actor, query, retirement or cancellation allowance changes. V33's failed 32769>32768 history
remains unchanged; reduced verbosity proves neither root cause, capture fit nor qualification.
Canonical source leaves 47 integration bytes; complete validation and separately authorized native
adoption remain pending.

## Proposed modern default-storage allocation

[ADR0098](../decisions/0098-modern-default-storage-capture.md) explicitly raises only
modern storage retrieval stdout 4096→8192, with stderr 4096. The unchanged native
allocator precharges three existing output slots before collectors/exec, including
one additional 4096 slot within the original 1MiB/245/10/150 aggregate limits. Legacy
and all other roles, including storage-install 4096/4096, remain unchanged.
The complete 4567-byte file passes the existing apply stdin chain; no source shrinking,
new framing/observer, error relaxation or fallback acceptance is added. Strict frozen
source inverses and raw poison/retirement rules remain. V34 inner statuses stay
unobserved; future fit/defaultSC/API/native acceptance and fresh adoption are separate.

## Proposed V13 kernel-bounded LIVE resource profile

[ADR0101](../decisions/0101-kernel-bounded-live-resource-envelope.md) defines the
source-bound owned-vm-live-v1 profile, V13 spec/result and qualified compatibility
record. All historical V12-and-earlier census/cache statements above retain their
original source meaning. The new sole post-kind vm-live-v1 call retains scalar and
owned-role PID guards but does not enumerate a whole-guest member list or claim
global PID/count, finite LIVE hard metadata, complete cache or atomic membership.
The three strict stable sample admissions and all resource/action/output/deadline/
poison/whole-target-retirement rules remain.

Under explicit coherent normal-LIVE stack/standard-VFS/managed4GiB premises, aggregate
user-FD occupancy is below the old numeric ceiling. Dead/leaked/in-flight/kernel objects
are outside that theorem and remain physically contained. The selected node uses the
existing first-stat/cgroup/second-stat reads with actual PID/start matching. Its interval
begins at the first stat; no creation/continuous/ABA claim is made.

Scoped signed-source qualification is compatibility evidence, not installed-binary
attestation, native fit or readiness. Canonical image and host-QEMU domain mismatch
refuses. Current source/proof enrollment needs independent final review and complete
validation before any separately adopted fresh run. V35 remains failed/spent/retired;
all35-kind, tool/fixture/API/runtime/controller and local/hosted obligations remain.
