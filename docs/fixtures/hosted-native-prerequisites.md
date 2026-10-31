# Hosted prerequisite observation

[Issue #69](https://github.com/Strukturpiloten/kubernetes-lens/issues/69) adds a manual-only,
read-only observation lane before anyone designs hosted native qualification. The workflow is
`.github/workflows/hosted-native-prerequisites.yml`; its standard-library collector is
`scripts/fixtures/hosted_native_prerequisites.py`. Ordinary CI and release validation run its
pure controls, never the external observations. No native support or completed observation is
claimed by delivering these files. Keep #69 open until its promised retained run evidence and
independent decision exist; #62, #2 and #14 retain their native/conformance obligations.

## Exact candidate and dispatch

The sole input is `expected_source_sha`, exactly forty lowercase hexadecimal characters. The
primary dispatches only an independently reviewed revision already on `main`. Before checkout,
the workflow requires the manual event, repository, `refs/heads/main`, and source/workflow SHAs
all matching that revision. Checkout uses the existing reviewed Action SHA/tag and disables
credentials. The collector rechecks those bindings, actual checkout HEAD and clean status before
host reads. It records run ID/attempt, workflow ref/SHA, source SHA, declared hosted Linux/X64
runner identity, and hashes of the workflow, collector and owning repository/Renovate policies.
There are no command, path, runner, repository or backend inputs.

The pre-existing runner Python bootstrap is explicit `/usr/bin/python3`, not a newly installed or
publisher-attested tool. Its observed interpreter version and identity relationship to the Python
role are reported. `contents: read` is the only workflow permission. No secrets, cache, installer,
custom image, artifact-upload Action or automatic trigger is introduced. Children receive only a
fixed clean environment; no runner credentials or GitHub context are inherited.

A workflow cannot authenticate its own changed definition. The primary must independently read
back the reviewed commit, actual workflow definition/ref/SHA, run ID/attempt, event/ref and job
result through host GitHub access. A main-branch race refuses mismatched identities; do not silently
substitute a newer revision. Issue #69 acceptance explicitly authorizes the future exact-reviewed-
main read-only dispatch within this task after normal reviewed delivery; this grants no VM,
service, cluster, native-harness or publication authority.

## Closed observation surface

Eight roles are fixed: QEMU, qemu-img, SSH, ssh-keygen, systemctl, systemd-run, busctl and Python.
Available executables require canonical root-managed ordinary ELF bytes, stable identity, safe
root-owned ancestors, no set-ID/write exposure and no file capabilities. Streaming hashes and
fixed version queries are observations, not reviewed operational pins. The ssh-keygen executable
is never run: the fixed installed `openssh-client` package query supplies only an explicitly
labelled upstream numeric prefix, not proof of that executable's version or package integrity.
Unrecognized/unsupported version output remains unknown; stderr and version banners are discarded.
Hashes do not attest publishers, the loader or shared libraries, nor issue an admitted host-tool
manifest. The package-query utility is inspected under the same bounds before its fixed read.

`/dev/kvm` permits only inspection, one owned control FD and `KVM_GET_API_VERSION`. There is no
VM-creation ioctl or guest. The manager query uses only an already-present own-UID user bus,
explicit address and `--auto-start=no`. A fixed `busctl call` first reads the bus daemon's
`org.freedesktop.DBus.NameHasOwner(s)` for the sole name `org.freedesktop.systemd1`. Its direct
reply requires exact `type: b` and a singleton `data` array containing an actual JSON boolean;
scalar/variant wrappers, numeric booleans, duplicates and malformed replies remain unknown.
Only an obtained boolean adds the optional `name_has_owner` fact. False records that name as
unowned on that bus at that instant, with scoped `missing`/`name-not-owned`, and skips all three
Gets; true continues them unchanged. An absent field, including in old records, is unobserved,
never false. Every nonzero NameHasOwner call is unknown regardless of stdout/stderr/exit value.
The following three fixed `busctl call` requests use
`org.freedesktop.DBus.Properties Get ss` for Manager.Version and the existing `init.scope`'s
Scope.ControlGroup/Scope.Delegate properties. This method-call route applies NO_AUTO_START in
reviewed upstream systemd v255; there is no generic Unit.ControlGroup property in that contract.
Only an exact JSON variant envelope with one typed string/boolean child is accepted. Legacy
`get-property` scalar replies and malformed/wrongly typed variants remain unknown.
Missing endpoints remain missing; nonzero method calls remain unknown regardless diagnostic
stderr. Unsupported queries remain unknown. There is no bus/session/login creation, manager start,
transient unit, system-manager fallback, sudo or permission/group change. A partial query retains
already obtained sanitized facts without inferring successful manager operations.

Manager.Version is an informational string with no parseable release-format guarantee. Any
bounded, correctly typed string, including an empty or distributor/VCS-specific value, produces
only `version_property: informational-string-observed-raw-omitted`. Its value, hash and length
are omitted; no numeric version/major is extracted. The manager release remains unattested.
Separately observed host executable version prefixes do not attest the manager's release.

Earlier `get-property --auto-start=no` argv assertions did not prove effective NO_AUTO_START in
systemd v255: that verb did not apply the flag. Those historical pure tests prove their recorded
argv checks only. No past service activation is inferred. The prior corrected Get route has retained failed/incomplete
observation evidence; the new name-owner read has no live result or future observation admission.

Manager failures add a bounded `diagnostics` list of fixed `{stage, reason}` records. Stages are
`deadline`, `endpoint`, `name-owner-query`, `version-query`, `cgroup-query`, `cgroup-scope`,
`cgroup-read` and `delegate-query`. Reasons distinguish missing endpoints/names, denied reads,
other OS errors, rejected endpoint/name-owner-reply/property/scope evidence, and known fixed collection
refusals. Unknown exception details remain `unknown`; exception text, stderr, UID, bus addresses
and host/environment values never enter these diagnostics. Cgroup reads that already returned a
sanitized missing/unknown result retain that generic reason and continue the original Delegate
query. At most two records are possible: that cgroup-read summary and a later Delegate failure.
Already obtained facts and existing missing/unknown statuses remain intact. These codes add no
retry, autostart, schema version or prerequisite/native admission. Name presence adds just the one
fixed query above; `invalid-name-owner-reply` and `name-not-owned` are closed reasons.

The earlier run `41107863705`, attempt 1, remains retained **incomplete-invalid** evidence with
an unknown user manager. Its absent diagnostic cannot be reconstructed from these new codes;
this correction does not complete that observation or authorize a replacement run.
The later run `41124326070`, attempt 1, remains failed/incomplete evidence. Its retained
`version-parse`/`invalid-version` diagnostic identifies the old parser branch, not the raw
Version value, its distribution, an activation event or the sole cause. All future observations
remain held until verified delivery and separate primary admission.
The corrected run `41140032241`, attempt 1, also remains incomplete-invalid: its first Get
returned nonzero (`version-query`/`query-failed`); no output/numeric exit was retained and later
reads were not reached. No name absence, raw Version, root cause, activation or nonactivation
is inferred for any of these attempts. This new read neither repairs nor authorizes their retry.

Name ownership is time-local: false can become true, and true can disappear/change before or
between Gets. Separate busctl connections do not establish one stable owner/transaction. A later
Get failure retains true plus any obtained facts and stays unknown, without rechecking or retry.
A missing name is not proof of no manager process/install, activation behavior or native readiness.

Only the collector's own job cgroup and existing own manager scope are read. Requested files are
`cgroup.controllers`, `cgroup.subtree_control`, `cpu.max`, `memory.max`, `pids.max` and
`cpuset.cpus.effective`; subtree writability is a permission indicator, never a write. No task or
process lists, unrelated cgroups or ancestor trees are traversed. Leaf CPU/memory/PID ceilings
are **not** globally effective limits. Ancestor-effective/combined limits explicitly remain
unknown, including when local controller/delegation indicators look compatible.

Provider `ImageOS`/`ImageVersion`, kernel release and architecture are allowlisted metadata.
The rolling hosted label and provider image version are not an authenticated VM-disk digest.
Host/user names, addresses, environment dumps, raw stderr, binaries and unrelated workload data
are excluded. Every future native attempt would need separate host/tool/source admission and
per-attempt retirement; this observation does not bind a later hosted instance.

## Bounds, cleanup and outcomes

The job has five minutes. Collection has sixty seconds plus at most ten seconds reserved for
owned cleanup within the original seventy-second absolute limit. At most sixteen fixed child
queries run; each has two seconds and 4 KiB combined stdout/stderr. With all inventory reads
eligible, the true path uses at most fourteen (two source Git + eight tool version/package +
one name-owner + three Get queries); false/name-query failure uses eleven and endpoint absence
ten. These consume the same original collection/cleanup/absolute ends; no new window is started. Hashing uses chunks up to 64 KiB,
128 MiB per executable and 512 MiB total. Source-policy hash inputs have a 1 MiB per-file cap.
Small fact reads are at most 4 KiB, with a 1 KiB own-cgroup locator. Canonical JSON is at most
64 KiB and the entire framed public output at most 80 KiB. These bounds do not change native
VM/lease/resource contracts or introduce another software version inventory.

Only collector-created child sessions are terminated/escalated/reaped. Owned readers and KVM/file
FDs close and empty private scratch is removed before final emission. Unexpected scratch contents,
unreaped children, uncertain close/removal, cancellation, timeout and output limits produce an
incomplete nonzero result. The original seventy-second absolute end also covers canonical framing
and every stdout write; cleanup never starts a fresh output interval. A direct FD1 writer uses
bounded chunks without Python buffering, flush, close or descriptor-flag changes, and the alarm
stays armed until output completes or the outer failure exit. Cancellation/expiry during framing
or transport aborts nonzero without a replacement frame. Reject partial output, and reject even
a complete-looking frame when the job failed. Hard kill without a final receipt leaves evidence
unavailable. Provider
VM disposal is additional containment, not a substitute for these per-run facts. No native unit,
VM, guest or cgroup retirement is claimed because none is created.

The report distinguishes `complete-compatible-indicators`, `complete-missing-unsupported`, and
`incomplete-invalid`. The first two exit zero for completed collection; incomplete results exit
nonzero. A concrete missing prerequisite can be reported while remaining native gaps stay visible.
Compatible local indicators still have an **unknown** required-native-prerequisite decision.
`native_admission` is always false; green inventory is never native readiness.

## Retained evidence

Job output has a fixed BEGIN marker, one canonical ASCII JSON line, its SHA-256 line, an END
marker and a bounded short summary. The digest addresses exactly the JSON bytes, excluding its
line terminator. No artifact uploader or persistent evidence store is assumed. Before logs expire
or are deleted, the primary retains the exact run/attempt/job metadata, raw transport-log digest,
framed record and report digest, reviewed source/workflow definitions, result and independent
review. Reject missing/duplicate/truncated frames, digest or identity mismatch and unknown cleanup;
never reconstruct absent observations. Logs are transport, not permanent custody.

Pure controls in `test_hosted_native_prerequisites.py` are discovered by the existing repository
policy runner and therefore local, PR, main, manual and release complete validation. They use
fixed fake facts/children and execute only the effect-free pre-checkout shell guard. They prove
no observed KVM, manager, QEMU, version or hosted availability. Actual Renovate tests exercise the
new workflow's native extraction, checkout SHA/tag replacement and effective existing Action/runner
policy. The primary owns formatting, final complete gate, protected exact-head delivery and the
later separately reviewed actual observation result.
