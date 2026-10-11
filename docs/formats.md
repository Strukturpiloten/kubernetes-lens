# Local Helm and Kustomize interfaces

The unpublished `formats` module accepts supplied rendered manifests through the existing strict
`ResourceSet` importer, plans exact explicit official-tool invocations, and generates new protected
in-memory Helm charts and Kustomize projects. The ordinary document/project APIs never acquire input paths or invoke a
renderer automatically, discover kubeconfig, apply resources, install/upgrade releases, fetch dependencies, publish
packages or reconstruct an original template/overlay organization.

The canonical version, command, artifact and execution-bound inventory remains
[the compatibility ledger](../schemas/capabilities/kubernetes-1.20-1.37.json). No versions or integrity
pins are duplicated here. Standalone and kubectl-embedded Kustomize profiles remain distinct; selecting
one never falls back to another. User-only `helm get manifest` and `helm get hooks` outputs are supplied
artifacts, never library subprocesses. Values alone are not complete chart input.

## Supplied input and private evidence

`import_rendered` preserves strict source evidence, caller source IDs/version, original bytes, native
identities and parser/codec findings. Helm release exports retain observed cluster-export origin;
local Helm stdout has HelmRendered origin. Hook annotations and CRDs retain independent lifecycle
findings. Kustomize transforms, generator names and all template origins retain `ProvenanceLimited`:
a rendered resource is not proof of its original chart/project association or complete semantics.

`ProjectSnapshot` accepts only caller-materialized regular file bytes under unique relative paths.
It cannot represent symlinks or acquire paths. Paths cannot escape its root, be absolute, collide with
another file/directory prefix, use backslashes or contain remote URL syntax. Snapshot limits are
cumulative and lower-configurable: at most 256 files, 16 MiB including path/provenance bytes, 1024-byte
paths and 4096 reference traversal operations. Strict parsing shares a native processing budget
across project inspection, preventing repeated references from resetting work allowances.
Helm counts the root chart and every dependency visit against that reference allowance, including
revisits through aliases. Completed shared subcharts are reusable; active recursive visits are refused.
Per-file provenance is a bounded opaque caller record; retain revision/digest/license and values or
dependency evidence there. Its assertions are not independently authenticated by a constructor.

All file bytes, paths, values, revision/digest evidence, renderer stdout/stderr, native unknown values
and generated artifacts remain protected. Debug and error presentation show fixed categories and
safe counts, never arbitrary source/argv/diagnostic strings. Raw input/project provenance requires
`ExplicitSourceAccess`; generated files and literal invocation arguments require
`ExplicitArtifactAccess`. Default native generation policies deny protected payload emission.
Explicit Include emits actual native bytes and retains native opaque/conflict findings.

## Explicit renderer seam

`ToolSelection` identifies an exact ledger profile and an explicit absolute executable.
`plan_helm` and `plan_kustomize` construct immutable `RenderRequest`s from the ledger's literal argv,
finite command classes and execution ceilings. Callers can only lower timeout/output/memory bounds.
This first source surface requires unpacked v2 chart metadata and supplied unpacked dependencies.
Helm explicitly supplies release/namespace, a local values file, exact Kubernetes patch capabilities,
repeated API versions and install/upgrade template context. Include-CRDs/client-only rendering is
mandatory. Pre-materialized unpacked chart dependencies are required; no repository/OCI download is
performed. Offline lookup completeness, release hook behavior and arbitrary random/time template
determinism remain explicit findings even when an executor reports native success.

Kustomize inspection follows bounded local resources/bases, strategic/JSON patches, generator file
and env inputs and configuration references. Missing/escaping/remote references fail closed. Shared
bases are permitted; cycles are refused. Generators, transformers, Helm inflation, plugins,
decryption and unrecognized extension keys are refused rather than fetched or executed. This first
finite surface conservatively rejects additional syntax; it does not claim exhaustive Kustomize
configuration validation. The selected official tool remains responsible for native syntax errors.

`execute_with` explicitly validates native render/lint/local-package replies; `render_with` also
imports manifest stdout. Both require a caller-selected `OfflineRenderer`.
The trait is an integration seam, **not a delivered process sandbox**. Its implementation must verify
actual official images/versions, immutable supplied-file staging, the explicitly selected deadline contract,
aggregate memory/output limits, network/IPC isolation, controlled environment, absent ambient
credentials/plugins, sole native reap and complete cleanup. Zero renderer exit without those
conditions is failure. KubernetesLens validates reply profile/status/deadline/output sizes and then
strictly imports native stdout; it never treats arbitrary stdout as an authorization receipt.
Successful and failed native replies retain protected stdout/stderr, with explicit access for
private debugging; ordinary failure reports expose only fixed codes and safe native findings.

## Opt-in supervised system broker

On Linux, the `supervised-renderer` feature adds `SupervisedRenderer`, an implementation of the
explicit `OfflineRenderer` seam. `SupervisedRenderer::new` requires `BrokerSelection` and
`RuntimeSelection`; it installs nothing and cannot invoke sudo, start its own broker or fall back
to a user manager. An unavailable exact historical profile remains unavailable even when a newer
renderer is registered. Explicit registry entries bind profile, canonical executable, executable
SHA-256 and protected canonical provenance. Both client and independently provisioned root registry
must agree exactly; caller provenance alone never authenticates an official tool.

A maintainer-provisioned root system service runs `kubernetes-lens-renderer-helper broker` with
explicit configuration and socket paths. No provisioning command is run by the library. The broker
requires actual administrative memory at most 64 MiB, zero swap and at most sixteen tasks. Its socket
and all immutable ancestors must be root owned and unwritable by ordinary users. Helper, gate,
manager and native control-tool digests must match the explicit root configuration. Configure the
helper under a system-visible executable location, not a home directory. Journal and transport roots
are private mode 0700; the root-owned staging root is mode 0711 under search-permitted immutable
ancestors, with each supplied input directory accessible only to the dedicated leased UID and root.

The versioned protocol authenticates peer PID/start time, caller UID, nonce, boot, exact request hash
and the original absolute monotonic deadline. Bounded metadata is separate from binary source frames;
per-file lengths and hashes are independently checked. Malformed, oversized, truncated or
misbound pre-admission connections are closed individually, before any owned administrative mutation;
the broker continues accepting callers. Failure to read the broker's monotonic clock or boot identity
propagates a fixed systemic error instead of refusing callers silently. Owned lifecycle and quarantine
failures retain their separate failure handling. Before accepting file bodies, the broker
creates durable nonce ownership and an execution slice, then launches and binds its controller unit
and current PID inside that slice. Snapshot reception, staging, controller collection, supervisor,
Bubblewrap and renderer share the caller-lowered aggregate memory/process ceilings. Swap is always
zero. Administrative broker, lease and watchdog units have separate finite limits. Only owned
transient slice properties can change; no user manager, user@ unit or persistent/foreign cgroup is
modified. Actual kernel ceilings are read back before the gate permit and final exec release.

The controller independently reconstructs the closed plan using native project inspection and
requires exact literal argv equality. It stages only the supplied regular files, mounts them read
only, isolates network/IPC/PID and other namespaces, and replaces ambient environment with fixed
private scratch/configuration locations. The initial bounded scratch, gate and exact held static
renderer have an independently checked mount/proc/FD/image closure. The root permit, single owning
ptrace thread and real-parent reap are separate evidence; a gate acknowledgement cannot replace
exec-stop verification. The first implementation admits the reviewed static x86_64 ELF closure only,
within its 64 MiB image ceiling. Other image/platform layouts fail closed.

`SupervisedRenderer::new` and `OfflineRenderer::execute` remain source-compatible.
Their legacy v1 behavior starts an execution timeout at the call, caps setup, native
execution, drain and packaging with it, and permits up to ten additional seconds for
cleanup/final transport. It does not propagate an earlier caller total deadline or
cancellation token. Select v2 explicitly for that contract:

- Construct `RendererOperationControl` once with the caller's absolute `Instant` end
  and a cloneable `RendererCancellationToken`; call `execute_with_control`.
- V2 converts the remaining caller end conservatively to one boot-bound monotonic
  `D_total`. It reserves ten seconds **inside** that end and sets
  `D_exec <= min(D_total - 10s, admission_time + request_timeout)`.
  Expired, insufficient, cancelled, invalid boot or malformed contexts refuse before
  owned work. Queue/setup delay consumes the original allowance; no stage restarts it.
- Header, immutable descriptor and durable journal bind the version, nonce, boot and
  both ends. V1 omits the added field; an old broker rejects v2 before owned work.
  No schema downgrade, new connection or nonce/deadline replacement is attempted.
- Cancelling a selected operation closes only that authenticated client socket's
  write half. Chunked I/O checks the token and end; the existing read half waits for
  the exact nonce/request/image-bound cleanup result until `D_total`. Cancellation
  remains a failure even when native output or an earlier receipt already exists.

The controller sends a private nonce/Bubblewrap/boot/both-ends-bound cancellation
message on its existing authenticated supervisor control channel. The supervisor
kills only its existing **unreaped owned `Child`**, polls its real wait status under
the original cleanup ceiling and sends the same bound `NativeWait` acknowledgement.
The owning tracer can consume terminal stops before the real-parent acknowledgement;
a trace terminal notice or gate acknowledgement never substitutes for that wait.
Only then does the controller terminate whole work and audit cgroup emptiness,
UID census and held PID death. Missing acknowledgement/supervisor permits bounded
whole-work fallback, retaining unproved cleanup/quarantine and the identity lease.
The broker retires its owned controller and slice before a reply; late caller
cancellation cannot turn a completed native result into success.

All v2 controller/watchdog/receipt/tracer and same-boot recovery paths retain
`D_total` as their ceiling. Cleanup chooses one shorter at-most-ten-second window
without renewal, with time reserved inside it for owned stops/retirement. Service
runtime guards are fixed at transient creation with one second reserved for activation
lag, 250ms runtime timer accuracy, four STOP/FINAL TERM/KILL waits of one second
plus 250ms timer accuracy each, and one microsecond for the activation witness's
rounding. Exact unit/invocation, activation timestamp, unchanged guard, zero runtime
randomization and the admitted stop policy (control-group killing, SIGKILL enabled,
one-second stop timeout, terminate failure mode, no stop/stop-post commands) must
fit the original operational end before native permission. Late activation
refuses and cleans the same cell. Active RuntimeMax mutation is unsupported on the
reviewed [systemd v261.3 transient-property contract](https://github.com/systemd/systemd/blob/v261.3/src/core/dbus-service.c#L912)
and is never used to renew a timer. This upstream source was consulted only for
behavioral facts; no implementation was copied or mechanically translated.
V2 recovery uses the minimum of the original total and any persisted shorter cleanup
end, including a complete interrupted `.pending` write. Recovery inspects that
root-private, bounded record without writes before choosing the stop deadline.
The complete pending record must retain the same ownership, boot, original ends,
stage and existing UID. A shorter pending deadline is enforced before any stop,
including exact-expiry refusal. Promotion/retries cannot widen an existing cleanup
end; a widening write remains unpromoted. Malformed, partial or foreign pending
bytes grant no authority: only the validated live record can permit a bounded
exact-owned fallback, then recovery fails with pending evidence retained. Recovery
refuses exact expiry or different-boot context without minting a new budget.
Same-boot orphan fallback lacks an authenticated native-wait receipt and retains
quarantine and the identity lease after group/UID audits. Legacy v1 reboot
reconciliation retains its explicitly documented legacy boundary. There is no public
raw PID/nonce/unit cancellation or live-recovery endpoint.

Current systemd documentation was checked through Context7 on 2026-10-11:
[transient settings](https://github.com/systemd/systemd/blob/main/docs/TRANSIENT-SETTINGS.md)
and [control-group interface](https://github.com/systemd/systemd/blob/main/docs/CONTROL_GROUP_INTERFACE.md).
RuntimeMax is activation-relative. Fixed creation guards, exact activation/readback
admission and timer arithmetic are supplementary source/model contracts; actual
installed-manager guard expiry, kernel containment,
real-parent reap and interruption/recovery evidence still require native acceptance.
The [reviewed systemd 261.3 stop states](https://github.com/systemd/systemd/blob/3255daee1572366b74fe92f002a3d60ecbb27103/src/core/service.c#L2554)
come from official upstream source corresponding to the installed version; downstream
package behavior is not established by that source review.
Timer arithmetic cannot bound scheduler stalls or establish task death/reap: those
remain independently observed proof, and failure retains quarantine.

Failure preserves bounded protected stdout/stderr and a fixed `FailureCause`. Missing cleanup proof
retains quarantine/lease evidence; no caller boolean or callback can assert cleanup. The persistent
administrative transport intent also bounds outstanding/quarantined requests. Interrupted snapshot
staging or unknown administrative remnants currently require manual, independently verified recovery;
the inherited cold-boot/recovery checks refuse unknown state rather than deleting unproven files.

`RendererOutput::package` returns a protected `PackagedChart` only for local Helm packaging. The
controller accepts exactly the expected regular chart/version `.tgz`, rejects links, directories,
extra/missing files and overflow, and collects through a held private scratch directory before
retirement. Package bytes and stdout together consume the existing stdout allowance. Other command
classes reject package artifacts. Package name and bytes require `ExplicitArtifactAccess`; local
packaging authorizes neither publication nor application.

The implementation reuses the repository-owned reviewed private route; it copies no official tool
source. Focused selection/protocol/packaging tests and compile/Clippy results are code evidence only.
Actual registered official-tool runs, hostile runtime cases, independent exact-binary review and all
ledger conformance cells remain pending until the primary's explicit runtime acceptance. No native
version support, isolation conformance or generally available backend is claimed from source tests.

## New generated projects

`generate_chart` first calls existing native generation under explicit target/privacy/opaque and
collection policies. It creates Chart.yaml, finite values.yaml/schema, static CRDs under crds/ and
native resources under templates/. CRDs are not templated. Hooks are rejected by default or retained
only by explicit `PreserveWithFinding`; they are never executed. No original chart dependency,
conditional branch, template code or formatting is reconstructed.

The values API is a finite subset of the ledger's v1 families: existing supplied replica counts,
existing named ordinary-container image strings, and existing CPU/memory/ephemeral-storage request
or limit quantities on delivered workload roots. At most 64 uniquely named fields can be selected.
Admission checks the complete group/version/kind and the registered typed workload; custom resources
named Pod or Deployment remain static data and cannot qualify for values or overlay fields.
Selected resource IDs are associated with trees by the same native projection that emits each root;
input document positions never substitute for that association. This also covers flattened Lists and
identically named resources in different namespaces. Defaults are exact supplied native values;
absence/null/defaults are not invented. Other fields,
including unknown protected descendants, remain static data. Every static scalar/key is serialized
as JSON and then quoted as a Go string argument to `print`. Thus supplied `{{ ... }}` bytes cannot
become template directives. Selected values use `toJson`, not `tpl` or raw template code. The generated
schema rejects extra keys and bounds replicas/string sizes. It does not prove server-side admission
of arbitrary changed caller values; official render/reimport/native target validation remains needed.

`generate_kustomize` creates a reusable base and only caller-requested named overlays. Overlay
variations select the same finite existing workload fields with explicit private replacements.
Each candidate is edited and validated through existing native generation before a minimal strategic
merge patch is produced. Container patches retain the native name key and unselected base members.
Initial native generation, generated-byte reparse, field edits, encoding and every overlay validation
share one cumulative processing budget. Source parser ceilings and caller-lowered processing ceilings
remain in force throughout; exhausting the operation cannot produce a successful artifact.
No source overlay layout is inferred. Output uses only the restricted common base/strategic-patch
syntax; each declared embedded/standalone profile still requires its own official build/reimport
conformance evidence. Lists require explicit native Flatten policy, preserving its own removal findings.

Artifact trees never write files or execute generated commands. They can plan generated chart strict
lint, local packaging, template rendering, and generated Kustomize base/overlay builds using declared
profiles. Packaging plans permit only an executor-owned local destination, never publication.
Private artifacts require explicit access before a caller can write them.

## Local validation and remaining acceptance

`cargo test --locked --test formats` exercises imports, native errors, source/provenance privacy,
profile/catalogue arguments, missing/remote/plugin/cyclic references, cumulative limits, explicit
mock execution failures, literal-template escaping, finite values and deterministic generated
projects with explicit native overlay edits. These focused cases are not official-tool conformance.
Primary owns owning ADR/API documentation integration, the complete repository gate and all Git or
GitHub writes. Tool oracle fixtures, official lint/build/package/reimport outcomes and independently
expected native resources remain pending under issues #2/#3/#4/#8/#14/#15.

### Bounded local v1beta1 vars

Kustomization `vars` declarations admit bounded variable names, local `objref` tuples containing
`apiVersion`, `kind` and `name`, and an optional string `fieldref.fieldpath` (default `metadata.name`).
The original project bytes remain supplied evidence; the official selected renderer performs string
substitution. No plugin, remote reference, Helm expansion or decryption is enabled by this admission.
Kustomize documents `vars` as deprecated but retained in the v1beta1 API; v1 declarations are refused.
Documentation source: upstream Kustomize `vars` reference, retrieved through Context7 on 2026-10-10.

The focused vars regression retains the unchanged 657-byte CNPG manager kustomization at
revision `2a35abb4628f209d149825ef3c38011e0701ff2f`, source path
`source/config/manager/kustomization.yaml`, SHA-256
`28af10f1f0cb4d7472b045c7647414ef9dad020599c2d5b7c6eb6befb2848908`.
This Apache-2.0 redistributable configuration fixture is used only for declaration admission with
local native payload placeholders; no oracle command is run by that test. Full unchanged source
rendering/substitution evidence remains independently required under the frozen compatibility gate.

## Native naming through generated artifacts

Renderer artifact generation uses the same target-selected native naming checks and cumulative
processing session as ordinary generation. Valid broader RBAC spellings remain exact private data;
undeclared GVK naming retains `NativeNamingUnverified` findings instead of borrowing a built-in
name grammar. Neither case bypasses protected-output authorization. Explicit inclusion preserves
original names in chart literals and Kustomize bases; raw artifact access remains separately explicit.
An undeclared workload-shaped document still cannot become a typed values parameter or variation.
The source-only bridge regression covers these policies without invoking either official renderer.
