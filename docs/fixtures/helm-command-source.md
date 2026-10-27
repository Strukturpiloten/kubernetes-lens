# Helm source fixture for frozen command cells

The [integrity companion](../evidence/helm-command-fixture-source-v1.json) binds nine original,
repository-owned MPL-2.0 input files under `fixtures/conformance/helm-local-template-source/`.
They cover the existing install/upgrade positive source cells for `helm-3.22.0` and `helm-4.3.0`.
This command-contract fixture supplements the official-project corpus. It replaces no vendor chart,
renderer cell, graph scenario, generated-artifact oracle or full CloudNativePG obligation.
The ledger and every tool/native/API/runtime state remain unchanged and pending.

## Authored oracle and chart closure

`expected.json` was written and frozen before the templates, using literal intended fields and
findings rather than renderer or product output. Its eight rows cover both exact Kubernetes patches
for all four cells. Compare four GVK/name/namespace identities and their typed JSON-pointer fields;
YAML layout and document order are intentionally outside this oracle.

Seven chart files define Deployment/Service templates, a hook Job, a static Widget CRD, v2 chart
metadata, defaults and a closed values schema. The other two files are external public values and
independent expectations. Both explicit API capability strings are required. Kubernetes `1.20.15`
and `1.37.0` select distinct version-band annotations. Install and upgrade select two and three
replicas and the corresponding `pre-install`/`pre-upgrade` hook annotation. Local `lookup` expects an
empty result but must retain `offline-lookup-incomplete`; that result proves nothing about a cluster.

Provenance, hook and CRD lifecycle findings stay explicit. Planning also retains the conservative
`nondeterministic-rendering` finding: this preparation has not established repeated-render equality.
Native finding results are pending, never an assumed empty set. The `example.invalid` images are
inert fixture text, with no pull, execution, deployment or operational version pin.

## Future input correspondence

A separately authorized run must use the ledger's exact local `helm template` contract and selected
profile: release `fixture`, namespace `fixture-space`, chart `chart`, values `public-values.json`,
one exact target patch, both repeated `--api-versions` strings, `--include-crds` and
`--dry-run=client`. Upgrade adds `--is-upgrade`. These are input descriptions, not permission to run
a tool. The original broker, deadline, wait, input-witness, privacy and resource bounds still apply.
No server dry-run, dependency fetch, plugin, post-renderer, ambient kubeconfig, network or fallback
is added. The chart has no dependencies and the CRD remains untemplated under `crds/`.

Public fixture values still follow the product's protected-by-default rules. Only a values-file
path belongs in argv; reports expose fixed codes/counts. Output bytes require explicit access.
Validation summaries return neither payloads nor a command, renderer capability or native permission.

## Pure controls and integration

Run `python3.11 -B -m unittest discover -s scripts/fixtures -p test_admission.py` for bounded
source-only feedback. The existing fixture test owner checks exact membership/digests, unsafe and
colliding paths, caller repinning, types, protected handling, phases, profiles, modes, fixture IDs
and explicit capabilities. The repository reader rejects links and special files; it assumes a
trusted checkout without concurrent writers and does not replace immutable broker staging.
No Helm renderer, product parser, Rust compiler or native runtime executes in these controls.
One bounded Python subprocess loads copied source in a private temporary directory to verify
cache-free imports and unchanged caller flags; it invokes no external tools.

Existing policy discovery already includes this test owner. No workflow, catalogue, dependency,
installer or operational pin changes are needed. These new development-only paths are outside the
current Cargo include allowlist; actual package-list verification and the complete gate remain
primary integration work. Integrity success is not renderer/native acceptance.

## Documentation provenance

Context7 supplied current official guidance on 2026-10-27 for
[chart metadata](https://helm.sh/docs/topics/charts/),
[release and capability objects](https://helm.sh/docs/chart_template_guide/builtin_objects/),
[lookup](https://helm.sh/docs/chart_template_guide/functions_and_pipelines/),
[hook annotations](https://helm.sh/docs/topics/charts_hooks/) and
[template flags](https://helm.sh/docs/helm/helm_template/).
The companion retains these references. Current syntax guidance does not advance or qualify the
frozen historical profiles. No upstream implementation or vendor chart was copied or translated;
no tool, chart dependency or source archive was downloaded or executed.
