# Native fixture sources

[Official source receipt](official/inventory.json) freezes project-provided artifacts for
KubernetesLens #14. It contains **160 unique assets**, **625 chart members**, **75 observed plain
documents**, **nine prospective renderer entrypoints**, **four chart dependency edges**, and
**73 Kustomize edges**. The research receipt had 149 observations; an identical repeated Grafana
Operator README observation is retained as metadata and materialized once. Seven supplemental
official files resolve the missing selected CR-source cases; five additional pinned
license/attribution/source companions retain the selected transitive terms. These companions
are not renderer inputs; they do not prove native acceptance.

This is source preparation only. Native parsing, rendering, generation/reparse, field classification,
API validation and runtime evidence are pending. A successful materialization never reports native
conformance. The [independent expectations](official/expected.json) and
[public value plans](official/public-values.json) are unexecuted preparation for those tests.

## Offline preparation

Use Python 3.11 or newer. Supply a previously acquired anonymous-public cache laid out according
to each receipt asset's `path`. Do not use authenticated user caches or private source content.
The destination must be absent, outside this checkout, with an existing trusted parent directory.

```sh
python3 scripts/fixtures/materialize.py --cache /path/to/public-cache --destination /tmp/official-fixtures
python3 -m unittest discover -s scripts/fixtures -p 'test_*.py'
```

The tool reads the fixed receipt and verifies its companion SHA-256 before reading source files.
It checks every asset's bytes/hash, bounded safe chart members, license evidence and complete
recorded local dependency graphs. Cache links, traversal, collisions, missing assets/dependencies,
unexpected members, oversized input and receipts claiming native success fail. Chart extraction
uses the original archives rather than trusting already extracted cache files. No dependencies
are downloaded, no source script is executed, no renderer is invoked, and no cluster is contacted.
Supplemental CR inputs carry verified Git-blob identities, complete document byte/line/hash slices,
and exact supplied CRD-manifest slice witnesses. Those witnesses provide source linkage only.
The complete private source tree appears only after preparation succeeds; source bytes and
exception paths are absent from ordinary diagnostics. Use a trusted parent directory with no
concurrent destination writers.

No upstream archives, manifests, documentation snippets or implementations are vendored here.
License texts remain pinned cache assets and are retained in the materialized tree. The private
`fixture-notices.json` retains companion asset IDs, paths, immutable source URLs/revisions, byte
counts, SHA-256 digests and license identities alongside the covered-path obligations. Detached
companion correspondence does not require the source cache or tracked inventory. The generated
notice excludes unselected cache metadata and source contents; its file count and bytes count
against the preparation budgets.

`notice_integration_date` records when license notices were integrated/corrected. For Grafana,
2026-10-10 is that correction date; the original extraction date is not independently established
and remains null with an explicit status. The notice describes the existing indentation-only
transformation without dating its execution. Original source and derived bytes remain unchanged.

The current Cargo package include allowlist excludes the official corpus under `fixtures/official/**`,
its preparation scripts and corpus documentation. Preserve that boundary and verify the actual
package list after integration. AGPL and ambiguous-license material must
not enter the native library package. Hash verification is content integrity evidence, not upstream
signature/attestation verification or redistribution approval.

See [the corpus contract](../docs/fixtures/official-corpus.md) for scope, provenance, version limits,
licensing gaps and remaining acceptance work. The repository policy runner includes all 97
preparation/admission tests through its required fixture discovery hook. Both the Cargo policy
harness and documentation phase use that runner; missing modules/witness tests or failures block
complete validation. Run `python3 scripts/test-repository-policy.py` for the integrated Python suite.
The complete repository gate remains required, and these Python tests provide preparation evidence
only; official corpus native/renderer/API/runtime acceptance remains pending.

## Renderer admission expectations

Kustomize receipt entries distinguish a bounded `supplied_root` from a
`relative_entrypoint`. CloudNativePG supplies `cloudnativepg/source/config` and selects
`default`; Grafana Operator supplies `grafana-operator/source/deploy/kustomize` and selects
one named overlay. Sibling directory bases may leave the entrypoint directory while staying
inside the supplied root. Every reached dependency must stay in that root; direct file loads
must also stay below their own Kustomization directory. `LoadRestrictionsNone` is forbidden.
These are source-graph checks, not proof that any producer accepts the graph.

Run the static admission expectation check without invoking any renderer:

```sh
python3 scripts/fixtures/admission.py
```

The tracked expectation plan freezes the three researched closures and 36 `hostUsers`
version/gate/value cases. Grafana Operator's chart condition emits this field at target
1.33 or later, but `hostUsers` remains outside the frozen PodSpec whitelist, including
when the gate is enabled or stable and when its value is `true`. Actual rendered input
must retain the source field and produce a structured `unadmitted-field` finding.
Desired output is denied by default. Source-preserving output requires an explicit
`preserve-source-with-findings` policy; that selection neither admits a typed field nor
bypasses protected-output permissions or an invalid TargetProfile. No field is silently
removed to make a chart pass. Producer execution, native diagnostics/output and API
acceptance remain pending.
