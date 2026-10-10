# Official Kubernetes source corpus

This early KubernetesLens #14 scaffold supplies an immutable portable source receipt, controlled
offline materialization, and independent expectation/public-value plans. It does not complete #14.
No official chart/project has passed KubernetesLens import, export, renderer or API conformance.
Kubernetes 1.20–1.37 remains the frozen compatibility specification from #8, not a supported-version
claim made by these fixtures.

## Sources and available formats

The machine [receipt](../../fixtures/official/inventory.json) is authoritative for immutable
revisions, URLs, application/chart metadata, source paths, SHA-256 and byte sizes, upstream license
records, chart dependency versions, Kustomize graph edges and renderer entrypoints. Its companion
digest freezes the entire dependency/provenance graph. Historical fixture revisions are evidence
anchors and do not auto-advance as operational tool dependencies. No software or tool pin is added.

Grafana's derived YAML uses **one-based inclusive payload lines 96–177** of its pinned Markdown,
with exactly three common indentation spaces removed and original line endings preserved. The
closing fence is line 178 and is excluded. The receipt retains the research observation's previous
end value 178 as a corrected provenance record; upstream and derived bytes/hashes remain unchanged.
Materialization reconstructs the declared source slice and verifies its derived hash before use.

| Project            | Official available input                                                                         | Boundary                                                                                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Immich             | `immich-app/immich-charts` Helm and official local examples                                      | Record backend, database-operator and storage prerequisites; references do not prove operator-owned resources exist.                                               |
| Forgejo            | `code.forgejo.org/forgejo-helm/forgejo-helm` Helm                                                | Preserve SSH/HTTP, configuration, database and storage relationships. The selected chart removed PostgreSQL/Valkey subcharts; the draft selects SQLite explicitly. |
| CloudNativePG      | Official operator/cluster charts, operator release YAML, `config/default` Kustomize, CR examples | Operator definitions and selected CRs have separate native acceptance; schema success does not prove reconciliation.                                               |
| Grafana standalone | Official documentation-provided YAML fence                                                       | Keep the Markdown source and exact extraction lines; only common list indentation was removed. `grafana/grafana:latest` in that sample is mutable image evidence.  |
| Grafana Operator   | Official release YAML, Helm, Kustomize overlays and CR examples                                  | Preserve CRD registration and Secret/config references; admit renderer profiles independently.                                                                     |
| Nextcloud AIO      | Official AIO Helm chart and generator/readme source records                                      | Review generated chart limitations and embedded NetworkPolicy attribution. UI, backup and TLS behavior differ from Docker AIO.                                     |

Helm-only projects do not gain fabricated official raw/Kustomize variants. The ordinary community
Grafana chart, community `nextcloud/helm`, Supabase Kubernetes packages, Podinfo/tutorials and
generated BoxFerry output are excluded. Argo CD, Flux and OpenShift are outside this corpus.
Application migration/user-data/application behavior belong to future BoxFerry #444, not a native
library dependency.

## Integrity and execution boundary

The stdlib-only [materializer](../../scripts/fixtures/materialize.py) admits the checked-in receipt,
not arbitrary live URLs or ambient credentials. Acquire sources separately by reviewed public GETs
and retain original bytes under receipt-relative paths. Acquiring a file from its URL is insufficient:
its fixed byte size and SHA-256 must match. The tool has no networking, credential discovery,
subprocess execution, environment-derived tool selection or Kubernetes runtime access.

Bounds are explicit: 4 MiB receipt, 8 MiB per asset/member, 32 MiB aggregate source/member bytes,
2,048 files, 16 MiB expanded tar bytes and 2,048 tar entries per archive. Symlinks/hardlinks,
nonregular source files, traversal/absolute/aliased paths, duplicate/unrecorded/missing archive
members, file/directory collisions and incomplete recorded graphs fail. OCI chart layers are checked
against the retained immutable manifest. The receipt distinguishes observed registry response
digests from independently computed content hashes; missing header evidence is not fabricated.

All declared chart dependencies are already bundled and hash-recorded. All Kustomize references
are local, remain within their owning project's source tree and resolve to admitted receipt files
or Kustomization directories. This proves closure of the reviewed source graph, not correctness
of a future Helm/Kustomize invocation. The frozen graph must later be compared with native parsing
of these inputs; this preparation script intentionally does not implement a YAML or Kubernetes parser.

Seven supplemental files at the existing CNPG/Grafana Operator revisions supply Pooler, Backup,
ScheduledBackup and GrafanaDatasource cases. Each raw file is checked against both SHA-256 and
its pinned Git blob identity (SHA-1 is Git object evidence, not the security checksum). Every CR
document has a complete byte-slice hash and one-based inclusive line range. Byte offsets are
zero-based half-open intervals. Each new selected CR document also has one exact supplied CRD
manifest/document witness. The materializer recomputes these slice hashes and boundaries; recorded
CRD scope, served/storage flags and schema presence are source observations, not KubernetesLens
schema/API validation or proof of installed controllers. All seven selected kinds now have official
source inputs; native acceptance remains pending.

Materialized files are private (0600), directories are private (0700), and the tool refuses a
destination within the repository or overlapping the cache. Failures leave no partial destination
or usable preparation receipt. Diagnostics report fixed codes/counts, not source values, paths or
exception fragments. An existing destination is preserved. The parent directory is caller-selected
and must be trusted, with no concurrent destination writers. Source-cache files are opened through
directory descriptors without following links. Privileged writers changing mount topology are
outside this local preparation boundary.

## Bounded renderer admission plan

The [tracked expectations](../../fixtures/official/expected.json) now include static
renderer admission contracts checked by
[the expectation checker](../../scripts/fixtures/admission.py). These are derived plans,
not renderer execution receipts. They do not replace the frozen canonical tool profiles,
command catalogue, TargetProfile contract or evidence cells.

Each Kustomize entry has an explicit portable supplied root and a relative entrypoint:

| Candidate         | Supplied root                              | Relative entrypoint         | Closure files / edges |
| ----------------- | ------------------------------------------ | --------------------------- | --------------------- |
| CNPG default      | `cloudnativepg/source/config`              | `default`                   | 30 / 29               |
| Grafana cluster   | `grafana-operator/source/deploy/kustomize` | `overlays/cluster_scoped`   | 11 / 10               |
| Grafana namespace | `grafana-operator/source/deploy/kustomize` | `overlays/namespace_scoped` | 11 / 10               |

The supplied root bounds every transitive load, including sibling bases reached from
`config/default`. It is distinct from each Kustomization directory's strict loader root:
directory bases may be siblings inside the supplied root, while direct file loads must
stay below their own loader root. Missing/aliased roots, mismatched relative entrypoints,
second-hop escapes, cycles and unsafe loader overrides fail preparation. Strict loader
execution remains pending. The upstream Grafana recommendation to disable restrictions
is source evidence only; never use `LoadRestrictionsNone` to repair a failed candidate.
If strict rendering later fails, retain a structured failure or review separately derived
input and provenance instead of changing the original supplied source.

Grafana Operator chart 5.25.0's pinned Deployment template lines 40–42 conditionally emits
`/spec/template/spec/hostUsers` at target `>=1.33-0`. Its supplied public plan explicitly
selects `hostUsers: true` at 1.37.0. This source condition and the documented
`UserNamespacesSupport` defaults are separate from frozen field admission: the field is
unadmitted for both boolean values at every target in this fixture plan. The expectation
matrix covers 1.32–1.37, default/enabled/disabled settings and both values. Every case uses
an explicitly selected setting for every frozen gate, with only this gate varied;
documentation defaults are not observed cluster settings. Explicit toggles at the stable
1.36 boundary are invalid target profiles and cannot be rescued by preservation.

At targets 1.33–1.37 with a valid profile, actual producer output containing the field must
retain source evidence and yield a structured `unadmitted-field` diagnostic with identity,
source location, field pointer, target profile, actionable remediation and private evidence
reference. Default desired output is denied. A caller may explicitly select
`preserve-source-with-findings` for source-preserving output, retaining the field and
finding without typed admission. Protected-value output authorization is still required
separately. Silently dropping the field, inferring admission from an enabled/stable gate,
or relabeling a producer version check as native support is forbidden.

The checker only validates these authored expectations against the frozen whitelist and
gate source records. Future real tests must observe two bounded renders per exact
producer/profile, native import/findings, denied default generation, selected
preservation/reparse and matching API evidence. Original source bytes, hashes, provenance,
license evidence and redistribution classifications remain unchanged.

## License and package evidence

Per-project license text assets are mandatory and verified with the rest of the cache. Preserve
upstream copyright, LICENSE/NOTICE and bundled dependency attribution when sources are used.
The receipt records missing archive-root/dependency license files; an omission is not permission.

Grafana's exact pinned `LICENSING.md` applies an AGPL-3.0-only default to the selected
installation Markdown and derived YAML. No evidenced separate documentation/sample exception
covers those paths. The full AGPL license, original Markdown, attribution, exact extraction
source/hash and dated notice-integration correction are retained. Immich and Nextcloud AIO have AGPLv3
repository evidence; an or-later grant is not inferred from the stock license appendix.

Forgejo's bundled common 2.41.0 source directly carries Apache-2.0 SPDX and Broadcom notices.
All 27 common files match the separately authenticated OCI chart layer. The receipt retains the
exact OCI manifest/config/layer identities and member linkage. Its separately pinned full
Apache/Broadcom license companion comes from a Bitnami revision whose common chart is 2.31.10:
that is a terms witness, not the selected 2.41.0 implementation source. The distributor's exact
implementation-source commit remains unresolved. The original MIT Forgejo chart license and
common copyright/SPDX/README trademark/disclaimer notices remain distinct and unchanged.

The AIO NetworkPolicy and generator retain a recipe-owner URL at mutable master. Three pinned
recipe companions retain the complete Apache license, Ahmet Alp Balkan attribution, Google 2017
copyright/disclaimer and current source correspondence. The immutable recipe witness does not
identify the historical revision copied by AIO. AIO repository AGPL terms stay alongside those
third-party Apache obligations; the whole AIO chart is not relabeled Apache.

Five additional companions increase the receipt from 155 to 160 unique assets; all original 155
source hashes and 625 chart members remain unchanged. Preparation requires the applicable
transitive companions even when every project root LICENSE is present. Missing, mismatched,
inapplicable or wrongly attributed companions refuse preparation. A private generated
`fixture-notices.json` records covered paths, retained contributors/licenses and original-source
correspondence. Its `companion_asset_evidence` embeds every required companion's asset ID,
project-relative path, byte count, SHA-256, immutable source URL/revision and license identity
(role, expression, repository, source path and revision). Companion correspondence survives
separation from the tracked inventory and source cache; immutable witnesses still do not establish
an unrecorded historical implementation/extraction revision. Only selected provenance fields are
serialized, without cache paths, unselected metadata or source contents. The notice remains private
(0600 inside a 0700 root), and its added file and bytes count against all preparation budgets.

`notice_integration_date` identifies notice integration/correction rather than upstream source
modification or historic extraction. Grafana's 2026-10-10 notice correction followed the existing
2026-10-09 preparation receipt. Its `original_extraction_date` is null and
`original_extraction_date_status` is `not-independently-established`. The notice describes the
previous indentation-only transformation and unchanged original/derived bytes; it does not infer
an extraction date from either receipt. Ambiguous `modification_date` metadata, invented extraction
dates or notice wording that claims a dated extraction refuse preparation.

The notice is one additional preparation metadata file, not a new upstream asset or Kubernetes
input. Root and transitive license copies accompany source files.
The full corpus remains fetch-only, isolated fixture-only and Cargo package-excluded. Publication,
redistribution approval and legal interpretation remain unestablished; no upstream signature,
cosign or provenance attestation was verified.

Only metadata, authored plans, preparation scripts and documentation are checked in. Upstream
source/chart/archive bytes remain in the explicit public cache and the disposable destination.
The current Cargo include allowlist excludes the entire corpus; preserve and check it at package
validation, especially before any future redistribution. This scaffold changes no shared manifest,
lockfile, Renovate configuration, workflow or product API.

## Independent acceptance still required

[Expected values](../../fixtures/official/expected.json) are source-reviewed plans independent of
KubernetesLens-generated output. They specify representative selectors, named ports, PVC mounts,
RBAC/webhook/Secret references and CRD registrations. Explicit default namespace `grafana` is
required for the credential sample; do not silently rewrite its unnamespaced Grafana. Public value
plans use named markers only and remain unrendered. Those credentials remain protected for ordinary
presentation even though their test values are public. Forgejo random/lookup branches and every
Nextcloud TODO/optional protected field require exact-profile review before admission.

The supplemental expectation groups are independent source sets. The complete Pooler sample
supplies its referenced Cluster; its separate auth variant omits both the referenced Cluster and
Secret and repeats the same Pooler identity. Do not union those cases blindly. Backup and
ScheduledBackup refer to unsupplied `Cluster/pg-backup`; retain expected unresolved evidence and
authored absence of unspecified backend/default fields. Grafana datasource URLs describe external
backends, not inferred Kubernetes Service identities. The PostgreSQL datasource explicitly uses
namespace `grafana`; apply that default to its namespace-absent companion source without changing
the datasource. Its `secureJsonData/password` is retained only in private source bytes: expectation
metadata identifies the protected path but contains no password payload. No source or CRD witness
proves callbacks, datasource provisioning, backend availability, backup completion or reconciliation.

Modern application releases must remain distinct from historical 1.20 floor fixtures. The selected
CNPG charts declare Kubernetes >=1.29 while operator runtime documentation lists 1.34–1.36.
Other minimums/profile details not established by source research remain unknown. A chart's
acceptance gate is not the operator's runtime support policy. Do not relabel modern releases as
1.20 evidence or infer feature-gate/image/storage prerequisites from successful parsing.

Continuation after #1, the native cohorts, and #3/#4 must:

- Execute native assertions for the supplied CNPG Cluster, Pooler, Backup and ScheduledBackup and
  Grafana/GrafanaDashboard/GrafanaDatasource samples, including missing/ambiguous CRD, schema and
  reference cases under #13. Their presence and slice witnesses do not prove native acceptance.
- Independently assert every admitted resource/value/reference and classify unsupported kinds/fields.
  Freeze actual kind/field coverage with no unexplained omission across all five resource cohorts.
- Admit exact offline Helm/Kustomize profiles, deterministic public overrides, limits and sanitized
  output; no dependency updates, remote bases, plugins, post-renderers or ambient kubeconfig.
- Generate/reparse native output, render generated authoring inputs where applicable, and run matching
  version-specific #2 offline/API validation. Preserve source/output independence.
- Add `tests/official_fixtures.rs` only when actual native/library renderer contracts exist. Never
  insert an empty success harness to stand in for those tests.
- Verify the actual Cargo package exclusions and run the complete gate after the final integration
  edit under primary ownership. The source-only preparation/admission suites are already included
  through the repository policy runner; that inclusion does not complete native acceptance.

The [focused suite](../../scripts/fixtures/test_materialize.py) exercises real byte integrity,
archive decoding, dependency/entrypoint closure, containment, budgets, atomic failure cleanup,
license/provenance requirements and diagnostic privacy. It is preparation evidence only.

Both preparation and admission modules are required by
[the repository policy runner](../../scripts/test-repository-policy.py), reached by the existing
Cargo policy harness and documentation gate. Its single discovery pass includes all 97 fixture
tests and requires the original source-receipt and renderer-expectation witness IDs. Missing
modules, missing witnesses, import/discovery errors and assertions fail validation. Gate
regressions independently exercise missing-module and fixture assertion failures with fake
build/tool commands; native scripts and runtime-pending evidence remain unchanged.
