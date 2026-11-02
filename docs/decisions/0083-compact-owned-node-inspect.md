# ADR0083: Compact full JSON for the one owned node inspect

Status: Accepted source presentation contract; independent final source review,
complete validation and separately adopted native qualification pending (#62).

## Context

V21n remains failed-retired: V7 pl1.n, null resource reason, command-call0, stdout
capture1, stderr capture0 and native return125. Capture1 folds dd/stat/ticket/IO/
size/setup failures together. No retained inspect bytes/size identify its predicate;
reserved823422 is not an actual byte count. Do not infer overflow, a Podman launch
or cause, or retroactively qualify that result. A full-data output representation
can reduce indentation bytes without a cap increase, new observation or projection.

## Decision

Add exactly --format '[{{json .}}]' to the existing n native invocation, keeping
--remote=false, --type=container, one quoted owned node, native16384/4096, original
OR/fail context and every existing jq/remember/semantic guard. No provider, image,
multi-target, --all/--latest/--size or runtime mode change is made. The same report
is serialized as one compact object in a root array, preserving all JSON field
values/arrays for valid encoding. This is not byte normalization after capture;
raw private evidence retains the bytes the native command actually produced.

The official Podman5.8.7 contracts at commit
c593b672bf3db1173aebea565ebf1a724ea196dc support this narrow choice:

- [Pinned CLI docs](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/docs/source/markdown/podman-container-inspect.1.md.in)
  define default JSON array output and per-result custom format.
- [Inspect dispatch](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/cmd/podman/inspect/inspect.go)
  passes the same collected report data to default or custom serialization.
- [Local engine](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/pkg/domain/infra/abi/containers.go)
  inspects each supplied name once and does not use Format to change collection.
- [Default serializer](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/cmd/podman/utils/utils.go)
  and [json helper](https://github.com/podman-container-tools/podman/blob/c593b672bf3db1173aebea565ebf1a724ea196dc/vendor/go.podman.io/common/pkg/report/template.go)
  use encoding/json with HTML escaping disabled; only the default sets indentation.
  The user formatter enforces a range; this wrapper is valid for the one fixed name,
  not a general multi-result replacement.

The official helper ignores Encode errors. Keep syntax/length1/identity/image/state/
args/network/ports checks unchanged: [] or malformed output must refuse, and no
serializer success is inferred from command-call0 alone. Large compact output,
helper error and all other failures still fail under the same bounds. This is a
prospective full-data presentation improvement, not evidence of a V21n overflow fix.

## History, privacy and limits

V7 schema/keys, all first-failure code/status/reason meanings, positive log proof,
catalogue/raw roles and public redaction remain unchanged; no V8 is introduced.
A separate strict new-source-to-frozen65246-byte b547819 V7 inverse precedes the
unchanged earlier chain/constants. Earlier pretty V7 evidence remains byte-exact and
decodable without a synthesized format/default. Current enrollment binds only the
new canonical source. Preserve all543 previous test IDs and314 prerequisite patterns.

This narrowly refines ADR0081's no-new-arguments slice only for this formatting flag.
The source adds24 bytes, raw/pinned-formatted65270, within target65408 and hard65536.
Native/utility/output reservations, actual waits, deadlines, resource limits and
cleanup remain unchanged. No process/helper/query/observer, catalogue role, retries,
budget/cap increase, decoder change, tool/pin or package change is introduced.

## Focused evidence and external provenance

Pure controls verify exact24-byte-only change and strict historical inverse; synthetic
JSON default/compact value equality with all fields, escapes, arrays/nulls/numbers;
existing host semantic refusal for empty/object/multiple/malformed/wrong-data output;
unchanged actual Bash jq predicates; original capture bound and nonoverflow failures;
guarded current/historical fixed-command projections; private wire durability and
public redaction with original outer failure/retirement semantics. Synthetic JSON
models do not execute or emulate Podman. No real Podman is permitted in projections:
replacement counts and absence of a native path are checked before local execution.

Official docs/source were read using Context7 then public gh API GET at v5.8.7,
resolved annotated tag29368ab643df027a9c33703273e50ff1ba11b21c to the commit above.
Local read-only research provenance/hashes are retained in the task packet. Podman
and vendored common licenses are Apache-2.0. No upstream implementation was copied,
mechanically translated or vendored into the repository; no publication occurred.
Existing tool/image pins and Renovate ownership are unchanged; these are reference
facts, not a new operational software dependency. Final independent source review,
repository format/lint, complete gate and separately adopted native work remain
primary responsibilities. No native success, retry or publication is authorized here.

Successor note: [ADR0084](0084-post-node-first-parent-failure.md) introduces V8 only
for bounded post-node first-parent-fail attribution. It supersedes the V7-current/
no-V8 description above; this compact full-JSON presentation contract remains.
