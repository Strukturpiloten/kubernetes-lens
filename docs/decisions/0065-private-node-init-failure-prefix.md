# ADR 0065: Private bounded pre-readiness node-init failure prefix

Status: Proposed for issue #62; runtime qualification remains pending.

## Context and narrow supersession

The V18 modern first-cohort attempt reached staging and kind creation, then
failed with kind-create status 1 and kind-delete status 0. Its trusted collector
reported 16385 stdout bytes against a 16384-byte limit, no established source EOF,
no startup marker and no observed child-wait status. Those observations do not
diagnose the underlying failure. No raw startup prefix survived outside the VM;
independent whole-VM retirement was separately established.

This decision refines ADR 0062's durable evidence catalogue and narrowly
supersedes the blanket raw-log exclusion in `docs/fixtures/owned-rootful-kind.md`
only for the fixed `node-init-stdout-prefix` private role below. The closed public
`logs` object still excludes raw bytes, paths, keys and credentials. ADR 0063,
all other exclusions, and ADR 0064's separately reserved issue #48 subject remain
unchanged. This proposal supplies no new runtime authorization or conformance.

## Decision

Only a failed kind-create result with source application submission not reached,
no established startup-marker/retirement record, and an existing closed stdout
collector record may retain this role. Its source is the original provider
`podman logs -f` node-init capture, through the existing fixed numeric work-token
stdout/stderr pair recorded by that route. No caller path, application resource
log, additional provider request or general log acquisition is admitted.

The original collector still captures at most the 16384-byte limit plus its
one-byte overflow sentinel. Overflow, missing EOF, failed waits, poison and all
other refusal conditions remain failures. One existing budgeted `dd` copies only
the first 16384 bytes of that already-captured file into a fresh fixed private
file. The sentinel is excluded. The original captured source is not rewritten.
The fixed role is handled by the existing directly used `remember` catalogue
entry, including EXIT failure cleanup; no new indirect-only function or lint
suppression is introduced. The success-state label is an explicitly quoted
literal, preserving its existing meaning. Existing catalogue stat/SHA256/base64
handling adds three more utility actions:
four total, charged honestly to the original 64-action cleanup partition, with
no refund, extra credit or alternate partition. Exhaustion or any artifact
failure remains failure and cannot authorize another attempt.

The role shares the original 128 KiB raw aggregate, 256 KiB wire envelope,
1 MiB delegated guest output allowance, absolute work/cleanup ends and metadata
limits. There is no new buffer allowance, native argv, metadata/version query,
observer, helper software, retry or fallback. All 49 original query sites and
24 prepaid record guards remain unchanged.

The host validates owner, plan and source-spec bindings, existing collector
metadata, failed pre-application scope, exact prefix length and raw byte hash.
The role is forbidden for a successful or post-application result. A short prefix
is still only diagnostic evidence: it never proves complete-stream capture,
source EOF, readiness, native success, controller behavior or retirement.

The existing fixed owner-derived exclusive/no-follow 0600 sidecar under its 0700
private output parent retains the protected bytes. Their content may contain
credentials and must remain private. Public receipts contain only the protected
role, scope, prefix-only classification, byte length, hashes and sidecar reference;
no prefix/base64 text enters the receipt, public logs or conformance reports.
Whole-target retirement must still be independently checked on success/failure.

## Validation and limitations

Pure controls cover binary/NUL preservation, exact overflow-prefix truncation,
private permissions, public-reference privacy, source/scope/hash rejection,
fixed-path and symlink refusal, utility charging/exhaustion and failure
preservation. The historical V16/V18 source and original-query digest checks
reverse only this explicit delta before applying their original assertions.
All existing Rust source and all 285 protected Rust test bodies remain unchanged.
The complete repository gate and fresh independently reviewed runtime attempt
remain main-agent obligations; passing these pure controls establishes neither.
