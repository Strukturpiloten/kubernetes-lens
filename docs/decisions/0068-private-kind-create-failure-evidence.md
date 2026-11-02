# ADR 0068: Private evidence from an existing failed kind-create capture

Status: Proposed source contract for issue #62; native qualification remains pending.

## Context

The independently retired V23 failure returned kind-create status 1 and delete status 0 before the source Deployment was reached. The existing startup predicate matches its authenticated node stdout prefix. Missing post-create retirement metadata therefore does not establish missing startup text, and this evidence establishes no underlying cause. The already bounded kind-create stderr and available wait statuses were lost when cleanup replaced the receiver's capture globals.

## Decision

Retain only existing evidence before cleanup. Add two fixed protected catalogue roles: a first 4096-byte `kind-create-stderr-prefix`, omitted when the capture is empty, and a maximum 1024-byte `kind-create-attribution` record. Keep the original captured stderr byte count, including its existing 32769th overflow sentinel. The record separates the kind child's wait status, the native wrapper's return and both collector waits. A failed or unavailable stderr collector leaves EOF unknown. Prefix truncation and overflow are explicit. Provider-specific statuses remain null because there is no existing durable pointer proving them; neither stderr interpretation nor generic status files supply one.

Publish the available diagnostic bindings in one assignment command. Validate every optional binding before dereferencing it; an interrupted or malformed snapshot makes evidence preservation ineligible and still permits original poison and cleanup. Independent partial-binding and self-signal controls cover this boundary.

Predebit only existing work utility credits before cleanup: eight for a nonempty stderr capture (stat, prefix copy and three catalogue operations for each role), or four for an empty capture (stat and three attribution operations). Never refund partial predebits. Refusal to preserve evidence leaves the original failure and poison intact and still permits original cleanup. The existing 64 cleanup utility credits, native credits, reservations, caps, deadlines and retirement obligations remain unchanged. Emission consumes each prepaid ticket once; existing catalogue operations retain their original charging.

Both roles remain 0600 in the existing private catalogue and sidecar. Public summaries contain only protected role, size, digest and fixed scope/completeness references. They never expose raw or encoded content. The original 64 KiB result metadata, 128 KiB raw catalogue aggregate and 256 KiB private wire limits still apply. Diagnostic preservation is no readiness, cause, success or native-conformance proof.

Preservation and emission use two fixed internal operations in the existing, genuinely used `remember` dispatch. They keep their original before-cleanup and catalogue-emission positions and utility charges. The dispatcher rejects extra arguments; no diagnostic path or general command input is accepted. Size syntax and positive aggregate checks are separate explicit refusals.

## Verification

Pure controls cover binary prefixes, empty/exact/overflow boundaries, unknown EOF, status binding, private persistence, ticket conservation and single use, exhausted work credits, preservation/emission failure with original cleanup, and maximum fixed metadata fields. Exact test-only inversion retains prior source anchors and all existing test bodies. No new producer, query, probe, runtime fallback, retry, tool pin or admission is introduced. Fresh normal validation and an independently admitted native attempt remain separate obligations.
