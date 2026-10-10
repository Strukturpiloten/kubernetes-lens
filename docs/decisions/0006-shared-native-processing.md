# ADR 0006: Shared native processing, protected bytes and supplied quantity order

Status: Accepted

Refines ADR 0004's independent constructor and graph budgets with one cumulative native-processing
session per public operation. Existing syntax/construction/snapshot caps remain independent.

## Decision

`NativeProcessingLimits` provides lower-configurable charged payload bytes (64 MiB), conservative
processing units (64 MiB), ordinary report entries (10,000) and report payload bytes (1 MiB).
Ceilings are componentwise bounded by these defaults. Zero allowances are valid. Private Rc-backed
handles share counters through phase-aware context clones, fields, resources, effective projection,
redecode and canonical reparsing. Arithmetic is checked, exhaustion is sticky and attempted work
never refunds allowance. Source identifiers are evidence identifiers, not counter identity.

An aggregate ResourceSet retains the componentwise minimum of its sources' processing ceilings,
including supplied edit evidence, bounded by defaults. Explicit validation/generation/graph ceilings
can only lower that ceiling. Source-free authoring retains its explicit authoring/default ceiling.
Authoring encoding, canonical snapshot, strict parse, native decode and validation share one session.
A later public operation receives a new session with the retained ceiling.

Charges preflight new binary/numeric buffers and copies, serialization buffers and report retention.
Processing units are conservative input/output scans, coefficient comparisons and traversals; they
are not measured visits inside the delegated base64 engine. Existing parser/source/tree caps still
apply. This contract does not meter every old allocation, allocator capacity, overhead or RSS.
Ordinary findings are bounded before retention. Loops stop on exhaustion. Earlier violations remain
visible; legacy Vec results may add one fixed, pathless, value-free emergency `LimitExceeded` outside
the ordinary report allowance. Suppressed findings cannot establish success.

`NativeBytes` owns one immutable decoded payload shared by clones; source spelling belongs only to
immutable evidence. Standard padded base64 permits CR/LF and native unused trailing bits, rejects
other whitespace, URL alphabet and malformed/noncanonical padding. Empty input is empty bytes.
New output is canonical. Fresh filter/decoded/encoded buffers reserve allowance before allocation.
Default diagnostics and Debug reveal no payload. Explicit source access reveals bytes; artifact
access remains separate and generation's protected-output denial remains the default. Decoding
bytes does not prove UTF-8, PEM, certificate validity, TLS acceptance or API-server admission.
The approved backend is exact base64 0.22.1, without default features, owned once by Cargo/Renovate.

Quantity comparison orders exact supplied mathematical values independently of native rounding,
capping, field acceptance and controller/provisioning behavior. Existing grammar, source spelling
and normalized coefficient/scale authority remain unchanged. Each comparison precharges 533
processing units even for sign/zero shortcuts. Checked symbolic i64 ranks and conceptual right-zero
padding use constant scratch space; no exponent expansion or floating point is introduced.
A separate result classifies nonnegative integral bytes no larger than i64::MAX as the conservative
arithmetic domain. Wider exact comparisons retain explicit native-semantics uncertainty. Owning
fields still establish positivity and applicability separately.

## Migration and evidence

ParseLimits gains `processing`; GenerationOptions and ReferenceContext gain optional lower ceilings.
Struct literals should use Default or supply the new members. SourceEvidence exposes retained limits.
The sealed field decoder takes a phase-aware shared context; native validation/reference/protected
projection hooks carry the existing session rather than constructing defaults. These are intentional
unpublished API/internal integration changes. Focused tests exercise primitives and actual native
Pod quantity fields. Compatibility, runtime and API-server conformance cells remain pending.

Constructor intake and identity scans charge work even for empty Lists and unique identities that
emit no ordinary findings. Retained List wrapper/item copies and source/resource/item-ID vectors
preflight conservative structural and payload charges; generation wrapper preparation/rewrapping
uses the same operation. Separately parsed sources cannot reset these aggregate allowances.
Independent regressions exercise empty and opaque Lists, and a private synthetic binary codec
checks unchanged spelling versus canonical changed output without adding a native registration.
