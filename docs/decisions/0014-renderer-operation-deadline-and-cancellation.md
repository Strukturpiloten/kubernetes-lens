# ADR 0014: Original renderer total deadline and owned-parent cancellation

Status: Accepted source contract; independent runtime evidence pending.

Refines ADR 0012's inherited deadline/cleanup contract. The explicitly provisioned
system broker, private evidence, finite resource/tool selections and subprocess-free
ordinary parsing/generation remain accepted.

## Decision

Add an explicitly selected opaque immutable operation control carrying the caller's
absolute `Instant` end and cloneable standard-library cancellation token. Keep
existing constructors and `OfflineRenderer::execute` source-compatible with honestly
documented legacy v1 execution-plus-up-to-ten-seconds cleanup semantics.

Selected v2 converts once to boot-bound monotonic `D_total`, reserves ten seconds
inside it and lowers `D_exec` by the request cap. Expired/insufficient/invalid context
refuses before owned effects. Versioned header, immutable descriptor and journal
bind both original ends; queue/setup/cancel/recovery never renew them or the nonce.
Old brokers reject v2 before owned work with no protocol or unsupervised fallback.

Cancellation closes only the selected execute's authenticated socket write half;
the retained read half receives its bound cleanup result within total. Bounded I/O
checks cancellation and deadlines, including after native output/receipt availability.
No public raw PID, nonce, unit cancellation or live recovery operation is added.

Whole-work kill alone destroys the supervisor before it can prove real-parent reap.
Use the existing authenticated supervisor channel for one private cancellation
message binding nonce, owned Bubblewrap child, boot and original ends. The supervisor
kills only its existing unreaped `Child`, polls/waits under the original cleanup end
and returns the same nonce/child-bound native wait acknowledgement. The owning tracer
may consume terminal stops before that acknowledgement. Controller whole-work stop,
cgroup/UID/PID audit and broker controller/slice retirement then precede reply.
Missing acknowledgement permits exact-owned bounded fallback but leaves cleanup
unproved and quarantined; no census or trace result fabricates a positive parent wait.

Controller, watchdog, receipt, cleanup-clock, tracer-failure and same-boot recovery
timers use total as ceiling. One shorter cleanup window is retained, never renewed.
Service runtime guards are fixed before activation. Reserve one second for
activation lag, 250ms runtime accuracy, four STOP/FINAL TERM/KILL waits of one second
plus 250ms accuracy each, and one microsecond of activation-witness rounding inside
the original end. Admit only the exact configured no-stop-command, terminate-failure,
control-group/SIGKILL policy with one-second stop timeout and zero runtime
randomization. Exact unit/invocation, activation timestamp and
unchanged guard must fit that end before native permission; late activation
refuses/cleans the same cell. Active RuntimeMax property mutation is unsupported
on reviewed systemd 261.3, so no rearming/readback assumption is made.
Configured timers remain supplementary: no inferred process death or reap, and no
claim that scheduler stalls are bounded. Actual death/reap remains observed proof.
Expired/different-boot v2 recovery cannot create a fresh cleanup timer; repeated
recovery preserves the minimum of total, live cleanup and a validated complete
pending cleanup end. Read-only bounded pending inspection precedes budget/owned
stop; exact expired pending context refuses before effects. Promotion cannot widen
a persisted cleanup end, and malformed/partial/foreign pending data grants no new
authority. Only the validated live deadline permits an exact-owned fallback, followed
by failure with unpromoted evidence retained. Same-boot
orphan fallback has no actual native-wait acknowledgment and retains quarantine
and the identity lease after cleanup audits.

## Consequences and migration

Callers requiring their original total end must select the new method and create
control before queue/setup. Clone the token to request cancellation; do not reconstruct
a timeout on retry or cancellation. Exhaustive `FailureCause` matches add `Cancelled`.
No dependency, tool inventory, native source oracle or resource/version ledger changes.

Pure source/model tests establish arithmetic, schema/ownership binding and decision
behavior only. Exact installed systemd timer behavior, socket cancellation during
setup/exec/drain, traced-child real-parent wait, missing-supervisor fallback, late
cancellation, original-end expiry, kernel cgroup/UID/PID cleanup, reboot/interruption,
all 90 command cells and three graph cases, and full unchanged CNPG default-render
acceptance remain separate mandatory native evidence. No publication or runtime
conformance is claimed from source or mock outcomes.
