# ADR 0071: Bounded evidence from the existing owned-VM retirement observer

Status: Accepted source contract; final validation and native qualification pending (#62)

Refines ADR0062 for #62. Use the existing parent observer outside the owned target;
record its existing reads instead of starting a second observer or sampling program.

## Evidence contract

Before starting a unit, reserve a bounded private trace inside the existing metadata
allowance. The trace is at most 32 KiB encoded; one atomic update temporary reserves
64 KiB total inside the unchanged 4 MiB metadata envelope. Prove the complete artifact
catalogue fits before unit effects. Files are exclusive with mode 0600 in the owned parent.

Capture each existing manager before/typed/after read, process start-identity check,
whole-cgroup identity/resource/emptiness read and boot observation at the same read
used by admission. Preserve raw bytes, parsed meaning and the individual observation
association. Keep initial policy/stop observations plus a bounded two-frame ring
whose newest slot may be partial.
Encoding deduplication changes representation only; it cannot create free observations,
retain evicted history indefinitely or replace missing bytes with invented values.

Use the same original deadline, cleanup duration, 128-command and 2 MiB output budget.
Each poll spends actual command fuel before spawning; earlier work reduces available
fuel. An explicit 128-poll bound adds no allowance. Manager actions are at most 5 seconds
within the original end. Once collection starts, its shorter end also bounds kernel reads,
persistence, completion, receipt staging, lease removal and publication. Late work cannot complete
a passing record. Two complete consecutive empty observations need at least
0.100 seconds spacing. Loaded and coherent-not-found readbacks retain their different
actual command costs. Guest/native fuel and diagnostic credit remain unchanged.

Manager bytes already charged by the command reader are not charged again for capture.
New kernel evidence uses the same output budget. The private codec and readback must
bound references, expansion and schema before accepting complete evidence. Partial
capture, persistence or budget failure remains sticky unavailable; existing safe cleanup
continues only with remaining original fuel. Preserve the first native failure separately.

Persist complete raw evidence and the staged private receipt before removing the lease.
Partial evidence cannot satisfy native barriers, permit deletion or produce a positive
receipt. Staged private bytes are prepared, non-authorizing evidence. A committed transaction
requires a matching source/receipt-bound public acknowledgement and successful controller exit.
A named positive-looking file alone cannot establish commit after I/O failure. Preserve structured
quarantine and the first native error; rollback only names proved created by this attempt.
Unknown retirement retains quarantine and the last valid private partial. If
publication fails after removing the staging link, retain the exact full prepared
receipt under its owned final name. Failed acknowledgement never permits deleting
the last full copy. Rollback may remove a created final link only after proving
the exact full staging copy remains; foreign replacements are never removed.

Budget checks fence existing normal file operations before and after each call. A
call that returns after the effective end cannot authorize the next normal read,
write, ownership check or deletion. Expiry preserves prepared receipts and atomic
update temporaries for quarantine without late ownership discovery or persistence.
Required descriptor close and unwinding still run; this contract does not claim
that an operating-system call can be interrupted at the exact deadline.

## Acceptance boundary

Recorded producer prefixes are the actual ordered prefix of zero to five recorded producers; missing later producers
are never fabricated. Exact unit/boot/invocation/no-restart checks and the whole bound
cgroup cover the declared target, including unregistered descendants. Completed raw
readback supports the exact two-point physical scope, not continuous/future absence
or a successful native scenario merely because its processes have retired.

Pure parser and mutation controls cover prefixes, scope drift, PID reuse, descendants,
spacing/fuel/output/storage exhaustion, codec tampering, partials, cancellation and
publication order. Existing policy discovery and kind self-test dispatch automatically
enroll the controls. Final complete gates and real owned legacy/modern execution remain
separate evidence. No new tool pin, container image, installer or product cluster input
is introduced by this source contract.
