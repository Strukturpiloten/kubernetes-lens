# ADR0097: Source-bound modern kubeadm logging

Status: Proposed bounded modern-only logging policy; canonical binding and targeted ShellCheck
are complete. Independent review, complete validation and native adoption remain pending.

Refines the source-bound provider boundary of ADR0091 and composes with the unchanged capture
status and compact-response policies of ADR0093/0094. The portable
[source facts](../../scripts/fixtures/owned-kubeadm-logging-source-facts.json) pin the official
kind 0.33.0/Kubernetes 1.37.0 sources, exact line spans, hashes and Apache-2.0 licenses.

## Requested and effective arguments

The pinned kind 0.33.0 source requests kubeadm init `--v=6` intentionally for debugging. Preserve
that exact requested form in `provider_classify`: modern init still has exactly eight tokens
and final requested token6; unknown verbosity/spelling/order/extra/bootstrap arguments remain
rejected. After successful classification **and** both original work/cleanup action guards,
only modern-1.37.0/init rewrites zero-based `args[7]` to `--v=0` before the existing dispatch.
Cleanup still rejects init before translation. Legacy-1.20.15 retains v6 and its exact existing
skip-preflight argument. Other actions, including run translation, remain unchanged.

This is one existing logging flag's value translation, with no new command, process, observer,
flag, bootstrap option, query, capture role or environment-wide verbosity setting. The same
existing profile/input/spec and exact canonical receiver hash bind the deterministic source
policy. No new wire field/schema is needed. This source relation is not a newly observed
per-run effective-argv transcript or source/binary reproducibility proof.

## Explicit diagnostic-detail tradeoff

Pinned kubeadm 1.37.0/klog defaults to verbosity 0. Base returned error messages, their stderr
error handling and exit 1 remain. Ungated Info, Warning and Error logging remain; v0 is **not**
a critical-errors-only mode. Positive-verbosity debug records and kubeadm's v>4 stacktrace
formatting are intentionally reduced; base message plus the v5 diagnostic hint remain. There
is no promise that every diagnostic byte, callsite or timing observation is equivalent.

The receiver does not discard, redirect, filter or truncate stderr and does not turn nonzero
status into success. Existing command/capture/wrapper status propagation, failure precedence,
poison, cancellation and independent retirement remain unchanged. A verbosity policy is not an
underlying kubeadm/provider root-cause fix or a guarantee that output fits.

## Unchanged limits and representation

Init remains 32768 bytes per stdout/stderr capture. Deployment remains 4096 per stream. Native
70/5/75 are work/cleanup/total **actions**; 1800/1680/120 are the separate original
total/work/cleanup **seconds**. All other actor, utility, query, output, read and retirement
limits remain; no allowance or threshold increases and no new observer or controller is added.

The three-line guard needs 85 raw bytes. Recover space only by shortening four identical
ordinary jq-variable comments while retaining their meaning: variables are supplied by jq
--arg and must not be shell-expanded. License text and ShellCheck pragmas stay exact. No code
compression or guard removal is used. The 65388-byte/491078… current predecessor and the
65378-byte/5bc0… capture predecessor remain exact frozen history through strict named inverse
domains. Current operational hash and frozen hashes are separate; unknown source never gets
accept-either normalization. Two historical Python controls normalize only their source inputs;
all assertions/counterexamples/registrations remain, alongside new current-source controls.

Pinned shfmt leaves the canonical receiver at 65361 bytes, SHA256
`35035fe7b0e2d981fff0a0bd44a2de57b97cb11040bef4371297d338eb6516b6`: 47 bytes below
integration 65408 and 175 below hard 65536. Targeted canonical ShellCheck passes. Exact current
QEMU/test/source-fact enrollment is rebound; the original strict frozen inverses remain.
This focused formatting/lint evidence is not complete-gate or native evidence.

## Source provenance and acceptance boundary

The existing frozen kind/Kubernetes/tool/image ledgers and sole Renovate owners do not change.
The new JSON is immutable source evidence, not an operational pin/version inventory or competing
installer. Existing **/fixtures/** ignorePaths and closed custom-manager paths cover it; no
Renovate policy change is required. Source URLs/revisions/hashes/licenses identify evidence;
upstream implementation was neither copied nor translated into the original guard.

V33 remains failed/spent and independently known retired. Its checked stderr32769>32768 is
preserved with wrapper125/capture23; a 4KiB prefix does not establish uncapped output or underlying
cause. No historical result is reclassified. New controls are authored, unexecuted fixture
DATA only. Independent review, actual integration, complete gate,
fresh input/source custody and separately authorized native adoption remain primary-owned.
No root-cause, physical/log-fit, successful bootstrap, API, source publication or native/runtime
qualification is claimed, and no automatic retry is authorized.
