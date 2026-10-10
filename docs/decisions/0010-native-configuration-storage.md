# ADR 0010: Native configuration and storage boundaries

Status: Accepted. Refines ADRs 0003, 0004 and 0007 without expanding the frozen field goal.

## Decision

Register the five selected configuration/storage kinds in the existing sealed native registry,
with typed native import, bounded authoring, validation, supplied graph facts and generation.
Native implementation remains independent of BoxFerry and never provisions storage or reads
a deployed resource. Unknown fields retain original evidence and require explicit output policy.

Protect ConfigMap text as well as binary data and Secret payloads. ConfigMap `data` uses
`Protected<String>` and explicit source access; ordinary Debug, findings and default generation
retain the protected-value boundary. Key inventories distinguish text-only from text/binary
domains and bind exact supplied maps and keys. No aggregate root-field capability is invented.

Check known-invalid selector members before reporting retained unsupported descendants.
Unknown descendants still cannot authorize a positive graph relationship. Admit `immutable`
only through the selected stable-only profile from Kubernetes 1.21; preserve 1.20 source
evidence without pretending that an enabled beta gate is the selected stable capability.

PV/PVC operation-specific checks require explicit Create intent. The finite PV source union
counts preserved Portworx evidence, while source-free Portworx output remains unsupported.
Require exactly one source, including the reviewed FlexVolume product restriction. Preserve
option/defaulting, transport/OS, plugin, quantity-arithmetic and update-baseline uncertainty
as structured context findings; no server, binding, scheduling or driver claim follows.

All projection, traversal, comparison and report work inherits the shared cumulative budget.
Exhaustion prevents positive relationships or output, retains one pathless terminal finding
and cannot reveal configuration values or traversal paths.

## Evidence

The canonical selected fields and historical boundaries remain in the capability ledger.
Independent static expectations come from authenticated Apache-2.0 Kubernetes source
witnesses and the PV specification contract, not copied oracle implementation. See
[storage limits](../storage.md). Offline tests and code/source guards are separate from
API-server, runtime, controller/driver and official-corpus evidence, which remains pending #2/#14.
