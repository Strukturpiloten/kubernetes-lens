# Script guidance

The [root guidance](../AGENTS.md) remains authoritative. Follow the
[automation guide](../docs/automation.md) and [development environment](../docs/development-environment.md):
use existing commands and the shared locked uv, Ruff and ty tooling. Preserve independent Python
and native fixture harnesses, source custody, privacy, budgets and cleanup. The user-selected
qualified FCOS VM remains fixed; see [ADR 0101](../docs/decisions/0101-kernel-bounded-live-resource-envelope.md).
Do not add a BoxFerry Kubernetes installer or product dependency.
