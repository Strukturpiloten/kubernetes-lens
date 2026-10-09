# Contributing

Read [AGENTS.md](AGENTS.md), architecture, decisions, and the policies relevant to your change.
Keep KubernetesLens independent and make support claims match recorded evidence. Implement native
code originally rather than translating or copying external implementations.

Use the shared workspace development tools. Run `./scripts/format-lint.sh --fix`, then
`./scripts/check-all.sh --check` after the final edit. The primary owns the complete gate and Git/PR
workflow. Record regressions, relevant documentation and dependency pin ownership in the same change.
Keep bootstrap work under #6 and native implementation under #7.
