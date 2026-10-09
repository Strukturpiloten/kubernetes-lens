#!/usr/bin/env bash
# Shared phase contracts for local, PR, main and manual validation.
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
case "${1:-}" in
  rust)
    cargo fmt --all -- --check
    cargo ci-check
    cargo ci-policy
    cargo ci-clippy
    cargo ci-test
    cargo ci-doctest
    RUSTDOCFLAGS='-D warnings' cargo ci-doc
    cargo package --locked --allow-dirty
    ;;
  msrv)
    msrv="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["rust-version"])')"
    rustup run "${msrv}" rustc --version
    cargo "+${msrv}" ci-check
    cargo "+${msrv}" ci-policy
    ;;
  dependencies)
    cargo deny --all-features check
    ;;
  documentation)
    bash scripts/check-files.sh --check
    git --no-pager diff --check
    actionlint
    zizmor .github/workflows
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-validation-plan.py
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-repository-policy.py
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-check-all.py
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-ci-tools.py
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-renovate-tool.py
    node scripts/test-renovate.mjs
    mapfile -d '' markdown_files < <(git ls-files --cached --others --exclude-standard -z -- '*.md')
    lychee --config lychee.toml --root-dir . --offline "${markdown_files[@]}"
    ;;
  *)
    printf 'Usage: %s {rust|msrv|dependencies|documentation}\n' "$0" >&2
    exit 2
    ;;
esac
