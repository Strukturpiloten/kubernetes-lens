#!/usr/bin/env bash
# Complete validation; default --fix matches the canonical workspace contract.
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repository_root
cd -- "${repository_root}"
mode="${1:---fix}"
if [[ "$#" -gt 1 || ("${mode}" != '--fix' && "${mode}" != '--check') ]]; then
  printf 'Usage: %s [--check|--fix]\n' "$0" >&2
  exit 2
fi
for tool in actionlint cargo cargo-deny git lychee markdownlint-cli2 node prettier python3 realpath rustup shellcheck shfmt tombi zizmor; do
  command -v "${tool}" > /dev/null || {
    printf 'Missing required tool %s; use the shared BoxFerry development environment.\n' "${tool}" >&2
    exit 2
  }
done
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  resolved_target="$(realpath -m -- "${CARGO_TARGET_DIR}")"
  case "${resolved_target}" in
    "${repository_root}/"*) export CARGO_TARGET_DIR="${resolved_target}" ;;
    *)
      printf 'CARGO_TARGET_DIR must be inside this worktree.\n' >&2
      exit 2
      ;;
  esac
fi
msrv="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["rust-version"])')"
rustup run "${msrv}" rustc --version > /dev/null
node -e "require('node:fs').accessSync('.ci-tools/renovate/package.json')"
current_step='format/lint'
report_failure() {
  local failed_status="$?"
  printf 'KubernetesLens complete validation failed in %s (exit %s).\n' \
    "${current_step}" "${failed_status}" >&2
  exit "${failed_status}"
}
trap report_failure ERR
bash scripts/format-lint.sh "${mode}"
for phase in rust msrv dependencies documentation; do
  current_step="${phase}"
  printf '\nComplete validation phase: %s\n' "${phase}"
  bash scripts/run-checks.sh "${phase}"
done
printf '\nKubernetesLens complete validation passed. Native conformance and published API compatibility are unavailable in this unpublished foundation.\n'
