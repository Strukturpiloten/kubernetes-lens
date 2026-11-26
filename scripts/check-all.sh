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
for tool in actionlint cargo cargo-deny git lychee node python3 realpath rustup shellcheck shfmt tombi zizmor; do
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
current_step='coverage tool preflight'
report_failure() {
  local failed_status="$?"
  printf 'KubernetesLens complete validation failed in %s (exit %s).\n' \
    "${current_step}" "${failed_status}" >&2
  exit "${failed_status}"
}
trap report_failure ERR
coverage_selection="$(python3 scripts/shared-ci.py cargo-tools verify --repository-root . --package cargo-llvm-cov --require-candidate)"
coverage_channel="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["rust_channel"])' <<< "${coverage_selection}")"
current_step='format/lint'
bash scripts/format-lint.sh "${mode}"
for phase in rust msrv dependencies documentation; do
  current_step="${phase}"
  printf '\nComplete validation phase: %s\n' "${phase}"
  bash scripts/run-checks.sh "${phase}"
done
current_step='coverage'
printf '\nComplete validation phase: %s\n' "${current_step}"
automation_revision="$(python3 -c 'import json; print(json.load(open(".github/automation.json"))["revision"])')"
RUSTUP_TOOLCHAIN="${coverage_channel}" python3 scripts/shared-ci.py run --event local --task coverage \
  --automation-sha "${automation_revision}" --report-json target/coverage-task.json
current_step='api-development'
printf '\nComplete validation phase: %s\n' "${current_step}"
python3 scripts/shared-ci.py run --event local --task api-development --report-json target/api-development-task.json
printf '\nKubernetesLens complete validation passed. Native conformance remains unavailable in this unpublished foundation.\n'
