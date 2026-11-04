#!/usr/bin/env bash
# Consume the immutable shared inventory; keep download/version ownership upstream.
set -Eeuo pipefail
if [[ "$#" != 1 ]]; then
  printf 'Usage: %s <checked-out shared BoxFerry root>\n' "$0" >&2
  exit 2
fi
shared_root="$(realpath -- "$1")"
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly shared_root repository_root
canonical_tools="${shared_root}/automation/src/boxferry_ci/tooling.py"
install_root="${repository_root}/.ci-tools"
readonly canonical_tools install_root
if [[ ! -f "${shared_root}/.devcontainer/Dockerfile" ||
  ! -f "${shared_root}/automation/tool-artifacts.json" ||
  ! -f "${canonical_tools}" ]]; then
  printf 'Shared checkout lacks the canonical tool inventory/installer; use the pinned adoption revision.\n' >&2
  exit 2
fi
: "${GITHUB_PATH:?CI path output required}"
zizmor_version="$(
  python3 - "${shared_root}/.devcontainer/Dockerfile" << 'PY'
from pathlib import Path
import re
import sys

matches = re.findall(r'^ARG ZIZMOR_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$', Path(sys.argv[1]).read_text(), re.M)
if len(matches) != 1:
    raise SystemExit('shared tool version missing or duplicated: ZIZMOR')
print(matches[0])
PY
)"
readonly zizmor_version
mkdir -p "${install_root}/bin" "${install_root}/node"
python3 "${canonical_tools}" --destination "${install_root}/bin" \
  --tools tombi shfmt shellcheck hadolint actionlint lychee
# Zizmor remains the shared Cargo --locked pin, with registry/lockfile integrity.
cargo install --locked --version "${zizmor_version}" --root "${install_root}" zizmor
cp "${shared_root}/package.json" "${shared_root}/package-lock.json" "${install_root}/node/"
npm ci --ignore-scripts --no-audit --no-fund --prefix "${install_root}/node"
printf '%s\n' "${install_root}/bin" "${install_root}/node/node_modules/.bin" >> "${GITHUB_PATH}"
