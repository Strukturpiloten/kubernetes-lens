#!/usr/bin/env bash
# Consume the immutable shared tool inventory; never maintain a second pin list here.
set -Eeuo pipefail
if [[ "$#" != 1 || ! -f "$1/.devcontainer/Dockerfile" ]]; then
  printf 'Usage: %s <checked-out shared BoxFerry root>\n' "$0" >&2
  exit 2
fi
shared_root="$(realpath -- "$1")"
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly shared_root repository_root
install_root="${repository_root}/.ci-tools"
readonly install_root
mkdir -p "${install_root}/bin" "${install_root}/node"
# The upstream Cargo --locked installs resolve checksums through each tool's release lock.
read_version() {
  python3 - "$shared_root/.devcontainer/Dockerfile" "$1" << 'PY'
from pathlib import Path
import re
import sys
matches = re.findall(r'^ARG ' + re.escape(sys.argv[2]) + r'_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$', Path(sys.argv[1]).read_text(), re.M)
if len(matches) != 1:
    raise SystemExit('shared tool version missing or duplicated: ' + sys.argv[2])
print(matches[0])
PY
}
for specification in 'LYCHEE lychee' 'ZIZMOR zizmor'; do
  read -r owner executable <<< "${specification}"
  cargo install --locked --version "$(read_version "${owner}")" --root "${install_root}" "${executable}"
done
bash "${shared_root}/scripts/install-file-tools.sh" "${install_root}/bin"
cp "${shared_root}/package.json" "${shared_root}/package-lock.json" "${install_root}/node/"
npm ci --ignore-scripts --no-audit --no-fund --prefix "${install_root}/node"
# Canonical actionlint checksum provenance matches BoxFerry's Dockerfile contract.
version="$(read_version ACTIONLINT)"
case "$(uname -m)" in
  x86_64) architecture=amd64 ;;
  aarch64 | arm64) architecture=arm64 ;;
  *)
    printf 'Unsupported CI architecture.\n' >&2
    exit 2
    ;;
esac
archive="actionlint_${version}_linux_${architecture}.tar.gz"
release_url="https://github.com/rhysd/actionlint/releases/download/v${version}"
temporary_directory="$(mktemp -d)"
trap 'rm -r -- "${temporary_directory}"' EXIT
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "${temporary_directory}/checksums.txt" "${release_url}/actionlint_${version}_checksums.txt"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "${temporary_directory}/${archive}" "${release_url}/${archive}"
checksum="$(awk -v name="${archive}" '$2 == name { print $1 }' "${temporary_directory}/checksums.txt")"
[[ "${checksum}" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "${checksum}" "${temporary_directory}/${archive}" | sha256sum --check --status
tar --extract --gzip --file "${temporary_directory}/${archive}" --directory "${temporary_directory}" actionlint
install -m 0755 "${temporary_directory}/actionlint" "${install_root}/bin/actionlint"
printf '%s\n' "${install_root}/bin" "${install_root}/node/node_modules/.bin" >> "${GITHUB_PATH:?CI path output required}"
