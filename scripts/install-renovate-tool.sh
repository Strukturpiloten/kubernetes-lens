#!/usr/bin/env bash
# Extract only the operational test runtime from the immutable official OCI artifact.
set -Eeuo pipefail
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly repository_root
container_engine="${KUBERNETES_LENS_CONTAINER_ENGINE:-docker}"
readonly container_engine
image="$(
  python3 - "${repository_root}/scripts/renovate-tool.json" << 'PY'
import json
import re
import sys
image = json.load(open(sys.argv[1]))['image']
if not re.fullmatch(r'ghcr\.io/renovatebot/renovate:[0-9]+\.[0-9]+\.[0-9]+@sha256:[a-f0-9]{64}', image):
    raise SystemExit('Renovate tool requires an exact official version and verified OCI digest')
print(image)
PY
)"
readonly image
command -v "${container_engine}" > /dev/null
mkdir -p "${repository_root}/.ci-tools"
scratch="$(mktemp -d "${repository_root}/.ci-tools/renovate-extract.XXXXXX")"
readonly scratch
container_id=''
cleanup() {
  if [[ -n "${container_id}" ]]; then
    "${container_engine}" rm --force "${container_id}" > /dev/null
  fi
  rm -rf -- "${scratch}"
}
trap cleanup EXIT
"${container_engine}" pull "${image}"
container_id="$("${container_engine}" create --network none "${image}")"
readonly container_id
"${container_engine}" cp "${container_id}:/usr/local/renovate/." "${scratch}/"
python3 - "${scratch}/package.json" "${image}" << 'PY'
import json
import sys
version = sys.argv[2].split(':', 1)[1].split('@', 1)[0]
if json.load(open(sys.argv[1]))['version'] != version:
    raise SystemExit('OCI artifact package version differs from its reviewed tag')
PY
node --input-type=module - "${scratch}" << 'JS'
import { pathToFileURL } from 'node:url';
const { regexEngineStatus } = await import(pathToFileURL(process.argv[2] + '/dist/util/regex.js'));
if (regexEngineStatus.type !== 'available') throw new Error('OCI runtime RE2 unavailable in this development environment');
JS
printf '%s\n' "${image}" > "${scratch}/source-image.txt"
rm -rf -- "${repository_root}/.ci-tools/renovate"
mv -- "${scratch}" "${repository_root}/.ci-tools/renovate"
printf 'Extracted immutable Renovate runtime %s. No platform operations were invoked.\n' "${image}"
