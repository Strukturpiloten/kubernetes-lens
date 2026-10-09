#!/usr/bin/env python3
"""Exercise canonical-inventory provisioning without real installations or downloads."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class SharedToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-ci-tools-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shared = self.root / "shared"
        self.repository = self.root / "repository"
        self.bin = self.root / "bin"
        for directory in (self.shared / ".devcontainer", self.shared / "scripts", self.repository / "scripts", self.bin):
            directory.mkdir(parents=True, exist_ok=True)
        (self.repository / "scripts/setup-ci-tools.sh").write_text((ROOT / "scripts/setup-ci-tools.sh").read_text())
        self.dockerfile = self.shared / ".devcontainer/Dockerfile"
        self.dockerfile.write_text("ARG LYCHEE_VERSION=1.2.3\nARG ZIZMOR_VERSION=2.3.4\nARG ACTIONLINT_VERSION=3.4.5\n")
        for name in ("package.json", "package-lock.json"):
            (self.shared / name).write_text('{}\n')
        installer = self.shared / "scripts/install-file-tools.sh"
        installer.write_text('#!/bin/bash\nprintf "shared-file-tools %s\\n" "$1" >> "$MOCK_COMMANDS"\n')
        for tool in ("cargo", "npm"):
            p = self.bin / tool
            p.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$MOCK_COMMANDS"\n')
            p.chmod(0o755)
        archive = self.root / "actionlint.tar.gz"
        binary = b'#!/bin/sh\nexit 0\n'
        with tarfile.open(archive, "w:gz") as tar:
            record = tarfile.TarInfo("actionlint")
            record.size = len(binary)
            tar.addfile(record, io.BytesIO(binary))
        self.checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        curl = self.bin / "curl"
        curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in --output) destination=$2; shift 2 ;; *) url=$1; shift ;; esac
done
case "$url" in
  *_checksums.txt) printf '%s  actionlint_3.4.5_linux_amd64.tar.gz\\n' "$MOCK_CHECKSUM" > "$destination" ;;
  *) cp "$MOCK_ARCHIVE" "$destination" ;;
esac
''')
        curl.chmod(0o755)
        self.log = self.root / "commands"
        self.path_output = self.root / "github-path"
        self.env = {**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin", "MOCK_COMMANDS": str(self.log),
                    "MOCK_ARCHIVE": str(archive), "MOCK_CHECKSUM": self.checksum,
                    "GITHUB_PATH": str(self.path_output)}

    def run_setup(self, **overrides: str) -> subprocess.CompletedProcess:
        return subprocess.run(["/bin/bash", str(self.repository / "scripts/setup-ci-tools.sh"), str(self.shared)],
                              env={**self.env, **overrides}, text=True, capture_output=True, check=False)

    def test_production_script_consumes_the_shared_versions_and_lock(self) -> None:
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.log.read_text()
        self.assertIn("cargo install --locked --version 1.2.3", commands)
        self.assertIn("cargo install --locked --version 2.3.4", commands)
        self.assertIn("shared-file-tools", commands)
        self.assertIn("npm ci --ignore-scripts", commands)
        self.assertEqual((self.repository / ".ci-tools/node/package-lock.json").read_text(), '{}\n')
        self.assertTrue((self.repository / ".ci-tools/bin/actionlint").exists())
        self.assertEqual(len(self.path_output.read_text().splitlines()), 2)

    def test_missing_or_duplicate_upstream_version_is_rejected(self) -> None:
        for content in ("ARG ZIZMOR_VERSION=2.3.4\n", "ARG LYCHEE_VERSION=1.2.3\nARG LYCHEE_VERSION=1.2.4\n"):
            self.dockerfile.write_text(content)
            result = self.run_setup()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or duplicated", result.stderr)
            self.assertFalse(self.path_output.exists())

    def test_download_checksum_mismatch_never_installs_or_exports_path(self) -> None:
        result = self.run_setup(MOCK_CHECKSUM="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.repository / ".ci-tools/bin/actionlint").exists())
        self.assertFalse(self.path_output.exists())

if __name__ == "__main__":
    unittest.main()
