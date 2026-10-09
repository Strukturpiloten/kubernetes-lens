#!/usr/bin/env python3
"""Exercise actual OCI extraction staging, failure cleanup and immutable source checks."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

class ExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-oci-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "scripts").mkdir()
        (self.root / "bin").mkdir()
        for name in ("install-renovate-tool.sh", "renovate-tool.json"):
            (self.root / "scripts" / name).write_text((ROOT / "scripts" / name).read_text())
        engine = self.root / "bin/mock-engine"
        engine.write_text('''#!/bin/sh
case "$1" in
  create) printf 'owned-test-container\\n' ;;
  cp)
    destination=$3
    printf '{"version":"%s"}\\n' "${MOCK_VERSION:-44.139.0}" > "$destination/package.json"
    if [ "${MOCK_FAIL_COPY:-0}" = 1 ]; then
      printf 'obsolete' > "$destination/obsolete.js"
      exit 17
    fi
    ;;
  rm) printf 'removed\\n' >> "$MOCK_CLEANUP_LOG" ;;
esac
''')
        engine.chmod(0o755)
        node = self.root / "bin/node"
        node.write_text('#!/bin/sh\nexit "${MOCK_RE2_STATUS:-0}"\n')
        node.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.root / 'bin'}:/usr/bin:/bin",
                    "KUBERNETES_LENS_CONTAINER_ENGINE": "mock-engine",
                    "MOCK_CLEANUP_LOG": str(self.root / "cleanup")}
        self.installed = self.root / ".ci-tools/renovate"
        self.installed.mkdir(parents=True)
        (self.installed / "old-good-artifact").write_text('retained until successful validation')

    def run_extract(self, **variables: str) -> subprocess.CompletedProcess:
        return subprocess.run(["/bin/bash", str(self.root / "scripts/install-renovate-tool.sh")],
                              env={**self.env, **variables}, text=True, capture_output=True, check=False)

    def test_failed_copy_cleanup_and_retry_cannot_mix_artifacts(self) -> None:
        failed = self.run_extract(MOCK_FAIL_COPY="1")
        self.assertEqual(failed.returncode, 17, failed.stderr)
        self.assertTrue((self.installed / "old-good-artifact").exists())
        self.assertEqual(list((self.root / ".ci-tools").glob("renovate-extract.*")), [])
        succeeded = self.run_extract()
        self.assertEqual(succeeded.returncode, 0, succeeded.stderr)
        self.assertFalse((self.installed / "old-good-artifact").exists())
        self.assertFalse((self.installed / "obsolete.js").exists())
        self.assertEqual(list((self.root / ".ci-tools").glob("renovate-extract.*")), [])
        self.assertEqual(len((self.root / "cleanup").read_text().splitlines()), 2)
        self.assertEqual((self.installed / "source-image.txt").read_text().strip(),
                         __import__('json').loads((self.root / "scripts/renovate-tool.json").read_text())["image"])

    def test_version_or_re2_mismatch_retains_previous_runtime(self) -> None:
        for variables in ({"MOCK_VERSION": "44.139.1"}, {"MOCK_RE2_STATUS": "18"}):
            result = self.run_extract(**variables)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((self.installed / "old-good-artifact").exists())
            self.assertEqual(list((self.root / ".ci-tools").glob("renovate-extract.*")), [])

if __name__ == "__main__":
    unittest.main()
