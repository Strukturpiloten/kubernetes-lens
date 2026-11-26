#!/usr/bin/env python3
"""Exercise the selected runtime installer with controlled engine and RE2 failures."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = runpy.run_path(str(ROOT / "scripts/prepare-renovate.py"))
MOCK_ENGINE = r"""#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$MOCK_ENGINE_LOG"
case "$1" in
  pull)
    test "$2" = "$MOCK_IMAGE"
    if [ -n "${MOCK_READY:-}" ]; then
      touch "$MOCK_READY"
      tries=0
      until [ -f "$MOCK_RELEASE" ]; do
        test "$tries" -lt 300
        tries=$((tries + 1))
        sleep 0.1
      done
    fi ;;
  image)
    test "$2" = inspect && test "$5" = "$MOCK_IMAGE" || exit 9
    printf '["%s"]\n' "${MOCK_INSPECT_IDENTITY:-$MOCK_IDENTITY}" ;;
  create)
    test "$2" = --name && test "$4" = --network && test "$5" = none &&
      test "$6" = "$MOCK_IMAGE" || exit 9
    printf '%s\n' "$3" > "$MOCK_CONTAINER"
    printf '0123456789abcdef\n' ;;
  cp)
    test "$2" = "$(cat "$MOCK_CONTAINER"):/usr/local/renovate/." || exit 9
    printf '{"version":"%s"}\n' "$MOCK_VERSION" > "$3/package.json"
    if [ "${MOCK_FAIL_COPY:-0}" = 1 ]; then
      printf 'partial' > "$3/obsolete.js"
      exit 17
    fi ;;
  rm)
    test "$2" = --force && test "$3" = "$(cat "$MOCK_CONTAINER")" || exit 9
    if [ "${MOCK_FAIL_CLEANUP:-0}" = 1 ]; then exit 19; fi
    rm -- "$MOCK_CONTAINER" ;;
  *) exit 9 ;;
esac
"""


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        cls.project: Path = stack.enter_context(LAUNCHER["selected_project"]())
        cls.image = json.loads((cls.project / "renovate-runtime.json").read_text())["image"]
        tagged, cls.digest = cls.image.rsplit("@", 1)
        repository, cls.version = tagged.rsplit(":", 1)
        cls.identity = f"{repository}@{cls.digest}"

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-oci-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name in ("podman", "docker"):
            engine = bin_dir / name
            engine.write_text(MOCK_ENGINE)
            engine.chmod(0o755)
        node = bin_dir / "node"
        node.write_text(
            '#!/bin/sh\n[ "${MOCK_RE2_STATUS:-0}" = 0 ] || exit "$MOCK_RE2_STATUS"\n'
            "printf native-re2-available\n"
        )
        node.chmod(0o755)
        self.log = self.root / "engine.log"
        self.container = self.root / "container"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "MOCK_ENGINE_LOG": str(self.log),
            "MOCK_CONTAINER": str(self.container),
            "MOCK_IMAGE": self.image,
            "MOCK_IDENTITY": self.identity,
            "MOCK_VERSION": self.version,
        }
        self.installed = self.root / ".ci-tools/renovate"
        self.installed.mkdir(parents=True)
        self.marker = self.installed / "source-image.txt"
        self.old_image = self.image[:-1] + ("1" if self.image.endswith("0") else "0")
        self.marker.write_text(f"{self.old_image}\n")
        (self.installed / "old-good-artifact").write_text("retained until successful validation")

    def run_extract(
        self, engine: str = "podman", **variables: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            LAUNCHER["installer_command"](self.project, engine, self.installed),
            env={**self.env, **variables},
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_clean_staging(self) -> None:
        self.assertEqual(list(self.installed.parent.glob(".renovate-extract-*")), [])

    def assert_retained(self) -> None:
        self.assertEqual(self.marker.read_text(), f"{self.old_image}\n")
        self.assertTrue((self.installed / "old-good-artifact").is_file())
        self.assert_clean_staging()

    def test_failed_copy_cleanup_and_retry_cannot_mix_artifacts(self) -> None:
        failed = self.run_extract(MOCK_FAIL_COPY="1")
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertIn("copy failed (exit status 17", failed.stderr)
        self.assertFalse(self.container.exists())
        self.assert_retained()

        succeeded = self.run_extract(engine="docker")
        self.assertEqual(succeeded.returncode, 0, succeeded.stderr)
        self.assertFalse((self.installed / "old-good-artifact").exists())
        self.assertFalse((self.installed / "obsolete.js").exists())
        self.assertFalse(self.container.exists())
        self.assert_clean_staging()
        self.assertEqual(self.marker.read_text(), f"{self.image}\n")
        self.assertEqual(
            json.loads((self.installed / "package.json").read_text())["version"], self.version
        )
        operations = self.log.read_text().splitlines()
        self.assertEqual(
            [operation.split()[0] for operation in operations],
            ["pull", "image", "create", "cp", "rm"] * 2,
        )
        reused = self.run_extract()
        self.assertEqual(reused.returncode, 0, reused.stderr)
        self.assertEqual(self.log.read_text().splitlines(), operations)

    def test_digest_package_and_re2_mismatches_retain_previous_runtime(self) -> None:
        major, minor, patch = self.version.split(".")
        wrong_version = f"{major}.{minor}.{int(patch) + 1}"
        wrong_identity = self.identity.removesuffix(self.digest) + self.old_image.rsplit("@", 1)[1]
        for variables, reason in (
            ({"MOCK_INSPECT_IDENTITY": wrong_identity}, "differs from the requested digest"),
            ({"MOCK_VERSION": wrong_version}, "package version differs"),
            ({"MOCK_RE2_STATUS": "18"}, "native-RE2 failed (exit status 18"),
        ):
            with self.subTest(reason=reason):
                result = self.run_extract(**variables)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertFalse(self.container.exists())
                self.assert_retained()

    def test_cleanup_failure_refuses_promotion(self) -> None:
        result = self.run_extract(MOCK_FAIL_CLEANUP="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("cleanup failed (exit status 19", result.stderr)
        self.assertEqual(
            sum(line.startswith("rm ") for line in self.log.read_text().splitlines()), 2
        )
        self.assert_retained()

    def test_unmanaged_destination_is_refused_without_calling_engine(self) -> None:
        self.marker.unlink()
        result = self.run_extract()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("not a managed Renovate cache", result.stderr)
        self.assertTrue((self.installed / "old-good-artifact").is_file())
        self.assertFalse(self.log.exists())

    def test_documentation_fixtures_keep_the_installer_export_intact(self) -> None:
        consumer = self.root / "consumer"
        for name in (
            ".github/automation.json",
            "Cargo.toml",
            "scripts/ci-api-transition.py",
            "scripts/prepare-renovate.py",
            "scripts/release-policy.json",
            "scripts/shared-ci.py",
            "scripts/test-shared-automation.py",
            "scripts/test-validation-plan.py",
            "scripts/validation-policy.json",
        ):
            destination = consumer / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        (consumer / "src").mkdir()
        (consumer / "src/lib.rs").touch()
        source = self.project.parent
        objects = source.with_suffix(".git")
        cache = consumer / "target/boxferry-automation"
        shutil.copytree(objects, cache / objects.name)
        sentinel = cache / source.name / "held-export"
        ready = self.root / "installer-ready"
        release = self.root / "installer-release"
        with subprocess.Popen(
            [sys.executable, "scripts/prepare-renovate.py", "--engine", "podman"],
            cwd=consumer,
            env={**self.env, "MOCK_READY": str(ready), "MOCK_RELEASE": str(release)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as installer:
            try:
                deadline = time.monotonic() + 10
                while (
                    not ready.exists() and installer.poll() is None and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                if not ready.exists():
                    release.touch()
                    stdout, stderr = installer.communicate(timeout=5)
                    self.fail(f"installer did not reach the controlled pull: {stdout}{stderr}")
                for case in (
                    "ApiTransitionTests.test_selected_producer_strict_tasks_preserve_policy_and_reject_absence",
                    "ReleaseAdoptionTests.test_actual_shared_producer_preparation_and_future_publish_contract",
                ):
                    with self.subTest(case=case):
                        sentinel.write_text("held by the operational launcher")
                        result = subprocess.run(
                            [sys.executable, "-B", "scripts/test-validation-plan.py", case],
                            cwd=consumer,
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=10,
                        )
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertTrue(sentinel.is_file(), "fixture replaced the live export")
                        self.assertIsNone(installer.poll(), "installer must still be in flight")
            finally:
                release.touch()
                try:
                    stdout, stderr = installer.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    installer.kill()
                    installer.communicate(timeout=5)
                    raise
            self.assertEqual(installer.returncode, 0, stdout + stderr)
        artifact = consumer / ".ci-tools/renovate"
        self.assertEqual((artifact / "source-image.txt").read_text(), f"{self.image}\n")
        self.assertEqual(
            json.loads((artifact / "package.json").read_text())["version"], self.version
        )


if __name__ == "__main__":
    unittest.main()
