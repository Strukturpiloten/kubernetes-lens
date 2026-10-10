#!/usr/bin/env python3
"""Execute production gate dispatch with fake tools, checking fail-fast contracts."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
TOOLS = "actionlint bash cargo cargo-deny git lychee markdownlint-cli2 node prettier python3 realpath rustup shellcheck shfmt tombi zizmor".split()
MOCK = r'''#!/bin/sh
name=${0##*/}
line="$name $*"
printf '%s\n' "$line" >> "$GATE_TEST_LOG"
case "$line" in
  python3\ -c*) printf '1.85.0\n' ;;
  realpath*) /usr/bin/realpath "$@" ;;
  git\ ls-files*) printf 'README.md\000' ;;
  bash\ scripts/run-checks.sh*)
    if [ "${GATE_TEST_REAL_POLICY:-}" = 1 ]; then exec /bin/bash "$@"; fi ;;
  python3\ scripts/test-repository-policy.py*)
    if [ "${GATE_TEST_REAL_POLICY:-}" = 1 ]; then exec /usr/bin/python3 -B "$@"; fi ;;
esac
if [ -n "${GATE_TEST_FAILURE:-}" ]; then
  case "$line" in *"$GATE_TEST_FAILURE"*) exit 17 ;; esac
fi
'''

class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-gate-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "repository"
        self.bin = Path(self.directory.name) / "bin"
        (self.root / "scripts").mkdir(parents=True)
        self.bin.mkdir()
        for name in ("check-all.sh", "format-lint.sh", "run-checks.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        mock = self.bin / "mock"
        mock.write_text(MOCK)
        mock.chmod(0o755)
        for tool in TOOLS:
            (self.bin / tool).symlink_to("mock")
        self.log = Path(self.directory.name) / "commands.log"
        self.env = {**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin", "GATE_TEST_LOG": str(self.log)}
        self.env.pop("CARGO_TARGET_DIR", None)
        self.env.pop("KUBERNETES_LENS_LINT_JOBS", None)
        self.env.pop("CARGO_BUILD_JOBS", None)

    def run_script(self, script: str, *args: str, **variables: str) -> subprocess.CompletedProcess:
        self.log.write_text("")
        return subprocess.run(["/bin/bash", str(self.root / "scripts" / script), *args],
                              env={**self.env, **variables}, text=True, capture_output=True, check=False)

    def commands(self) -> list[str]:
        return self.log.read_text().splitlines()

    def test_default_fix_and_check_dispatch_the_same_complete_phases(self) -> None:
        for args, mode in (((), "--fix"), (("--fix",), "--fix"), (("--check",), "--check")):
            with self.subTest(args=args):
                result = self.run_script("check-all.sh", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                dispatched = [line for line in self.commands() if line.startswith("bash ")]
                self.assertEqual(dispatched, [f"bash scripts/format-lint.sh {mode}"] +
                                 [f"bash scripts/run-checks.sh {phase}" for phase in
                                  ("rust", "msrv", "dependencies", "documentation")])

    def test_each_phase_failure_propagates_without_running_later_phases(self) -> None:
        phases = ["format-lint.sh", "run-checks.sh rust", "run-checks.sh msrv", "run-checks.sh dependencies", "run-checks.sh documentation"]
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                result = self.run_script("check-all.sh", "--check", GATE_TEST_FAILURE=phase)
                self.assertEqual(result.returncode, 17)
                self.assertIn("complete validation failed", result.stderr)
                for later in phases[index + 1:]:
                    self.assertFalse(any(later in line for line in self.commands()))

    def test_external_target_fails_before_validation(self) -> None:
        result = self.run_script("check-all.sh", "--check", CARGO_TARGET_DIR="/tmp/shared-gate-target")
        self.assertEqual(result.returncode, 2)
        self.assertIn("inside this worktree", result.stderr)
        self.assertFalse(any(line.startswith("bash ") for line in self.commands()))

    def test_missing_tool_and_invalid_arguments_fail_closed(self) -> None:
        (self.bin / "tombi").unlink()
        result = self.run_script("check-all.sh", "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Missing required tool tombi", result.stderr)
        for arguments in (("--skip-tests",), ("--check", "--fix")):
            self.assertEqual(self.run_script("check-all.sh", *arguments).returncode, 2)
            self.assertEqual(self.commands(), [])

    def test_missing_msrv_or_renovate_cannot_become_a_success(self) -> None:
        for failure in ("rustup run 1.85.0", "node -e"):
            result = self.run_script("check-all.sh", "--check", GATE_TEST_FAILURE=failure)
            self.assertEqual(result.returncode, 17)
            self.assertFalse(any(line.startswith("bash ") for line in self.commands()))

    def test_format_lint_executes_no_tests_and_caps_clippy(self) -> None:
        result = self.run_script("format-lint.sh", "--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cargo fmt --all -- --check", self.commands())
        self.assertIn("cargo ci-clippy", self.commands())
        self.assertFalse(any("ci-test" in line or "test-" in line for line in self.commands()))
        self.assertIn("at most 2 Cargo build jobs", result.stdout)
        self.assertEqual(self.run_script("format-lint.sh", KUBERNETES_LENS_LINT_JOBS="0").returncode, 2)

    def test_lint_failure_stops_before_clippy(self) -> None:
        result = self.run_script("format-lint.sh", "--check", GATE_TEST_FAILURE="actionlint")
        self.assertEqual(result.returncode, 17)
        self.assertNotIn("cargo ci-clippy", self.commands())

    def prepare_real_policy_with_synthetic_fixtures(self) -> Path:
        # Only the pure policy runner is real; Cargo/build/runtime/tool commands remain fake.
        paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "release-plz.toml", "CHANGELOG.md",
                 ".codex/config.toml", "scripts/validation-policy.json", ".github/workflows/ci.yml",
                 ".github/workflows/release.yml", "scripts/renovate-tool.json", "LICENSE",
                 "scripts/test-repository-policy.py"]
        paths.extend(f".codex/agents/{role}.toml" for role in
                     ("implementation-worker", "specification-researcher", "reviewer", "verifier"))
        for name in paths:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        fixtures = self.root / "scripts" / "fixtures"
        fixtures.mkdir()
        (fixtures / "test_materialize.py").write_text(
            "import unittest\n"
            "class OfficialReceiptTests(unittest.TestCase):\n"
            "    def test_official_source_receipt_is_portable_complete_and_has_no_native_success(self):\n"
            "        self.assertEqual(1, 1)\n")
        (fixtures / "test_admission.py").write_text(
            "import unittest\n"
            "class AdmissionExpectationTests(unittest.TestCase):\n"
            "    def test_official_plan_remains_pending_with_independent_closure_counts(self):\n"
            "        self.assertEqual(1, 1)\n")
        return fixtures

    def test_official_fixture_assertion_failure_stops_the_complete_gate(self) -> None:
        fixtures = self.prepare_real_policy_with_synthetic_fixtures()
        result = self.run_script("check-all.sh", "--check", GATE_TEST_REAL_POLICY="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("python3 scripts/test-repository-policy.py", self.commands())
        self.assertIn("python3 scripts/test-check-all.py", self.commands())
        admission = fixtures / "test_admission.py"
        admission.write_text(admission.read_text().replace("self.assertEqual(1, 1)",
                                                         "self.fail('fixture-gate-assertion-witness')"))
        result = self.run_script("check-all.sh", "--check", GATE_TEST_REAL_POLICY="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("fixture-gate-assertion-witness", result.stderr)
        self.assertIn("complete validation failed in documentation", result.stderr)
        self.assertNotIn("python3 scripts/test-check-all.py", self.commands())
        self.assertNotIn("node scripts/test-renovate.mjs", self.commands())

    def test_missing_either_official_fixture_module_cannot_pass_the_complete_gate(self) -> None:
        fixtures = self.prepare_real_policy_with_synthetic_fixtures()
        for name in ("test_materialize.py", "test_admission.py"):
            path = fixtures / name
            original = path.read_text()
            path.unlink()
            with self.subTest(module=name):
                result = self.run_script("check-all.sh", "--check", GATE_TEST_REAL_POLICY="1")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("required official fixture test module missing", result.stderr)
                self.assertIn("complete validation failed in documentation", result.stderr)
                self.assertNotIn("python3 scripts/test-check-all.py", self.commands())
            path.write_text(original)

    def test_nonempty_unrelated_fixture_suite_cannot_replace_expected_test_ids(self) -> None:
        fixtures = self.prepare_real_policy_with_synthetic_fixtures()
        (fixtures / "test_materialize.py").write_text(
            "import unittest\n"
            "class UnrelatedTests(unittest.TestCase):\n"
            "    def test_unrelated_success(self):\n"
            "        pass\n")
        result = self.run_script("check-all.sh", "--check", GATE_TEST_REAL_POLICY="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("required official fixture test identities missing", result.stderr)
        self.assertNotIn("python3 scripts/test-check-all.py", self.commands())

    def test_shared_phase_failure_propagates(self) -> None:
        for phase, failure, later in (("rust", "cargo ci-check", "cargo ci-clippy"),
                                      ("msrv", "rustup run", "cargo +1.85.0 ci-check"),
                                      ("documentation", "actionlint", "node scripts/test-renovate.mjs"),
                                      ("documentation", "python3 scripts/compatibility-ledger.py", "python3 scripts/test-compatibility-ledger.py"),
                                      ("documentation", "python3 scripts/test-compatibility-ledger.py", "node scripts/test-renovate.mjs")):
            result = self.run_script("run-checks.sh", phase, GATE_TEST_FAILURE=failure)
            self.assertEqual(result.returncode, 17)
            self.assertNotIn(later, self.commands())

if __name__ == "__main__":
    unittest.main()
