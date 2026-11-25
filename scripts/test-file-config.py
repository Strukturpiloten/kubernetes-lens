#!/usr/bin/env python3
"""Exercise production formatter isolation with real Prettier and unrelated lint stubs."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_JSON = ('{ "values": ["alpha-alpha-alpha", "bravo-bravo-bravo", '
                 '"charlie-charlie", "delta-delta"] }\n')
INPUT_JSON = ('{"values":["alpha-alpha-alpha","bravo-bravo-bravo",'
              '"charlie-charlie","delta-delta"]}\n')
PROSE = ("# Fixture\n\n"
         "A deliberately long paragraph keeps its supplied line because this repository "
         "uses preserved prose, regardless of the conflicting workspace and nested "
         "formatter settings.\n")


class FileConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-file-config-")
        self.addCleanup(self.directory.cleanup)
        self.parent = Path(self.directory.name)
        self.repository = self.parent / "repository"
        self.bin = self.parent / "bin"
        self.unrelated = self.parent / "unrelated"
        for directory in (self.repository / "scripts", self.repository / "nested", self.bin, self.unrelated):
            directory.mkdir(parents=True)
        self.script = self.repository / "scripts/check-files.sh"
        shutil.copyfile(ROOT / "scripts/check-files.sh", self.script)
        # Normal gates use the production immutable launcher. An explicitly supplied
        # development fixture can exercise an unadmitted producer without repinning.
        launcher = Path(os.environ.get("KUBERNETES_LENS_TEST_SHARED_CI", ROOT / "scripts/shared-ci.py"))
        shutil.copyfile(launcher, self.repository / "scripts/shared-ci.py")
        (self.repository / ".github").mkdir()
        shutil.copyfile(ROOT / ".github/automation.json", self.repository / ".github/automation.json")
        shutil.copyfile(ROOT / ".markdownlint.json", self.repository / ".markdownlint.json")
        self.config = self.repository / ".prettierrc.json"
        shutil.copyfile(ROOT / ".prettierrc.json", self.config)
        shutil.copyfile(ROOT / ".editorconfig", self.repository / ".editorconfig")
        (self.repository / ".prettierignore").write_text("")
        (self.parent / ".prettierrc.json").write_text('{"printWidth":20,"proseWrap":"always"}\n')
        (self.repository / "nested/.prettierrc.json").write_text(
            '{"printWidth":20,"proseWrap":"always"}\n')
        (self.repository / "README.md").write_text(PROSE)
        for name in ("resource.json", "nested/resource.json"):
            (self.repository / name).write_text(INPUT_JSON)
        (self.repository / "untouched.bin").write_bytes(b"unrelated-sentinel\x00\xff")
        # Only file enumeration and unrelated linters are stubs. The production script
        # resolves and executes the actual installed Prettier for every invocation.
        git = self.bin / "git"
        git.write_text(r"""#!/bin/sh
[ "$1" = ls-files ] || exec /usr/bin/git "$@"
case "$*" in
  *'*.md'*) printf 'README.md\000' ;;
  *'*.json'*) printf '.prettierrc.json\000resource.json\000nested/.prettierrc.json\000nested/resource.json\000' ;;
  *'*.yaml'* | *'*.toml'* | *'*.sh'* | *Dockerfile*) : ;;
  *) exec /usr/bin/git "$@" ;;
esac
""")
        git.chmod(0o755)
        for name in ("hadolint", "shellcheck", "shfmt", "tombi"):
            tool = self.bin / name
            tool.write_text("#!/bin/sh\nexit 0\n")
            tool.chmod(0o755)
        for name in ("prettier", "markdownlint-cli2"):
            tool = self.bin / name
            tool.write_text("#!/bin/sh\necho unrelated-PATH-formatter >&2\nexit 97\n")
            tool.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"}
        self.parent_before = (self.parent / ".prettierrc.json").read_bytes()
        self.script_before = self.script.read_bytes()
        self.sentinel_before = (self.repository / "untouched.bin").read_bytes()

    def run_script(self, mode: str) -> subprocess.CompletedProcess:
        return subprocess.run(["/bin/bash", str(self.script), mode], cwd=self.unrelated,
                              env=self.env, text=True, capture_output=True, timeout=60, check=False)

    def snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.repository)): path.read_bytes()
                for path in self.repository.rglob("*")
                if path.is_file() and "target" not in path.relative_to(self.repository).parts}

    def assert_unrelated_preserved(self) -> None:
        self.assertEqual((self.parent / ".prettierrc.json").read_bytes(), self.parent_before)
        self.assertEqual(self.script.read_bytes(), self.script_before)
        self.assertEqual((self.repository / "untouched.bin").read_bytes(), self.sentinel_before)

    def test_actual_prettier_uses_independent_width_and_prose_expectations(self) -> None:
        self.assertGreater(len(EXPECTED_JSON.rstrip()), 80)
        self.assertLessEqual(len(EXPECTED_JSON.rstrip()), 100)
        result = self.run_script("--fix")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ("resource.json", "nested/resource.json"):
            self.assertEqual((self.repository / name).read_text(), EXPECTED_JSON)
        self.assertEqual((self.repository / "README.md").read_text(), PROSE)
        self.assert_unrelated_preserved()

    def test_fix_check_converges_from_unrelated_working_directory(self) -> None:
        result = self.run_script("--fix")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        before = self.snapshot()
        result = self.run_script("--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assert_unrelated_preserved()

    def test_dirty_check_and_markdown_lint_failures_propagate(self) -> None:
        result = self.run_script("--check")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        (self.repository / "README.md").write_text("# Fixture\n\n# Fixture\n")
        result = self.run_script("--fix")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("MD024", result.stdout + result.stderr)

    def test_explicit_ignore_preserves_ignored_consumer_input(self) -> None:
        (self.repository / ".prettierignore").write_text("resource.json\n")
        result = self.run_script("--fix")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repository / "resource.json").read_text(), INPUT_JSON)

    def test_selected_prettier_preserves_stdin_and_stdout(self) -> None:
        result = subprocess.run(
            ["python3", str(self.repository / "scripts/shared-ci.py"), "node-tool",
             "--cwd", str(self.repository), "prettier", "--config", str(self.config),
             "--ignore-path", str(self.repository / ".prettierignore"),
             "--stdin-filepath", "resource.json"],
            cwd=self.unrelated, env=self.env, input=INPUT_JSON, text=True,
            capture_output=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, EXPECTED_JSON)

    def test_missing_owning_config_refuses_despite_valid_ancestor(self) -> None:
        self.config.unlink()
        before = self.snapshot()
        for mode in ("--fix", "--check"):
            with self.subTest(mode=mode):
                result = self.run_script(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(".prettierrc.json", result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assert_unrelated_preserved()

    def test_malformed_owning_config_refuses_without_fallback(self) -> None:
        self.config.write_text("{invalid-config\n")
        before = self.snapshot()
        for mode in ("--fix", "--check"):
            with self.subTest(mode=mode):
                result = self.run_script(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(".prettierrc.json", result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assert_unrelated_preserved()

    def test_control_without_explicit_config_uses_nearer_conflicting_settings(self) -> None:
        source = self.script.read_text()
        qualified = 'prettier --config "${repository_root}/.prettierrc.json" '
        self.assertEqual(source.count(qualified), 4)
        self.script.write_text(source.replace(qualified, "prettier "))
        result = self.run_script("--fix")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repository / "resource.json").read_text(), EXPECTED_JSON)
        self.assertNotEqual((self.repository / "nested/resource.json").read_text(), EXPECTED_JSON)
        self.assertEqual((self.parent / ".prettierrc.json").read_bytes(), self.parent_before)
        self.assertEqual((self.repository / "untouched.bin").read_bytes(), self.sentinel_before)


if __name__ == "__main__":
    unittest.main()
