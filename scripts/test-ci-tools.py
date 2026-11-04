#!/usr/bin/env python3
"""Exercise canonical tool delegation without real downloads or installations."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ["tombi", "shfmt", "shellcheck", "hadolint", "actionlint", "lychee"]


class SharedToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="kubernetes-lens-ci-tools-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shared = self.root / "shared"
        self.repository = self.root / "repository"
        self.bin = self.root / "bin"
        for directory in (
            self.shared / ".devcontainer",
            self.shared / "automation/src/boxferry_ci",
            self.repository / "scripts",
            self.bin,
        ):
            directory.mkdir(parents=True)
        (self.repository / "scripts/setup-ci-tools.sh").write_text(
            (ROOT / "scripts/setup-ci-tools.sh").read_text()
        )
        self.dockerfile = self.shared / ".devcontainer/Dockerfile"
        # Canonical550 removed the other version ARGs; this fixture must not need them.
        self.dockerfile.write_text("ARG ZIZMOR_VERSION=2.3.4\n")
        self.inventory = self.shared / "automation/tool-artifacts.json"
        self.inventory.write_text('{"schema": 1}\n')
        for name in ("package.json", "package-lock.json"):
            (self.shared / name).write_text("{}\n")
        self.installer = self.shared / "automation/src/boxferry_ci/tooling.py"
        self.installer.write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "with open(os.environ['MOCK_COMMANDS'], 'a') as log:\n"
            "    log.write('canonical-tools ' + json.dumps(sys.argv[1:]) + '\\n')\n"
            "if os.environ.get('MOCK_FAILURE') == 'canonical':\n"
            "    print('canonical fixture integrity failure', file=sys.stderr)\n"
            "    raise SystemExit(19)\n"
            "assert sys.argv[1] == '--destination' and sys.argv[3] == '--tools'\n"
            f"assert sys.argv[4:] == {TOOLS!r}\n"
            "for name in sys.argv[4:]:\n"
            "    (Path(sys.argv[2]) / name).write_text('shared verified binary fixture\\n')\n"
        )
        for tool, code in (("cargo", 17), ("npm", 13)):
            executable = self.bin / tool
            executable.write_text(
                "#!/bin/sh\n"
                "name=${0##*/}\n"
                'printf "%s %s\\n" "$name" "$*" >> "$MOCK_COMMANDS"\n'
                f'[ "${{MOCK_FAILURE:-}}" != "$name" ] || exit {code}\n'
            )
            executable.chmod(0o755)
        for tool in ("curl", "wget", "tar"):
            executable = self.bin / tool
            executable.write_text('#!/bin/sh\nprintf "unexpected downloader\\n" >&2\nexit 98\n')
            executable.chmod(0o755)
        self.log = self.root / "commands"
        self.path_output = self.root / "github-path"
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "MOCK_COMMANDS": str(self.log),
            "GITHUB_PATH": str(self.path_output),
        }

    def run_setup(
        self, arguments: list[str] | None = None, **overrides: str
    ) -> subprocess.CompletedProcess[str]:
        selected = [str(self.shared)] if arguments is None else arguments
        return subprocess.run(
            ["/bin/bash", str(self.repository / "scripts/setup-ci-tools.sh"), *selected],
            env={**self.env, **overrides},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_production_script_uses_six_shared_tools_without_removed_args(self) -> None:
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.log.read_text().splitlines()
        self.assertEqual(
            json.loads(commands[0].removeprefix("canonical-tools ")),
            [
                "--destination",
                str(self.repository / ".ci-tools/bin"),
                "--tools",
                *TOOLS,
            ],
        )
        self.assertEqual(
            commands[1],
            f"cargo install --locked --version 2.3.4 --root {self.repository / '.ci-tools'} zizmor",
        )
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", commands[2])
        self.assertEqual(len(commands), 3)
        self.assertEqual((self.repository / ".ci-tools/node/package-lock.json").read_text(), "{}\n")
        self.assertTrue(all((self.repository / ".ci-tools/bin" / name).is_file() for name in TOOLS))
        self.assertEqual(
            self.path_output.read_text().splitlines(),
            [
                str(self.repository / ".ci-tools/bin"),
                str(self.repository / ".ci-tools/node/node_modules/.bin"),
            ],
        )

    def test_missing_or_duplicate_remaining_cargo_pin_fails_before_installation(self) -> None:
        for content in ("", "ARG ZIZMOR_VERSION=2.3.4\nARG ZIZMOR_VERSION=2.3.5\n"):
            with self.subTest(content=content):
                self.dockerfile.write_text(content)
                result = self.run_setup()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("missing or duplicated: ZIZMOR", result.stderr)
                self.assertFalse(self.log.exists())
                self.assertFalse(self.path_output.exists())

    def test_missing_canonical_inventory_or_installer_has_no_legacy_fallback(self) -> None:
        for path in (self.inventory, self.installer):
            with self.subTest(path=path.name):
                contents = path.read_bytes()
                path.unlink()
                result = self.run_setup()
                self.assertEqual(result.returncode, 2)
                self.assertIn("pinned adoption revision", result.stderr)
                self.assertFalse(self.log.exists())
                self.assertFalse(self.path_output.exists())
                path.write_bytes(contents)

    def test_canonical_integrity_failure_propagates_without_cargo_npm_or_path(self) -> None:
        result = self.run_setup(MOCK_FAILURE="canonical")
        self.assertEqual(result.returncode, 19)
        self.assertIn("canonical fixture integrity failure", result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)
        self.assertFalse(self.path_output.exists())

    def test_cargo_failure_prevents_npm_and_path_export(self) -> None:
        result = self.run_setup(MOCK_FAILURE="cargo")
        self.assertEqual(result.returncode, 17)
        self.assertEqual(len(self.log.read_text().splitlines()), 2)
        self.assertFalse(self.path_output.exists())

    def test_npm_failure_prevents_path_export(self) -> None:
        result = self.run_setup(MOCK_FAILURE="npm")
        self.assertEqual(result.returncode, 13)
        self.assertEqual(len(self.log.read_text().splitlines()), 3)
        self.assertFalse(self.path_output.exists())

    def test_invalid_arguments_never_install(self) -> None:
        for arguments in ([], [str(self.shared), "extra"]):
            with self.subTest(arguments=arguments):
                result = self.run_setup(arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)
                self.assertFalse(self.log.exists())
                self.assertFalse(self.path_output.exists())


if __name__ == "__main__":
    unittest.main()
