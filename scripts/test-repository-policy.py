#!/usr/bin/env python3
"""Repository boundaries and required source-only official fixture preparation/admission tests."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
LICENSE_SHA256 = "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"


def snapshot() -> dict[str, str]:
    paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "release-plz.toml", "CHANGELOG.md",
             ".codex/config.toml", "scripts/validation-policy.json", ".github/workflows/ci.yml",
             ".github/workflows/release.yml", "scripts/renovate-tool.json", "LICENSE"]
    return {name: (ROOT / name).read_text() for name in paths}


def validate(files: dict[str, str]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"])
    package = manifest["package"]
    assert package["name"] == "kubernetes-lens"
    assert package["edition"] == "2024" and package["rust-version"] == "1.85.0"
    assert package["license"] == "MPL-2.0" and package["publish"] is False
    assert package["repository"] == "https://github.com/Strukturpiloten/kubernetes-lens"
    assert hashlib.sha256(files["LICENSE"].encode()).hexdigest() == LICENSE_SHA256
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        assert not any(name.startswith("boxferry") for name in manifest.get(section, {}))
    dependencies = manifest.get("dependencies", {})
    assert set(dependencies) >= {"serde", "serde_json", "yaml-rust2"}
    target_dependencies = manifest["target"]['cfg(target_os = "linux")']["dependencies"]
    assert set(target_dependencies) == {"libc"}
    for dependency in [*dependencies.values(), *target_dependencies.values()]:
        version = dependency if isinstance(dependency, str) else dependency["version"]
        assert re.fullmatch(r"=\d+\.\d+\.\d+", version), "exact product dependency required"
    assert "raw_value" in dependencies["serde_json"]["features"]
    assert dependencies["yaml-rust2"]["default-features"] is False
    assert "/schemas/capabilities/**" in package["include"]
    assert "/docs/compatibility/licenses/**" in package["include"]
    lock = tomllib.loads(files["Cargo.lock"])
    assert any(p["name"] == package["name"] and p["version"] == package["version"] for p in lock["package"])
    for entry in lock["package"]:
        if entry["name"] != package["name"]:
            assert entry.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
            assert re.fullmatch(r"[a-f0-9]{64}", entry.get("checksum", "")), "registry integrity required"
    toolchain = tomllib.loads(files["rust-toolchain.toml"])["toolchain"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["channel"])
    assert set(toolchain["components"]) >= {"clippy", "rustfmt"}
    release = tomllib.loads(files["release-plz.toml"])
    for settings in [release["workspace"], *release["package"]]:
        assert all(settings[key] is False for key in ("publish", "git_tag_enable", "git_release_enable"))
    assert files["CHANGELOG.md"].count("## [Unreleased]") == 1
    assert not re.search(r"^## \[\d", files["CHANGELOG.md"], re.M), "no fabricated release record before initial publication"
    agent = tomllib.loads(files[".codex/config.toml"])
    assert agent["model"] == "gpt-6.1-sol" and agent["model_reasoning_effort"] == "xhigh"
    assert agent["agents"]["max_concurrent_threads_per_session"] == 8
    policy = json.loads(files["scripts/validation-policy.json"])
    ci = files[".github/workflows/ci.yml"]
    jobs = set(re.findall(r"^  ([a-z][a-z-]*):$", ci.split("\njobs:\n", 1)[1], re.M))
    assert jobs == {"validation-plan", "pr-gate", *policy["jobs"]}
    assert "      [" in ci and "if: always()" in ci
    for name in (".github/workflows/ci.yml", ".github/workflows/release.yml"):
        workflow = files[name]
        assert workflow.startswith("---\n")
        assert not re.search(r"^\s+(?:contents|packages|id-token|actions):\s*write", workflow, re.M)
        assert not re.search(r"cargo publish|git tag|gh release create|kubectl apply|helm (?:install|upgrade)", workflow)
        for declaration in re.findall(r"^\s+uses: (.+)$", workflow, re.M):
            assert declaration.startswith("./") or re.fullmatch(r"[^@\s]+@[0-9a-f]{40} # v[0-9.]+", declaration)
    manual = files[".github/workflows/release.yml"].split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert manual.strip() == "workflow_dispatch:"
    assert "uses: ./.github/workflows/ci.yml" in files[".github/workflows/release.yml"]
    tool = json.loads(files["scripts/renovate-tool.json"])
    assert re.fullmatch(r"ghcr\.io/renovatebot/renovate:[0-9]+\.[0-9]+\.[0-9]+@sha256:[a-f0-9]{64}", tool["image"])



class RepositoryPolicyTests(unittest.TestCase):
    def test_checked_in_policy(self) -> None:
        validate(snapshot())
        self.assertFalse((ROOT / "package.json").exists(), "no local operational npm graph")
        self.assertFalse((ROOT / "package-lock.json").exists())
        self.assertFalse((ROOT / ".devcontainer").exists(), "shared development container has one owner")
        self.assertFalse((ROOT / "scripts/install-kubernetes-tools.sh").exists())
        self.assertFalse((ROOT / "scripts/install-file-tools.sh").exists())

    def test_agent_role_files_match_supported_standalone_schema(self) -> None:
        for role, model, sandbox in (("implementation-worker", "gpt-6.1-sol", "workspace-write"),
                                     ("specification-researcher", "gpt-6.1-sol", "read-only"),
                                     ("reviewer", "gpt-6.1-sol", "read-only"),
                                     ("verifier", "gpt-6-luna", "workspace-write")):
            agent = tomllib.loads((ROOT / f".codex/agents/{role}.toml").read_text())
            self.assertTrue(all(agent.get(field) for field in ("name", "description", "developer_instructions")))
            self.assertEqual(agent["model"], model)
            self.assertEqual(agent["model_reasoning_effort"], "high")
            self.assertEqual(agent["sandbox_mode"], sandbox)

    def rejected(self, name: str, old: str, new: str) -> None:
        changed = copy.deepcopy(snapshot())
        self.assertIn(old, changed[name])
        changed[name] = changed[name].replace(old, new)
        with self.assertRaises(AssertionError):
            validate(changed)

    def test_publication_and_privilege_mutations_fail(self) -> None:
        self.rejected("Cargo.toml", "publish = false", "publish = true")
        self.rejected("release-plz.toml", "git_tag_enable = false", "git_tag_enable = true")
        self.rejected(".github/workflows/ci.yml", "contents: read", "contents: write")
        self.rejected(".github/workflows/release.yml", "workflow_dispatch:", "push:")

    def test_license_msrv_and_manager_selection_are_hard_contracts(self) -> None:
        self.rejected("LICENSE", "Mozilla Public License", "Other License")
        self.rejected("Cargo.toml", 'rust-version = "1.85.0"', 'rust-version = "1.98.1"')
        self.rejected(".codex/config.toml", 'model = "gpt-6.1-sol"', 'model = "gpt-6-sol"')

    def test_foundation_dependency_integrity_and_packaged_licenses(self) -> None:
        dependency = re.search(r'version = "(=\d+\.\d+\.\d+)"', snapshot()["Cargo.toml"])
        self.assertIsNotNone(dependency)
        self.rejected("Cargo.toml", dependency.group(0), f'version = "{dependency.group(1)[1:]}"')
        self.rejected("Cargo.toml", 'features = ["raw_value"]', 'features = []')
        self.rejected("Cargo.toml", '"/docs/compatibility/licenses/**"', '"/missing-license/**"')
        checksum = re.search(r'checksum = "([a-f0-9]{64})"', snapshot()["Cargo.lock"])
        self.assertIsNotNone(checksum)
        self.rejected("Cargo.lock", checksum.group(0), 'checksum = "invalid"')

    def test_removed_job_or_unpinned_action_fails(self) -> None:
        self.rejected(".github/workflows/ci.yml", "  msrv:\n", "  renamed-msrv:\n")
        checkout_pin = re.search(
            r"actions/checkout@[0-9a-f]{40}", snapshot()[".github/workflows/ci.yml"]
        )
        self.assertIsNotNone(checkout_pin)
        self.rejected(
            ".github/workflows/ci.yml", checkout_pin.group(0), "actions/checkout@floating"
        )

    def test_fake_published_history_or_duplicate_inventory_fails(self) -> None:
        self.rejected("CHANGELOG.md", "## [Unreleased]", "## [Unreleased]\n\n## [0.1.0]")
        self.rejected("scripts/renovate-tool.json", "@sha256:", "@sha256-invalid:")

REQUIRED_OFFICIAL_FIXTURE_TEST_IDS = {
    "test_materialize.OfficialReceiptTests.test_official_source_receipt_is_portable_complete_and_has_no_native_success",
    "test_admission.AdmissionExpectationTests.test_official_plan_remains_pending_with_independent_closure_counts",
}


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """Include the source-only fixtures in every existing policy/gate invocation."""
    directory = ROOT / "scripts" / "fixtures"
    for name in ("test_materialize.py", "test_admission.py"):
        if not (directory / name).is_file():
            raise RuntimeError("required official fixture test module missing")
    fixtures = loader.discover(str(directory), pattern="test_*.py", top_level_dir=str(directory))

    def case_ids(suite: unittest.TestSuite):
        for case in suite:
            if isinstance(case, unittest.TestSuite):
                yield from case_ids(case)
            else:
                yield case.id()

    identities = list(case_ids(fixtures))
    if (not REQUIRED_OFFICIAL_FIXTURE_TEST_IDS.issubset(identities)
            or len(set(identities)) != len(identities)):
        raise RuntimeError("required official fixture test identities missing or duplicated")
    tests.addTests(fixtures)
    return tests


if __name__ == "__main__":
    unittest.main()
