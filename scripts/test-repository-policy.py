#!/usr/bin/env python3
"""Repository boundaries and required source-only official fixture preparation/admission tests."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import tomllib
import unittest
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LICENSE_SHA256 = "3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04"


def snapshot() -> dict[str, str]:
    paths = [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "clippy.toml",
        "release-plz.toml",
        "CHANGELOG.md",
        ".codex/config.toml",
        "scripts/validation-policy.json",
        "scripts/ci-api-transition.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/workflows/dependency-eligibility.yml",
        ".github/automation.json",
        "scripts/release-policy.json",
        "scripts/renovate-tool.json",
        "LICENSE",
    ]
    return {name: (ROOT / name).read_text() for name in paths}


def validate(files: dict[str, str]) -> None:
    manifest = tomllib.loads(files["Cargo.toml"])
    package = manifest["package"]
    assert package["name"] == "kubernetes-lens"
    assert package["edition"] == "2024" and package["rust-version"] == "1.98.1"
    assert tomllib.loads(files["clippy.toml"])["msrv"] == package["rust-version"]
    assert package["license"] == "MPL-2.0" and package["publish"] is False
    assert package["repository"] == "https://github.com/Strukturpiloten/kubernetes-lens"
    assert hashlib.sha256(files["LICENSE"].encode()).hexdigest() == LICENSE_SHA256
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        assert not any(name.startswith("boxferry") for name in manifest.get(section, {}))
    dependencies = manifest.get("dependencies", {})
    assert set(dependencies) >= {"serde", "serde_json", "yaml-rust2"}
    target_dependencies = manifest["target"]['cfg(target_os = "linux")']["dependencies"]
    assert set(target_dependencies) == {"libc", "nix", "rustix", "command-fds", "close_fds", "sha2"}
    renderer_dependencies = {"nix", "rustix", "command-fds", "close_fds", "sha2"}
    assert set(manifest["features"]["supervised-renderer"]) == {
        "dep:" + name for name in renderer_dependencies
    }
    assert all(target_dependencies[name].get("optional") is True for name in renderer_dependencies)
    assert target_dependencies["sha2"]["default-features"] is False
    assert dependencies["serde"]["features"] == ["derive"]
    assert {binary["name"] for binary in manifest["bin"]} == {
        "kubernetes-lens-renderer-helper",
        "renderer-gate",
    }
    assert all(binary["required-features"] == ["supervised-renderer"] for binary in manifest["bin"])
    for dependency in [*dependencies.values(), *target_dependencies.values()]:
        version = dependency if isinstance(dependency, str) else dependency["version"]
        assert re.fullmatch(r"=\d+\.\d+\.\d+", version), "exact product dependency required"
    assert "raw_value" in dependencies["serde_json"]["features"]
    assert dependencies["yaml-rust2"]["default-features"] is False
    assert "/schemas/capabilities/**" in package["include"]
    assert "/docs/compatibility/licenses/**" in package["include"]
    lock = tomllib.loads(files["Cargo.lock"])
    assert any(
        p["name"] == package["name"] and p["version"] == package["version"] for p in lock["package"]
    )
    for entry in lock["package"]:
        if entry["name"] != package["name"]:
            assert entry.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
            assert re.fullmatch(r"[a-f0-9]{64}", entry.get("checksum", "")), (
                "registry integrity required"
            )
    toolchain = tomllib.loads(files["rust-toolchain.toml"])["toolchain"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["channel"])
    assert tuple(map(int, toolchain["channel"].split("."))) >= tuple(
        map(int, package["rust-version"].split("."))
    ), "normal toolchain must support the declared minimum"
    assert set(toolchain["components"]) >= {"clippy", "rustfmt"}
    release = tomllib.loads(files["release-plz.toml"])
    for settings in [release["workspace"], *release["package"]]:
        assert all(
            settings[key] is False for key in ("publish", "git_tag_enable", "git_release_enable")
        )
    assert files["CHANGELOG.md"].count("## [Unreleased]") == 1
    assert not re.search(r"^## \[\d", files["CHANGELOG.md"], re.M), (
        "no fabricated release record before initial publication"
    )
    agent = tomllib.loads(files[".codex/config.toml"])
    assert agent["model"] == "gpt-6.1-sol" and agent["model_reasoning_effort"] == "xhigh"
    assert agent["agents"]["max_concurrent_threads_per_session"] == 8
    policy = json.loads(files["scripts/validation-policy.json"])
    ci = files[".github/workflows/ci.yml"]
    jobs = set(re.findall(r"^  ([a-z][a-z-]*):$", ci.split("\njobs:\n", 1)[1], re.M))
    assert jobs == {"validation-plan", "pr-gate", *policy["jobs"]}
    aggregate = ci.split("\n  pr-gate:\n", 1)[1]
    next_job = re.search(r"^  [a-z][a-z-]*:\n", aggregate, re.M)
    if next_job:
        aggregate = aggregate[: next_job.start()]
    assert re.findall(r"^    name: (.+)$", aggregate, re.M) == ["Required CI"], (
        "protected aggregate check name must match the organization rule"
    )
    assert len(re.findall(r"^    name: Required CI$", ci, re.M)) == 1, (
        "protected aggregate check name must be unique"
    )
    prerequisite = re.search(r"^    needs:\s*\[([^]]+)\]", aggregate, re.M)
    assert prerequisite, "aggregate must declare every planned job dependency"
    assert {name.strip() for name in prerequisite.group(1).split(",")} == {
        "validation-plan",
        *policy["jobs"],
    }
    assert "    if: always()" in aggregate
    automation = json.loads(files[".github/automation.json"])
    assert re.fullmatch(r"[a-f0-9]{40}", automation["revision"]), (
        "shared implementation must be immutable"
    )
    for name in (
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ):
        workflow = files[name]
        assert workflow.startswith("---\n")
        assert not re.search(r"^\s+(?:contents|packages|id-token|actions):\s*write", workflow, re.M)
        assert not re.search(
            r"cargo publish|git tag|gh release create|kubectl apply|helm (?:install|upgrade)",
            workflow,
        )
        for declaration in re.findall(r"^\s+uses: (.+)$", workflow, re.M):
            if declaration.startswith("./"):
                continue
            pinned = re.fullmatch(r"([^@\s]+)@([0-9a-f]{40}) # (.+)", declaration)
            assert pinned, "every remote action and workflow requires a full immutable SHA"
            action, _revision, comment = pinned.groups()
            shared = {
                "Strukturpiloten/boxferry/.github/workflows/shared-rust-ci.yml",
                "Strukturpiloten/boxferry/.github/workflows/shared-rust-semver.yml",
                "Strukturpiloten/boxferry/.github/workflows/shared-rust-dependencies.yml",
                "Strukturpiloten/boxferry/.github/workflows/shared-release-validation.yml",
                "Strukturpiloten/boxferry/.github/workflows/shared-dependency-wait.yml",
            }
            if action in shared:
                assert comment == "automation-v1 interface v1", (
                    "initial shared infrastructure must not invent a release tag"
                )
                assert _revision == automation["revision"], (
                    "shared workflow and implementation revisions must match"
                )
            else:
                assert re.fullmatch(r"v[0-9.]+", comment), (
                    "other remote actions need exact release comments"
                )
    manual = (
        files[".github/workflows/release.yml"].split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    )
    assert manual.strip() == "workflow_dispatch:"
    assert "uses: ./.github/workflows/ci.yml" in files[".github/workflows/release.yml"]
    release_policy = json.loads(files["scripts/release-policy.json"])
    assert release_policy == {
        "schema": 1,
        "repository": "Strukturpiloten/kubernetes-lens",
        "packages": ["kubernetes-lens"],
        "required_jobs": ["validate"],
        "publication_enabled": False,
    }, "unpublished release validation cannot authorize publication"
    assert "config_path: scripts/release-policy.json" in files[".github/workflows/release.yml"]
    assert "needs_json: ${{ toJSON(needs) }}" in files[".github/workflows/release.yml"]
    assert "candidate_sha: ${{ steps.gate.outputs.candidate_sha }}" in ci
    automation = json.loads(files[".github/automation.json"])
    assert automation["repository"] == "Strukturpiloten/boxferry" and automation["interface"] == 1
    assert re.fullmatch(r"[a-f0-9]{40}", automation["revision"]), (
        "shared implementation must be immutable"
    )
    service = files[".github/workflows/dependency-eligibility.yml"]
    assert service.startswith("---\n")
    triggers = re.split(r"\non:[^\n]*\n", service, maxsplit=1)[1].split("\npermissions:", 1)[0]
    assert "  schedule:" in triggers
    assert "  workflow_run:" in triggers
    assert "    workflows: [CI]" in triggers and "    types: [requested, completed]" in triggers
    assert re.findall(r"^name: (.+)$", ci, re.M) == ["CI"]
    assert not re.search(r"^  (?:pull_request|pull_request_target|merge_group):", triggers, re.M)
    declarations = re.findall(r"^\s+uses: (.+)$", service, re.M)
    expected = (
        "Strukturpiloten/boxferry/.github/workflows/shared-dependency-eligibility.yml@"
        + automation["revision"]
        + " # automation-v1 interface v1"
    )
    assert declarations == [expected], (
        "trusted service caller executes only its exact immutable implementation"
    )
    assert f"      automation-sha: {automation['revision']}" in service
    assert not re.search(r"^\s+(?:run|steps|secrets):", service, re.M)
    permissions = service.split("\npermissions:\n", 1)[1].split("\nconcurrency:", 1)[0]
    assert set(permissions.splitlines()) == {
        "  contents: read",
        "  actions: write",
        "  pull-requests: read",
        "  statuses: write",
    }
    tool = json.loads(files["scripts/renovate-tool.json"])
    assert re.fullmatch(
        r"ghcr\.io/renovatebot/renovate:[0-9]+\.[0-9]+\.[0-9]+@sha256:[a-f0-9]{64}", tool["image"]
    )


class RepositoryPolicyTests(unittest.TestCase):
    def test_checked_in_policy(self) -> None:
        validate(snapshot())
        self.assertFalse((ROOT / "package.json").exists(), "no local operational npm graph")
        self.assertFalse((ROOT / "package-lock.json").exists())
        self.assertFalse(
            (ROOT / ".devcontainer").exists(), "shared development container has one owner"
        )
        self.assertFalse((ROOT / "scripts/install-kubernetes-tools.sh").exists())
        self.assertFalse((ROOT / "scripts/install-file-tools.sh").exists())

    def test_agent_role_files_match_supported_standalone_schema(self) -> None:
        for role, model, effort, sandbox in (
            ("implementation-worker", "gpt-6.1-sol", "high", "workspace-write"),
            ("specification-researcher", "gpt-6.1-sol", "high", "read-only"),
            ("reviewer", "gpt-6.1-sol", "high", "read-only"),
            ("presentation-worker", "gpt-6.1-terra", "medium", "workspace-write"),
            ("verifier", "gpt-6-luna", "high", "workspace-write"),
        ):
            agent = tomllib.loads((ROOT / f".codex/agents/{role}.toml").read_text())
            self.assertTrue(
                all(agent.get(field) for field in ("name", "description", "developer_instructions"))
            )
            self.assertEqual(agent["model"], model)
            self.assertEqual(agent["model_reasoning_effort"], effort)
            self.assertEqual(agent["sandbox_mode"], sandbox)
            if role == "presentation-worker":
                for required in (
                    "explicit file ownership",
                    "Escalate architecture, native-format semantics, security, migrations",
                    "Browser and application inspection is read-only",
                    "Git or GitHub writes",
                    "A Sol reviewer independently checks the original requirements",
                ):
                    self.assertIn(required, agent["developer_instructions"])

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
        self.rejected("Cargo.toml", 'rust-version = "1.98.1"', 'rust-version = "1.85.0"')
        self.rejected(".codex/config.toml", 'model = "gpt-6.1-sol"', 'model = "gpt-6-sol"')

    def test_rust_minimum_and_normal_toolchain_drift_fail(self) -> None:
        for old_minimum in ("1.85.0", "1.98.0"):
            with self.subTest(minimum=old_minimum):
                self.rejected(
                    "Cargo.toml", 'rust-version = "1.98.1"', f'rust-version = "{old_minimum}"'
                )
                self.rejected("clippy.toml", 'msrv = "1.98.1"', f'msrv = "{old_minimum}"')
                self.rejected(
                    "rust-toolchain.toml", 'channel = "1.98.1"', f'channel = "{old_minimum}"'
                )
        changed = snapshot()
        changed["rust-toolchain.toml"] = changed["rust-toolchain.toml"].replace(
            'channel = "1.98.1"', 'channel = "1.99.0"'
        )
        validate(changed)

    def test_foundation_dependency_integrity_and_packaged_licenses(self) -> None:
        dependency = re.search(r'version = "(=\d+\.\d+\.\d+)"', snapshot()["Cargo.toml"])
        self.assertIsNotNone(dependency)
        assert dependency is not None
        self.rejected("Cargo.toml", dependency.group(0), f'version = "{dependency.group(1)[1:]}"')
        self.rejected("Cargo.toml", 'features = ["raw_value"]', "features = []")
        self.rejected("Cargo.toml", '"/docs/compatibility/licenses/**"', '"/missing-license/**"')
        checksum = re.search(r'checksum = "([a-f0-9]{64})"', snapshot()["Cargo.lock"])
        self.assertIsNotNone(checksum)
        assert checksum is not None
        self.rejected("Cargo.lock", checksum.group(0), 'checksum = "invalid"')

    def test_removed_job_or_unpinned_action_fails(self) -> None:
        self.rejected(".github/workflows/ci.yml", "  msrv:\n", "  renamed-msrv:\n")
        checkout_pin = re.search(
            r"actions/checkout@[0-9a-f]{40}", snapshot()[".github/workflows/ci.yml"]
        )
        self.assertIsNotNone(checkout_pin)
        assert checkout_pin is not None
        self.rejected(
            ".github/workflows/ci.yml", checkout_pin.group(0), "actions/checkout@floating"
        )

    def test_aggregate_dependency_cannot_disappear_while_job_still_exists(self) -> None:
        self.rejected(
            ".github/workflows/ci.yml",
            "[validation-plan, rust, api, msrv, dependencies, documentation, lockfile-release-age]",
            "[validation-plan, msrv, dependencies, documentation, lockfile-release-age]",
        )

    def test_protected_aggregate_name_cannot_drift_disappear_or_duplicate(self) -> None:
        name = "    name: Required CI\n"
        for replacement in ("    name: PR gate\n", "", name + name):
            with self.subTest(replacement=replacement):
                self.rejected(".github/workflows/ci.yml", name, replacement)
        self.rejected(".github/workflows/ci.yml", "    name: Rust quality\n", name)

    def test_protected_name_on_another_job_does_not_replace_the_aggregate(self) -> None:
        changed = snapshot()
        changed[".github/workflows/ci.yml"] = (
            changed[".github/workflows/ci.yml"]
            .replace("    name: Required CI\n", "    name: PR gate\n")
            .replace("    name: Rust quality\n", "    name: Required CI\n")
        )
        with self.assertRaises(AssertionError):
            validate(changed)

    def test_shared_workflow_exception_never_accepts_floating_or_forged_pins(self) -> None:
        revision = json.loads(snapshot()[".github/automation.json"])["revision"]
        workflow = "Strukturpiloten/boxferry/.github/workflows/shared-rust-ci.yml"
        pin = workflow + "@" + revision + " # automation-v1 interface v1"
        for invalid in ("main", "automation-v1", "v1", "a" * 39, "g" * 40, "A" * 40):
            with self.subTest(invalid=invalid):
                self.rejected(
                    ".github/workflows/ci.yml",
                    pin,
                    workflow + "@" + invalid + " # automation-v1 interface v1",
                )
        self.rejected(
            ".github/workflows/ci.yml", pin, pin.replace("# automation-v1 interface v1", "# v1")
        )
        self.rejected(
            ".github/workflows/ci.yml",
            pin,
            pin.replace("Strukturpiloten/boxferry", "other/boxferry"),
        )
        other_revision = "a" * 40 if revision != "a" * 40 else "b" * 40
        self.rejected(
            ".github/workflows/ci.yml", pin, pin.replace("@" + revision, "@" + other_revision)
        )

    def test_dependency_waiter_uses_base_authority_via_shared_contract(self) -> None:
        ci = snapshot()[".github/workflows/ci.yml"]
        reader = ci.split("\n  lockfile-release-age:\n", 1)[1].split("\n  pr-gate:\n", 1)[0]
        revision = json.loads(snapshot()[".github/automation.json"])["revision"]
        self.assertEqual(re.findall(r"^    name: (.+)$", reader, re.M), ["Dependency eligibility"])
        self.assertIn(
            "uses: Strukturpiloten/boxferry/.github/workflows/shared-dependency-wait.yml@"
            + revision
            + " # automation-v1 interface v1",
            reader,
        )
        self.assertIn(
            "policy_sha: ${{ github.event.pull_request.base.sha || "
            "github.event.merge_group.base_sha || github.sha }}",
            reader,
        )
        self.assertNotIn("--implementation-revision", reader)
        self.assertNotIn("runs-on:", reader)
        self.assertNotIn("steps:", reader)

    def test_shared_release_gate_cannot_enable_publication_or_skip_exact_candidate(self) -> None:
        self.rejected(
            "scripts/release-policy.json",
            '"publication_enabled": false',
            '"publication_enabled": true',
        )
        self.rejected(
            ".github/workflows/ci.yml",
            "candidate_sha: ${{ steps.gate.outputs.candidate_sha }}",
            "candidate_sha: arbitrary",
        )
        self.rejected(
            ".github/workflows/release.yml", "needs_json: ${{ toJSON(needs) }}", 'needs_json: "{}"'
        )

    def test_privileged_eligibility_service_never_runs_candidate_events(self) -> None:
        for event in ("pull_request", "pull_request_target", "merge_group"):
            with self.subTest(event=event):
                self.rejected(
                    ".github/workflows/dependency-eligibility.yml",
                    "  workflow_run:",
                    f"  {event}:",
                )
        self.rejected(".github/workflows/ci.yml", "name: CI", "name: Renamed CI")

    def test_privileged_service_rejects_every_mutable_or_invalid_pin(self) -> None:
        revision = json.loads(snapshot()[".github/automation.json"])["revision"]
        for invalid in ("main", "automation-v1", "v1", "a" * 39, "g" * 40, "A" * 40):
            with self.subTest(invalid=invalid):
                self.rejected(
                    ".github/workflows/dependency-eligibility.yml", "@" + revision, "@" + invalid
                )

    def test_fake_published_history_or_duplicate_inventory_fails(self) -> None:
        self.rejected("CHANGELOG.md", "## [Unreleased]", "## [Unreleased]\n\n## [0.1.0]")
        self.rejected("scripts/renovate-tool.json", "@sha256:", "@sha256-invalid:")


REQUIRED_OFFICIAL_FIXTURE_TEST_IDS = {
    "test_materialize.OfficialReceiptTests.test_official_source_receipt_is_portable_complete_and_has_no_native_success",
    "test_admission.AdmissionExpectationTests.test_official_plan_remains_pending_with_independent_closure_counts",
}


def load_tests(
    loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None
) -> unittest.TestSuite:
    """Include the source-only fixtures in every existing policy/gate invocation."""
    directory = ROOT / "scripts" / "fixtures"
    for name in ("test_materialize.py", "test_admission.py"):
        if not (directory / name).is_file():
            raise RuntimeError("required official fixture test module missing")
    fixtures = loader.discover(str(directory), pattern="test_*.py", top_level_dir=str(directory))

    def case_ids(suite: unittest.TestSuite) -> Iterator[str]:
        for case in suite:
            if isinstance(case, unittest.TestSuite):
                yield from case_ids(case)
            else:
                yield case.id()

    identities = list(case_ids(fixtures))
    if not REQUIRED_OFFICIAL_FIXTURE_TEST_IDS.issubset(identities) or len(set(identities)) != len(
        identities
    ):
        raise RuntimeError("required official fixture test identities missing or duplicated")
    tests.addTests(fixtures)
    return tests


if __name__ == "__main__":
    unittest.main()
