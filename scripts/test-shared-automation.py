#!/usr/bin/env python3
"""Consumer invariants; shared classifier behavior is tested once in BoxFerry."""

import copy
import importlib.util
import io
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType
from typing import Any, ClassVar, cast
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = runpy.run_path(str(ROOT / "scripts/shared-ci.py"))
LOAD_CONFIG = cast(Callable[[Path], dict[str, object]], BOOTSTRAP["load_config"])


def validate_policy_execution_contract(
    policy_text: str, alias_text: str, wrapper: str, manifest_text: str
) -> None:
    policy = json.loads(policy_text)
    aliases = tomllib.loads(alias_text)["alias"]
    manifest = tomllib.loads(manifest_text)
    assert aliases["ci-policy"] == "test --locked --test repository_policy"
    assert aliases["ci-check"] == "check --locked --workspace --all-targets --all-features"
    assert aliases["ci-test"] == "test --locked --workspace --all-targets --all-features"
    assert policy["tasks"]["rust-quality"]["commands"] == [
        ["cargo", "fmt", "--all", "--", "--check"],
        ["cargo", "ci-check"],
        ["cargo", "ci-policy", "--no-run"],
        ["cargo", "ci-clippy"],
        ["cargo", "ci-test"],
        ["cargo", "ci-doctest"],
        ["env", "RUSTDOCFLAGS=-D warnings", "cargo", "ci-doc"],
        ["cargo", "package", "--locked", "--allow-dirty"],
    ]
    assert policy["tasks"]["rust-quality"]["timeout_seconds"] == 1800
    assert policy["tasks"]["msrv"]["timeout_seconds"] == 1800
    assert policy["tasks"]["msrv"]["commands"] == [
        ["cargo", "ci-check"],
        ["cargo", "ci-policy", "--no-run"],
    ]
    assert set(policy["jobs"]) == {
        "rust",
        "api",
        "msrv",
        "dependencies",
        "documentation",
        "lockfile-release-age",
    }
    for profile, jobs in policy["profile_jobs"].items():
        if profile != "prose":
            assert "rust" in jobs, "semantic documentation requires the Rust policy harness"
    assert policy["local_commands"]["full"] == [["bash", "scripts/check-all.sh", "--check"]]
    assert policy["local_commands"]["executable-docs"] == policy["local_commands"]["full"]
    assert all(
        "scripts/test-repository-policy.py" not in " ".join(command)
        for command in policy["tasks"]["documentation"]["commands"]
    )
    assert manifest["package"].get("autotests", True) is True
    policy_target = (ROOT / "tests/repository_policy.rs").resolve()
    for target in manifest.get("test", []):
        assert target.get("name") != "repository_policy", (
            "keep the canonical automatic policy target"
        )
        if "path" in target:
            assert (ROOT / target["path"]).resolve() != policy_target, (
                "do not alias the policy target"
            )
    assert re.search(r"#\s*\[\s*(?:cfg(?:_attr)?|ignore)\b", wrapper) is None
    assert wrapper.count("#[test]") == 1
    assert "fn repository_policy()" in wrapper
    assert 'Command::new("python3")' in wrapper
    assert '"/scripts/test-repository-policy.py"' in wrapper
    assert ".status()?" in wrapper and "status.success()" in wrapper


def validate_strict_rust_callers(ci: str, revision: str) -> None:
    for job, task in (("rust", "rust-quality"), ("msrv", "msrv")):
        match = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", ci)
        assert match is not None, f"missing configured Rust job {job}"
        block = match[1]
        assert re.findall(r"(?m)^      require_configured_task: (.*)$", block) == ["true"]
        assert re.findall(r"(?m)^      task: (.*)$", block) == [task]
        assert f"shared-rust-ci.yml@{revision} # automation-v1 interface v1" in block
        assert f"automation_sha: {revision}" in block
        assert "candidate_sha: ${{ github.sha }}" in block
        assert (
            "policy_sha: ${{ github.event.pull_request.base.sha || "
            "github.event.merge_group.base_sha || github.sha }}" in block
        )
        assert "config_path: scripts/validation-policy.json" in block
        assert "needs: validation-plan" in block
        assert f"if: needs.validation-plan.outputs.select_{job} == 'true'" in block


class SharedAutomationTests(unittest.TestCase):
    def test_direct_quality_api_calls_preserve_commands_and_exact_gate_contract(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        jobs = ["rust", "api", "msrv", "dependencies", "documentation", "lockfile-release-age"]
        self.assertEqual(policy["jobs"], jobs)
        self.assertEqual(
            policy["profile_jobs"],
            {
                "prose": ["documentation", "lockfile-release-age"],
                "executable-docs": jobs,
            },
        )
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertFalse((ROOT / ".github/workflows/shared-rust-api.yml").exists())
        self.assertEqual(
            re.findall(r"^  ([a-z][a-z-]*):$", ci.split("\njobs:\n", 1)[1], re.M),
            ["validation-plan", *jobs, "pr-gate"],
        )
        rust = ci.split("\n  rust:\n", 1)[1].split("\n  api:\n", 1)[0]
        api = ci.split("\n  api:\n", 1)[1].split("\n  msrv:\n", 1)[0]
        self.assertIn("shared-rust-ci.yml@", rust)
        self.assertIn("task: rust-quality", rust)
        self.assertIn(
            "select_api == 'true' || needs.validation-plan.outputs.select_rust == 'true'", api
        )
        for declaration in (
            "shared-rust-semver.yml@",
            "package: kubernetes-lens",
            "initial_api_contract: true",
            'release_type: ""',
            "api_purpose: ${{ inputs.api_purpose || 'development' }}",
        ):
            self.assertIn(declaration, api)
        self.assertIn(
            "needs: [validation-plan, rust, api, msrv, dependencies, documentation, "
            "lockfile-release-age]",
            ci,
        )
        self.assertIn("timeout-minutes: 10", ci.split("\n  pr-gate:\n")[1])
        self.assertIn("id: gate\n        timeout-minutes: 5", ci)
        self.assertIn("python scripts/ci-api-transition.py", ci)
        self.assertIn('--plan-json "${PLAN_JSON}" --needs-json "${NEEDS_JSON}"', ci)
        self.assertIn("value: ${{ jobs.pr-gate.outputs.published_api_candidate_sha }}", ci)
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn(
            "uses: ./.github/workflows/ci.yml\n    with:\n      api_purpose: published", release
        )

    def test_api_tasks_use_central_identity_and_real_unfiltered_initial_contract(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        self.assertEqual(
            policy["tasks"]["api-development"],
            {
                "timeout_seconds": 1200,
                "commands": [
                    [
                        "python",
                        "-m",
                        "boxferry_ci.api_baselines",
                        "run",
                        "--repository-root",
                        ".",
                        "--repository",
                        "Strukturpiloten/kubernetes-lens",
                        "--api-purpose",
                        "development",
                        "--event",
                        "local",
                        "--package",
                        "kubernetes-lens",
                        "--report-json",
                        "target/api-baseline-local.json",
                    ]
                ],
            },
        )
        self.assertEqual(
            policy["tasks"]["initial-api-contract"],
            {
                "timeout_seconds": 1200,
                "commands": [["cargo", "test", "--locked", "--test", "foundation"]],
            },
        )
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertTrue(manifest["package"].get("autotests", True))
        for target in manifest.get("test", []):
            self.assertNotEqual(target.get("name"), "foundation")
            self.assertNotEqual(target.get("path"), "tests/foundation.rs")
        foundation = (ROOT / "tests/foundation.rs").read_text()
        self.assertGreater(foundation.count("#[test]"), 0)
        self.assertNotIn("#[ignore]", foundation)
        for assertion in (
            "fn strict_json_duplicate_escape_keys_and_redaction()",
            "FindingCode::DuplicateKey",
            "assert_eq!",
            "assert!",
        ):
            self.assertIn(assertion, foundation)
        gate = (ROOT / "scripts/check-all.sh").read_text()
        self.assertIn(
            "python3 scripts/shared-ci.py run --event local --task api-development "
            "--report-json target/api-development-task.json",
            gate,
        )

    def test_strict_rust_callers_reject_missing_or_false_opt_in(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        revision = str(LOAD_CONFIG(ROOT)["revision"])
        validate_strict_rust_callers(ci, revision)
        for job in ("rust", "msrv"):
            match = re.search(rf"(?ms)^  {job}:\n.*?(?=^  [a-z][a-z-]*:\n|\Z)", ci)
            assert match is not None
            for replacement in ("", "      require_configured_task: false\n"):
                with self.subTest(job=job, replacement=replacement):
                    changed = match[0].replace("      require_configured_task: true\n", replacement)
                    self.assertNotEqual(changed, match[0])
                    with self.assertRaises(AssertionError):
                        validate_strict_rust_callers(ci.replace(match[0], changed), revision)

    def test_manifest_uses_immutable_boxferry_implementation(self) -> None:
        config = LOAD_CONFIG(ROOT)
        self.assertEqual(config["repository"], "Strukturpiloten/boxferry")
        self.assertEqual(config["policy"], "scripts/validation-policy.json")
        self.assertRegex(str(config["revision"]), r"^[a-f0-9]{40}$")

    def test_interface_one_loader_executes_b_and_its_central_tool_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumer = root / "consumer-a"
            (consumer / "scripts").mkdir(parents=True)
            (consumer / ".github").mkdir()
            loader = consumer / "scripts/shared-ci.py"
            shutil.copyfile(ROOT / "scripts/shared-ci.py", loader)
            config = json.loads((ROOT / ".github/automation.json").read_text())
            (consumer / ".github/automation.json").write_text(
                json.dumps({**config, "revision": "b" * 40})
            )
            project = root / "implementation-b/automation"
            implementation = project / "src/boxferry_ci/bootstrap.py"
            implementation.parent.mkdir(parents=True)
            report = root / "central-tool-helper.json"
            implementation.write_text(
                "import json\n"
                "from pathlib import Path\n"
                f"REPORT = Path({str(report)!r})\n"
                "def ensure_uv(project):\n"
                "    return 'implementation-b-tool-setup'\n"
                "def run_project(repository_root, project, arguments):\n"
                "    REPORT.write_text(json.dumps({'root': str(repository_root), "
                "'project': str(project), 'arguments': arguments, "
                "'tool_setup': ensure_uv(project)}))\n"
                "    return 23\n"
            )
            spec = importlib.util.spec_from_file_location("consumer_a_frontloader", loader)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            main = cast(Callable[[list[str]], int], module.main)
            for arguments in (["plan", "--event", "local"], ["future-tool", "--version"]):
                with self.subTest(arguments=arguments):
                    with patch.object(
                        module, "prepare_implementation", return_value=project
                    ) as fetch:
                        with patch.dict(sys.modules):
                            result = main(arguments)
                    fetch.assert_called_once_with(consumer, "b" * 40)
                    self.assertEqual(result, 23, "A must preserve B's exact result")
                    evidence = json.loads(report.read_text())
                    self.assertEqual(evidence["root"], str(consumer))
                    self.assertEqual(evidence["project"], str(project))
                    self.assertEqual(evidence["tool_setup"], "implementation-b-tool-setup")
                    self.assertEqual(evidence["arguments"], arguments)

    def test_mutable_short_and_invalid_revisions_are_rejected(self) -> None:
        config = json.loads((ROOT / ".github/automation.json").read_text())
        for revision in ("main", "automation-v1", "v1", "a" * 39, "g" * 40, "A" * 40):
            with self.subTest(revision=revision), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / ".github").mkdir()
                (root / ".github/automation.json").write_text(
                    json.dumps({**config, "revision": revision})
                )
                with self.assertRaises(ValueError):
                    LOAD_CONFIG(root)

    def test_loader_reconstructs_exact_cargo_metadata_as_nonexecutable_data(self) -> None:
        revision = "b" * 40
        metadata = b"ARG ZIZMOR_VERSION=1.0.0\nRUN this-must-never-execute\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "fixture.tar"
            with tarfile.open(archive, "w") as output:
                for name, data in {
                    "automation/pyproject.toml": b"[project]\nname='fixture'\n",
                    "automation/uv.lock": b"version = 1\n",
                    "renovate-presets/common.json": b"{}",
                    ".devcontainer/Dockerfile": metadata,
                }.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o755
                    output.addfile(member, io.BytesIO(data))
            objects = root / f"target/boxferry-automation/{revision}.git"
            objects.mkdir(parents=True)

            def git_response(directory: Path, *arguments: str, binary: bool = False) -> bytes | str:
                self.assertEqual(directory, objects)
                if arguments[0] == "archive":
                    self.assertTrue(binary)
                    self.assertEqual(
                        arguments,
                        (
                            "archive",
                            "--format=tar",
                            revision,
                            "automation",
                            "renovate-presets",
                            ".devcontainer/Dockerfile",
                        ),
                    )
                    return archive.read_bytes()
                return revision if arguments[0] == "rev-parse" else ""

            prepare = cast(Callable[[Path, str], Path], BOOTSTRAP["prepare_implementation"])
            with patch.dict(
                cast(FunctionType, prepare).__globals__,
                validate_cache=lambda _: None,
                run_git=git_response,
            ):
                for _ in range(2):
                    project = prepare(root, revision)
                    data_path = project.parent / ".devcontainer/Dockerfile"
                    self.assertEqual(data_path.read_bytes(), metadata)
                    self.assertEqual(data_path.stat().st_mode & 0o777, 0o644)
                    self.assertEqual(
                        {path.name for path in data_path.parent.iterdir()}, {"Dockerfile"}
                    )
                    self.assertFalse((project.parent / "templates").exists())
                    data_path.write_text("candidate tampering")
                    (data_path.parent / "not-exported.json").write_text("candidate tampering")

    def test_loader_rejects_ancillary_devcontainer_data_and_metadata_links(self) -> None:
        extract = cast(Callable[[Path, Path], None], BOOTSTRAP["extract_archive"])
        for name, kind in (
            (".devcontainer/extra.json", tarfile.REGTYPE),
            (".devcontainer/nested/Dockerfile", tarfile.REGTYPE),
            (".devcontainer//Dockerfile", tarfile.REGTYPE),
            (".devcontainer/./Dockerfile", tarfile.REGTYPE),
            (".devcontainer/Dockerfile", tarfile.SYMTYPE),
            (".devcontainer/Dockerfile", tarfile.LNKTYPE),
        ):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "fixture.tar"
                with tarfile.open(archive, "w") as output:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/etc/passwd"
                    output.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    extract(archive, root / "output")

    def policy_contract_inputs(self) -> tuple[str, str, str, str]:
        return (
            (ROOT / "scripts/validation-policy.json").read_text(),
            (ROOT / ".cargo/config.toml").read_text(),
            (ROOT / "tests/repository_policy.rs").read_text(),
            (ROOT / "Cargo.toml").read_text(),
        )

    def test_repository_tasks_preserve_every_existing_rust_check(self) -> None:
        validate_policy_execution_contract(*self.policy_contract_inputs())

    def test_policy_execution_and_link_guarantees_reject_mutations(self) -> None:
        policy_text, aliases, wrapper, manifest = self.policy_contract_inputs()
        original = json.loads(policy_text)
        policy_mutations = []
        for task in ("rust-quality", "msrv"):
            dropped = copy.deepcopy(original)
            dropped["tasks"][task]["commands"].remove(["cargo", "ci-policy", "--no-run"])
            policy_mutations.append((f"missing {task} default build", dropped))
            for flags in (
                [],
                ["--all-features", "--no-run"],
                ["--no-default-features", "--no-run"],
            ):
                changed = copy.deepcopy(original)
                commands = changed["tasks"][task]["commands"]
                index = commands.index(["cargo", "ci-policy", "--no-run"])
                commands[index] = ["cargo", "ci-policy", *flags]
                policy_mutations.append((f"{task} policy flags {flags}", changed))
        for flags in (["--no-run"], ["--test", "foundation"], ["--", "one_case"]):
            changed = copy.deepcopy(original)
            commands = changed["tasks"]["rust-quality"]["commands"]
            commands[commands.index(["cargo", "ci-test"])] = ["cargo", "ci-test", *flags]
            policy_mutations.append((f"production test flags {flags}", changed))
        changed = copy.deepcopy(original)
        changed["profile_jobs"]["executable-docs"].remove("rust")
        policy_mutations.append(("executable docs without Rust", changed))
        changed = copy.deepcopy(original)
        changed["jobs"].remove("rust")
        policy_mutations.append(("full inventory without Rust", changed))
        changed = copy.deepcopy(original)
        changed["tasks"]["documentation"]["commands"].append(
            ["python3", "scripts/test-repository-policy.py"]
        )
        policy_mutations.append(("documentation repeats corpus", changed))
        changed = copy.deepcopy(original)
        changed["local_commands"]["executable-docs"] = changed["local_commands"]["prose"]
        policy_mutations.append(("local executable docs omit complete gate", changed))
        for label, changed_policy in policy_mutations:
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate_policy_execution_contract(
                    json.dumps(changed_policy), aliases, wrapper, manifest
                )
        for label, changed_aliases, changed_wrapper, changed_manifest in (
            (
                "global no-run alias",
                aliases.replace(
                    "test --locked --test repository_policy",
                    "test --locked --test repository_policy --no-run",
                ),
                wrapper,
                manifest,
            ),
            (
                "test alias no-run",
                aliases.replace(
                    'ci-test = "test --locked --workspace --all-targets --all-features"',
                    'ci-test = "test --locked --workspace --all-targets --all-features --no-run"',
                ),
                wrapper,
                manifest,
            ),
            (
                "wrapper ignored",
                aliases,
                wrapper.replace("#[test]", "#[test]\n#[ignore]", 1),
                manifest,
            ),
            (
                "wrapper conditionally compiled",
                aliases,
                wrapper.replace(
                    "#[test]", '#[cfg(not(feature = "supervised-renderer"))]\n#[test]', 1
                ),
                manifest,
            ),
            ("wrapper removed", aliases, "", manifest),
            (
                "test discovery disabled",
                aliases,
                wrapper,
                manifest.replace("[package]\n", "[package]\nautotests = false\n", 1),
            ),
        ):
            with self.subTest(label=label), self.assertRaises(AssertionError):
                validate_policy_execution_contract(
                    policy_text, changed_aliases, changed_wrapper, changed_manifest
                )

        for alias_name in ("ci-check", "ci-test"):
            original_line = next(
                line for line in aliases.splitlines() if line.startswith(alias_name + " = ")
            )
            for flag in ("--all-targets", "--all-features"):
                changed_aliases = aliases.replace(original_line, original_line.replace(flag, ""), 1)
                with self.subTest(alias=alias_name, flag=flag), self.assertRaises(AssertionError):
                    validate_policy_execution_contract(
                        policy_text, changed_aliases, wrapper, manifest
                    )

    def test_policy_target_cannot_be_redirected_disabled_or_duplicated(self) -> None:
        policy, aliases, wrapper, manifest = self.policy_contract_inputs()
        self.assertTrue((ROOT / "tests/foundation.rs").is_file())
        unrelated_target = (
            '\n[[test]]\nname = "foundation"\npath = "tests/foundation.rs"\n'
            "harness = true\ntest = true\nbench = false\n"
        )
        validate_policy_execution_contract(policy, aliases, wrapper, manifest + unrelated_target)
        validate_policy_execution_contract(
            policy,
            aliases,
            wrapper,
            manifest.replace("[package]\n", "[package]\nautotests = true\n", 1),
        )
        for name, path, metadata in (
            ("repository_policy", "tests/foundation.rs", ""),
            ("repository_policy", "tests/repository_policy.rs", ""),
            ("policy_copy", "tests/repository_policy.rs", ""),
            ("policy_copy", "./tests/repository_policy.rs", ""),
            ("policy_copy", "tests/../tests/repository_policy.rs", ""),
            ("policy_copy", str(ROOT / "tests/repository_policy.rs"), ""),
            ("repository_policy", "tests/repository_policy.rs", "harness = false\n"),
            ("repository_policy", "tests/repository_policy.rs", "test = false\n"),
            (
                "repository_policy",
                "tests/repository_policy.rs",
                'required-features = ["supervised-renderer"]\n',
            ),
        ):
            candidate = (
                manifest
                + f"\n[[test]]\nname = {json.dumps(name)}\npath = {json.dumps(path)}\n"
                + metadata
            )
            tomllib.loads(candidate)
            with (
                self.subTest(name=name, path=path, metadata=metadata),
                self.assertRaises(AssertionError),
            ):
                validate_policy_execution_contract(policy, aliases, wrapper, candidate)

    def assert_kind_runtime_failure_contract(self, probe: str, timing_helper: str) -> None:
        declaration = "fn external_kind_runtime_pure_contracts_are_part_of_the_gate()"
        self.assertIn(declaration, probe)
        body = probe.split(declaration, 1)[1].split("\n}", 1)[0]
        for fragment in (
            "selftest_timings::run(",
            'std::process::Command::new("/usr/bin/python3")',
            '.arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fixtures/kind_runtime.py"))',
            '.arg("--self-test")',
            ".env_clear()",
            '.env("LANG", "C")',
            '.env("LC_ALL", "C")',
            '.env("TZ", "UTC")',
            '.env("PYTHONDONTWRITEBYTECODE", "1")',
            '.current_dir(env!("CARGO_MANIFEST_DIR"))',
        ):
            self.assertEqual(body.count(fragment), 1, fragment)
        self.assertRegex(body, r"\)\?;\s*Ok\(\(\)\)\s*$")
        self.assertIn('#[path = "support/selftest_timings.rs"]\nmod selftest_timings;', probe)
        helper = timing_helper.split("pub(super) fn run(", 1)[1].split("\n}", 1)[0]
        self.assertIn('.env("KUBERNETES_LENS_SELFTEST_TIMINGS", &transport.path)', helper)
        self.assertEqual(helper.count(".output()?"), 1)
        self.assertRegex(
            helper,
            r"if !outcome\.status\.success\(\) \{\s*"
            r'return Err\(io::Error::other\("external kind runtime pure contracts failed"\)\);',
        )

    def test_distinct_kind_runtime_contract_remains_in_the_all_target_suite(self) -> None:
        probe = (ROOT / "tests/official_native_probe.rs").read_text()
        helper = (ROOT / "tests/support/selftest_timings.rs").read_text()
        self.assert_kind_runtime_failure_contract(probe, helper)
        self.assertIn("fn original_python_driver_pure_contracts_are_part_of_the_gate()", probe)
        self.assertIn(
            '#[cfg(target_os = "linux")]\n#[test]\n'
            "fn external_kind_runtime_pure_contracts_are_part_of_the_gate()",
            probe,
        )
        driver = " ".join((ROOT / "scripts/fixtures/kind_runtime.py").read_text().split())
        self.assertIn(
            "for module in (test_kind_runtime, test_owned_qemu, test_owned_host_view, "
            "test_owned_guest_stage, test_owned_guest_receiver, test_owned_guest_rootful)",
            driver,
        )
        self.assertIn('require(len(sys.argv) == 2, "self-test-isolation")', driver)
        self.assertEqual(driver.count("return selftest_timings.run_suite(suite)"), 1)
        self.assertLess(
            driver.index("return selftest_timings.run_suite(suite)"),
            driver.index('required = ["phase"'),
        )
        validate_policy_execution_contract(*self.policy_contract_inputs())

    def test_kind_runtime_failure_delegation_and_propagation_cannot_be_removed(self) -> None:
        probe = (ROOT / "tests/official_native_probe.rs").read_text()
        helper = (ROOT / "tests/support/selftest_timings.rs").read_text()
        for label, changed_probe, changed_helper in (
            (
                "missing-delegate",
                probe.replace("selftest_timings::run(", "unrelated::run(", 1),
                helper,
            ),
            (
                "swallowed-helper-error",
                probe.replace("    )?;\n    Ok(())", "    );\n    Ok(())", 1),
                helper,
            ),
            (
                "missing-status-refusal",
                probe,
                helper.replace("if !outcome.status.success()", "if false", 1),
            ),
            (
                "inverted-status",
                probe,
                helper.replace("if !outcome.status.success()", "if outcome.status.success()", 1),
            ),
            (
                "successful-failure-return",
                probe,
                helper.replace(
                    'return Err(io::Error::other("external kind runtime pure contracts failed"));',
                    "return Ok(());",
                    1,
                ),
            ),
        ):
            with self.subTest(mutation=label), self.assertRaises(AssertionError):
                self.assert_kind_runtime_failure_contract(changed_probe, changed_helper)

    def test_pure_prose_avoids_native_controls_and_rust_builds(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        calls = policy["tasks"]["documentation-prose"]["commands"]
        self.assertEqual(calls, policy["local_commands"]["prose"])
        self.assertEqual([call[0] for call in calls], ["bash", "lychee"])
        self.assertEqual(calls[0], ["bash", "scripts/check-files.sh", "--check"])
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("profile == 'prose' && 'documentation-prose'", ci)
        self.assertIn("if: needs.validation-plan.outputs.profile != 'prose'", ci)

    def test_candidate_workflow_is_read_only_and_plans_merge_queue(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("  merge_group:", ci)
        self.assertIn("github.event.merge_group.base_sha", ci)
        self.assertIn("--config _policy/scripts/validation-policy.json", ci)
        self.assertEqual(len(re.findall(r"^    name: Required CI$", ci, re.M)), 1)
        self.assertNotRegex(ci, r"(?m)^\s+(?:actions|statuses|contents): write$")
        self.assertNotIn("Strukturpiloten/.github", ci)
        self.assertIn("candidate_sha: ${{ github.sha }}", ci)

    def test_all_shared_execution_and_preset_refs_match_manifest(self) -> None:
        revision = str(LOAD_CONFIG(ROOT)["revision"])
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            content = path.read_text()
            self.assertNotIn("__AUTOMATION_SHA__", content)
            for value in re.findall(
                r"(?:AUTOMATION_SHA:|automation[-_]sha:)\s*([a-f0-9]{40})", content
            ):
                self.assertEqual(value, revision, str(path))
            for value in re.findall(
                r"# renovate: datasource=github-digest depName=Strukturpiloten/boxferry "
                r"currentValue=automation-v1\n\s+ref:\s*([a-f0-9]{40})",
                content,
            ):
                self.assertEqual(value, revision, str(path))
            for value in re.findall(
                r"Strukturpiloten/boxferry/\.github/workflows/[^@]+@([a-f0-9]{40})", content
            ):
                self.assertEqual(value, revision, str(path))
        renovate = json.loads((ROOT / ".github/renovate.json").read_text())
        for preset in ("common", "rust"):
            self.assertIn(
                f"github>Strukturpiloten/boxferry//renovate-presets/{preset}#{revision}",
                renovate["extends"],
            )


@dataclass
class TransitionCase:
    root: Path
    config: Path
    base: str
    tested: str
    event: str
    plan: str
    needs: dict[str, Any]


class ApiTransitionTests(unittest.TestCase):
    project: ClassVar[Path]
    source: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = str(LOAD_CONFIG(ROOT)["revision"])
        prepare = cast(Callable[[Path, str], Path], BOOTSTRAP["prepare_implementation"])
        cls.project = prepare(ROOT, cls.source)

    def setUp(self) -> None:
        self.bridge = runpy.run_path(str(ROOT / "scripts/ci-api-transition.py"))
        self.proof = cast(FunctionType, self.bridge["joint_proof"])
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    @staticmethod
    def git(root: Path, *args: str) -> str:
        return (
            subprocess.check_output(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "user.name=Contract fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-C",
                    str(root),
                    *args,
                ],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )

    def canonical(self, *args: str) -> subprocess.CompletedProcess[str]:
        root = Path(args[args.index("--repository-root") + 1])
        return subprocess.run(
            [sys.executable, "-m", "boxferry_ci", *args],
            env=self.environment(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

    def environment(self, root: Path) -> dict[str, str]:
        project = root / "target/boxferry-automation" / self.source / "automation"
        return {**os.environ, "PYTHONPATH": str(project / "src"), "PYTHONDONTWRITEBYTECODE": "1"}

    def fixture(
        self, *, legacy: bool, profile: str = "full", event: str = "pull_request"
    ) -> TransitionCase:
        root = self.directory / f"consumer-{len(list(self.directory.iterdir()))}"
        (root / "scripts").mkdir(parents=True)
        (root / ".github").mkdir()
        shutil.copyfile(ROOT / ".github/automation.json", root / ".github/automation.json")
        (root / "docs/public").mkdir(parents=True)
        (root / "docs/public/page.md").write_text("# Page\n\nOriginal prose.\n")
        current = (ROOT / "scripts/validation-policy.json").read_bytes()
        old = (ROOT / "scripts/fixtures/ci-api-transition/p5-policy.json.txt").read_bytes()
        policy = root / "scripts/validation-policy.json"
        policy.write_bytes(old if legacy else current)
        self.git(root, "init", "--quiet", "--template=")
        self.git(root, "add", ".")
        self.git(root, "commit", "--quiet", "-m", "trusted policy fixture")
        base = self.git(root, "rev-parse", "HEAD")
        if event in {"pull_request", "merge_group"}:
            if profile == "prose":
                (root / "docs/public/page.md").write_text("# Page\n\nChanged prose.\n")
            else:
                policy.write_bytes(current)
                (root / "unknown-input").write_text("forces full validation\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "--quiet", "-m", "exact candidate fixture")
        tested = self.git(root, "rev-parse", "HEAD")
        trusted = root / "_policy"
        self.git(root, "clone", "--quiet", "--no-hardlinks", str(root), str(trusted))
        self.git(trusted, "checkout", "--quiet", "--detach", base)
        cache = root / "target/boxferry-automation"
        cache.mkdir(parents=True)
        shutil.copytree(
            ROOT / "target/boxferry-automation" / (self.source + ".git"),
            cache / (self.source + ".git"),
        )
        prepare = cast(Callable[[Path, str], Path], BOOTSTRAP["prepare_implementation"])
        prepare(root, self.source)
        case = TransitionCase(
            root, trusted / "scripts/validation-policy.json", base, tested, event, "", {}
        )
        result = self.canonical("plan", *self.arguments(case))
        self.assertEqual(result.returncode, 0, result.stderr)
        case.plan = result.stdout.strip()
        plan = json.loads(case.plan)
        jobs = plan["jobs"]
        outputs = {
            "plan": case.plan,
            "profile": plan["profile"],
            **{
                "select_" + name.replace("-", "_"): str(selected).lower()
                for name, selected in jobs.items()
            },
        }
        case.needs = {"validation-plan": {"result": "success", "outputs": outputs}}
        for name in self.bridge["JOBS"]:
            selected = jobs.get(name, jobs["rust"])
            child = {"candidate_sha": tested} if selected and name in {"rust", "api"} else {}
            case.needs[name] = {"result": "success" if selected else "skipped", "outputs": child}
        return case

    def arguments(self, case: TransitionCase) -> list[str]:
        return [
            "--repository-root",
            str(case.root),
            "--config",
            str(case.config),
            "--event",
            case.event,
            "--base-sha",
            case.base,
            "--head-sha",
            case.tested,
            "--tested-sha",
            case.tested,
            "--policy-sha",
            case.base,
            "--automation-sha",
            self.source,
        ]

    def execute(self, case: TransitionCase, purpose: str = "development") -> tuple[int, str]:
        output = self.directory / "gate-output"
        output.unlink(missing_ok=True)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/ci-api-transition.py"),
                *self.arguments(case),
                "--plan-json",
                case.plan,
                "--needs-json",
                json.dumps(case.needs),
                "--api-purpose",
                purpose,
                "--github-output",
                str(output),
            ],
            env={**self.environment(case.root), "GITHUB_SHA": case.tested},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result.returncode, output.read_text() if output.exists() else ""

    def test_selected_producer_strict_tasks_preserve_policy_and_reject_absence(self) -> None:
        script = """
import argparse
from dataclasses import replace
from pathlib import Path
import sys
from boxferry_ci.__main__ import _task
from boxferry_ci.contracts import ContractError
from boxferry_ci.policy import load_policy
policy = load_policy(Path(sys.argv[1]))
for name in ("rust-quality", "msrv"):
    configured = policy.tasks[name]
    assert configured.timeout_seconds == 1800
    for mode in ("run", "check-task"):
        args = argparse.Namespace(task=name, command=mode, require_configured_task=mode == "run")
        assert _task(args, policy) == configured
        remaining = {key: value for key, value in policy.tasks.items() if key != name}
        missing = replace(policy, tasks=remaining)
        try:
            _task(args, missing)
        except ContractError:
            pass
        else:
            raise AssertionError(f"missing explicit {name} accepted by {mode}")
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(ROOT / "scripts/validation-policy.json")],
            cwd=ROOT,
            env=self.environment(ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def configured_task(
        self, case: TransitionCase, task: str, mode: str
    ) -> subprocess.CompletedProcess[str]:
        tools = case.root / "task-tools"
        tools.mkdir(exist_ok=True)
        cargo = tools / "cargo"
        cargo.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "with pathlib.Path('task-commands.jsonl').open('a') as stream:\n"
            "    stream.write(json.dumps({'argv': sys.argv[1:], "
            "'rustdocflags': os.environ.get('RUSTDOCFLAGS')}) + '\\n')\n"
        )
        cargo.chmod(0o755)
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "boxferry_ci",
                mode,
                *self.arguments(case),
                "--task",
                task,
                *(["--require-configured-task"] if mode == "run" else []),
                "--report-json",
                str(case.root / "task-report.json"),
            ],
            cwd=case.root,
            env={
                **self.environment(case.root),
                "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                "CARGO_TARGET_DIR": str(case.root / "target"),
                "RUSTDOCFLAGS": "",
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

    def test_selected_producer_executes_exact_configured_rust_tasks(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        for task in ("rust-quality", "msrv"):
            with self.subTest(task=task):
                case = self.fixture(legacy=False, event="workflow_dispatch")
                marker = case.root / "task-commands.jsonl"
                # A candidate's different task must never replace trusted-base commands.
                candidate = json.loads((case.root / "scripts/validation-policy.json").read_text())
                candidate["tasks"][task]["commands"] = [["cargo", "candidate-only"]]
                (case.root / "scripts/validation-policy.json").write_text(json.dumps(candidate))
                self.git(case.root, "add", "scripts/validation-policy.json")
                self.git(case.root, "commit", "--quiet", "-m", "different candidate task")
                case.tested = self.git(case.root, "rev-parse", "HEAD")
                for mode in ("check-task", "run"):
                    result = self.configured_task(case, task, mode)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    if mode == "check-task":
                        self.assertFalse(marker.exists(), "preflight must never execute a command")
                expected = [
                    {
                        "argv": call[3:] if call[0] == "env" else call[1:],
                        "rustdocflags": "-D warnings" if call[0] == "env" else "",
                    }
                    for call in policy["tasks"][task]["commands"]
                ]
                self.assertEqual(
                    [json.loads(line) for line in marker.read_text().splitlines()], expected
                )
                report = json.loads((case.root / "task-report.json").read_text())
                self.assertEqual(report["status"], "success")
                self.assertEqual(len(report["results"]), len(expected))
                self.assertTrue(all(item["returncode"] == 0 for item in report["results"]))

    def test_selected_producer_refuses_invalid_trusted_tasks_before_execution(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        for task in ("rust-quality", "msrv"):
            case = self.fixture(legacy=False, event="workflow_dispatch")
            valid = policy["tasks"][task]
            mutations = {
                "missing": None,
                "empty-commands": {**valid, "commands": []},
                "malformed-later-command": {**valid, "commands": [["cargo", "must-not-run"], []]},
                "missing-commands": {"timeout_seconds": 1800},
                "unknown-key": {**valid, "unexpected": True},
                "boolean-timeout": {**valid, "timeout_seconds": True},
                "zero-timeout": {**valid, "timeout_seconds": 0},
                "excess-timeout": {**valid, "timeout_seconds": 7201},
            }
            for label, value in mutations.items():
                trusted = copy.deepcopy(policy)
                if value is None:
                    del trusted["tasks"][task]
                else:
                    trusted["tasks"][task] = value
                case.config.write_text(json.dumps(trusted))
                self.git(case.config.parent, "add", "validation-policy.json")
                self.git(case.config.parent, "commit", "--quiet", "-m", label)
                case.base = self.git(case.config.parent, "rev-parse", "HEAD")
                for mode in ("check-task", "run"):
                    with self.subTest(task=task, mutation=label, mode=mode):
                        result = self.configured_task(case, task, mode)
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        report = json.loads((case.root / "task-report.json").read_text())
                        self.assertEqual(report["status"], "infrastructure")
                        self.assertIn(task, report["cause"])
                        if label == "missing":
                            self.assertIn("not explicitly configured", report["cause"])
                        self.assertFalse((case.root / "task-commands.jsonl").exists())

    def test_actual_old_and_new_canonical_plan_gate_paths_and_release_outputs(self) -> None:
        for legacy in (True, False):
            for event in ("pull_request", "merge_group"):
                for profile in ("full", "prose"):
                    with self.subTest(legacy=legacy, event=event, profile=profile):
                        case = self.fixture(legacy=legacy, profile=profile, event=event)
                        plan = json.loads(case.plan)
                        self.assertEqual(plan["profile"], profile)
                        self.assertEqual(len(plan["jobs"]), 5 if legacy else 6)
                        self.assertEqual(self.execute(case), (0, f"candidate_sha={case.tested}\n"))
                        if profile == "full":
                            case.needs["api"]["outputs"]["published_api_candidate_sha"] = (
                                case.tested
                            )
                            self.assertEqual(
                                self.execute(case, "published"),
                                (
                                    0,
                                    f"candidate_sha={case.tested}\npublished_api_candidate_sha={case.tested}\n",
                                ),
                            )
                            del case.needs["api"]["outputs"]["published_api_candidate_sha"]
                        projected, published = self.proof(
                            case.plan,
                            json.dumps(case.needs),
                            case.tested,
                            "development",
                            legacy=legacy,
                        )
                        self.assertFalse(published)
                        expected = {
                            name: outcome
                            for name, outcome in case.needs.items()
                            if not legacy or name != "api"
                        }
                        self.assertEqual(json.loads(projected), expected)
                        if not legacy:
                            self.assertEqual(projected, json.dumps(case.needs))
        for event in ("push", "workflow_dispatch", "workflow_call"):
            case = self.fixture(legacy=False, event=event)
            case.needs["api"]["outputs"]["published_api_candidate_sha"] = case.tested
            self.assertEqual(
                self.execute(case, "published"),
                (0, f"candidate_sha={case.tested}\npublished_api_candidate_sha={case.tested}\n"),
            )

    def test_every_child_failure_missing_or_mixed_proof_refuses_before_canonical_gate(self) -> None:
        for legacy in (True, False):
            case = self.fixture(legacy=legacy)
            baseline = copy.deepcopy(case.needs)
            for name in ("rust", "api"):
                for result in ("failure", "cancelled", "skipped", "unknown", None):
                    case.needs = copy.deepcopy(baseline)
                    case.needs[name]["result"] = result
                    with self.assertRaises(ValueError):
                        self.proof(
                            case.plan,
                            json.dumps(case.needs),
                            case.tested,
                            "development",
                            legacy=legacy,
                        )
                for receipt in ("", "b" * 40, None, True):
                    case.needs = copy.deepcopy(baseline)
                    case.needs[name]["outputs"]["candidate_sha"] = receipt
                    with self.assertRaises(ValueError):
                        self.proof(
                            case.plan,
                            json.dumps(case.needs),
                            case.tested,
                            "development",
                            legacy=legacy,
                        )
            case.needs = copy.deepcopy(baseline)
            self.assertNotEqual(self.execute(case, "published")[0], 0)
            self.assertEqual(self.execute(case, "unknown")[1], "")

    def test_original_plan_bytes_reach_actual_gate_and_invalid_api_never_reaches_it(self) -> None:
        case = self.fixture(legacy=True)
        case.plan = " \n" + case.plan + "\n "
        case.needs["validation-plan"]["outputs"]["plan"] = case.plan
        output = self.directory / "delegated-output"
        arguments = [
            *self.arguments(case),
            "--plan-json",
            case.plan,
            "--needs-json",
            json.dumps(case.needs),
            "--api-purpose",
            "development",
            "--github-output",
            str(output),
        ]
        entrypoint = cast(FunctionType, self.bridge["main"])
        original_run = subprocess.run
        with (
            patch.dict(os.environ, {**self.environment(case.root), "GITHUB_SHA": case.tested}),
            patch.object(subprocess, "run", wraps=original_run) as executed,
        ):
            self.assertEqual(entrypoint(arguments), 0)
        calls = [
            call.args[0]
            for call in executed.call_args_list
            if call.args[0][:4] == [sys.executable, "-m", "boxferry_ci", "gate"]
        ]
        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertEqual(command[command.index("--plan-json") + 1], case.plan)
        self.assertEqual(
            json.loads(command[command.index("--needs-json") + 1]),
            {name: value for name, value in case.needs.items() if name != "api"},
        )
        output.unlink()
        case.needs["api"]["result"] = "cancelled"
        arguments[arguments.index("--needs-json") + 1] = json.dumps(case.needs)
        with (
            patch.dict(os.environ, {**self.environment(case.root), "GITHUB_SHA": case.tested}),
            patch.object(subprocess, "run", wraps=original_run) as refused,
        ):
            self.assertEqual(entrypoint(arguments), 1)
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                call.args[0][:4] == [sys.executable, "-m", "boxferry_ci", "gate"]
                for call in refused.call_args_list
            )
        )

    def test_raw_inventory_plan_identity_selections_and_serialization_are_closed(self) -> None:
        case = self.fixture(legacy=True)
        baseline = copy.deepcopy(case.needs)
        for missing in baseline:
            needs = {name: value for name, value in baseline.items() if name != missing}
            with self.assertRaises(ValueError):
                self.proof(case.plan, json.dumps(needs), case.tested, "development", legacy=True)
        needs = {**baseline, "unexpected": {"result": "success", "outputs": {}}}
        with self.assertRaises(ValueError):
            self.proof(case.plan, json.dumps(needs), case.tested, "development", legacy=True)
        for key, value in (
            ("tested_sha", "b" * 40),
            ("repository", "attacker/repo"),
            ("jobs", {"rust": True}),
            ("jobs", {**json.loads(case.plan)["jobs"], "rust": 1}),
        ):
            with self.assertRaises(ValueError):
                self.proof(
                    json.dumps({**json.loads(case.plan), key: value}),
                    json.dumps(baseline),
                    case.tested,
                    "development",
                    legacy=True,
                )
        # Same parsed plan but different original bytes cannot silently replace the plan output.
        with self.assertRaises(ValueError):
            self.proof(
                " " + case.plan, json.dumps(baseline), case.tested, "development", legacy=True
            )
        case.needs["documentation"]["result"] = "failure"
        self.assertEqual(self.execute(case)[1], "")  # Real canonical gate refuses after API proof.

    def test_trusted_blob_hash_custody_and_initial_contract_cannot_be_substituted(self) -> None:
        case = self.fixture(legacy=True)
        old = case.config.read_bytes()
        case.config.write_bytes((ROOT / "scripts/validation-policy.json").read_bytes())
        self.assertEqual(
            self.execute(case)[1], ""
        )  # Known P6 in P5 worktree is still not B's blob.
        case.config.write_bytes(old + b"\n")
        self.assertNotEqual(self.execute(case)[0], 0)
        for mutation in ("filtered", "missing-quality", "wrong-repository", "wrong-schema"):
            root = self.directory / ("bad-policy-" + mutation)
            (root / "scripts").mkdir(parents=True)
            policy = json.loads(old)
            if mutation == "filtered":
                policy["tasks"]["initial-api-contract"]["commands"][0].append("one_test")
            elif mutation == "missing-quality":
                policy["tasks"]["rust-quality"]["commands"].pop()
            elif mutation == "wrong-repository":
                policy["repository"] = "attacker/repo"
            else:
                policy["schema"] = 3
            path = root / "scripts/validation-policy.json"
            path.write_text(json.dumps(policy))
            self.git(root, "init", "--quiet", "--template=")
            self.git(root, "add", ".")
            self.git(root, "commit", "--quiet", "-m", "unsupported policy fixture")
            verify = cast(FunctionType, self.bridge["trusted_policy"])
            with self.assertRaises(ValueError):
                verify(path, self.git(root, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
