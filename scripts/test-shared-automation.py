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
import textwrap
import tomllib
import unittest
from collections.abc import Callable
from pathlib import Path
from types import FunctionType
from typing import cast
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
    assert policy["tasks"]["msrv"]["commands"] == [
        ["cargo", "ci-check"],
        ["cargo", "ci-policy", "--no-run"],
    ]
    assert set(policy["jobs"]) == {
        "rust",
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


class SharedAutomationTests(unittest.TestCase):
    def test_rust_api_wrapper_preserves_trusted_outer_inventory(self) -> None:
        policy = json.loads((ROOT / "scripts/validation-policy.json").read_text())
        jobs = ["rust", "msrv", "dependencies", "documentation", "lockfile-release-age"]
        self.assertEqual(policy["jobs"], jobs)
        self.assertEqual(
            policy["profile_jobs"],
            {
                "prose": ["documentation", "lockfile-release-age"],
                "executable-docs": jobs,
            },
        )
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(
            re.findall(r"^  ([a-z][a-z-]*):$", ci.split("\njobs:\n", 1)[1], re.M),
            ["validation-plan", *jobs, "pr-gate"],
        )
        rust = ci.split("\n  rust:\n", 1)[1].split("\n  msrv:\n", 1)[0]
        self.assertIn("needs: validation-plan", rust)
        self.assertIn("if: needs.validation-plan.outputs.select_rust == 'true'", rust)
        self.assertIn("uses: ./.github/workflows/shared-rust-api.yml", rust)
        self.assertIn("api_purpose: ${{ inputs.api_purpose || 'development' }}", rust)
        self.assertIn("        default: published", ci)
        self.assertIn(
            "needs: [validation-plan, rust, msrv, dependencies, documentation, "
            "lockfile-release-age]",
            ci,
        )
        wrapper = (ROOT / ".github/workflows/shared-rust-api.yml").read_text()
        self.assertEqual(wrapper.count("required: true"), 3)
        self.assertIn("default: published", wrapper)
        self.assertIn("if: always()\n    needs: [quality, api]", wrapper)
        for literal in (
            "task: rust-quality",
            "package: kubernetes-lens",
            "initial_api_contract: true",
            'release_type: ""',
        ):
            self.assertIn(literal, wrapper)
        self.assertEqual(wrapper.count("config_path: scripts/validation-policy.json"), 2)
        self.assertNotIn("continue-on-error", wrapper)
        self.assertNotIn("concurrency:", wrapper)
        self.assertIn("value: ${{ jobs.result.outputs.candidate_sha }}", wrapper)
        self.assertIn("value: ${{ jobs.result.outputs.published_api_candidate_sha }}", wrapper)
        self.assertIn("value: ${{ jobs.pr-gate.outputs.published_api_candidate_sha }}", ci)
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn(
            "uses: ./.github/workflows/ci.yml\n    with:\n      api_purpose: published", release
        )

    @staticmethod
    def run_aggregate(workflow: str, **changes: str) -> tuple[int, str]:
        # Execute the actual final workflow run block. Only the upstream canonical gate is stubbed.
        script = textwrap.dedent(workflow.rsplit("        run: |\n", 1)[1])
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "outputs"
            uv = directory / "uv"
            uv.write_text('#!/bin/sh\nexit "${GATE_STATUS:-0}"\n')
            uv.chmod(0o755)
            environment = {
                **os.environ,
                "PATH": f"{directory}:/usr/bin:/bin",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_SHA": candidate,
                "CANDIDATE_SHA": candidate,
                "API_PURPOSE": "published",
                "QUALITY_RESULT": "success",
                "API_RESULT": "success",
                "QUALITY_CANDIDATE_SHA": candidate,
                "API_CANDIDATE_SHA": candidate,
                "PUBLISHED_API_CANDIDATE_SHA": candidate,
                "EVENT_NAME": "workflow_dispatch",
                "BASE_SHA": candidate,
                "HEAD_SHA": candidate,
                "POLICY_SHA": candidate,
                "AUTOMATION_SHA": "b" * 40,
                "PLAN_JSON": "{}",
                "NEEDS_JSON": "{}",
                **changes,
            }
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode, output.read_text() if output.exists() else ""

    def test_wrapper_requires_both_exact_successes_for_every_purpose(self) -> None:
        workflow = (ROOT / ".github/workflows/shared-rust-api.yml").read_text()
        candidate = "a" * 40
        for purpose in ("development", "published"):
            expected = f"candidate_sha={candidate}\n"
            if purpose == "published":
                expected = f"published_api_candidate_sha={candidate}\n" + expected
            self.assertEqual(self.run_aggregate(workflow, API_PURPOSE=purpose), (0, expected))
            for key in ("QUALITY_RESULT", "API_RESULT"):
                for outcome in ("failure", "cancelled", "skipped", "", "unknown"):
                    with self.subTest(purpose=purpose, key=key, outcome=outcome):
                        status, output = self.run_aggregate(
                            workflow,
                            API_PURPOSE=purpose,
                            **{key: outcome},
                        )
                        self.assertNotEqual(status, 0)
                        self.assertEqual(output, "")
            for key in (
                "CANDIDATE_SHA",
                "GITHUB_SHA",
                "QUALITY_CANDIDATE_SHA",
                "API_CANDIDATE_SHA",
            ):
                for wrong in ("", "b" * 40, "A" * 40, "bad"):
                    with self.subTest(purpose=purpose, key=key, wrong=wrong):
                        status, output = self.run_aggregate(
                            workflow, API_PURPOSE=purpose, **{key: wrong}
                        )
                        self.assertNotEqual(status, 0)
                        self.assertEqual(output, "")
        for purpose in ("", "wrong", "Published"):
            status, output = self.run_aggregate(workflow, API_PURPOSE=purpose)
            self.assertNotEqual(status, 0)
            self.assertEqual(output, "")
        for published in ("", "b" * 40, "bad"):
            status, output = self.run_aggregate(workflow, PUBLISHED_API_CANDIDATE_SHA=published)
            self.assertNotEqual(status, 0)
            self.assertEqual(output, "")
            self.assertEqual(
                self.run_aggregate(
                    workflow, API_PURPOSE="development", PUBLISHED_API_CANDIDATE_SHA=published
                ),
                (0, f"candidate_sha={candidate}\n"),
            )

    def test_required_ci_emits_nothing_until_canonical_gate_and_published_binding_pass(
        self,
    ) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        candidate = "a" * 40
        for purpose in ("development", "published"):
            for failure in ("1", "17"):
                status, output = self.run_aggregate(ci, API_PURPOSE=purpose, GATE_STATUS=failure)
                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
        for published in ("", "b" * 40):
            status, output = self.run_aggregate(ci, PUBLISHED_API_CANDIDATE_SHA=published)
            self.assertNotEqual(status, 0)
            self.assertEqual(output, "")
            # Trusted prose planning may skip rust in development; no published receipt is emitted.
            self.assertEqual(
                self.run_aggregate(
                    ci, API_PURPOSE="development", PUBLISHED_API_CANDIDATE_SHA=published
                ),
                (0, f"candidate_sha={candidate}\n"),
            )
        self.assertEqual(
            self.run_aggregate(ci),
            (
                0,
                f"published_api_candidate_sha={candidate}\ncandidate_sha={candidate}\n",
            ),
        )
        status, output = self.run_aggregate(ci, API_PURPOSE="unknown")
        self.assertNotEqual(status, 0)
        self.assertEqual(output, "")

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

    def test_distinct_kind_runtime_contract_remains_in_the_all_target_suite(self) -> None:
        probe = (ROOT / "tests/official_native_probe.rs").read_text()
        self.assertIn("fn external_kind_runtime_pure_contracts_are_part_of_the_gate()", probe)
        body = probe.split("fn external_kind_runtime_pure_contracts_are_part_of_the_gate()", 1)[1]
        self.assertIn('/scripts/fixtures/kind_runtime.py"', body)
        self.assertIn('.arg("--self-test")', body)
        self.assertIn("if !output.status.success()", body)
        validate_policy_execution_contract(*self.policy_contract_inputs())

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


if __name__ == "__main__":
    unittest.main()
