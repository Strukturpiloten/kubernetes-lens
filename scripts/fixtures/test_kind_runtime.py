"""Independent pure controls: no executable, runtime socket, image or cluster is used."""
from contextlib import nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import kind_runtime as runtime


class OwnedVMDispatchControls(unittest.TestCase):
    def test_owned_vm_is_an_explicit_separate_mode(self):
        import owned_qemu
        with patch.object(runtime.sys, "argv", ["kind_runtime.py", "--owned-vm", "--phase", "qualify-vm"]), \
             patch.object(owned_qemu, "main", return_value=17) as main:
            self.assertEqual(runtime.main(), 17)
        main.assert_called_once_with(["--phase", "qualify-vm"])

    def test_owned_vm_does_not_relax_existing_rootless_refusal(self):
        with self.assertRaisesRegex(runtime.Refusal, "helper"):
            runtime._selected_helper_profile_admission()


def limits():
    return {"seconds": 600, "cleanup_seconds": 120, "cpus": 2, "memory_bytes": 4 * 1024**3,
            "pids": 4096, "nodes": 1, "store_bytes": 16 * 1024**3, "output_bytes": 8 * 1024**2, "commands": 256}


def policy():
    cluster = runtime.PREFIX + "a" * 32
    return {"phase": "run", "owner": "a" * 32, "cluster": cluster, "node": cluster + "-control-plane", "volume": cluster + "-var",
            "cgroup": "/sys/fs/cgroup/user.slice/" + runtime.PREFIX + "test.slice", "directory": "/private/control", "store": "/private",
            "store_identity": [1, 2], "limits": limits(), "end": time.monotonic() + 600,
            "profile": {"node_image": "kindest/node:v1.20.15@sha256:" + "b" * 64, "server_patch": "1.20.15"}}


def state():
    p = policy()
    return {"owner": p["owner"], "cluster": p["cluster"], "container": [], "network": [], "volume": [], "image": [],
            "run_attempted": False, "network_attempted": False, "volume_attempted": False, "pull_attempted": False, "prepared": False,
            "commands": 0, "output": 0, "cleanup_output": 0, "input": 0, "proxies": {}, "creation": None, "volume_result": None, "network_result": None, "volume_fingerprint": None}


def node_command(p):
    return ["run", "--name=" + p["node"], "--hostname=" + p["node"], "--privileged", "--detach", "--tty",
            "--label=io.x-k8s.kind.cluster=" + p["cluster"], "--label=io.x-k8s.kind.role=control-plane",
            "--net=kind", "--publish=127.0.0.1:0:6443/TCP", "--volume=" + p["volume"] + ":/var:suid,exec,dev", "--volume=/lib/modules:/lib/modules:ro", p["profile"]["node_image"]]


class ProfileControls(unittest.TestCase):
    def setUp(self):
        self.ledger = json.loads(runtime.LEDGER.read_bytes())

    def test_historical_profile_uses_owned_floor_tools(self):
        selected, tools = runtime.select_profile(self.ledger, "legacy-1.20.15", None)
        self.assertEqual(selected["server_patch"], "1.20.15")
        self.assertEqual(tools["kind"]["version"], "0.14.0")
        self.assertEqual(tools["kubectl"]["version"], "1.20.15")
        self.assertEqual(tools["kubectl"]["sha256"], "d283552d3ef3b0fd47c08953414e1e73897a1b3f88c8a520bb2e7de4e37e96f3")

    def test_modern_profile_cannot_accept_an_arbitrary_checksum_owner(self):
        with self.assertRaisesRegex(runtime.Refusal, "canonical-owner-integrity"):
            runtime.select_profile(self.ledger, "modern-1.37.0", b"caller checksum inventory")

    def test_modern_extraction_is_version_and_architecture_specific(self):
        source = b'readonly kind_version="0.33.0"\nreadonly kubectl_version="1.37.0"\n  x86_64)\n    readonly kind_checksum="' + b"c" * 64 + b'"\n    readonly kubectl_checksum="' + b"d" * 64 + b'"\n    ;;\n'
        self.ledger["canonical_tool_owner"]["sha256"] = runtime.sha(source)
        _, tools = runtime.select_profile(self.ledger, "modern-1.37.0", source)
        self.assertEqual(tools["kind"]["sha256"], "c" * 64)
        bad = source.replace(b'kind_version="0.33.0"', b'kind_version="0.34.0"')
        self.ledger["canonical_tool_owner"]["sha256"] = runtime.sha(bad)
        with self.assertRaisesRegex(runtime.Refusal, "canonical-owner-version"):
            runtime.select_profile(self.ledger, "modern-1.37.0", bad)

    def test_unknown_duplicate_and_unpinned_profiles_refuse(self):
        with self.assertRaisesRegex(runtime.Refusal, "unknown-runtime-profile"):
            runtime.select_profile(self.ledger, "arbitrary-existing-cluster", None)
        self.ledger["runtime_profiles"][0]["node_image"] = "kindest/node:latest"
        with self.assertRaisesRegex(runtime.Refusal, "unpinned-image"):
            runtime.select_profile(self.ledger, "legacy-1.20.15", None)

    def test_image_evidence_requires_digest_and_platform(self):
        p = policy()
        row = {"Id": "c" * 64, "RepoDigests": [runtime.image_reference(p["profile"])], "Architecture": "amd64", "Os": "linux"}
        self.assertEqual(runtime.image_identity(p["profile"], [row]), "c" * 64)
        for key, value in [("RepoDigests", ["docker.io/kindest/node:latest"]), ("Architecture", "arm64"), ("Os", "windows")]:
            varied = deepcopy(row)
            varied[key] = value
            with self.assertRaises(runtime.Refusal):
                runtime.image_identity(p["profile"], [varied])


class ProviderControls(unittest.TestCase):
    def test_exact_single_node_has_caps_owner_and_named_volume_before_image(self):
        p = policy()
        command = runtime.node_arguments(p, node_command(p))
        for flag, expected in [("--memory", "4294967296"), ("--memory-swap", "4294967296"), ("--cpus", "2"), ("--pids-limit", "4096"), ("--cgroup-parent", Path(p["cgroup"]).name)]:
            self.assertEqual(runtime.argument_value(command, flag), expected)
        self.assertIn("--pull=never", command)
        self.assertIn("--cgroups=no-conmon", command)
        self.assertIn("--image-volume=ignore", command)
        self.assertIn("--log-opt=max-size=1048576", command)
        self.assertIn(runtime.LABEL + "=" + p["owner"], command)
        self.assertIn(p["volume"] + ":/var:suid,exec,dev", command)
        self.assertEqual(command[-1], runtime.image_reference(p["profile"]))

    def test_foreign_node_image_host_mount_listener_and_cap_override_refuse(self):
        p = policy()
        original = node_command(p)
        mutations = [original[:-1] + ["kindest/node:latest"],
                     [v.replace(p["node"], "preexisting-control-plane") for v in original],
                     [v.replace("/lib/modules:/lib/modules:ro", "/etc:/host") for v in original],
                     [v.replace("127.0.0.1:0:6443", "0.0.0.0:6443:6443") for v in original],
                     original[:-1] + ["--memory=0", original[-1]],
                     original[:-1] + ["-m", "0", original[-1]],
                     original[:-1] + ["--cgroups=disabled", original[-1]]]
        for command in mutations:
            with self.subTest(command=command):
                with self.assertRaises(runtime.Refusal):
                    runtime.node_arguments(p, command)

    def test_cluster_and_role_labels_are_required(self):
        p = policy()
        for marker in ["io.x-k8s.kind.cluster=", "io.x-k8s.kind.role="]:
            with self.assertRaises(runtime.Refusal):
                runtime.node_arguments(p, [v for v in node_command(p) if marker not in v])

    def test_provider_never_forwards_destructive_or_global_commands(self):
        with patch.object(runtime, "tool") as forwarded:
            for command in [["rm", "--all"], ["stop", "existing"], ["system", "reset"], ["--remote", "ps"], ["pull", "foreign:latest"]]:
                with self.assertRaises(runtime.Refusal):
                    runtime.provider(policy(), command)
            forwarded.assert_not_called()

    def test_exec_against_preexisting_name_refuses_before_effect(self):
        with patch.object(runtime, "state_read", return_value=state()), patch.object(runtime, "tool") as forwarded:
            with self.assertRaisesRegex(runtime.Refusal, "foreign-container-target"):
                runtime.provider(policy(), ["exec", "existing", "true"])
            forwarded.assert_not_called()

    def test_second_creation_is_refused(self):
        existing = state()
        existing["run_attempted"] = True
        existing["prepared"] = True
        with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "tool") as forwarded:
            with self.assertRaisesRegex(runtime.Refusal, "second-node-refused"):
                runtime.provider(policy(), node_command(policy()))
            forwarded.assert_not_called()

    def test_owned_container_identity_and_label_are_both_required(self):
        p, identity = policy(), "c" * 64
        row = {"Id": identity, "Name": p["node"], "Config": {"Labels": {runtime.LABEL: p["owner"], "io.x-k8s.kind.cluster": p["cluster"]}}}
        with patch.object(runtime, "json_command", return_value=[row]):
            self.assertEqual(runtime.inspect_owned(p, "container", identity), row)
            row["Id"] = "d" * 64
            with self.assertRaisesRegex(runtime.Refusal, "ownership-drift"):
                runtime.inspect_owned(p, "container", identity)
            row["Id"] = identity
            row["Config"]["Labels"][runtime.LABEL] = "foreign"
            with self.assertRaisesRegex(runtime.Refusal, "ownership-drift"):
                runtime.inspect_owned(p, "container", identity)

    def test_unrecorded_own_label_cannot_mint_creation_authority(self):
        existing = state()
        existing["container"] = ["c" * 64]
        with patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "json_command") as discovery:
            with self.assertRaisesRegex(runtime.Refusal, "missing-creation-intent"):
                runtime.reconcile(policy())
            discovery.assert_not_called()

    def test_cleanup_rechecks_ownership_after_reconciliation_race(self):
        existing = state()
        existing["container"] = ["c" * 64]
        with patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "reconcile"), patch.object(runtime, "inspect_owned", side_effect=runtime.Refusal("ownership-drift")), patch.object(runtime, "checked") as mutation:
            errors = runtime.cleanup_resources(policy())
            self.assertIn("ownership-drift", errors)
            mutation.assert_not_called()

    def test_cleanup_failure_is_not_pass_and_preserves_original_error(self):
        receipt = runtime.join_receipt({}, runtime.Refusal("tool-nonzero-kind-17"), ["ownership-drift"])
        self.assertEqual(receipt["state"], "failed")
        self.assertEqual(receipt["error"], "tool-nonzero-kind-17")
        self.assertEqual(receipt["cleanup"], "incomplete-quarantined")
        self.assertEqual(runtime.exit_status(receipt), 1)

    def test_unproved_group_retirement_never_races_cleanup(self):
        existing = state()
        existing["retirement_unproved"] = True
        with patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "reconcile") as reconciliation:
            self.assertEqual(runtime.cleanup_resources(policy()), ["child-retirement-unproved"])
            reconciliation.assert_not_called()


class BudgetControls(unittest.TestCase):
    def test_limits_refuse_unbounded_and_extra_nodes(self):
        runtime.limits_valid(limits())
        for key, value in [("seconds", 0), ("cleanup_seconds", 0), ("nodes", 2), ("pids", 0), ("cpus", 0), ("memory_bytes", 0), ("output_bytes", 0), ("commands", 513)]:
            varied = limits()
            varied[key] = value
            with self.assertRaises(runtime.Refusal):
                runtime.limits_valid(varied)

    def test_original_deadline_reserves_cleanup_without_renewal(self):
        p = policy()
        p["end"] = 1000
        operation = runtime.Budget(p, clock=lambda: 900)
        with self.assertRaisesRegex(runtime.Refusal, "operation-deadline"):
            operation.remaining()
        self.assertEqual(runtime.Budget(p, cleanup=True, clock=lambda: 900).remaining(), 100)
        with self.assertRaisesRegex(runtime.Refusal, "cleanup-deadline"):
            runtime.Budget(p, cleanup=True, clock=lambda: 1000).remaining()

    def test_precreation_cgroup_requires_real_finite_caps_and_delegation(self):
        p = policy()
        contents = {"memory.max": "4294967296", "pids.max": "4096", "memory.swap.max": "0", "cpu.max": "200000 100000", "cgroup.controllers": "cpu memory pids"}
        current = "0::" + p["cgroup"].removeprefix("/sys/fs/cgroup") + "/caller.scope\n"
        with patch.object(Path, "read_text", new=lambda path: contents[path.name]), patch.object(Path, "is_symlink", return_value=False):
            self.assertEqual(runtime.cgroup_limits(p["cgroup"], limits(), current)["pids"], 4096)
            contents["memory.max"] = "max"
            with self.assertRaisesRegex(runtime.Refusal, "finite-cgroup-limits-required"):
                runtime.cgroup_limits(p["cgroup"], limits(), current)
            contents["memory.max"] = "4294967296"
            contents["cpu.max"] = "300000 100000"
            with self.assertRaisesRegex(runtime.Refusal, "cgroup-cap-mismatch"):
                runtime.cgroup_limits(p["cgroup"], limits(), current)
            contents["cpu.max"] = "200000 100000"
            contents["cgroup.controllers"] = "memory pids"
            with self.assertRaisesRegex(runtime.Refusal, "cgroup-delegation-required"):
                runtime.cgroup_limits(p["cgroup"], limits(), current)
        with self.assertRaisesRegex(runtime.Refusal, "caller-outside-task-slice"):
            runtime.cgroup_limits(p["cgroup"], limits(), "0::/foreign.scope\n")

    def test_command_budget_refuses_before_executable_launch(self):
        p, existing = policy(), state()
        existing["commands"] = p["limits"]["commands"]
        with patch.object(runtime, "cgroup_limits"), patch.object(runtime, "authenticate_helpers"), patch.object(runtime, "store_limit"), patch.object(Path, "stat", return_value=SimpleNamespace(st_dev=1, st_ino=2)), patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "bounded_run") as spawn:
            with self.assertRaisesRegex(runtime.Refusal, "command-budget"):
                runtime.tool(p, "podman", ["info"])
            spawn.assert_not_called()

    def test_output_overflow_retires_owned_group_without_real_process(self):
        process = SimpleNamespace(pid=424242, stdout=Mock(), stderr=Mock(), wait=Mock(), kill=Mock())
        key = SimpleNamespace(fd=42, data=0, fileobj=process.stdout)
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.get_map.return_value = {42: key}
        selector.select.return_value = [(key, 1)]
        with patch.object(runtime.subprocess, "Popen", return_value=process) as spawn, patch.object(runtime.selectors, "DefaultSelector", return_value=selector), patch.object(runtime.os, "set_blocking"), patch.object(runtime.os, "read", return_value=b"X" * 20), patch.object(runtime.os, "killpg") as kill, patch.object(runtime, "live_group", return_value=[]):
            with self.assertRaisesRegex(runtime.Refusal, "subprocess-output-budget"):
                runtime.bounded_run(["/explicit/tool"], {"HOME": "/private"}, runtime.Budget(policy()), 10)
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            kill.assert_called_once_with(424242, signal.SIGKILL)
            process.wait.assert_called_once()

    def test_store_measurement_is_private_and_measured_not_hard_quota(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime.os, "statvfs", return_value=SimpleNamespace(f_bavail=32 * 1024**3, f_frsize=1)):
            path = Path(directory)
            path.chmod(0o700)
            (path / "data").write_bytes(b"public")
            result = runtime.store_limit(path, 16 * 1024**3)
            self.assertGreater(result["entries"], 0)
            self.assertEqual(result["disk_enforcement"], "measured-not-quota")
            with self.assertRaisesRegex(runtime.Refusal, "measured-store-budget"):
                runtime.store_limit(path, 1)

    def test_file_reader_refuses_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "real").write_bytes(b"abc")
            (path / "link").symlink_to("real")
            with self.assertRaisesRegex(runtime.Refusal, "symlink-input"):
                runtime.regular(path / "link", 3)
            self.assertEqual(runtime.regular(path / "real", 3), b"abc")

    def test_unavailable_preparation_skips_and_cancellation_are_never_pass(self):
        for status in ["unavailable", "preflight-only", "image-prepared-only", "skipped", "failed"]:
            self.assertNotEqual(runtime.exit_status({"state": status}), 0)
        self.assertEqual(runtime.exit_status({"state": "readiness-passed"}, signal.SIGTERM), 143)


class EvidenceControls(unittest.TestCase):
    def test_exact_patch_major_minor_commit_and_platform_are_required(self):
        doc = {"gitVersion": "v1.20.15", "major": "1", "minor": "20", "gitCommit": "c" * 40, "platform": "linux/amd64"}
        self.assertEqual(runtime.version_evidence(doc, "1.20.15")["gitVersion"], "v1.20.15")
        for key, value in [("gitVersion", "v1.20.14"), ("gitVersion", "v1.20.15+vendor"), ("minor", "20+"), ("gitCommit", ""), ("platform", "linux/arm64")]:
            varied = dict(doc)
            varied[key] = value
            with self.assertRaises(runtime.Refusal):
                runtime.version_evidence(varied, "1.20.15")

    def test_node_must_be_inside_capped_slice_with_actual_caps(self):
        p = policy()
        row = {"HostConfig": {"Memory": 4 * 1024**3, "MemorySwap": 4 * 1024**3, "PidsLimit": 4096, "NanoCpus": 2 * 10**9, "CgroupParent": Path(p["cgroup"]).name}, "State": {"Pid": 123}}
        path = p["cgroup"].removeprefix("/sys/fs/cgroup")
        runtime.verify_node_limits(p, row, "0::" + path + "/libpod-owned.scope\n")
        with self.assertRaisesRegex(runtime.Refusal, "node-outside-capped-slice"):
            runtime.verify_node_limits(p, row, "0::/user.slice/foreign.scope\n")
        row["HostConfig"]["Memory"] = 0
        with self.assertRaisesRegex(runtime.Refusal, "node-cap-inspect-mismatch"):
            runtime.verify_node_limits(p, row, "0::" + path + "/libpod-owned.scope\n")

    def test_kubeconfig_for_existing_context_plugin_or_external_server_refuses(self):
        p = policy()
        context = "kind-" + p["cluster"]
        doc = {"clusters": [{"name": context, "cluster": {"server": "https://127.0.0.1:12345", "certificate-authority-data": "Y2E="}}],
               "contexts": [{"name": context, "context": {"cluster": context, "user": context}}],
               "users": [{"name": context, "user": {"client-certificate-data": "Y2VydA==", "client-key-data": "a2V5"}}]}
        row = {"NetworkSettings": {"Ports": {"6443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "12345"}]}}}
        runtime.validate_kubeconfig(p, doc, row)
        for mutation in ["plugin", "server", "context"]:
            varied = deepcopy(doc)
            if mutation == "plugin":
                varied["users"][0]["user"]["exec"] = {"command": "/ambient/credentials"}
            elif mutation == "server":
                varied["clusters"][0]["cluster"]["server"] = "https://existing-cluster:6443"
            else:
                varied["contexts"][0]["name"] = "existing-cluster"
            with self.assertRaises(runtime.Refusal):
                runtime.validate_kubeconfig(p, varied, row)

    def test_preexisting_store_workloads_refuse_without_mutation(self):
        p = policy()
        info = {"host": {"security": {"rootless": True}, "cgroupVersion": "v2", "cgroupManager": "systemd", "serviceIsRemote": False}, "store": {"graphRoot": "/private/graph", "runRoot": "/private/run"}}
        with patch.object(runtime, "json_command", side_effect=[info, [{"Id": "foreign"}]]), patch.object(runtime, "checked") as mutation:
            with self.assertRaisesRegex(runtime.Refusal, "preexisting-container-refused"):
                runtime.preflight(p)
            mutation.assert_not_called()


class HelperClosureControls(unittest.TestCase):
    def record(self, path="/usr/bin/explicit-helper"):
        return {"path": path, "sha256": "b" * 64, "bytes": 32, "uid": 0, "gid": 0,
                "mode": "0755", "capability_sha256": runtime.sha(b"file-capabilities")}

    def test_authenticated_catalogue_and_capability_metadata_are_retained(self):
        helpers = {name: self.record("/usr/libexec/reviewed/" + name) for name in runtime.REQUIRED_HELPERS}
        raw = json.dumps({"schema": "podman-host-helper-closure-v1", "helpers": helpers}).encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "closure.json"
            path.write_bytes(raw)
            with patch.object(runtime, "helper_file_identity", side_effect=lambda item: {**item, "device": 1, "inode": 2}) as authentication:
                closure = runtime.load_helper_closure(path, runtime.sha(raw))
                self.assertEqual(set(closure["helpers"]), runtime.REQUIRED_HELPERS)
                self.assertEqual(authentication.call_count, len(runtime.REQUIRED_HELPERS))
                self.assertEqual(closure["helpers"]["newuidmap"]["mode"], "0755")
                self.assertEqual(closure["helpers"]["newuidmap"]["capability_sha256"], runtime.sha(b"file-capabilities"))
                with self.assertRaisesRegex(runtime.Refusal, "helper-manifest-integrity"):
                    runtime.load_helper_closure(path, "0" * 64)

    def test_missing_or_arbitrary_helpers_and_nonroot_records_refuse(self):
        original = {name: self.record("/usr/libexec/reviewed/" + name) for name in runtime.REQUIRED_HELPERS}
        mutations = [dict(original), {**original, "sh": self.record("/usr/bin/sh")},
                     {name: {**row, "uid": 1000} for name, row in original.items()}]
        mutations[0].pop("newuidmap")
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, "helper_file_identity") as authentication:
            path = Path(directory) / "closure.json"
            for helpers in mutations:
                raw = json.dumps({"schema": "podman-host-helper-closure-v1", "helpers": helpers}).encode()
                path.write_bytes(raw)
                with self.assertRaises(runtime.Refusal):
                    runtime.load_helper_closure(path, runtime.sha(raw))
            authentication.assert_not_called()

    def test_helper_bytes_mode_and_capability_drift_refuse_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-helper"
            data = b"\x7fELF" + b"synthetic-not-executable" * 2
            path.write_bytes(data)
            path.chmod(0o500)
            info = path.stat()
            record = {"path": str(path), "sha256": runtime.sha(data), "bytes": len(data), "uid": info.st_uid,
                      "gid": info.st_gid, "mode": "0500", "capability_sha256": runtime.sha(b"caps")}
            with patch.object(runtime, "secure_host_path"), patch.object(runtime, "helper_capability", return_value=runtime.sha(b"caps")):
                identity = runtime.helper_file_identity(record)
                self.assertEqual(identity["inode"], info.st_ino)
                varied = {**record, "mode": "0755"}
                with self.assertRaisesRegex(runtime.Refusal, "helper-identity-drift"):
                    runtime.helper_file_identity(varied)
                varied = {**record, "sha256": "0" * 64}
                with self.assertRaisesRegex(runtime.Refusal, "helper-identity-drift"):
                    runtime.helper_file_identity(varied)
            with patch.object(runtime, "secure_host_path"), patch.object(runtime, "helper_capability", return_value=runtime.sha(b"")):
                with self.assertRaisesRegex(runtime.Refusal, "helper-identity-drift"):
                    runtime.helper_file_identity(record)

    def test_writable_host_helper_ancestor_refuses(self):
        with patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o40777)):
            with self.assertRaisesRegex(runtime.Refusal, "helper-host-path-writable"):
                runtime.secure_host_path("/usr/bin/native-helper")

    def test_private_symlink_preserves_host_path_and_refuses_retargeting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "helpers").mkdir()
            item = {**self.record("/usr/bin/newuidmap"), "device": 1, "inode": 2}
            closure = {"manifest_sha256": "a" * 64, "helpers": {"newuidmap": item}}
            runtime.install_helper_links(root, closure)
            p = {**policy(), "directory": str(root), "helper_closure": closure, "configuration_sha256": {}}
            with patch.object(runtime, "helper_file_identity", return_value=item), patch.object(runtime, "regular", return_value=b""):
                runtime.authenticate_helpers(p)
                link = root / "bin/newuidmap"
                self.assertTrue(link.is_symlink())
                self.assertEqual(os.readlink(link), "/usr/bin/newuidmap")
                link.unlink()
                link.symlink_to("/usr/bin/foreign-helper")
                with self.assertRaisesRegex(runtime.Refusal, "helper-private-link-drift"):
                    runtime.authenticate_helpers(p)
            # Rechecked host inode is part of the approved identity, even if bytes are equal.
            with patch.object(runtime, "helper_file_identity", return_value={**item, "inode": 3}):
                with self.assertRaisesRegex(runtime.Refusal, "helper-host-inode-drift"):
                    runtime.authenticate_helpers(p)

    def test_helper_drift_refuses_before_any_tool_launch(self):
        p = policy()
        with patch.object(runtime, "cgroup_limits"), patch.object(runtime, "authenticate_helpers", side_effect=runtime.Refusal("helper-identity-drift")), patch.object(runtime, "bounded_run") as launch:
            with self.assertRaisesRegex(runtime.Refusal, "helper-identity-drift"):
                runtime.tool(p, "podman", ["info"])
            launch.assert_not_called()

    def test_actual_reported_backend_and_runtime_paths_must_match_closure(self):
        p = policy()
        p["helper_closure"] = {"helpers": {name: self.record("/reviewed/" + name) for name in runtime.REQUIRED_HELPERS}}
        host = {"networkBackend": "netavark", "networkBackendInfo": {"backend": "netavark", "path": "/reviewed/netavark", "dns": {"path": "/reviewed/aardvark-dns"}},
                "conmon": {"path": "/reviewed/conmon"}, "ociRuntime": {"path": "/reviewed/crun"}, "pasta": {"executable": "/reviewed/pasta"}}
        runtime.verify_helper_selection(p, host)
        host["ociRuntime"]["path"] = "/ambient/runc"
        with self.assertRaisesRegex(runtime.Refusal, "helper-reported-path-mismatch"):
            runtime.verify_helper_selection(p, host)


class CreationOutcomeControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.p = {**policy(), "directory": self.directory.name}
        self.current = state()
        self.current["prepared"] = True
        for target, replacement in [("state_read", Mock(return_value=self.current)),
                                    ("state_write", Mock()), ("state_lock", Mock(return_value=nullcontext())),
                                    ("inspect_owned", Mock(return_value={}))]:
            context = patch.object(runtime, target, replacement)
            context.start()
            self.addCleanup(context.stop)

    def cid(self, value="c" * 64):
        path = runtime.creation_cidfile(self.p)
        path.write_bytes(value.encode() + b"\n")
        path.chmod(0o600)
        return path

    def started(self):
        runtime.claim_creation(self.p)
        runtime.start_creation(self.p)

    def verified(self, status=0):
        self.started()
        self.cid()
        runtime.complete_creation(self.p, (status, b"c" * 64 + b"\n", b""))

    def test_one_shot_intent_does_not_precreate_cidfile(self):
        runtime.claim_creation(self.p)
        self.assertFalse(runtime.creation_cidfile(self.p).exists())
        self.assertTrue(self.current["run_attempted"])
        self.assertFalse(self.current["creation"]["started"])
        with self.assertRaisesRegex(runtime.Refusal, "second-node-refused"):
            runtime.claim_creation(self.p)

    def test_existing_cidfile_refuses_before_claim(self):
        self.cid()
        with self.assertRaisesRegex(runtime.Refusal, "cidfile-preexisting-refused"):
            runtime.claim_creation(self.p)
        self.assertFalse(self.current["run_attempted"])

    def test_returned_result_cid_and_owned_inspection_form_the_join(self):
        self.verified()
        self.assertEqual(self.current["container"], ["c" * 64])
        self.assertEqual(self.current["creation"]["outcome"], "verified")
        runtime.creation_guard(self.p, self.current)
        runtime.inspect_owned.assert_called_once_with(self.p, "container", "c" * 64, session=False)

    def test_missing_cid_after_success_is_quarantine_not_empty_cleanup(self):
        self.started()
        with self.assertRaises(OSError):
            runtime.complete_creation(self.p, (0, b"c" * 64, b""))
        with patch.object(runtime, "checked") as deletion:
            errors = runtime.cleanup_resources(self.p)
            self.assertIn("creation-outcome-unproved", errors)
            self.assertIsNone(self.current["late_cid_evidence_only"])
            deletion.assert_not_called()

    def test_late_cid_cannot_promote_absent_original_result(self):
        self.started()
        self.cid()
        with patch.object(runtime, "checked") as deletion:
            errors = runtime.cleanup_resources(self.p)
            self.assertIn("creation-outcome-unproved", errors)
            self.assertEqual(self.current["late_cid_evidence_only"], "c" * 64)
            self.assertEqual(self.current["container"], [])
            self.assertFalse(self.current["creation"]["returned"])
            deletion.assert_not_called()

    def test_interrupted_result_with_cid_still_quarantines(self):
        self.started()
        self.cid()
        with self.assertRaisesRegex(runtime.Refusal, "creation-interrupted-quarantined"):
            runtime.complete_creation(self.p, (-signal.SIGTERM, b"c" * 64, b""))
        with self.assertRaisesRegex(runtime.Refusal, "creation-outcome-unproved"):
            runtime.creation_guard(self.p, self.current)
        self.assertEqual(self.current["creation"]["status"], -signal.SIGTERM)
        runtime.inspect_owned.assert_not_called()

    def test_stdout_cid_mismatch_never_authorizes_cleanup(self):
        self.started()
        self.cid()
        with self.assertRaisesRegex(runtime.Refusal, "creation-result-cid-mismatch"):
            runtime.complete_creation(self.p, (0, b"d" * 64, b""))
        self.assertEqual(self.current["container"], [])
        with self.assertRaisesRegex(runtime.Refusal, "creation-outcome-unproved"):
            runtime.creation_guard(self.p, self.current)

    def test_natural_nonzero_result_keeps_status_and_exact_owned_id(self):
        self.verified(status=17)
        self.assertEqual(self.current["creation"]["status"], 17)
        runtime.creation_guard(self.p, self.current)
        receipt = runtime.join_receipt({}, runtime.Refusal("tool-nonzero-podman-17"), [])
        self.assertEqual(runtime.exit_status(receipt), 1)
        self.assertEqual(receipt["error"], "tool-nonzero-podman-17")

    def test_changed_cidfile_identity_refuses_even_with_same_name(self):
        self.verified()
        path = runtime.creation_cidfile(self.p)
        path.unlink()
        self.cid("d" * 64)
        with self.assertRaisesRegex(runtime.Refusal, "creation-cid-drift"):
            runtime.creation_guard(self.p, self.current)

    def test_same_cid_bytes_with_changed_inode_do_not_preserve_authority(self):
        self.verified()
        changed = {**self.current["creation"]["cid_identity"], "st_ino": self.current["creation"]["cid_identity"]["st_ino"] + 1}
        with patch.object(runtime, "creation_file_record", return_value=changed):
            with self.assertRaisesRegex(runtime.Refusal, "creation-cid-drift"):
                runtime.creation_guard(self.p, self.current)

    def test_unproved_retirement_blocks_cleanup_even_with_valid_cid(self):
        self.verified()
        self.current["retirement_unproved"] = True
        with patch.object(runtime, "checked") as deletion:
            self.assertEqual(runtime.cleanup_resources(self.p), ["child-retirement-unproved"])
            deletion.assert_not_called()

    def test_recorded_ids_are_rechecked_without_label_discovery(self):
        self.verified()
        self.current["network_attempted"] = True
        self.current["network"] = ["d" * 64]
        self.current["network_result"] = {"returned": True, "status": 0, "identity": "d" * 64}
        with patch.object(runtime, "json_command") as discovery:
            runtime.reconcile(self.p, cleanup=True)
            discovery.assert_not_called()
        self.assertIn(unittest.mock.call(self.p, "network", "d" * 64, True, True), runtime.inspect_owned.call_args_list)

    def test_unrecorded_volume_creation_cannot_be_discovered_by_label(self):
        self.current["volume_attempted"] = True
        with patch.object(runtime, "checked") as deletion, patch.object(runtime, "json_command") as discovery:
            self.assertIn("volume-creation-outcome-unproved", runtime.cleanup_resources(self.p))
            discovery.assert_not_called()
            deletion.assert_not_called()


class AdditionalRaceControls(unittest.TestCase):
    def test_ignored_sigchld_refuses_before_process_creation(self):
        with patch.object(runtime.signal, "getsignal", return_value=signal.SIG_IGN), patch.object(runtime.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(runtime.Refusal, "sigchld-default-required"):
                runtime.bounded_run(["/explicit/tool"], {"HOME": "/private"}, runtime.Budget(policy()), 1024)
            spawn.assert_not_called()

    def test_zombie_leader_with_live_thread_is_not_retired(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = root / "42/task"
            for identity, status in [(42, "Z"), (43, "D")]:
                task = tasks / str(identity)
                task.mkdir(parents=True)
                (task / "stat").write_text(str(identity) + " (thread name) " + status + " 1 4242 4242 0\n")
            self.assertEqual(runtime.live_group(4242, root), [43])
            (tasks / "43/stat").write_text("43 (thread name) Z 1 4242 4242 0\n")
            self.assertEqual(runtime.live_group(4242, root), [])

    def test_node_ulimit_cannot_exceed_inherited_hard_ceiling(self):
        p = policy()
        command = node_command(p)
        command.insert(-1, "--ulimit=nofile=65536:65536")
        with patch.object(runtime.resource, "getrlimit", return_value=(256, 1024)):
            with self.assertRaisesRegex(runtime.Refusal, "host-nofile-prerequisite"):
                runtime.node_arguments(p, command)
        with patch.object(runtime.resource, "getrlimit", return_value=(256, 65536)):
            self.assertIn("--ulimit=nofile=65536:65536", runtime.node_arguments(p, command))

    def test_volume_replacement_after_recorded_result_refuses(self):
        p = policy()
        row = {"Name": p["volume"], "CreatedAt": "2026-10-21T00:00:00Z", "Mountpoint": "/private/graph/volumes/owned/_data", "Labels": {runtime.LABEL: p["owner"]}}
        existing = state()
        existing["volume_fingerprint"] = runtime.volume_fingerprint(row)
        row["CreatedAt"] = "2026-10-21T00:00:01Z"
        with patch.object(runtime, "state_read", return_value=existing), patch.object(runtime, "json_command", return_value=[row]):
            with self.assertRaisesRegex(runtime.Refusal, "volume-identity-drift"):
                runtime.inspect_owned(p, "volume", p["volume"], cleanup=True)



class FrozenProviderCatalogueControls(unittest.TestCase):
    def test_exact_versions_are_finite_global_exceptions(self):
        with patch.object(runtime, "tool", return_value=(0, b"podman version\n", b"")) as tool:
            for flag in ["-v", "--version"]:
                self.assertEqual(runtime.provider(policy(), [flag])[0], 0)
                self.assertEqual(tool.call_args.args[2], [flag])
            for command in [["-v", "info"], ["--remote", "--version"], ["--url=unix:/foreign", "-v"]]:
                with self.assertRaises(runtime.Refusal):
                    runtime.provider(policy(), command)
            self.assertEqual(tool.call_count, 2)

    def test_both_frozen_kind_node_catalogues_use_normalized_digest_env_fuse_and_blank_port(self):
        ledger = json.loads(runtime.LEDGER.read_bytes())
        for selected in ledger["runtime_profiles"]:
            if selected["id"] not in {"legacy-1.20.15", "modern-1.37.0"}:
                continue
            with self.subTest(profile=selected["id"]):
                p = {**policy(), "profile": selected}
                command = node_command(p)
                command[-1] = runtime.image_reference(selected)
                command = [v.replace("127.0.0.1:0:6443/TCP", "127.0.0.1::6443/tcp") for v in command]
                command[-1:-1] = ["-e", "container=podman", "-e", "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER",
                                  "-e", "KUBECONFIG=/etc/kubernetes/admin.conf", "--device", "/dev/fuse"]
                transformed = runtime.node_arguments(p, command)
                self.assertEqual(transformed[-1], "docker.io/kindest/node@sha256:" + selected["node_image"].split("@sha256:")[1])
                self.assertIn("--publish=127.0.0.1::6443/tcp", transformed)
                for expected in ["container=podman", "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER", "KUBECONFIG=/etc/kubernetes/admin.conf", "/dev/fuse"]:
                    self.assertIn(expected, transformed)
                for value in ["/dev/kvm", "/dev/mapper", "/dev/fuse:/different", "/etc"]:
                    with self.assertRaises(runtime.Refusal):
                        runtime.node_arguments(p, [v if v != "/dev/fuse" else value for v in command])
                with self.assertRaisesRegex(runtime.Refusal, "provider-node-env"):
                    runtime.node_arguments(p, [v if v != "container=podman" else "PRIVATE_TOKEN=secret" for v in command])

    def test_official_precreated_volume_returns_only_inspected_named_identity(self):
        p, current = policy(), state()
        row = {"Name": p["volume"], "CreatedAt": "2026-10-21T00:00:00Z",
               "Mountpoint": str(Path(p["store"]) / "graph/volumes" / p["volume"] / "_data")}
        result = (0, p["volume"].encode() + b"\n", b"")
        with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "tool", return_value=result) as tool, patch.object(runtime, "inspect_owned", return_value=row):
            self.assertEqual(runtime.provider(p, ["volume", "create", "--label", p["node"] + "=true"]), result)
            self.assertEqual(tool.call_args.args[2], ["volume", "create", "--label", p["node"] + "=true", "--label", runtime.LABEL + "=" + p["owner"], p["volume"]])
            self.assertEqual(current["volume"], [p["volume"]])
            self.assertEqual(current["volume_result"]["identity"], p["volume"])
            with self.assertRaisesRegex(runtime.Refusal, "second-volume-refused"):
                runtime.provider(p, ["volume", "create", "--label", p["node"] + "=true"])
            self.assertEqual(tool.call_count, 1)

    def test_streamed_owned_logs_and_interactive_cp_preserve_stdin_selection(self):
        p, identity = policy(), "c" * 64
        with patch.object(runtime, "owned_target", return_value=identity), patch.object(runtime, "streaming_tool", return_value=(0, b"", b"")) as stream:
            runtime.provider(p, ["logs", "-f", p["node"]])
            self.assertEqual(stream.call_args.args, (p, ["logs", "-f", identity]))
            command = ["exec", "--privileged", "-i", "-e", "KUBECONFIG=/etc/kubernetes/admin.conf", p["node"], "cp", "/dev/stdin", "/kind/kubeadm.conf"]
            runtime.provider(p, command)
            expected = [identity if value == p["node"] else value for value in command]
            self.assertEqual(stream.call_args.args, (p, expected, True))
            with self.assertRaises(runtime.Refusal):
                runtime.provider(p, ["logs", "--tail=all", p["node"]])
            with self.assertRaises(runtime.Refusal):
                runtime.provider(p, ["exec", "--detach", p["node"], "true"])

    def test_live_tool_output_is_never_replayed_as_buffered_reply(self):
        with patch.object(runtime, "tool", return_value=(7, b"protected-live-output", b"protected-live-error")) as tool:
            self.assertEqual(runtime.streaming_tool(policy(), ["logs", "owned"]), (7, b"", b""))
            self.assertIsNone(tool.call_args.kwargs["io_spec"]["stdin_fd"])
            runtime.streaming_tool(policy(), ["exec", "-i", "owned", "cp"], True)
            self.assertEqual(tool.call_args.kwargs["io_spec"]["stdin_fd"], 0)


class DuplexTransportControls(unittest.TestCase):
    def test_partial_delivery_and_eof_preserve_exact_binary_bytes(self):
        charges = []
        buffers = runtime.DuplexBuffers(100, interactive=True, forward=True, charge=lambda *item: charges.append(item))
        buffers.input(b"A\x00\xffB")
        buffers.sent_input(2)
        self.assertEqual(buffers.input_pending, b"\xffB")
        buffers.input(b"")
        self.assertTrue(buffers.input_eof)
        self.assertEqual(buffers.input_pending, b"\xffB")
        buffers.sent_input(2)
        self.assertFalse(buffers.input_pending)
        buffers.output(0, b"ready\n")
        buffers.sent_output(0, 2)
        buffers.output(0, b"")
        self.assertEqual(buffers.output_pending[0], b"ady\n")
        self.assertEqual(buffers.captured[0], b"ready\n")
        self.assertEqual(charges, [("input", 4), ("output", 6)])
        for action in [lambda: buffers.input(b"late"), lambda: buffers.output(0, b"late"), lambda: buffers.sent_output(1, 1)]:
            with self.assertRaises(runtime.Refusal):
                action()

    def test_pending_and_total_bounds_are_independent_and_combined_output_is_charged(self):
        buffers = runtime.DuplexBuffers(200000, interactive=True, forward=True)
        buffers.input(b"x" * 65536)
        with self.assertRaisesRegex(runtime.Refusal, "stdin-pending-budget"):
            buffers.input(b"x")
        buffers.output(0, b"x" * 65536)
        with self.assertRaisesRegex(runtime.Refusal, "output-pending-budget"):
            buffers.output(0, b"x")
        small = runtime.DuplexBuffers(4, interactive=True)
        small.input(b"1234")
        small.sent_input(4)
        with self.assertRaisesRegex(runtime.Refusal, "subprocess-input-budget"):
            small.input(b"5")
        small.output(0, b"12")
        with self.assertRaisesRegex(runtime.Refusal, "subprocess-output-budget"):
            small.output(1, b"345")

    def test_aggregate_charge_refusal_precedes_new_queue_bytes(self):
        def refuse(*_args):
            raise runtime.Refusal("aggregate-output-budget")
        buffers = runtime.DuplexBuffers(100, forward=True, charge=refuse)
        with self.assertRaisesRegex(runtime.Refusal, "aggregate-output-budget"):
            buffers.output(0, b"private")
        self.assertEqual(buffers.output_total, 0)
        self.assertEqual(buffers.captured, [bytearray(), bytearray()])

    def test_real_pipes_forward_before_eof_deliver_large_binary_stdin_and_restore_flags(self):
        # Stdlib threads model a child. No external process, executable or runtime is invoked.
        pairs = [os.pipe() for _ in range(6)]
        source, child_input, child_output, child_error, target_output, target_error = pairs
        child = SimpleNamespace(stdin=os.fdopen(child_input[1], "wb", buffering=0),
                                stdout=os.fdopen(child_output[0], "rb", buffering=0),
                                stderr=os.fdopen(child_error[0], "rb", buffering=0))
        ready, errors, received = threading.Event(), [], bytearray()
        payload = bytes(range(256)) * 513
        marker = b"kubelet ready before EOF\n"
        actual_write = os.write
        def write_all(fd, data):
            while data:
                count = actual_write(fd, data[:4096])
                data = data[count:]
        def producer():
            try:
                if not ready.wait(2):
                    raise AssertionError("readiness was buffered until EOF")
                write_all(source[1], payload)
            except BaseException as caught:
                errors.append(caught)
            finally:
                os.close(source[1])
        def fake_child():
            try:
                write_all(child_output[1], marker)
                if not ready.wait(2):
                    raise AssertionError("stdout did not reach kind before node pipe EOF")
                while True:
                    block = os.read(child_input[0], 997)
                    if not block:
                        break
                    received.extend(block)
                write_all(child_error[1], b"bounded stderr\n")
            except BaseException as caught:
                errors.append(caught)
            finally:
                for fd in [child_input[0], child_output[1], child_error[1]]:
                    os.close(fd)
        def consumer():
            try:
                data = bytearray()
                while len(data) < len(marker):
                    block = os.read(target_output[0], len(marker) - len(data))
                    if not block:
                        raise AssertionError("early stdout EOF")
                    data.extend(block)
                if data != marker:
                    raise AssertionError("readiness bytes changed")
                ready.set()
            except BaseException as caught:
                errors.append(caught)
        threads = [threading.Thread(target=action, daemon=True) for action in [producer, fake_child, consumer]]
        descriptor_list = [source[0], child.stdout.fileno(), child.stderr.fileno(), target_output[1], target_error[1]]
        original = {fd: os.get_blocking(fd) for fd in descriptor_list}
        try:
            for thread in threads:
                thread.start()
            p = policy()
            p["end"] = time.monotonic() + 6
            p["limits"]["cleanup_seconds"] = 1
            spec = {"stdin_fd": source[0], "stdout_fd": target_output[1], "stderr_fd": target_error[1]}
            attempts = []
            def short_interrupted_write(fd, data):
                attempts.append(len(data))
                if len(attempts) == 1:
                    raise InterruptedError()
                if len(attempts) == 2:
                    raise BlockingIOError()
                return actual_write(fd, data[:7])
            with patch.object(runtime.os, "write", side_effect=short_interrupted_write):
                out, err, count = runtime.pump_child(child, runtime.Budget(p), len(payload) + 1024, spec, None)
            for thread in threads:
                thread.join(2)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertEqual(bytes(received), payload)
            self.assertEqual(count, len(payload))
            self.assertEqual(out, marker)
            self.assertEqual(err, b"bounded stderr\n")
            self.assertEqual(os.read(target_error[0], len(err)), err)
            self.assertTrue(child.stdin.closed)
            self.assertEqual({fd: os.get_blocking(fd) for fd in descriptor_list}, original)
        finally:
            for pipe in [child.stdin, child.stdout, child.stderr]:
                pipe.close()
            thread_owned = {source[1], child_input[0], child_output[1], child_error[1]}
            file_owned = {child_input[1], child_output[0], child_error[0]}
            for pair in pairs:
                for fd in pair:
                    if fd in file_owned or fd in thread_owned:
                        continue
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            for thread in threads:
                thread.join(2)


    def test_child_stdin_early_close_and_downstream_close_are_fixed_refusals(self):
        for interactive, expected in [(True, "stdin-not-consumed"), (False, "forwarding-consumer-closed")]:
            with self.subTest(interactive=interactive):
                pairs = [os.pipe() for _ in range(6)]
                source, child_input, child_output, child_error, target_output, target_error = pairs
                child = SimpleNamespace(stdin=os.fdopen(child_input[1], "wb", buffering=0),
                                        stdout=os.fdopen(child_output[0], "rb", buffering=0),
                                        stderr=os.fdopen(child_error[0], "rb", buffering=0))
                closed = set()
                try:
                    os.close(child_input[0])
                    closed.add(child_input[0])
                    if interactive:
                        os.write(source[1], b"private-binary\x00\xff")
                    else:
                        os.close(target_output[0])
                        closed.add(target_output[0])
                        os.write(child_output[1], b"ready\n")
                    for fd in [source[1], child_output[1], child_error[1]]:
                        os.close(fd)
                        closed.add(fd)
                    spec = {"stdin_fd": source[0] if interactive else None, "stdout_fd": target_output[1], "stderr_fd": target_error[1]}
                    with self.assertRaisesRegex(runtime.Refusal, expected):
                        runtime.pump_child(child, runtime.Budget(policy()), 100, spec, None)
                finally:
                    for pipe in [child.stdin, child.stdout, child.stderr]:
                        closed.add(pipe.fileno()) if not pipe.closed else None
                        pipe.close()
                    for pair in pairs:
                        for fd in pair:
                            if fd not in closed:
                                os.close(fd)

    def test_stream_failure_retires_actual_child_session_before_return(self):
        process = SimpleNamespace(pid=424242, stdout=Mock(), stderr=Mock(), stdin=Mock(), wait=Mock())
        with patch.object(runtime.subprocess, "Popen", return_value=process) as spawn, patch.object(runtime, "pump_child", side_effect=runtime.Refusal("provider-parent-cancelled")), patch.object(runtime.os, "killpg") as kill, patch.object(runtime, "live_group", return_value=[]):
            with self.assertRaisesRegex(runtime.Refusal, "provider-parent-cancelled"):
                runtime.bounded_run(["/explicit/tool"], {"HOME": "/private"}, runtime.Budget(policy()), 100, True, {"stdin_fd": 0})
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            self.assertEqual(spawn.call_args.kwargs["stdin"], runtime.subprocess.PIPE)
            kill.assert_called_once_with(424242, signal.SIGKILL)
            process.wait.assert_called_once()


class ProxyCancellationControls(unittest.TestCase):
    def identity(self):
        return {"pid": 4242, "group": 4242, "session": 4242, "start": 17}

    def test_front_registers_private_backend_before_releasing_gate(self):
        p, events = policy(), []
        p["environment"], p["source_sha256"] = {"HOME": "/private"}, runtime.sha(b"source")
        process = SimpleNamespace(pid=4242, poll=Mock(return_value=0), wait=Mock(return_value=0))
        with patch.object(runtime, "regular", side_effect=[json.dumps(p).encode(), b"source"]), patch.object(runtime.os, "pipe", return_value=(21, 22)), patch.object(runtime.os, "close"), patch.object(runtime.os, "write", side_effect=lambda fd, data: events.append(("gate", fd, data)) or len(data)), patch.object(runtime, "register_proxy", side_effect=lambda *_args: events.append(("registered",))), patch.object(runtime.subprocess, "Popen", return_value=process) as spawn:
            self.assertEqual(runtime.provider_front("/private/policy.json", runtime.sha(json.dumps(p).encode()), ["logs", "-f", p["node"]]), 0)
            self.assertEqual(events, [("registered",), ("gate", 22, b"G")])
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            self.assertEqual(spawn.call_args.kwargs["pass_fds"], (21,))
            self.assertIn("--podman-proxy", spawn.call_args.args[0])

    def test_front_registration_failure_never_releases_gate_or_kills_unknown_backend(self):
        p = policy()
        p["environment"], p["source_sha256"] = {"HOME": "/private"}, runtime.sha(b"source")
        process = SimpleNamespace(pid=4242, poll=Mock(return_value=None), wait=Mock(return_value=1), kill=Mock())
        with patch.object(runtime, "regular", side_effect=[json.dumps(p).encode(), b"source"]), patch.object(runtime.os, "pipe", return_value=(21, 22)), patch.object(runtime.os, "close") as close, patch.object(runtime.os, "write") as gate, patch.object(runtime, "register_proxy", side_effect=runtime.Refusal("proxy-identity-drift")), patch.object(runtime.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(runtime.Refusal, "proxy-identity-drift"):
                runtime.provider_front("/private/policy.json", runtime.sha(json.dumps(p).encode()), [])
            gate.assert_not_called()
            process.kill.assert_not_called()
            self.assertIn(unittest.mock.call(22), close.call_args_list)

    def test_gate_eof_or_changed_identity_never_authorizes_provider_effect(self):
        for data, record, expected in [(b"", self.identity(), "proxy-gate-closed"), (b"G", {**self.identity(), "start": 18}, "proxy-lease-identity-drift")]:
            read_fd, write_fd = os.pipe()
            try:
                if data:
                    os.write(write_fd, data)
                os.close(write_fd)
                with patch.object(runtime, "state_read", return_value={"proxies": {"lease": record}}), patch.object(runtime, "process_identity", return_value=self.identity()):
                    with self.assertRaisesRegex(runtime.Refusal, expected):
                        runtime.await_proxy_gate(policy(), "lease", read_fd)
            finally:
                os.close(read_fd)

    def test_parent_sigkill_is_control_eof_even_when_kind_pipes_stay_open(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        try:
            with patch.object(runtime, "PROXY_CONTROL", read_fd), patch.object(runtime, "PROXY_POLICY", policy()), patch.object(runtime, "PROXY_LEASE", "lease"), patch.object(runtime, "state_read", return_value={"proxies": {"lease": {"cancel": False}}}):
                with self.assertRaisesRegex(runtime.Refusal, "provider-parent-cancelled"):
                    runtime.check_cancel()
        finally:
            os.close(read_fd)

    def test_controller_cancellation_reaches_backend_without_pipe_eof(self):
        read_fd, write_fd = os.pipe()
        try:
            with patch.object(runtime, "PROXY_CONTROL", read_fd), patch.object(runtime, "PROXY_POLICY", policy()), patch.object(runtime, "PROXY_LEASE", "lease"), patch.object(runtime, "state_read", return_value={"proxies": {"lease": {"cancel": True}}}):
                with self.assertRaisesRegex(runtime.Refusal, "provider-parent-cancelled"):
                    runtime.check_cancel()
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_missing_changed_and_unacknowledged_backend_quarantine_before_deletion(self):
        for observed in [OSError("gone"), {**self.identity(), "start": 18}, self.identity()]:
            with self.subTest(observed=type(observed).__name__):
                current = state()
                current["proxies"]["lease"] = {**self.identity(), "cancel": False, "retired": False}
                clock = iter([0, 0, 0, 6])
                with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "process_identity", side_effect=observed if isinstance(observed, Exception) else None, return_value=observed), patch.object(runtime, "reconcile") as reconcile, patch.object(runtime, "checked") as deletion:
                    errors = runtime.retire_proxies(policy(), clock=lambda: next(clock), sleep=lambda _value: None)
                    self.assertEqual(errors, ["proxy-retirement-unproved"])
                    self.assertTrue(current["retirement_unproved"])
                    self.assertTrue(current["proxies"]["lease"]["cancel"])
                    with patch.object(runtime, "retire_proxies", return_value=errors):
                        self.assertEqual(runtime.cleanup_resources(policy()), ["proxy-retirement-unproved"])
                    reconcile.assert_not_called()
                    deletion.assert_not_called()

    def test_backend_acknowledgement_requires_unchanged_identity_and_proved_children(self):
        current = state()
        current["proxies"]["lease"] = {**self.identity(), "retired": False}
        with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "process_identity", return_value=self.identity()):
            runtime.finish_proxy(policy(), "lease")
            self.assertTrue(current["proxies"]["lease"]["retired"])
            current["retirement_unproved"] = True
            runtime.finish_proxy(policy(), "lease")
            self.assertFalse(current["proxies"]["lease"]["retired"])
            current["proxies"]["lease"]["start"] += 1
            with self.assertRaisesRegex(runtime.Refusal, "proxy-lease-identity-drift"):
                runtime.finish_proxy(policy(), "lease")


    def test_registered_backend_getting_eof_before_gate_cannot_start(self):
        p, current = policy(), state()
        read_fd, write_fd = os.pipe()
        try:
            with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "process_identity", return_value=self.identity()):
                runtime.register_proxy(p, SimpleNamespace(pid=4242), "lease")
                os.close(write_fd)
                with self.assertRaisesRegex(runtime.Refusal, "proxy-gate-closed"):
                    runtime.await_proxy_gate(p, "lease", read_fd)
                self.assertFalse(current["proxies"]["lease"]["retired"])
                runtime.finish_proxy(p, "lease")
                self.assertTrue(current["proxies"]["lease"]["retired"])
        finally:
            os.close(read_fd)

    def test_controller_waits_for_retirement_ack_and_never_signals_reused_pid(self):
        p, current, observations = policy(), state(), []
        current["proxies"]["lease"] = {**self.identity(), "cancel": False, "retired": False}
        def acknowledge(_duration):
            observations.append((current["proxies"]["lease"]["cancel"], current["proxies"]["lease"]["retired"]))
            current["proxies"]["lease"]["retired"] = True
        with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "process_identity", return_value=self.identity()), patch.object(runtime.os, "killpg") as kill:
            self.assertEqual(runtime.retire_proxies(p, clock=lambda: 0, sleep=acknowledge), [])
            self.assertEqual(observations, [(True, False)])
            kill.assert_not_called()
        current["proxies"]["lease"]["retired"] = False
        with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "process_identity", return_value={**self.identity(), "start": 99}), patch.object(runtime.os, "killpg") as kill:
            self.assertEqual(runtime.retire_proxies(p, clock=lambda: 0), ["proxy-retirement-unproved"])
            kill.assert_not_called()

    def test_untrusted_exception_body_and_command_are_not_persisted_in_diagnostics(self):
        p, current = policy(), state()
        p["source_sha256"] = runtime.sha(b"source")
        raw = json.dumps(p).encode()
        with patch.object(runtime.sys, "argv", ["harness", "--podman-proxy", "/private/policy", runtime.sha(raw), "21", "lease", "exec", "private-command-body"]), patch.object(runtime, "regular", side_effect=[raw, b"source"]), patch.object(runtime, "await_proxy_gate"), patch.object(runtime, "_selected_helper_profile_admission"), patch.object(runtime, "provider", side_effect=ValueError("private-exception-body")) as provider, patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "finish_proxy"), patch.object(runtime, "PROXY_CONTROL"), patch.object(runtime, "PROXY_POLICY"), patch.object(runtime, "PROXY_LEASE"):
            self.assertEqual(runtime.main(), 1)
            provider.assert_called_once_with(p, ["exec", "private-command-body"])
        self.assertEqual(current["provider_diagnostics"], [{"code": "provider-unavailable", "state": "failed"}])
        self.assertNotIn("private-", json.dumps(current))


class EffectQuarantineControls(unittest.TestCase):
    def test_missing_negative_or_unjoined_network_and_volume_result_quarantines(self):
        for kind in ["network", "volume"]:
            for result in [None, {"returned": True, "status": -9, "identity": None}, {"returned": True, "status": 0, "identity": "late"}]:
                with self.subTest(kind=kind, result=result):
                    current = state()
                    current[kind + "_attempted"] = True
                    current[kind + "_result"] = result
                    with patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "read_creation_cid", side_effect=FileNotFoundError()), patch.object(runtime, "checked") as deletion, patch.object(runtime, "json_command") as discovery:
                        self.assertEqual(runtime.cleanup_resources(policy()), [kind + "-creation-outcome-unproved"])
                        deletion.assert_not_called()
                        discovery.assert_not_called()

    def test_incomplete_image_pull_is_quarantined_without_unrecorded_image_deletion(self):
        current = state()
        current["pull_attempted"] = True
        with patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "checked") as deletion:
            self.assertEqual(runtime.cleanup_resources(policy()), ["partial-image-preparation-quarantined"])
            deletion.assert_not_called()


class ScopedRetirementControls(unittest.TestCase):
    """Decision controls only: mocks do not establish native helper containment."""
    def prepared(self, phase="run"):
        p = policy()
        p["phase"], p["end"] = phase, 1000
        p["retirement"] = {"worker": {"pid": 10, "group": 10, "session": 10, "start": 5},
            "finalization_seconds": 30, "contract": {"launch_shell": {"pid": 11, "group": 11, "session": 11, "start": 6},
                "cgroup": p["cgroup"], "cgroup_identity": [7, 8], "boot_id": "boot", "unit": {"name": "owned.slice"}}}
        receipt = {"state": {"run": "readiness-observed-pending-retirement", "preflight": "preflight-only",
                    "prepare-image": "image-prepared-only"}[phase], "cleanup": "complete",
            "runtime_conformance": "pending", "api_acceptance": "pending",
            "producer_barrier": {"policy_sha256": "b" * 64, "at": 960, "cancelled": 0,
                "gates": {"objects": True, "proxies": True, "client_groups": True}}}
        boundary = SimpleNamespace(validate=Mock(), populated=Mock(return_value=0))
        return p, receipt, boundary

    def observe(self, p, receipt, boundary, clock=lambda: 980, sleep=lambda _seconds: None):
        with patch.object(runtime, "retirement_binding", return_value="b" * 64), patch.object(runtime, "check_retirement_process", return_value=False):
            return runtime.observe_scoped_retirement(boundary, p, receipt, clock, sleep)

    def test_exact_full_subtree_zero_is_productive_scoped_evidence_only(self):
        p, receipt, boundary = self.prepared()
        evidence = self.observe(p, receipt, boundary)
        self.assertEqual(evidence["state"], "subtree-empty-observed")
        self.assertEqual(evidence["boundary"], p["cgroup"])
        self.assertEqual(evidence["cgroup_identity"], [7, 8])
        self.assertEqual(evidence["producer_barrier_at"], 960)
        self.assertEqual(boundary.populated.call_count, 2)
        final = runtime.scoped_final_receipt(receipt, evidence)
        self.assertEqual(final["detached-helper-retirement"], "not-established")
        self.assertEqual(final["helper_containment"]["state"], "not-established")
        self.assertEqual(runtime.exit_status(final), 1)

    def test_no_caller_receipt_can_create_a_containment_provider(self):
        p, receipt, boundary = self.prepared()
        for untrusted in [True, {"closed": True}, {"all_helpers": "retired"}]:
            with self.subTest(untrusted=untrusted):
                forged = dict(receipt, state="readiness-passed", helper_containment=untrusted)
                forged["detached-helper-retirement"] = "retired"
                final = runtime.scoped_final_receipt(forged, self.observe(p, receipt, boundary))
                self.assertEqual(final["state"], "readiness-observed-pending-retirement")
                self.assertEqual(final["detached-helper-retirement"], "not-established")
                self.assertEqual(runtime.exit_status(forged), 1)
                self.assertEqual(runtime.exit_status(final), 1)

    def test_preflight_and_image_only_stay_nonreadiness(self):
        for phase in ["preflight", "prepare-image"]:
            with self.subTest(phase=phase):
                p, receipt, boundary = self.prepared(phase)
                final = runtime.scoped_final_receipt(receipt, self.observe(p, receipt, boundary))
                self.assertEqual(final["state"], receipt["state"])
                self.assertEqual(runtime.exit_status(final), 2)
                self.assertEqual(final["runtime_conformance"], "pending")
                self.assertEqual(final["api_acceptance"], "pending")

    def test_surviving_subtree_population_includes_detached_and_live_thread_cases(self):
        # The kernel subtree bit includes all member threads/sessions; no PID/name census.
        for survivor in ["setsid-helper", "grandchild", "zombie-leader-live-thread", "empty-leaf-live-sibling"]:
            with self.subTest(survivor=survivor):
                p, receipt, boundary = self.prepared()
                boundary.populated.return_value = 1
                ticks = iter([980, 980, 1000])
                with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                    self.observe(p, receipt, boundary, clock=lambda: next(ticks))

    def test_repopulation_before_confirmed_witness_is_failure(self):
        p, receipt, boundary = self.prepared()
        boundary.populated.side_effect = [0, 1]
        with self.assertRaisesRegex(runtime.Refusal, "retirement-repopulation"):
            self.observe(p, receipt, boundary)

    def test_original_deadline_and_cancellation_cannot_be_renewed(self):
        p, receipt, boundary = self.prepared()
        for cancelled, now, code in [(0, 1000, "retirement-deadline"), (signal.SIGTERM, 980, "cancelled")]:
            with self.subTest(cancelled=cancelled), patch.object(runtime, "CANCELLED", cancelled):
                with self.assertRaisesRegex(runtime.Refusal, code):
                    self.observe(p, receipt, boundary, clock=lambda: now)
        boundary.populated.assert_not_called()
        self.assertEqual(p["end"], 1000)
        self.assertEqual(runtime.Budget(p, cleanup=True, clock=lambda: 960).remaining(), 10)
        with self.assertRaisesRegex(runtime.Refusal, "cleanup-deadline"):
            runtime.Budget(p, cleanup=True, clock=lambda: 970).remaining()

    def test_object_proxy_group_and_late_barriers_block_before_kernel_witness(self):
        for gate in ["objects", "proxies", "client_groups", "cancelled", "late"]:
            with self.subTest(gate=gate):
                p, receipt, boundary = self.prepared()
                if gate == "cancelled":
                    receipt["producer_barrier"]["cancelled"] = signal.SIGTERM
                elif gate == "late":
                    receipt["producer_barrier"]["at"] = 971
                else:
                    receipt["producer_barrier"]["gates"][gate] = False
                with self.assertRaises(runtime.Refusal):
                    self.observe(p, receipt, boundary)
                boundary.populated.assert_not_called()

    def test_cleanup_errors_survive_finalization(self):
        p, receipt, boundary = self.prepared()
        receipt = runtime.join_receipt(receipt, runtime.Refusal("original-command-error"), ["proxy-retirement-unproved"])
        final = runtime.scoped_final_receipt(receipt, {"state": "not-established"}, "retirement-producer-barrier-incomplete")
        self.assertEqual(final["error"], "original-command-error")
        self.assertEqual(final["cleanup_errors"], ["proxy-retirement-unproved"])
        self.assertEqual(final["cleanup"], "incomplete-quarantined")
        self.assertEqual(runtime.exit_status(final), 1)

    def test_producer_identity_reuse_and_placement_drift_fail_closed(self):
        p, _receipt, _boundary = self.prepared()
        record = p["retirement"]["worker"]
        with patch.object(runtime, "retirement_process", return_value=dict(record, start=99)):
            with self.assertRaisesRegex(runtime.Refusal, "retirement-process-identity-drift"):
                runtime.check_retirement_process(record, p["cgroup"], True, True)
        with patch.object(runtime, "retirement_process", return_value=record), patch.object(runtime, "kernel_text", return_value="0::/elsewhere\n"):
            with self.assertRaisesRegex(runtime.Refusal, "retirement-process-placement-drift"):
                runtime.check_retirement_process(record, p["cgroup"], True, True)
        with patch.object(runtime, "retirement_process", side_effect=FileNotFoundError()):
            self.assertFalse(runtime.check_retirement_process(record, p["cgroup"], True, True))

    def test_live_worker_or_launch_shell_prevents_witness_even_with_zero_bit(self):
        for live in [[True, False], [False, True]]:
            with self.subTest(live=live):
                p, receipt, boundary = self.prepared()
                ticks = iter([980, 980, 1000])
                with patch.object(runtime, "retirement_binding", return_value="b" * 64), patch.object(runtime, "check_retirement_process", side_effect=live):
                    with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                        runtime.observe_scoped_retirement(boundary, p, receipt, lambda: next(ticks), lambda _seconds: None)
                boundary.populated.assert_not_called()

    def test_kernel_events_strict_bounded_and_identity_checked(self):
        boundary = runtime.RetirementBoundary({})
        boundary.events = 42
        for data in [b"", b"populated 0", b"populated 2\n", b"populated 0\npopulated 0\n", b"frozen 0\n", b"populated 0 extra\n"]:
            with self.subTest(data=data), patch.object(boundary, "validate"), patch.object(runtime, "bounded_kernel_read", return_value=data):
                with self.assertRaisesRegex(runtime.Refusal, "retirement-malformed-events"):
                    boundary.populated()
        with patch.object(boundary, "validate") as validate, patch.object(runtime, "bounded_kernel_read", return_value=b"populated 0\nfrozen 0\n"):
            self.assertEqual(boundary.populated(), 0)
            self.assertEqual(validate.call_count, 2)
        for error in [FileNotFoundError(), PermissionError(), runtime.Refusal("retirement-kernel-read-budget")]:
            with self.subTest(error=type(error).__name__), patch.object(boundary, "validate"), patch.object(runtime, "bounded_kernel_read", side_effect=error):
                with self.assertRaises(type(error)):
                    boundary.populated()
        with patch.object(runtime.os, "lseek"), patch.object(runtime.os, "read", return_value=b"x" * 17):
            with self.assertRaisesRegex(runtime.Refusal, "retirement-kernel-read-budget"):
                runtime.bounded_kernel_read(42, 16)

    def test_controller_inside_slice_boot_and_inode_drift_or_removed_path_refuse(self):
        p, _receipt, _boundary = self.prepared()
        contract = p["retirement"]["contract"]
        boundary = runtime.RetirementBoundary(contract)
        boundary.directory, boundary.events_identity = 20, [7, 9]
        for boot, text, identity, code in [("changed", "0::/outside\n", [7, 8], "retirement-boot-drift"),
                ("boot", "0::" + p["cgroup"].removeprefix("/sys/fs/cgroup") + "\n", [7, 8], "retirement-controller-inside-slice"),
                ("boot", "0::/outside\n", [7, 99], "retirement-slice-identity-drift")]:
            with self.subTest(code=code), patch.object(runtime, "boot_identity", return_value=boot), patch.object(runtime, "kernel_text", return_value=text), patch.object(runtime, "nofollow_directory", return_value=21), patch.object(runtime.os, "fstat", return_value=SimpleNamespace(st_dev=identity[0], st_ino=identity[1])), patch.object(runtime.os, "close"):
                with self.assertRaisesRegex(runtime.Refusal, code):
                    boundary.validate()
        with patch.object(runtime, "boot_identity", return_value="boot"), patch.object(runtime, "kernel_text", return_value="0::/outside\n"), patch.object(runtime, "nofollow_directory", side_effect=FileNotFoundError()):
            with self.assertRaises(FileNotFoundError):
                boundary.validate()

    def test_no_runtime_command_or_process_launch_in_finalizer(self):
        p, receipt, boundary = self.prepared()
        with patch.object(runtime.subprocess, "Popen") as launch, patch.object(runtime, "tool") as tool, patch.object(runtime, "checked") as mutation:
            self.observe(p, receipt, boundary)
            launch.assert_not_called()
            tool.assert_not_called()
            mutation.assert_not_called()

    def test_outer_envelope_caps_use_exact_kernel_files_and_refuse_unbounded(self):
        with tempfile.TemporaryDirectory() as directory:
            files = {"memory.max": "4294967296\n", "pids.max": "4096\n", "memory.swap.max": "0\n", "cpu.max": "200000 100000\n"}
            for name, value in files.items():
                (Path(directory) / name).write_text(value)
            envelope = runtime.ControllerEnvelope("/sys/fs/cgroup/" + runtime.PREFIX + "outer.slice")
            envelope.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = envelope.snapshot()
                self.assertEqual(result["memory"], 4294967296)
                self.assertEqual(result["cpu"], [200000, 100000])
                self.assertEqual(result["cgroup_identity"], [os.fstat(envelope.fd).st_dev, os.fstat(envelope.fd).st_ino])
                for name, value in [("memory.max", "max\n"), ("pids.max", "65537\n"), ("memory.swap.max", "1\n"), ("cpu.max", "max 100000\n")]:
                    with self.subTest(name=name):
                        (Path(directory) / name).write_text(value)
                        with self.assertRaises((runtime.Refusal, ValueError)):
                            envelope.snapshot()
                        (Path(directory) / name).write_text(files[name])
            finally:
                envelope.__exit__()

    def test_controller_must_enter_existing_envelope_before_contract_read(self):
        with patch.object(runtime, "ControllerEnvelope") as envelope, patch.object(runtime, "retirement_contract") as read_contract, patch.object(runtime.os, "geteuid", return_value=1000), patch.object(runtime.sys, "platform", "linux"):
            envelope.return_value.__enter__.side_effect = runtime.Refusal("retirement-envelope-finite-caps-required")
            with self.assertRaisesRegex(runtime.Refusal, "retirement-envelope-finite-caps-required"):
                runtime.retirement_controller("/private/contract", "b" * 64, "/explicit/envelope", clock=lambda: 10,
                    startup={"seconds": 600, "output_bytes": 8388608, "store_bytes": 17179869184,
                             "controller_output_bytes": 4194304, "controller_store_bytes": 1048576})
            read_contract.assert_not_called()

    def test_operator_unit_record_replacement_cannot_keep_old_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            store, handoff = Path(directory) / "store", Path(directory) / "handoff"
            store.mkdir(mode=0o700)
            handoff.mkdir(mode=0o700)
            contract = {"schema": 1, "owner": "a" * 32, "phase": "preflight", "boot_id": "boot",
                "source_sha256": runtime.sha(Path(runtime.__file__).read_bytes()), "cgroup": policy()["cgroup"],
                "unit": {"name": Path(policy()["cgroup"]).name, "transient": True, "invocation_id": "c" * 32},
                "limits": limits(), "store": str(store), "store_identity": [store.stat().st_dev, store.stat().st_ino],
                "cgroup_identity": [7, 8], "launch_shell": {"pid": 11, "group": 11, "session": 11, "start": 6},
                "envelope": {"cgroup": "/sys/fs/cgroup/outer.slice", "cgroup_identity": [1, 2],
                    "memory": 4294967296, "pids": 4096, "swap": 0, "cpu": [200000, 100000]},
                "controller_reservation": {"output_bytes": 4194304, "store_bytes": 1048576}}
            path = handoff / "contract.json"
            runtime.write_json(path, contract)
            digest = runtime.sha(path.read_bytes())
            with patch.object(runtime, "boot_identity", return_value="boot"):
                self.assertEqual(runtime.retirement_contract(path, digest)[0], contract)
                contract["unit"]["invocation_id"] = "d" * 32
                runtime.write_json(path, contract)
                with self.assertRaisesRegex(runtime.Refusal, "retirement-contract-integrity"):
                    runtime.retirement_contract(path, digest)

    def test_missing_native_gate_never_triggers_execute_or_cleanup_commands(self):
        p, _receipt, _boundary = self.prepared("preflight")
        p["retirement"]["handoff"] = "/private/handoff"
        p["profile"]["id"], p["store_before"], p["ledger_sha256"] = "fake-profile", {}, "a" * 64
        values = {key: value for key, value in limits().items()}
        values.update({key: "explicit" for key in ["profile", "kind", "kubectl", "podman", "podman_sha256", "helper_manifest", "helper_manifest_sha256", "retirement_contract", "retirement_contract_sha256"]})
        args = SimpleNamespace(**values, phase="preflight", self_test=False, cgroup=p["cgroup"], store=p["store"],
            controller_output_bytes=4194304, controller_store_bytes=1048576,
            retirement_original_start=time.monotonic(), retirement_original_end=time.monotonic() + 600)
        worker_io = Mock()
        # Isolate only this earlier refusal seam so the original missing-gate path is reached.
        with patch.object(runtime, "_selected_helper_profile_admission", return_value=None) as admission, patch.object(runtime.sys, "argv", ["harness"]), patch.object(runtime, "arguments", return_value=(Mock(), args)), patch.object(runtime.os, "open", return_value=5), patch.object(runtime.os, "close"), patch.object(runtime.os, "umask"), patch.object(runtime.fcntl, "flock"), patch.object(runtime.signal, "signal"), patch.object(runtime, "worker_retirement", return_value=({"contract_sha256": "a" * 64, "arm_sha256": "b" * 64, "handoff": "/private/handoff"}, worker_io)), patch.object(runtime, "make_policy", return_value=p), patch.object(runtime, "worker_native_gate", side_effect=runtime.Refusal("retirement-native-gate-drift")) as native_gate, patch.object(runtime, "execute") as execute, patch.object(runtime, "cleanup_resources") as cleanup, patch.object(runtime, "state_read", return_value=state()), patch.object(runtime, "store_limit", return_value={}), patch.object(runtime, "retirement_binding", return_value="b" * 64), patch.object(runtime, "write_json"), patch("builtins.print"), patch.object(runtime, "CANCELLED", 0):
            self.assertEqual(runtime.main(), 1)
            admission.assert_called_once_with()
            native_gate.assert_called_once_with(p, worker_io)
            execute.assert_not_called()
            cleanup.assert_not_called()


class OriginalControllerBudgetControls(unittest.TestCase):
    """Real controller/IO composition with synthetic kernel facts; no native evidence."""
    def io(self, clock=lambda: 10):
        return runtime.ControllerIO(10, 600, 8 * 1024**2, 16 * 1024**3,
                                    4 * 1024**2, 1024**2, clock)

    def composition(self, directory, phase="preflight", before_contract=None, final_hook=None, construction_hook=None):
        handoff, store = Path(directory) / "handoff", Path(directory) / "store"
        handoff.mkdir(mode=0o700)
        (store / "control").mkdir(parents=True)
        path = handoff / "contract.json"
        path.write_bytes(b"{}\n")
        now = [10]
        io = self.io(lambda: now[0])
        envelope = SimpleNamespace(path="/sys/fs/cgroup/outer.slice", record={
            "cgroup": "/sys/fs/cgroup/outer.slice", "cgroup_identity": [1, 2],
            "memory": 4294967296, "pids": 4096, "swap": 0, "cpu": [200000, 100000]})
        contract = {"cgroup": envelope.path + "/" + runtime.PREFIX + "target.slice",
            "cgroup_identity": [3, 4], "boot_id": "boot", "owner": "a" * 32,
            "unit": {"name": "target.slice", "transient": True, "invocation_id": "c" * 32},
            "limits": limits(), "controller_reservation": io.reservation, "envelope": envelope.record,
            "store": str(store), "store_identity": [5, 6], "source_sha256": "d" * 64,
            "phase": phase, "launch_shell": {"pid": 11, "group": 11, "session": 11, "start": 6}}
        controller = {"pid": 12, "group": 12, "session": 12, "start": 7}
        worker = {"pid": 13, "group": 13, "session": 13, "start": 8}
        produced = {}
        def read_contract(*_args, **_kwargs):
            if before_contract:
                before_contract(now, contract)
            return contract, handoff
        def wait_record(target, *_args, **_kwargs):
            if target.name == "worker.json":
                arm_raw = (handoff / "armed.json").read_bytes()
                arm = json.loads(arm_raw)
                record = {"contract": contract, "contract_sha256": "b" * 64,
                    "handoff": str(handoff), "arm_sha256": runtime.sha(arm_raw),
                    "worker": worker, "controller": controller, "end": io.end,
                    "controller_reservation": io.reservation, "worker_io": arm["worker_io"],
                    "finalization_seconds": 30}
                p = {"directory": str(store / "control"), "store": str(store),
                    "cluster": "test-cluster", "retirement": record, "end": io.end,
                    "owner": contract["owner"], "phase": phase, "store_identity": [5, 6],
                    "cgroup": contract["cgroup"], "limits": contract["limits"], "source_sha256": "d" * 64}
                raw = json.dumps(p).encode()
                (store / "control/policy.json").write_bytes(raw)
                (store / "control/ownership.json").write_text(json.dumps({"owner": p["owner"],
                    "cluster": p["cluster"], "commands": 0, "output": io.reservation["output_bytes"], "input": 0}))
                produced["binding"] = runtime.sha(raw)
                return {"policy_sha256": produced["binding"], "arm_sha256": record["arm_sha256"], "worker": worker}
            return {"state": "preflight-only", "cleanup": "complete", "producer_barrier": {
                "policy_sha256": produced["binding"], "at": 10, "cancelled": 0,
                "gates": {"objects": True, "proxies": True, "client_groups": True}}}
        boundary = SimpleNamespace(validate=Mock(), populated=Mock(return_value=0))
        original_receipt = runtime.scoped_final_receipt
        def construct(*args, **kwargs):
            value = original_receipt(*args, **kwargs)
            if construction_hook:
                construction_hook(now)
            return value
        original = io._serialize_precharged
        def serialize(value, bound):
            raw = original(value, bound)
            if final_hook and "helper_containment" in value:
                final_hook(now)
            return raw
        with patch.object(runtime, "retirement_contract", side_effect=read_contract), \
                patch.object(runtime, "RetirementBoundary", return_value=nullcontext(boundary)), \
                patch.object(runtime, "retirement_process", return_value=controller), \
                patch.object(runtime, "check_retirement_process", return_value=False), \
                patch.object(runtime, "store_limit", return_value={"allocated_bytes": 0}), \
                patch.object(runtime, "wait_retirement_record", side_effect=wait_record), \
                patch.object(io, "_serialize_precharged", side_effect=serialize), \
                patch.object(runtime, "scoped_final_receipt", side_effect=construct), \
                patch.object(runtime.sys, "stdout") as stdout, \
                patch.object(runtime.subprocess, "Popen") as launch, \
                patch.object(runtime, "tool") as tool:
            try:
                result = runtime.controlled_retirement(path, "b" * 64, envelope, 10, lambda: now[0], io)
            finally:
                launch.assert_not_called()
                tool.assert_not_called()
            return result, io, stdout, boundary

    def test_real_accounted_controller_publishes_scoped_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            result, io, stdout, boundary = self.composition(directory)
            receipt = json.loads((Path(directory) / "handoff/final.json").read_bytes())
            self.assertEqual(result, 2)
            self.assertEqual(receipt["scoped_retirement"]["state"], "subtree-empty-observed")
            self.assertEqual(receipt["helper_containment"]["state"], "not-established")
            self.assertEqual(boundary.populated.call_count, 2)
            self.assertEqual(json.loads(stdout.write.call_args.args[0]), receipt)
            self.assertGreater(io.used, runtime._worker_io_reservation(Path(runtime.__file__).stat().st_size)["output_bytes"])
            self.assertLessEqual(io.used, io.reservation["output_bytes"])
            self.assertLessEqual(io.stored, io.reservation["store_bytes"])
            self.assertEqual(io.end, 610)

    def test_contract_acquisition_expiry_or_cancel_has_no_claim_arm_or_gate(self):
        for mode in ["expired", "cancelled"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, patch.object(runtime, "CANCELLED", 0):
                def stop(now, _contract):
                    if mode == "expired":
                        now[0] = 610
                    else:
                        runtime.CANCELLED = signal.SIGTERM
                with self.assertRaises(runtime.Refusal):
                    self.composition(directory, before_contract=stop)
                self.assertEqual([p.name for p in (Path(directory) / "handoff").iterdir()], ["contract.json"])

    def test_original_partition_drift_has_no_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            def change(_now, contract):
                contract["limits"]["seconds"] = 601
            with self.assertRaisesRegex(runtime.Refusal, "retirement-original-partition-drift"):
                self.composition(directory, before_contract=change)
            self.assertFalse((Path(directory) / "handoff/controller.claim").exists())

    def test_expiry_during_final_construction_or_serialization_has_no_final_file(self):
        for stage in ["construction_hook", "final_hook"]:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                    self.composition(directory, **{stage: lambda now: now.__setitem__(0, 610)})
                self.assertFalse((Path(directory) / "handoff/final.json").exists())

    def test_exact_output_bound_and_one_over_precede_serializer(self):
        # Independent formula for {"state":"failed"}: punctuation 5, strings 62+74.
        for budget, accepted in [(141, True), (140, False)]:
            with self.subTest(budget=budget):
                io = self.io()
                io.output_share = budget
                with patch.object(runtime.json, "dumps", wraps=json.dumps) as serialize:
                    if accepted:
                        self.assertEqual(json.loads(io.encode({"state": "failed"})), {"state": "failed"})
                        self.assertEqual(io.used, 141)
                    else:
                        with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                            io.encode({"state": "failed"})
                        serialize.assert_not_called()

    def test_store_rounding_partition_exact_fit_and_one_over(self):
        for share, accepted in [(8192, True), (8191, False)]:
            with self.subTest(share=share):
                io = self.io()
                io.directory, io.store_share = Path("/synthetic"), share
                with patch.object(runtime.os, "statvfs", return_value=SimpleNamespace(f_frsize=4096)), patch.object(io, "handoff_measure"):
                    if accepted:
                        io.reserve_store(3)
                        self.assertEqual(io.stored, 8192)
                    else:
                        with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-store-budget"):
                            io.reserve_store(3)

    def test_closed_receipts_reject_unknown_nested_protected_and_large_records(self):
        for record in [{"protected_body": "secret"}, {"profile": {"secret": "value"}},
                       {"state": "x" * 4097}, {"state": "x" * 4096, "error": "x" * 4096},
                       {"cleanup_errors": ["error"] * 513},
                       {"provider_diagnostics": [{"code": "valid", "state": "failed", "body": "secret"}]}]:
            with self.subTest(record=record), patch.object(runtime.json, "dumps") as serialize:
                with self.assertRaises(runtime.Refusal):
                    self.io().encode(record, runtime.CONTROLLER_RECORD_KEYS)
                serialize.assert_not_called()

    def test_json_depth_tokens_and_duplicate_fields_refuse_before_decode_or_copy(self):
        io = self.io()
        for raw in [b"[" * 13 + b"0" + b"]" * 13, b"[" + b"0," * 4097 + b"0]"]:
            with self.subTest(raw_length=len(raw)), patch.object(runtime.json, "loads") as decode:
                with self.assertRaises(runtime.Refusal):
                    io.decode(raw, 65536)
                decode.assert_not_called()
        with self.assertRaisesRegex(runtime.Refusal, "retirement-duplicate-field"):
            io.decode(b'{"state":"failed","state":"passed"}', 65536)

    def test_read_charges_shared_credit_and_missing_polls_never_refund(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record"
            path.write_bytes(b"123")
            io = self.io()
            self.assertEqual(io.read(path, 3), b"123")
            self.assertEqual(io.used, 5 + 256 * (len(path.parts) + 3))
            with self.assertRaises(FileNotFoundError):
                io.read(path.parent / "absent", 3)
            self.assertEqual(io.used, 6 + 256 * (len(path.parts) + 4))

    def test_expired_fsync_and_stdout_cannot_return_success(self):
        with tempfile.TemporaryDirectory() as directory:
            for stage in ["fsync", "stdout"]:
                with self.subTest(stage=stage):
                    now = [10]
                    io = self.io(lambda: now[0])
                    io.directory, io.contract_name = Path(directory), "contract.json"
                    if stage == "fsync":
                        with patch.object(runtime.os, "fsync", side_effect=lambda _fd: now.__setitem__(0, 610)), patch.object(runtime.os, "replace") as replace:
                            with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                                io.write(Path(directory) / "final.json", {"state": "failed"})
                            replace.assert_not_called()
                        for path in Path(directory).iterdir():
                            path.unlink()
                    else:
                        with patch.object(runtime.sys, "stdout") as stdout:
                            stdout.write.side_effect = lambda _text: now.__setitem__(0, 610)
                            with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                                io.publish({"state": "preflight-only", "cleanup": "complete"})

    def test_worker_partition_precharges_output_without_reducing_input_cap(self):
        p = policy()
        p["retirement"] = {"controller_reservation": {"output_bytes": 123456, "store_bytes": 1048576}}
        current = state()
        runtime._worker_budget_counters(current, p["retirement"])
        self.assertEqual((current["output"], current["input"], current["commands"]), (123456, 0, 0))
        self.assertEqual(p["limits"]["output_bytes"], 8388608)
        self.assertEqual(runtime._worker_store_limit(p), 17179869184 - 1048576)

    def test_known_unsupported_proxy_and_front_refuse_before_every_effect(self):
        for argv in [["harness", "--podman-front", "/policy", "digest"],
                     ["harness", "--podman-proxy", "/policy", "digest", "7", "lease"]]:
            with self.subTest(argv=argv), patch.object(runtime.sys, "argv", argv), \
                    patch.object(runtime, "regular") as read, patch.object(runtime, "provider_front") as front, \
                    patch.object(runtime, "provider") as provider, patch.object(runtime.subprocess, "Popen") as launch:
                self.assertEqual(runtime.main(), 1)
                for effect in [read, front, provider, launch]:
                    effect.assert_not_called()

    def test_known_unsupported_worker_refuses_with_prepaid_handoff_before_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            store, handoff = Path(directory) / "store", Path(directory) / "handoff"
            store.mkdir()
            handoff.mkdir(mode=0o700)
            start = time.monotonic()
            io = runtime.ControllerIO(start, 600, 8388608, 17179869184, 4194304, 1048576)
            io.directory, io.contract_name = handoff, "contract.json"
            values = limits()
            values.update({name: "explicit" for name in ["profile", "kind", "kubectl", "podman", "podman_sha256",
                "helper_manifest", "helper_manifest_sha256", "retirement_contract", "retirement_contract_sha256"]})
            args = SimpleNamespace(**values, phase="preflight", self_test=False, cgroup="/synthetic", store=str(store),
                controller_output_bytes=4194304, controller_store_bytes=1048576,
                retirement_original_start=start, retirement_original_end=start + 600)
            record = {"contract_sha256": "a" * 64, "arm_sha256": "b" * 64, "handoff": str(handoff)}
            with patch.object(runtime.sys, "argv", ["harness"]), patch.object(runtime, "arguments", return_value=(Mock(), args)), \
                    patch.object(runtime, "worker_retirement", return_value=(record, io)), \
                    patch.object(runtime, "make_policy") as bootstrap, patch.object(runtime, "execute") as execute, \
                    patch.object(runtime, "worker_native_gate") as gate, patch.object(runtime, "cleanup_resources") as cleanup, \
                    patch.object(runtime.subprocess, "Popen") as launch, patch.object(runtime, "CANCELLED", 0):
                self.assertEqual(runtime.main(), 1)
                for effect in [bootstrap, execute, gate, cleanup, launch]:
                    effect.assert_not_called()
            refusal = json.loads((handoff / "worker.json").read_bytes())
            self.assertEqual(set(refusal), {"state", "error", "contract_sha256", "arm_sha256"})
            self.assertEqual(refusal["error"], "unsupported-selected-helper-containment")
            self.assertGreater(io.used, 0)


class StoreTraversalAdmissionControls(unittest.TestCase):
    """Filesystem metadata stages spend original credit; no native tool is used."""
    def test_default_measurement_remains_usable_without_controller_callbacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            data = child / "data"
            data.write_bytes(b"bounded payload")
            expected = (child.stat().st_blocks + data.stat().st_blocks) * 512
            self.assertEqual(runtime.store_limit(root, 16 * 1024**2), {
                "allocated_bytes": expected, "entries": 2, "disk_enforcement": "measured-not-quota"})

    def test_real_store_and_controller_io_success_charge_exact_original_metadata_credit(self):
        # This uses real store_limit and real ControllerIO. The full-controller positive
        # above uses synthetic kernel facts and a store stub; it covers a separate layer.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir(mode=0o700)
            outer_file, inner_file = root / "outer", child / "inner"
            outer_file.write_bytes(b"outer payload")
            inner_file.write_bytes(b"inner payload")
            entries = [child, outer_file, inner_file]
            measured_bytes = sum(path.stat().st_blocks for path in entries) * 512
            # Independent known-tree contract: ancestor probes; four root probes;
            # two directory opens; three entry stats; five next steps (3+2 ends);
            # one free-space query. Every metadata access costs 256 original bytes.
            expected_accesses = len(root.parts) + 4 + 2 + 3 + 5 + 1
            expected_credit = expected_accesses * 256
            now = [10]
            io = runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576,
                                      clock=lambda: now[0])
            io.output_share = expected_credit
            self.assertGreater(expected_credit, 0)
            self.assertEqual(io.measure_store(root, 16 * 1024**2), {
                "allocated_bytes": measured_bytes, "entries": 3, "disk_enforcement": "measured-not-quota"})
            self.assertEqual(io.used, expected_credit)
            self.assertEqual((io.start, io.end, io.original["seconds"], io.original["output_bytes"]),
                             (10, 610, 600, 8388608))
            # A second traversal cannot renew any of the spent metadata share.
            with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                io.measure_store(root, 16 * 1024**2)
            self.assertEqual(io.used, expected_credit)
            now[0] = 610
            with self.assertRaisesRegex(runtime.Refusal, "retirement-deadline"):
                io.check()
            self.assertEqual((io.start, io.end), (10, 610))

    def test_admission_and_account_failure_precede_first_metadata_access(self):
        for mode in ["admit", "account"]:
            with self.subTest(mode=mode), patch.object(Path, "is_symlink") as probe, \
                    patch.object(runtime.os, "scandir") as scan:
                check, charge = Mock(), Mock()
                if mode == "admit":
                    check.side_effect = runtime.Refusal("retirement-deadline")
                else:
                    charge.side_effect = runtime.Refusal("retirement-controller-output-budget")
                with self.assertRaises(runtime.Refusal):
                    runtime.store_limit("/private/store", 16 * 1024**2, check, charge)
                probe.assert_not_called()
                scan.assert_not_called()
                if mode == "admit":
                    charge.assert_not_called()
                else:
                    charge.assert_called_once_with(256)

    def test_each_directory_next_is_charged_and_bracketed_before_entry_stat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode in ["budget-before-next", "deadline-after-next"]:
                with self.subTest(mode=mode):
                    now = [10]
                    io = runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576,
                                              clock=lambda: now[0])
                    entry_stat = Mock()
                    entry = SimpleNamespace(stat=entry_stat, path=str(root / "entry"))
                    class DirectoryIterator:
                        def __next__(self):
                            next_step()
                            return entry
                        def close(self):
                            closed()
                    next_step, closed = Mock(), Mock()
                    # Ancestor probes, four root probes and the directory open fit exactly.
                    # The next directory step needs an additional 256 original bytes.
                    before_next = 256 * (len([root, *root.parents]) + 5)
                    if mode == "budget-before-next":
                        io.output_share = before_next
                    else:
                        next_step.side_effect = lambda: now.__setitem__(0, 610)
                    with patch.object(runtime.os, "scandir", return_value=DirectoryIterator()):
                        with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget" if mode == "budget-before-next" else "retirement-deadline"):
                            io.measure_store(root, 16 * 1024**2)
                    entry_stat.assert_not_called()
                    closed.assert_called_once_with()
                    if mode == "budget-before-next":
                        next_step.assert_not_called()
                        self.assertEqual(io.used, before_next)
                    else:
                        next_step.assert_called_once_with()
                        self.assertEqual(io.used, before_next + 256)


class HandoffMetadataAdmissionControls(unittest.TestCase):
    """Real cumulative surface debits; none represents physical filesystem Work."""
    def prepared(self, directory, clock=lambda: 10):
        path = Path(directory) / "contract.json"
        path.touch(mode=0o600)
        path.write_bytes(b"{}\n")
        io = runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576, clock=clock)
        io.directory, io.contract_name = Path(directory), path.name
        return io, path

    def test_real_repeat_handoff_and_reservation_measurements_spend_original_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            io, path = self.prepared(directory)
            measured = (Path(directory).stat().st_blocks + path.stat().st_blocks) * 512
            # One directory stat/open, two next steps and one entry stat = five.
            each_measurement = 5 * 256
            self.assertEqual(io.handoff_measure(), measured)
            self.assertEqual(io.used, each_measurement)
            self.assertEqual(io.handoff_measure(), measured)
            self.assertEqual(io.used, 2 * each_measurement)
            io.reserve_store(3)
            self.assertEqual(io.used, 3 * each_measurement + 256)  # Includes statvfs.
            self.assertEqual((io.start, io.end, io.original["output_bytes"]), (10, 610, 8388608))
            self.assertGreater(io.used, 0)
            self.assertLessEqual(io.used, io.output_share)

    def test_exact_and_one_over_metadata_credit_block_before_next_os_access(self):
        with tempfile.TemporaryDirectory() as directory:
            io, _path = self.prepared(directory)
            io.output_share = 6 * 256  # statvfs plus the five-step measurement.
            block = os.statvfs(directory).f_frsize
            io.reserve_store(3)
            self.assertEqual(io.used, 6 * 256)
            self.assertEqual(io.stored, 2 * ((3 + block - 1) // block) * block)
            io, _path = self.prepared(directory)
            io.output_share = 6 * 256 - 1
            original_scan = os.scandir
            next_step = Mock()
            class TrackedIterator:
                def __init__(self, underlying):
                    self.underlying = underlying
                def __next__(self):
                    next_step()
                    return next(self.underlying)
                def close(self):
                    self.underlying.close()
            with patch.object(runtime.os, "scandir", side_effect=lambda path: TrackedIterator(original_scan(path))):
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.reserve_store(3)
            # The over-budget terminal next was never allowed into the OS iterator.
            self.assertEqual(next_step.call_count, 1)
            self.assertEqual(io.used, 5 * 256)
            io, _path = self.prepared(directory)
            io.output_share = 255
            with patch.object(runtime.os, "statvfs", side_effect=AssertionError("unadmitted OS access")) as probe:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.reserve_store(3)
                probe.assert_not_called()
            self.assertEqual(io.used, 0)

    def test_deadline_and_cancel_trip_before_metadata_and_after_directory_step(self):
        for mode in ["deadline", "cancel"]:
            for stage in ["before-first", "after-next"]:
                with self.subTest(mode=mode, stage=stage), tempfile.TemporaryDirectory() as directory, patch.object(runtime, "CANCELLED", 0):
                    now = [10]
                    io, _path = self.prepared(directory, clock=lambda: now[0])
                    def stop():
                        if mode == "deadline":
                            now[0] = 610
                        else:
                            runtime.CANCELLED = signal.SIGTERM
                    if stage == "before-first":
                        stop()
                        with patch.object(Path, "stat", side_effect=AssertionError("late stat")) as stat_probe, \
                                patch.object(runtime.os, "statvfs", side_effect=AssertionError("late statvfs")) as vfs_probe:
                            with self.assertRaises(runtime.Refusal):
                                io.handoff_measure()
                            with self.assertRaises(runtime.Refusal):
                                io.reserve_store(3)
                            stat_probe.assert_not_called()
                            vfs_probe.assert_not_called()
                        self.assertEqual(io.used, 0)
                    else:
                        entry_stat, closed = Mock(), Mock()
                        entry = SimpleNamespace(name="contract.json", stat=entry_stat)
                        class DirectoryIterator:
                            def __next__(self):
                                stop()
                                return entry
                            def close(self):
                                closed()
                        with patch.object(runtime.os, "scandir", return_value=DirectoryIterator()):
                            with self.assertRaises(runtime.Refusal):
                                io.handoff_measure()
                        entry_stat.assert_not_called()
                        closed.assert_called_once_with()
                        self.assertEqual(io.used, 3 * 256)
                    self.assertEqual((io.start, io.end), (10, 610))


class CompleteMetadataSurfaceControls(unittest.TestCase):
    """Real filesystem effects share original credit; synthetic caps are not native proof."""
    def io(self, clock=lambda: 10):
        return runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576, clock=clock)

    def handoff(self, directory):
        path = Path(directory) / "contract.json"
        path.touch(mode=0o600)
        path.write_bytes(b"{}\n")
        io = self.io()
        io.directory, io.contract_name = Path(directory), path.name
        return io

    def test_real_empty_read_exact_and_one_short_before_fstat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty"
            path.touch()
            # Two content framing units; outer stat, one ancestor lstat per part,
            # open and fstat. Reads/EOF have the separately prepaid content window.
            exact = 2 + 256 * (len(path.parts) + 3)
            io = self.io()
            io.output_share = exact
            self.assertEqual(io.read(path, 0), b"")
            self.assertEqual(io.used, exact)
            io = self.io()
            io.output_share = exact - 1
            original = os.fstat
            with patch.object(runtime.os, "fstat", wraps=original) as fstat:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.read(path, 0)
                fstat.assert_not_called()
            self.assertEqual(io.used, exact - 256)
            # The reported residual-two case must fail before even the outer stat.
            io = self.io()
            io.output_share = 2
            with patch.object(runtime.os, "stat", wraps=os.stat) as stat_probe:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.read(path, 0)
                stat_probe.assert_not_called()
            self.assertEqual(io.used, 1)

    def test_real_read_failure_and_post_stat_expiry_or_cancel_keep_spent_debits(self):
        with tempfile.TemporaryDirectory() as directory:
            io = self.io()
            with self.assertRaises(FileNotFoundError):
                io.read(Path(directory) / "missing", 0)
            self.assertEqual(io.used, 257)
            path = Path(directory) / "record"
            path.write_bytes(b"payload")
            for mode in ["deadline", "cancel"]:
                with self.subTest(mode=mode), patch.object(runtime, "CANCELLED", 0):
                    now = [10]
                    io = self.io(lambda: now[0])
                    original = Path.stat
                    visited = []
                    def stop_after_stat(target, *args, **kwargs):
                        result = original(target, *args, **kwargs)
                        visited.append(str(target))
                        if target == path:
                            if mode == "deadline":
                                now[0] = 610
                            else:
                                runtime.CANCELLED = signal.SIGTERM
                        return result
                    with patch.object(Path, "stat", new=stop_after_stat), patch.object(runtime.os, "open", wraps=os.open) as opened:
                        with self.assertRaises(runtime.Refusal):
                            io.read(path, 7)
                        opened.assert_not_called()
                    self.assertEqual(visited, [str(path)])
                    self.assertEqual(io.used, 257)
                    self.assertEqual((io.start, io.end), (10, 610))

    def test_real_nofollow_components_exact_one_short_and_depth_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "child" / "leaf"
            target.mkdir(parents=True)
            exact = len(target.parts) * 256
            io = self.io()
            io.output_share = exact
            fd = runtime.nofollow_directory(target, io.check, io.charge)
            try:
                self.assertEqual(os.fstat(fd).st_ino, target.stat().st_ino)
            finally:
                os.close(fd)
            self.assertEqual(io.used, exact)
            io = self.io()
            io.output_share = exact - 1
            actual_open, entered = os.open, []
            def observed_open(path, *args, **kwargs):
                entered.append(path)
                return actual_open(path, *args, **kwargs)
            with patch.object(runtime.os, "open", side_effect=observed_open):
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    runtime.nofollow_directory(target, io.check, io.charge)
            self.assertEqual(len(entered), len(target.parts) - 1)
            self.assertNotIn("leaf", entered)
            self.assertEqual(io.used, exact - 256)
            excessive = Path("/" + "/".join(["component"] * 64))
            deep_io = self.io()
            with patch.object(runtime.os, "open", wraps=actual_open) as opened:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-metadata-path-depth"):
                    runtime.nofollow_directory(excessive, deep_io.check, deep_io.charge)
                opened.assert_not_called()
                with self.assertRaisesRegex(runtime.Refusal, "retirement-metadata-path-depth"):
                    runtime.regular(excessive, 1)
                opened.assert_not_called()

    def test_real_kernel_window_open_and_seek_are_separate_from_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record"
            path.write_bytes(b"abc")
            exact = 4 + 2 * 256
            io = self.io()
            io.output_share = exact
            self.assertEqual(io.kernel_text(path, 3), "abc")
            self.assertEqual(io.used, exact)
            io = self.io()
            io.output_share = exact - 1
            with patch.object(runtime.os, "lseek", wraps=os.lseek) as seek:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.kernel_text(path, 3)
                seek.assert_not_called()
            self.assertEqual(io.used, exact - 256)

    def test_real_envelope_snapshot_exact_and_one_short_before_last_seek(self):
        with tempfile.TemporaryDirectory() as directory:
            records = {"memory.max": "4294967296\n", "pids.max": "4096\n", "memory.swap.max": "0\n", "cpu.max": "200000 100000\n"}
            for name, value in records.items():
                (Path(directory) / name).write_text(value)
            # One fstat + four (open,seek) pairs; four independent128+EOF windows.
            exact = 9 * 256 + 4 * 129
            for share in [exact, exact - 1]:
                with self.subTest(share=share):
                    io = self.io()
                    io.output_share = share
                    envelope = runtime.ControllerEnvelope("/sys/fs/cgroup/" + runtime.PREFIX + "outer.slice", io)
                    envelope.fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with patch.object(runtime.os, "lseek", wraps=os.lseek) as seek:
                            if share == exact:
                                self.assertEqual(envelope.snapshot()["cpu"], [200000, 100000])
                                self.assertEqual(io.used, exact)
                                self.assertEqual(seek.call_count, 4)
                            else:
                                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                                    envelope.snapshot()
                                self.assertEqual(seek.call_count, 3)
                                self.assertEqual(io.used, exact - 256)
                    finally:
                        envelope.__exit__()

    def test_real_contract_reader_exact_original_metadata_and_source_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            store, handoff = Path(directory) / "store", Path(directory) / "handoff"
            store.mkdir(mode=0o700)
            handoff.mkdir(mode=0o700)
            path = handoff / "contract.json"
            cgroup = policy()["cgroup"]
            source = Path(runtime.__file__)
            source_bytes = source.read_bytes()
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            contract = {"schema": 1, "owner": "a" * 32, "phase": "preflight", "boot_id": boot,
                "source_sha256": runtime.sha(source_bytes), "cgroup": cgroup, "cgroup_identity": [1, 2],
                "unit": {"name": Path(cgroup).name, "transient": True, "invocation_id": "b" * 32},
                "limits": limits(), "store": str(store), "store_identity": [store.stat().st_dev, store.stat().st_ino],
                "launch_shell": {"pid": 11, "group": 11, "session": 11, "start": 6},
                "envelope": {"cgroup": "/sys/fs/cgroup/" + runtime.PREFIX + "outer.slice", "cgroup_identity": [3, 4],
                    "memory": 4294967296, "pids": 4096, "swap": 0, "cpu": [200000, 100000]},
                "controller_reservation": {"output_bytes": 4194304, "store_bytes": 1048576}}
            path.touch(mode=0o600)
            raw = json.dumps(contract).encode()
            path.write_bytes(raw)
            # Two regular reads each cost parts+3; path/parent2; boot open+seek2;
            # store ancestry/probes cost store.parts+4. Content includes boot4097.
            events = len(path.parts) + len(source.parts) + len(store.parts) + 14
            exact = len(raw) + len(source_bytes) + 4101 + events * 256
            io = self.io()
            io.output_share = exact
            self.assertEqual(runtime.retirement_contract(path, runtime.sha(raw), io=io), (contract, handoff))
            self.assertEqual(io.used, exact)
            self.assertEqual((io.start, io.end), (10, 610))

    def test_real_write_exact_and_one_short_before_temporary_open(self):
        with tempfile.TemporaryDirectory() as directory:
            io = self.handoff(directory)
            # {state:failed} bound141. statvfs1, pre-measure5, file effects6,
            # post-measure7 (contract+final) =19 independently enumerated effects.
            exact = 141 + 19 * 256
            io.output_share = exact
            io.write(Path(directory) / "final.json", {"state": "failed"}, runtime.CONTROLLER_RECORD_KEYS)
            self.assertEqual(io.used, exact)
            self.assertEqual(json.loads((Path(directory) / "final.json").read_bytes()), {"state": "failed"})
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["contract.json", "final.json"])
        with tempfile.TemporaryDirectory() as directory:
            io = self.handoff(directory)
            io.output_share = 141 + 6 * 256 + 255
            with patch.object(runtime.os, "open", wraps=os.open) as opened:
                with self.assertRaisesRegex(runtime.Refusal, "retirement-controller-output-budget"):
                    io.write(Path(directory) / "final.json", {"state": "failed"}, runtime.CONTROLLER_RECORD_KEYS)
                opened.assert_not_called()
            self.assertEqual(io.used, 141 + 6 * 256)
            self.assertEqual([path.name for path in Path(directory).iterdir()], ["contract.json"])

    def test_real_failed_write_open_is_debited_without_diagnostic_refund(self):
        with tempfile.TemporaryDirectory() as directory:
            io = self.handoff(directory)
            target = Path(directory) / "absent" / "final.json"
            with self.assertRaises(FileNotFoundError):
                io.write(target, {"state": "failed"}, runtime.CONTROLLER_RECORD_KEYS)
            self.assertEqual(io.used, 141 + 7 * 256)
            self.assertFalse(target.exists())
            self.assertEqual((io.start, io.end), (10, 610))

    def test_worker_role_derivation_and_attempt_cap_are_bound_and_finite(self):
        for invalid in [-1, 32 * 1024**2 + 1, True]:
            with self.subTest(source_bytes=invalid), self.assertRaisesRegex(runtime.Refusal, "retirement-source-window"):
                runtime._worker_io_reservation(invalid)
        prepaid = runtime._worker_io_reservation(1000)
        expected = {"source_stat": 1, "reads": 469, "contract": 70, "kernel": 34,
                    "replay": 4, "lease": 2, "writes": 231, "store": 256, "polls": 256}
        self.assertEqual(prepaid["metadata_operations"], expected)
        self.assertEqual(prepaid["windows"]["metadata"], 1323 * 256)
        self.assertEqual(prepaid["output_bytes"], sum(prepaid["windows"].values()))
        with tempfile.TemporaryDirectory() as directory:
            io = self.io()
            with self.assertRaisesRegex(runtime.Refusal, "retirement-record-attempt-window"):
                runtime.wait_retirement_record(Path(directory) / "absent", 610, clock=lambda: 10,
                    sleep=lambda _seconds: None, io=io, maximum_attempts=2)
            self.assertEqual(io.used, 2 * 258)  # stat256 plus two framing units per failure.
            self.assertEqual((io.start, io.end), (10, 610))


class PostStatDisappearanceControls(unittest.TestCase):
    """Actual filesystem loss cannot multiply a prepaid regular-read role window."""
    def test_real_late_open_loss_refuses_once_with_fixed_pathless_error(self):
        for route in ["direct", "wait"]:
            with self.subTest(route=route), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "provisional.json"
                raw = b'{"state":"failed"}\n'
                path.write_bytes(raw)
                io = runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576,
                                          clock=lambda: 10)
                original_open, original_stat = os.open, os.stat
                opened = []
                def disappear_at_real_open(target, *args, **kwargs):
                    if Path(target) == path:
                        opened.append(str(target))
                        path.unlink()  # The test's independent race actor, before real open.
                    return original_open(target, *args, **kwargs)
                sleeper = Mock()
                with patch.object(runtime.os, "open", side_effect=disappear_at_real_open), \
                        patch.object(runtime.os, "stat", wraps=original_stat) as stat_probe, \
                        patch.object(runtime.os, "fstat", wraps=os.fstat) as fstat_probe, \
                        patch.object(io, "read", wraps=io.read) as reader, \
                        patch.object(runtime.json, "dumps", wraps=json.dumps) as serializer, \
                        patch.object(io, "publish", wraps=io.publish) as publisher, \
                        patch.object(runtime.subprocess, "Popen") as launch:
                    with self.assertRaises(runtime.Refusal) as caught:
                        if route == "direct":
                            io.read(path, 65536)
                        else:
                            runtime.wait_retirement_record(path, 610, clock=lambda: 10, sleep=sleeper,
                                io=io, maximum=65536, maximum_attempts=257)
                    reader.assert_called_once_with(path, 65536)
                    fstat_probe.assert_not_called()
                    serializer.assert_not_called()
                    publisher.assert_not_called()
                    launch.assert_not_called()
                    outer_stats = [call for call in stat_probe.call_args_list
                                   if Path(call.args[0]) == path and call.kwargs.get("follow_symlinks", True)]
                    self.assertEqual(len(outer_stats), 1)
                sleeper.assert_not_called()
                self.assertEqual(opened, [str(path)])
                # Initial stat, each real ancestor lstat, then the failed open; no fstat.
                self.assertEqual(io.used, len(raw) + 2 + 256 * (len(path.parts) + 2))
                failure = caught.exception
                self.assertEqual(failure.code, "retirement-input-disappeared")
                self.assertEqual(failure.args, ("retirement-input-disappeared",))
                self.assertEqual(str(failure), "retirement-input-disappeared")
                self.assertIsNone(failure.__cause__)
                self.assertTrue(failure.__suppress_context__)
                rendered = "".join(traceback.format_exception(failure))
                self.assertNotIn(str(path), rendered)
                self.assertNotIn("FileNotFoundError", rendered)
                self.assertEqual((io.start, io.end), (10, 610))

    def test_real_initial_stat_absence_retries_after_one_sleep_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "worker.json"
            raw = b'{"state":"refused"}\n'
            io = runtime.ControllerIO(10, 600, 8388608, 17179869184, 4194304, 1048576,
                                      clock=lambda: 10)
            delays = []
            def publish_on_test_sleep(seconds):
                delays.append(seconds)
                self.assertEqual(len(delays), 1)
                path.write_bytes(raw)  # Independent publisher, not a product write/debit.
            with patch.object(io, "read", wraps=io.read) as reader:
                result = runtime.wait_retirement_record(path, 610, clock=lambda: 10,
                    sleep=publish_on_test_sleep, io=io, maximum=16384, maximum_attempts=257)
                self.assertEqual(reader.call_count, 2)
            self.assertEqual(result, {"state": "refused"})
            self.assertEqual(delays, [0.05])
            # One absent outer-stat poll256+two framing units, then one full read.
            self.assertEqual(io.used, 258 + len(raw) + 2 + 256 * (len(path.parts) + 3))
            self.assertEqual((io.start, io.end, io.original["output_bytes"]), (10, 610, 8388608))


if __name__ == "__main__":
    unittest.main()
