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
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import kind_runtime as runtime


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
        with patch.object(runtime.sys, "argv", ["harness", "--podman-proxy", "/private/policy", runtime.sha(raw), "21", "lease", "exec", "private-command-body"]), patch.object(runtime, "regular", side_effect=[raw, b"source"]), patch.object(runtime, "await_proxy_gate"), patch.object(runtime, "provider", side_effect=ValueError("private-exception-body")), patch.object(runtime, "state_lock", return_value=nullcontext()), patch.object(runtime, "state_read", return_value=current), patch.object(runtime, "state_write"), patch.object(runtime, "finish_proxy"), patch.object(runtime, "PROXY_CONTROL"), patch.object(runtime, "PROXY_POLICY"), patch.object(runtime, "PROXY_LEASE"):
            self.assertEqual(runtime.main(), 1)
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


if __name__ == "__main__":
    unittest.main()
