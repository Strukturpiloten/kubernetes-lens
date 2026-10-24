"""Pure lifecycle controls. Never starts systemd, QEMU, SSH, Podman or a VM."""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import json
import lzma
import os
from pathlib import Path
import signal
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import owned_qemu as vm


def config():
    return {"unit": "kubernetes-lens-vm-" + "a" * 32 + ".service", "owner": "a" * 32,
            "directory": "/private/owned", "tools": {name: {"path": "/usr/bin/" + name} for name in vm.ROLES},
            "cpus": 2, "memory_bytes": 4 * 1024**3, "guest_memory_mib": 2048, "pids": 256,
            "overlay_max": 8 * 1024**3, "start": 100.0, "work_end": 650.0, "end": 700.0,
            "port": 22222, "boot": "boot", "cleanup_seconds": 50}


def unit():
    row = dict.fromkeys(vm.SHOW_FIELDS, "")
    row.update({"Id": config()["unit"], "Description": "KubernetesLens owned VM " + "a" * 32,
                "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Transient": "yes",
                "MainPID": "321", "InvocationID": "b" * 32, "ControlGroup": "/owned/" + config()["unit"],
                "Restart": "no", "KillMode": "control-group", "RemainAfterExit": "yes", "NRestarts": "0",
                "RuntimeMaxUSec": "8min", "TimeoutStopUSec": "1s", "ExecMainStartTimestampMonotonic": "100000000",
                "FailureAction": "none", "SuccessAction": "none", "StartLimitAction": "none", "RuntimeRandomizedExtraUSec": "0"})
    return row


def identity(pid=321):
    return {"pid": pid, "group": pid, "session": pid, "start": 123}


def barrier():
    return {"stage": "producer-stopped", "error": None, "guest": {"rootful": True, "local": True,
            "cgroup_version": "v2", "podman_version": "5.8.7"}, "qemu": identity(444), "ssh": None,
            "qemu_reaped": True, "ssh_reaped": True, "original_end": 700.0}


def simple_unit_text(row):
    return "".join(name + "=" + row[name] + "\n" for name in vm.SIMPLE_FIELDS).encode()


def empty_stop_properties():
    line = vm.encode({"type": "a(sasbttttuii)", "data": []}) + b"\n"
    return line + line


class TypedStopPropertyControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def unloaded(self):
        return {**unit(), "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead",
                "MainPID": "0", "InvocationID": "", "ControlGroup": ""}

    def test_loaded_unit_gets_full_semantic_fields_only_after_typed_empty_arrays(self):
        with patch.object(vm, "run", side_effect=[(0, simple_unit_text(unit())), (0, empty_stop_properties()),
                                                (0, simple_unit_text(unit()))]) as run:
            row = vm.unit_show(config(), self.budget)
        self.assertEqual(set(row), set(vm.SHOW_FIELDS))
        self.assertEqual(row["ExecStop"], "")
        self.assertEqual(row["ExecStopPost"], "")
        text_argument = next(value for value in run.call_args_list[0].args[0] if value.startswith("--property="))
        self.assertNotIn("ExecStop", text_argument)
        argv = run.call_args_list[1].args[0]
        self.assertEqual(argv, [config()["tools"]["busctl"]["path"], "--user", "--no-pager", "--timeout=5s",
                               "--json=short", "get-property", "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1/unit/kubernetes_2dlens_2dvm_2d" + "a" * 32 + "_2eservice",
                               "org.freedesktop.systemd1.Service", "ExecStop", "ExecStopPost"])
        self.assertTrue(run.call_args_list[1].kwargs["manager"])

    def test_replacement_or_disappearance_cannot_inherit_typed_proof(self):
        for after in ({**unit(), "InvocationID": "c" * 32}, self.unloaded(),
                      {**unit(), "Restart": "always"}, {**unit(), "UpheldBy": "foreign.service"}):
            replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(after))]
            with self.subTest(after=after), patch.object(vm, "run", side_effect=replies):
                with self.assertRaisesRegex(vm.Refusal, "unit-changed-during-stop-proof"):
                    vm.unit_show(config(), self.budget)

    def test_unsupported_nonempty_malformed_and_ambiguous_typed_proofs_refuse(self):
        empty = vm.encode({"type": "a(sasbttttuii)", "data": []}) + b"\n"
        cases = [(1, empty_stop_properties()), (0, b""), (0, empty), (0, empty * 3),
                 (0, empty + b'{"type":"a(sasbttttuii)","data":['),
                 (0, empty + b'{"type":"a(sasbttttuii)","data":[],"data":[]}\n'),
                 (0, empty + vm.encode({"type": "as", "data": []}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": {}}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": [["/unexpected/stop"]]}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": [], "extra": True}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)"}) + b"\n")]
        for status, raw in cases:
            with self.subTest(status=status, raw=raw), patch.object(vm, "run", return_value=(status, raw)):
                with self.assertRaises(vm.Refusal):
                    vm.prove_no_stop_commands(config(), self.budget)

    def test_object_path_cannot_be_substituted_with_a_foreign_unit(self):
        c = {**config(), "unit": "kubernetes-lens-vm-" + "b" * 32 + ".service"}
        with patch.object(vm, "run") as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-object-path-identity"):
                vm.prove_no_stop_commands(c, self.budget)
        run.assert_not_called()

    def test_typed_call_timeout_shrinks_inside_original_end(self):
        with patch.object(vm.time, "monotonic", return_value=99.75), \
             patch.object(vm, "run", return_value=(0, empty_stop_properties())) as run:
            vm.prove_no_stop_commands(config(), vm.Budget(100.0, 0), cleanup=True)
        self.assertIn("--timeout=250000us", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["cleanup"])

    def test_simple_typed_confirm_chain_shares_one_shorter_end_and_budget(self):
        replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(unit()))]
        cutoff = time.monotonic() + 2
        with patch.object(vm, "run", side_effect=replies) as run:
            vm.unit_show(config(), self.budget, deadline=cutoff)
        self.assertEqual(len(run.call_args_list), 3)
        self.assertTrue(all(call.args[1] is self.budget for call in run.call_args_list))
        self.assertTrue(all(call.kwargs["deadline"] == cutoff for call in run.call_args_list))

    def test_missing_simple_property_is_not_replaced_by_empty_value(self):
        text = simple_unit_text(unit()).replace(b"Restart=no\n", b"")
        with patch.object(vm, "run", return_value=(0, text)) as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-state-incomplete"):
                vm.unit_show(config(), self.budget)
        run.assert_called_once()

    def test_unloaded_terminal_case_has_no_asserted_complex_property_values(self):
        with patch.object(vm, "run", return_value=(4, simple_unit_text(self.unloaded()))) as run:
            row = vm.unit_show(config(), self.budget, cleanup=True)
        self.assertEqual(row["LoadState"], "not-found")
        self.assertEqual(set(row), set(vm.SIMPLE_FIELDS))
        self.assertNotIn("ExecStop", row)
        self.assertNotIn("ExecStopPost", row)
        run.assert_called_once()

    def test_not_found_with_an_invocation_process_cgroup_or_job_refuses(self):
        for name, value in (("MainPID", "123"), ("InvocationID", "c" * 32), ("ControlGroup", "/foreign"),
                            ("Job", "3 /job/3"), ("ActiveState", "active")):
            row = {**self.unloaded(), name: value}
            with self.subTest(name=name), patch.object(vm, "run", return_value=(0, simple_unit_text(row))):
                with self.assertRaisesRegex(vm.Refusal, "unit-not-found-state-inconsistent"):
                    vm.unit_show(config(), self.budget, cleanup=True)

    def test_retirement_handles_unloaded_service_after_previously_typed_loaded_proof(self):
        replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(unit())), (0, b""),
                   (4, simple_unit_text(self.unloaded())), (4, simple_unit_text(self.unloaded()))]
        with patch.object(vm, "run", side_effect=replies) as run, \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", return_value="removed") as empty, patch.object(vm.time, "sleep"):
            receipt = vm.retire(config(), self.budget, "b" * 32, {"path": "/target"}, identity(), identity(444), barrier())
        self.assertEqual(receipt["state"], "retired")
        self.assertEqual(empty.call_count, 2)
        self.assertEqual(sum(call.args[0][0] == config()["tools"]["busctl"]["path"] for call in run.call_args_list), 1)

    def test_busctl_is_required_in_the_reviewed_manifest_without_auto_installation(self):
        document = {"schema": "kubernetes-lens-owned-vm-tools-v1",
                    "tools": {name: {} for name in vm.ROLES - {"busctl"}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_bytes(vm.encode(document))
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-schema"):
                vm.admit_tools(path, vm.digest(path.read_bytes()))


class PublicationControls(unittest.TestCase):
    def test_full_undrained_pipe_cannot_extend_original_end(self):
        reader, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b"x" * 65536)
                except BlockingIOError:
                    break
            start = time.monotonic()
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, start + 0.025,
                                               descriptor=writer))
            self.assertLess(time.monotonic() - start, 1)
            self.assertFalse(os.get_blocking(writer))
        finally:
            os.close(writer)
            os.close(reader)

    def test_partial_nonblocking_writes_keep_exact_receipt_bytes(self):
        collected = bytearray()
        def partial(_descriptor, data):
            count = min(3, len(data))
            collected.extend(data[:count])
            return count
        with patch.object(vm.os, "get_blocking", return_value=True), \
             patch.object(vm.os, "set_blocking") as blocking, \
             patch.object(vm.os, "write", side_effect=partial):
            self.assertTrue(vm.publish_receipt({"state": "vm-qualified-retired"},
                                              time.monotonic() + 1, descriptor=123))
        self.assertEqual(blocking.call_args_list, [((123, False),), ((123, True),)])
        self.assertEqual(bytes(collected), b'{"state":"vm-qualified-retired"}\n')

    def test_expired_end_and_broken_output_never_publish_success(self):
        with patch.object(vm.os, "get_blocking", return_value=True), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "write") as output:
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, time.monotonic() - 1))
            output.assert_not_called()
            output.side_effect = BrokenPipeError
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, time.monotonic() + 1))


class InputControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def test_overlong_control_socket_parent_refuses_before_image_or_runtime(self):
        args = SimpleNamespace(deadline_seconds=900, cleanup_seconds=90, cpus=2,
                               memory_mib=8192, guest_memory_mib=4096, pids=256,
                               disk_gib=16, ssh_port=22222, output_parent="/tmp/" + "p" * 80)
        with patch.object(vm, "canonical", return_value=Path(args.output_parent)), \
             patch.object(vm.Path, "stat") as inspection:
            with self.assertRaisesRegex(vm.Refusal, "private-control-socket-path-budget"):
                vm.validate_config_args(args)
        inspection.assert_not_called()

    def test_pin_strict_schema_and_immutable_url(self):
        item = {"schema": "kubernetes-lens-owned-vm-image-v1", "release": "44.20260928.3.2", "archive_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pin.json"
            path.write_bytes(vm.encode(item))
            observed, sha = vm.pin_document(path)
            self.assertEqual(observed, item)
            self.assertEqual(sha, vm.digest(path.read_bytes()))
            self.assertEqual(vm.official_url(item), "https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.2/x86_64/fedora-coreos-44.20260928.3.2-qemu.x86_64.qcow2.xz")
            for key, value in (("release", "latest"), ("archive_sha256", "X" * 64), ("url", "https://attacker")):
                invalid = {**item, key: value}
                path.write_bytes(vm.encode(invalid))
                with self.assertRaises(vm.Refusal):
                    vm.pin_document(path)

    def test_duplicate_and_nonfinite_json_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(vm.Refusal):
                vm.strict_json(raw)

    def test_symlink_input_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "real").write_text("safe")
            (path / "link").symlink_to(path / "real")
            with self.assertRaisesRegex(vm.Refusal, "symlink-path-refused"):
                vm.read(path / "link")

    def test_archive_authenticates_before_decompression(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / "bad.xz"
            source.write_bytes(b"not XZ")
            with patch.object(vm.lzma, "LZMADecompressor") as decoder:
                with self.assertRaisesRegex(vm.Refusal, "archive-integrity"):
                    vm.admit_archive(source, path, {"archive_sha256": "a" * 64}, vm.Budget(time.monotonic() + 60, 10))
                decoder.assert_not_called()

    def test_bounded_authenticated_qcow2_expansion(self):
        header = bytearray(104)
        header[:4] = b"QFI\xfb"
        struct.pack_into(">I", header, 4, 3)
        compressed = lzma.compress(bytes(header))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / "source.xz"
            source.write_bytes(compressed)
            pin = {"archive_sha256": vm.digest(compressed), "release": "44.20260928.3.2"}
            result = vm.admit_archive(source, path, pin, vm.Budget(time.monotonic() + 60, 10))
            self.assertEqual(result["expanded_bytes"], 104)
            self.assertEqual(result["expanded_sha256"], vm.digest(header))
            self.assertEqual((path / "image.qcow2").stat().st_mode & 0o777, 0o400)
            self.assertFalse((path / "image.qcow2.xz").exists())

    def test_concatenated_truncated_overbudget_and_backing_xz_refuse(self):
        header = bytearray(104)
        header[:4] = b"QFI\xfb"
        struct.pack_into(">I", header, 4, 3)
        good = lzma.compress(header)
        bad_backing = bytearray(header)
        struct.pack_into(">Q", bad_backing, 8, 64)
        cases = [(good + good, "trailing-xz-data", vm.EXPANDED_MAX),
                 (good[:-8], "truncated-xz", vm.EXPANDED_MAX),
                 (good, "expanded-image-budget", 32),
                 (lzma.compress(bad_backing), "qcow2-external-or-unsupported-features", vm.EXPANDED_MAX)]
        for compressed, code, maximum in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.xz"
                source.write_bytes(compressed)
                with patch.object(vm, "EXPANDED_MAX", maximum):
                    with self.assertRaisesRegex(vm.Refusal, code):
                        vm.admit_archive(source, directory, {"archive_sha256": vm.digest(compressed)}, vm.Budget(time.monotonic() + 60, 10))

    def test_unreviewed_manifest_and_missing_role_refuse_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text('{"schema":"kubernetes-lens-owned-vm-tools-v1","tools":{}}')
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-integrity"):
                vm.admit_tools(path, "a" * 64)
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-schema"):
                vm.admit_tools(path, vm.digest(path.read_bytes()))


class InvocationControls(unittest.TestCase):
    def test_ignition_restricts_the_key_masks_zincati_and_pins_host_identity(self):
        document = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE TEST KEY", "ssh-ed25519 BBBB\n")
        self.assertEqual(document["systemd"]["units"], [{"name": "zincati.service", "mask": True}])
        key = document["passwd"]["users"][0]["sshAuthorizedKeys"][0]
        self.assertEqual(key, 'restrict,command="' + vm.FIXED_COMMAND + '" ssh-ed25519 AAAA')
        self.assertEqual(document["storage"]["files"][0]["mode"], 0o600)
        self.assertNotIn("python", json.dumps(document))
        self.assertNotIn("http", json.dumps(document))

    def test_qemu_has_only_restricted_user_network_and_one_loopback_forward(self):
        argv = vm.qemu_arguments(config())
        network = argv[argv.index("-nic") + 1]
        self.assertEqual(network, "user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22")
        self.assertEqual(argv.count("-nic"), 1)
        for denied in ("-daemonize", "-virtfs", "-fsdev", "-chardev", "-qmp", "-netdev", "-pidfile"):
            self.assertNotIn(denied, argv)
        self.assertEqual(argv[argv.index("-monitor") + 1], "none")
        self.assertIn("spawn=deny", " ".join(argv))

    def test_ssh_exactly_one_fixed_command_and_no_ambient_sources(self):
        argv = vm.ssh_arguments(config())
        self.assertEqual(argv[-2:], ["core@127.0.0.1", vm.FIXED_COMMAND])
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ControlPath=none", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ConnectionAttempts=1", argv)
        self.assertEqual(argv[argv.index("-F") + 1], "/dev/null")
        self.assertNotIn("SSH_AUTH_SOCK", vm.clean_environment("/private"))

    def test_guest_positive_and_independent_failure_variants(self):
        info = {"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                         "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}}
        self.assertEqual(vm.guest_info(vm.encode(info)), barrier()["guest"])
        for section, key, value in (("security", "rootless", True), ("host", "serviceIsRemote", True),
                                    ("host", "cgroupVersion", "v1"), ("host", "arch", "arm64"),
                                    ("version", "Version", "5.8.8")):
            invalid = deepcopy(info)
            destination = invalid["host"]["security"] if section == "security" else invalid[section]
            destination[key] = value
            with self.subTest(key=key), self.assertRaises(vm.Refusal):
                vm.guest_info(vm.encode(invalid))
        with self.assertRaises(vm.Refusal):
            vm.guest_info(b"{}")

    def test_unit_has_real_caps_no_respawn_no_ambient_credentials(self):
        with patch.object(vm.time, "monotonic", return_value=100):
            argv = vm.unit_arguments(config(), "/private/config.json", "c" * 64,
                                     ["SSH_AUTH_SOCK", "LD_PRELOAD", "MALICIOUS_VARIABLE"])
        for item in ("CPUQuota=200%", "MemoryMax=4294967296", "MemorySwapMax=0", "TasksMax=256",
                     "Restart=no", "KillMode=control-group", "NoNewPrivileges=yes", "ReadOnlyPaths=/sys/fs/cgroup", "PrivateUsers=self", "DynamicUser=no",
                     "RestrictNamespaces=yes", "SystemCallArchitectures=native", "CapabilityBoundingSet=",
                     "AmbientCapabilities=", "SystemCallErrorNumber=ENOSYS",
                     "StandardOutput=null", "StandardError=null"):
            self.assertIn("--property=" + item, argv)
        unset = next(item for item in argv if item.startswith("--property=UnsetEnvironment="))
        self.assertIn("MALICIOUS_VARIABLE", unset)
        self.assertIn("SSH_AUTH_SOCK", unset)
        self.assertEqual(argv[-3:], ["--_worker", "/private/config.json", "c" * 64])

    def test_unit_authenticates_invocation_and_rejects_pending_or_restart(self):
        self.assertEqual(vm.validate_unit(unit(), config()), "b" * 32)
        for key, value in (("InvocationID", "c" * 32), ("Restart", "always"), ("Job", "123 /job/123"),
                           ("NRestarts", "1"), ("UpheldBy", "foreign.service"), ("OnFailure", "foreign.service"),
                           ("RuntimeMaxUSec", "infinity"), ("RuntimeMaxUSec", "1h"),
                           ("RuntimeRandomizedExtraUSec", "1s"), ("Transient", "no")):
            row = {**unit(), key: value}
            with self.subTest(key=key), self.assertRaises(vm.Refusal):
                vm.validate_unit(row, config(), invocation="b" * 32)

    def test_timer_parses_official_timespans_without_infinity(self):
        self.assertEqual(vm.duration_seconds("2min 3s 400ms"), 123.4)
        self.assertEqual(vm.duration_seconds("0"), 0)
        for text in ("infinity", "NaN", "-1s", "2s garbage", "2seconds"):
            with self.assertRaises(vm.Refusal):
                vm.duration_seconds(text)

    def test_barrier_wrong_placement_refuses_before_go(self):
        hello = {"stage": "barrier", "worker": identity(), "config_sha256": "c" * 64}
        with patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", return_value="/sys/fs/cgroup/foreign.service"), \
             patch.object(vm, "cgroup_snapshot") as snapshot:
            with self.assertRaisesRegex(vm.Refusal, "outside-controller-placement"):
                vm.attest_barrier(unit(), hello, identity(), config(), "c" * 64)
            snapshot.assert_not_called()

    def test_valid_external_barrier_keeps_actual_kernel_identity(self):
        target = "/sys/fs/cgroup" + unit()["ControlGroup"]
        hello = {"stage": "barrier", "worker": identity(), "config_sha256": "c" * 64}
        with patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", side_effect=lambda pid: target if pid == 321 else "/sys/fs/cgroup/outside"), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target, "inode": 42}), \
             patch.object(vm, "boot_id", return_value="boot"):
            invocation, observed = vm.attest_barrier(unit(), hello, identity(), config(), "c" * 64)
        self.assertEqual(invocation, "b" * 32)
        self.assertEqual(observed["inode"], 42)

    def test_actual_cgroup_caps_must_be_finite_and_exact(self):
        c = config()
        path = Path("/sys/fs/cgroup/owned") / c["unit"]
        original = {"cpu.max": "200000 100000", "memory.max": str(c["memory_bytes"]),
                    "pids.max": "256", "memory.swap.max": "0"}
        cases = [(None, None), ("cpu.max", "max 100000"), ("cpu.max", "300000 100000"),
                 ("memory.max", "max"), ("memory.max", str(c["memory_bytes"] + 1)),
                 ("pids.max", "max"), ("pids.max", "257"), ("memory.swap.max", "1")]
        for key, value in cases:
            contents = {**original, **({key: value} if key else {})}
            with self.subTest(key=key), patch.object(vm, "canonical", return_value=path), \
                 patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=os.getuid(), st_dev=1, st_ino=2)), \
                 patch.object(Path, "read_text", lambda item: contents[item.name]):
                if key:
                    with self.assertRaises(vm.Refusal):
                        vm.cgroup_snapshot(path, c)
                else:
                    self.assertEqual(vm.cgroup_snapshot(path, c)["memory_max"], c["memory_bytes"])


class RetirementControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def inactive(self):
        return {**unit(), "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "InvocationID": ""}

    def test_outside_retirement_stops_exact_unit_then_twice_proves_empty(self):
        row = unit()
        calls = []
        with patch.object(vm, "unit_show", side_effect=[row, self.inactive(), self.inactive()]), \
             patch.object(vm, "run", side_effect=lambda *a, **kw: (calls.append(a[0]) or (0, b""))), \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", return_value="removed") as empty, \
             patch.object(vm.time, "sleep"):
            receipt = vm.retire(config(), self.budget, "b" * 32, {"path": "/target"}, identity(), identity(444), barrier())
        self.assertEqual(receipt["state"], "retired")
        self.assertEqual(empty.call_count, 2)
        self.assertEqual(calls[0][-3:], ["stop", "--no-block", config()["unit"]])

    def test_stale_invocation_cannot_be_stopped(self):
        with patch.object(vm, "unit_show", return_value={**unit(), "InvocationID": "c" * 32}), \
             patch.object(vm, "run") as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-invocation-drift"):
                vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), barrier())
            run.assert_not_called()

    def test_subtree_repopulation_quarantines_even_after_one_empty(self):
        with patch.object(vm, "unit_show", side_effect=[unit(), self.inactive(), self.inactive()]), \
             patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", side_effect=["held-empty", vm.Refusal("retirement-cgroup-populated")]), \
             patch.object(vm.time, "sleep"):
            with self.assertRaisesRegex(vm.Refusal, "retirement-cgroup-populated"):
                vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), barrier())

    def test_restart_producer_and_missing_barrier_each_refuse(self):
        for changed, producer in (({**self.inactive(), "TriggeredBy": "foreign.socket"}, barrier()),
                                  (self.inactive(), None)):
            with self.subTest(changed=changed["TriggeredBy"]), \
                 patch.object(vm, "unit_show", side_effect=[unit(), changed, changed]), \
                 patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
                 patch.object(vm, "process_retired", return_value=True), patch.object(vm, "empty_cgroup", return_value="removed"), \
                 patch.object(vm.time, "sleep"):
                with self.assertRaises(vm.Refusal):
                    vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), producer)

    def test_pid_reuse_is_uncertain_not_absence(self):
        with patch.object(vm, "process_identity", return_value=identity(999)):
            with self.assertRaisesRegex(vm.Refusal, "retirement-pid-reused"):
                vm.process_retired(identity())
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            self.assertTrue(vm.process_retired(identity()))

    def test_cgroup_descendant_population_cannot_hide_behind_empty_direct_procs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            (path / "cgroup.procs").write_text("")
            snapshot = {"path": str(path)}
            with patch.object(vm, "cgroup_snapshot", return_value=snapshot):
                with self.assertRaisesRegex(vm.Refusal, "retirement-cgroup-populated"):
                    vm.empty_cgroup(snapshot, config())

    def test_deadline_and_cancellation_are_never_renewed_for_cleanup(self):
        budget = vm.Budget(100, 20)
        with patch.object(vm.time, "monotonic", return_value=75):
            self.assertEqual(budget.remaining(), 5)
            vm.CANCELLED = signal.SIGINT
            with self.assertRaisesRegex(vm.Refusal, "cancelled"):
                budget.remaining()
            self.assertEqual(budget.remaining(cleanup=True), 25)
        with patch.object(vm.time, "monotonic", return_value=101):
            with self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                budget.remaining(cleanup=True)


class WorkerControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def test_gate_failure_starts_no_child(self):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60, "cleanup_seconds": 10})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel = Mock()
        with patch.object(vm, "read", return_value=raw), patch.object(vm, "verify_source"), \
             patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c.get("controller")), \
             patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "send") as send, patch.object(vm, "receive", return_value={"stage": "forged"}), \
             patch.object(vm, "run") as run, patch.object(vm.subprocess, "Popen") as popen:
            c["controller"] = identity(111)
            raw = vm.encode(c)
            with patch.object(vm, "read", return_value=raw), patch.object(vm, "peer_identity", return_value=c["controller"]):
                self.assertEqual(vm.worker("/private/config", vm.digest(raw)), 1)
            run.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(send.call_args.args[1]["error"], "worker-gate-schema")

    def test_source_refusal_is_authenticated_reported_and_precedes_every_child(self):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60,
                  "cleanup_seconds": 10, "controller": identity(111)})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32,
                "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        events = []
        def peer(_channel):
            events.append("authenticated-parent")
            return c["controller"]
        def receive(_channel, _budget):
            events.append("received-go")
            return gate
        def verify(_config, _budget, **_kwargs):
            self.assertEqual(events, ["authenticated-parent", "received-go"])
            raise vm.Refusal("host-tool-writable")
        with patch.object(vm, "read", return_value=raw), \
             patch.object(vm.socket, "socket", return_value=Mock()), \
             patch.object(vm, "peer_identity", side_effect=peer), \
             patch.object(vm, "receive", side_effect=receive), patch.object(vm, "send") as send, \
             patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "verify_source", side_effect=verify) as verify_source, \
             patch.object(vm, "run") as run, patch.object(vm.subprocess, "Popen") as popen:
            self.assertEqual(vm.worker("/private/config", vm.digest(raw)), 1)
        verify_source.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()
        self.assertEqual([call.args[1]["stage"] for call in send.call_args_list], ["barrier", "producer-stopped"])
        self.assertEqual(send.call_args.args[1]["error"], "host-tool-writable")
        self.assertIsNone(send.call_args.args[1]["qemu"])

    def test_bounded_ssh_capture_does_not_wait_for_live_qemu_console_eof(self):
        process, console, selector = Mock(), Mock(), Mock()
        process.returncode = 0
        process.poll.return_value = 0
        stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
        stderr = SimpleNamespace(fd=12, fileobj=process.stderr)
        serial = SimpleNamespace(fd=13, fileobj=console)
        selector.select.side_effect = [[(stdout, None), (stderr, None), (serial, None)], [(stdout, None)]]
        with patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), \
             patch.object(vm.os, "read", side_effect=[b"{}", b"", b"console remains open", b""]):
            status, raw = vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic() + 60, 10), "/private", extra_streams=(console,))
        self.assertEqual((status, raw), (0, b"{}"))
        self.assertEqual(selector.select.call_count, 2)
        process.kill.assert_not_called()

    def test_short_command_cutoff_reuses_counters_and_original_retirement_reservation(self):
        clock = [100.0]
        process, selector = Mock(), Mock()
        process.pid = 444
        process.poll.return_value = None
        def stalled(_timeout):
            clock[0] = 101.1
            return []
        selector.select.side_effect = stalled
        budget = vm.Budget(200.0, 20)
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "killpg") as kill:
            with self.assertRaisesRegex(vm.Refusal, "command-deadline-expired"):
                vm.run(["/reviewed/systemctl"], budget, "/private", deadline=101.0)
        kill.assert_called_once_with(444, signal.SIGKILL)
        self.assertAlmostEqual(process.wait.call_args.kwargs["timeout"], 98.9)
        self.assertEqual(budget.end, 200.0)
        self.assertEqual(budget.work_end, 180.0)
        self.assertEqual(budget.commands_left, 127)
        self.assertEqual(budget.output_left, vm.OUTPUT_MAX)

    def test_optional_command_end_cannot_widen_original_work_or_cleanup_end(self):
        budget = vm.Budget(200.0, 20)
        with patch.object(vm.time, "monotonic", return_value=100.0):
            self.assertEqual(vm.command_remaining(budget, deadline=1000.0), 80.0)
            self.assertEqual(vm.command_remaining(budget, cleanup=True, deadline=1000.0), 100.0)

    def _worker_ssh_case(self, ssh_status, guest, *, guard_error_at=None):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60, "cleanup_seconds": 10,
                  "controller": identity(111)})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel, qemu, selector = Mock(), Mock(), Mock()
        qemu.pid = 444
        qemu.poll.return_value = None
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32, "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        key = SimpleNamespace(fd=123, fileobj=qemu.stdout)
        selector.select.return_value = [(key, None)]
        def execute(argv, *_args, **kwargs):
            if argv[0] == c["tools"]["ssh"]["path"]:
                kwargs["on_start"](SimpleNamespace(pid=555))
                return ssh_status, guest
            return (0, b'{"format":"qcow2","virtual-size":1024}') if argv[1] == "info" else (0, b"")
        with patch.object(vm, "read", return_value=raw), patch.object(vm, "verify_source"), \
             patch.object(vm, "worker_pre_child", side_effect=[vm.Refusal("host-view-local-drift")
                          if index == guard_error_at else None for index in range(1, 4)]) as guard, \
             patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c["controller"]), \
             patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "send") as send, patch.object(vm, "receive", return_value=gate), \
             patch.object(vm, "run", side_effect=execute) as run, \
             patch.object(vm.subprocess, "Popen", return_value=qemu), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "read", return_value=b"Reached target Multi-User System\n"), \
             patch.object(vm, "reap", return_value=True) as reap:
            result = vm.worker("/private/config", vm.digest(raw))
        self.last_native_calls = [call.args[0] for call in run.call_args_list]
        self.last_guard_count = guard.call_count
        if guard_error_at is None:
            self.assertEqual(guard.call_count, 3)
            self.assertTrue(all(call.args[1] is guard.call_args_list[0].args[1] for call in guard.call_args_list))
            self.assertEqual(sum(call.args[0][0] == c["tools"]["ssh"]["path"] for call in run.call_args_list), 1)
            self.assertEqual([call.args[1]["stage"] for call in send.call_args_list],
                             ["barrier", "qemu-started", "ssh-started", "producer-stopped"])
        reap.assert_called_once()
        return result, send.call_args.args[1]

    def test_refused_pre_child_view_never_starts_that_or_any_later_child(self):
        for index in (1, 2, 3):
            with self.subTest(index=index):
                result, producer = self._worker_ssh_case(0, b"", guard_error_at=index)
                self.assertEqual(result, 1)
                self.assertEqual(producer["error"], "host-view-local-drift")
                self.assertEqual(self.last_guard_count, index)
                self.assertEqual(len(self.last_native_calls), min(index, 2))
                self.assertFalse(any(argv[0] == config()["tools"]["ssh"]["path"] for argv in self.last_native_calls))
                self.assertIsNone(producer["guest"])
                self.assertEqual(producer["qemu"] is None, index < 3)

    def test_ambiguous_ssh_disconnect_is_not_retried(self):
        result, producer = self._worker_ssh_case(255, b"")
        self.assertEqual(result, 1)
        self.assertEqual(producer["error"], "authenticated-guest-check-failed")

    def test_positive_production_worker_still_returns_only_provisional_guest_evidence(self):
        info = {"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                         "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}}
        result, producer = self._worker_ssh_case(0, vm.encode(info))
        self.assertEqual(result, 0)
        self.assertIsNone(producer["error"])
        self.assertEqual(producer["ssh"], identity(555))
        self.assertEqual(producer["guest"], barrier()["guest"])
        self.assertNotIn("vm-qualified-retired", json.dumps(producer))


class OutsideLifecycleControls(unittest.TestCase):
    """Run the production outside lifecycle against finite fake unit/worker peers."""
    def setUp(self):
        vm.CANCELLED = 0

    def test_failed_worker_is_detected_before_long_original_deadline(self):
        server = Mock()
        server.accept.side_effect = socket.timeout
        budget = vm.Budget(time.monotonic() + 900, 60)
        row = {**unit(), "ActiveState": "failed", "SubState": "failed", "MainPID": "0"}
        with patch.object(vm, "unit_show", return_value=row) as show:
            with self.assertRaisesRegex(vm.Refusal, "owned-worker-exited-before-barrier"):
                vm.await_worker_connection(server, config(), budget)
        show.assert_called_once()
        server.accept.assert_called_once()

    def test_startup_cutoff_does_not_renew_original_budget_or_poll_forever(self):
        clock = [100.0]
        server = Mock()
        def timeout():
            clock[0] += 0.1
            raise socket.timeout
        server.accept.side_effect = timeout
        budget = vm.Budget(1000.0, 60)
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm, "unit_show", return_value=unit()) as show:
            with self.assertRaisesRegex(vm.Refusal, "owned-worker-startup-cutoff"):
                vm.await_worker_connection(server, config(), budget)
        self.assertEqual(budget.end, 1000.0)
        self.assertEqual(budget.work_end, 940.0)
        self.assertLess(clock[0], 111)
        self.assertLessEqual(show.call_count, 21)

    def test_startup_acceptance_alone_does_not_fabricate_health_or_native_permission(self):
        server, channel = Mock(), Mock()
        server.accept.return_value = (channel, None)
        with patch.object(vm, "unit_show") as show, patch.object(vm, "send") as send:
            self.assertIs(vm.await_worker_connection(server, config(), vm.Budget(time.monotonic() + 60, 10)), channel)
        show.assert_not_called()
        send.assert_not_called()

    def exercise(self, parent, *, guest_error=None, retirement_failure=False, view_error=None):
        c = config()
        target = "/sys/fs/cgroup/owned/" + c["unit"]
        tools = c["tools"]
        server, probe, channel = MagicMock(), MagicMock(), Mock()
        server.accept.return_value = (channel, None)
        args = SimpleNamespace(deadline_seconds=120, cleanup_seconds=20, cpus=2, pids=256,
                               memory_mib=4096, guest_memory_mib=2048, disk_gib=16, ssh_port=22222,
                               host_tools=str(parent / "tools.json"), host_tools_sha256="a" * 64,
                               image=str(parent / "input.xz"), output_parent=str(parent))
        def archive(_source, directory, _pin, _budget):
            (directory / "image.qcow2").write_bytes(b"private base")
            return {"expanded_sha256": vm.digest(b"private base"), "expanded_bytes": 12, "archive_bytes": 21}
        def execute(argv, _budget, directory, **_kwargs):
            if argv[0] == tools["ssh_keygen"]["path"]:
                path = Path(argv[-1])
                path.write_text("PRIVATE TEST KEY")
                Path(str(path) + ".pub").write_text("ssh-ed25519 AAAA\n")
            return 0, b""
        events = []
        def receive(_channel, budget, **_kwargs):
            index = len(events)
            if index == 0:
                event = {"stage": "barrier", "worker": identity(), "config_sha256": "unused"}
            elif index == 1:
                event = {"stage": "qemu-started", "qemu": identity(444)}
            elif index == 2:
                event = {"stage": "ssh-started", "ssh": identity(555)}
            else:
                event = {**barrier(), "error": guest_error, "ssh": identity(555), "original_end": budget.end}
            events.append(event)
            return event
        rows = [*([unit()] * (3 if view_error else 2)), {**unit(), "ActiveState": "inactive", "MainPID": "0", "InvocationID": ""},
                {**unit(), "ActiveState": "inactive", "MainPID": "0", "InvocationID": ""}]
        fake_view = Mock()
        fake_view.ParentView.return_value.attest.return_value = {"test": "parent-bound-view"}
        fake_view.ParentView.return_value.attest.side_effect = vm.Refusal(view_error) if view_error else None
        fake_view.ParentView.return_value.partial = {"schema": "kubernetes-lens-owned-host-view-partial-v1", "qualification": "incomplete"}
        with patch.object(vm, "host_view_module", return_value=fake_view), \
             patch.object(vm, "validate_config_args", return_value=parent), \
             patch.object(vm, "admit_tools", return_value=tools), \
             patch.object(vm, "pin_document", return_value=({"release": "44.20260928.3.2"}, "c" * 64)), \
             patch.object(vm.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)), \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm.socket, "socket", side_effect=[server, probe]), \
             patch.object(vm, "admit_archive", side_effect=archive), \
             patch.multiple(vm, verify_source=Mock(), check_source_bindings=Mock()), patch.object(vm, "run", side_effect=execute) as run, \
             patch.object(vm, "peer_identity", return_value=identity()), \
             patch.object(vm, "receive", side_effect=receive), \
             patch.object(vm, "attest_barrier", return_value=("b" * 32, {"path": target})), \
             patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "unit_show", side_effect=rows), \
             patch.object(vm, "send") as send, patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", side_effect=vm.Refusal("retirement-cgroup-populated") if retirement_failure else None,
                          return_value="removed"), patch.object(vm.time, "sleep"):
            receipt, status = vm.qualify(args)
        private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
        return receipt, status, private, run.call_args_list, send.call_args_list

    def test_refused_parent_host_view_never_sends_go_and_still_requires_outside_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, status, private, _calls, sends = self.exercise(Path(directory), view_error="host-view-object-not-equivalent")
        self.assertEqual(status, 1)
        self.assertEqual(receipt["error"], "host-view-object-not-equivalent")
        self.assertEqual(receipt["state"], "failed-retired")
        self.assertFalse(any(call.args[1].get("stage") == "go" for call in sends))
        self.assertEqual(private["host_view"]["qualification"], "incomplete")
        self.assertEqual(private["retirement"]["state"], "retired")

    def test_only_outside_retirement_promotes_positive_prerequisite(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            receipt, status, private, calls, sends = self.exercise(parent)
            self.assertEqual(status, 0)
            self.assertEqual(receipt["state"], "vm-qualified-retired")
            self.assertEqual(private["retirement"]["state"], "retired")
            self.assertEqual(len(private["retirement"]["observations"]), 2)
            self.assertEqual(private["retirement"]["ssh"], identity(555))
            self.assertFalse(private["control_plane"]["target_limits_cover_controller"])
            self.assertEqual(sends[0].args[1]["stage"], "go")
            self.assertFalse((parent / ("kubernetes-lens-vm-" + "a" * 32)).exists())
            self.assertNotIn("PRIVATE TEST KEY", json.dumps(private))
            self.assertEqual(private["kubernetes_readiness"], "not-performed")
            self.assertEqual(private["guest_info"], barrier()["guest"])
            self.assertTrue(any("stop" in call.args[0] for call in calls))

    def test_earliest_guest_failure_survives_retirement_failure_and_keys_are_quarantined(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            receipt, status, private, _calls, _sends = self.exercise(parent, guest_error="authenticated-guest-check-failed", retirement_failure=True)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["state"], "failed-quarantined")
            self.assertEqual(receipt["error"], "authenticated-guest-check-failed")
            self.assertEqual(receipt["retirement_error"], "retirement-cgroup-populated")
            self.assertTrue((parent / ("kubernetes-lens-vm-" + "a" * 32)).is_dir())
            self.assertIsNone(private["retirement"])
            self.assertIsNone(private["guest_info"])

    def test_validated_guest_summary_remains_observation_when_retirement_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, status, private, _calls, _sends = self.exercise(Path(directory), retirement_failure=True)
        self.assertEqual(status, 1)
        self.assertEqual(receipt["state"], "failed-quarantined")
        self.assertEqual(private["guest_info"], barrier()["guest"])
        self.assertEqual(set(private["guest_info"]), {"rootful", "local", "cgroup_version", "podman_version"})
        self.assertIsNone(private["retirement"])



class StagePhaseControls(unittest.TestCase):
    """Fake caller/worker paths, with no systemd, QEMU, SSH or native program."""
    def setUp(self):
        vm.CANCELLED = 0
        import owned_guest_stage
        self.stage = owned_guest_stage

    def plan(self):
        raw = vm.encode({"schema": "kubernetes-lens-owned-guest-stage-plan-v1", "owner": "a" * 32,
            "profile": "modern-1.37.0", "files": {role: {"path": "/tmp/" + role, "bytes": 3,
                "sha256": vm.digest(b"abc")} for role in self.stage.ROLES}})
        return raw, self.stage.parse_plan(raw, vm.digest(raw))

    def test_parent_guard_is_strict_and_works_before_private_inputs_exist(self):
        c = {**config(), "manifest": "/private/tools.json", "manifest_sha256": "a" * 64}
        budget = vm.Budget(time.monotonic() + 60, 10)
        self.assertNotIn("input_files", c)
        seen = []
        with patch.object(vm, "check_source_bindings", side_effect=lambda *args: seen.append(("source", args))), \
             patch.object(vm, "admit_tools", side_effect=lambda *args: seen.append(("tools", args)) or c["tools"]):
            vm.parent_pre_child(c, budget)
        self.assertEqual([item[0] for item in seen], ["source", "tools"])
        self.assertIs(seen[0][1][1], budget)
        with patch.object(vm, "check_source_bindings"), patch.object(vm, "admit_tools", return_value={}):
            with self.assertRaisesRegex(vm.Refusal, "host-tools-drift"):
                vm.parent_pre_child(c, budget)
        with patch.object(vm, "check_source_bindings", side_effect=vm.Refusal("host-boot-changed")), \
             patch.object(vm, "admit_tools") as tools:
            with self.assertRaisesRegex(vm.Refusal, "host-boot-changed"):
                vm.parent_pre_child(c, budget)
        tools.assert_not_called()

    def test_ignition_separates_info_and_stage_keys_and_source_bound_files(self):
        raw, _plan = self.plan()
        files = self.stage.guest_files(raw, b"original receiver bytes")
        basic = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE", "ssh-ed25519 BBBB\n")
        extended = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE", "ssh-ed25519 BBBB\n",
                              stage_public="ssh-ed25519 CCCC\n", stage_files=files)
        original_key = basic["passwd"]["users"][0]["sshAuthorizedKeys"][0]
        keys = extended["passwd"]["users"][0]["sshAuthorizedKeys"]
        self.assertEqual(keys[0], original_key)
        self.assertIn(vm.FIXED_COMMAND, keys[0])
        self.assertIn(self.stage.RECEIVER_COMMAND, keys[1])
        self.assertNotIn("directories", basic["storage"])
        self.assertEqual(extended["storage"]["directories"], [{"path": "/var/lib/kubernetes-lens-stage", "mode": 0o700}])
        self.assertEqual({item["path"] for item in extended["storage"]["files"]} - {item["path"] for item in basic["storage"]["files"]}, set(files))

    def test_stage_ssh_retains_isolation_and_uses_only_separate_stage_key(self):
        c = config()
        before = vm.ssh_arguments(c)
        actual = self.stage.ssh_arguments(c)
        expected = before.copy()
        expected.remove("-n")
        expected[expected.index("-i") + 1] = "/private/owned/stage_key"
        expected[-1] = self.stage.RECEIVER_COMMAND
        self.assertEqual(actual, expected)
        self.assertEqual(vm.ssh_arguments(c), before)

    def test_every_real_producer_requires_parent_identity_before_acknowledgment(self):
        records, target = [], {"path": "/owned"}
        for index, phase in enumerate(("guest-info", *self.stage.PHASES)):
            process = identity(555 + index)
            event = {"stage": "stage-producer-started", "index": index, "phase": phase, "ssh": process}
            with patch.object(vm, "process_identity", return_value=process), patch.object(vm, "process_cgroup", return_value="/owned"):
                vm.admit_producer_event(event, records, identity(444), target)
        self.assertEqual(len(records), 4)
        with self.assertRaises(vm.Refusal):
            vm.admit_producer_event(event, records, identity(444), target)
        records = []
        event = {"stage": "stage-producer-started", "index": 0, "phase": "guest-info", "ssh": identity(555)}
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(vm.Refusal, "stage-producer-disappeared-before-admission"):
                vm.admit_producer_event(event, records, identity(444), target)
        self.assertEqual(records, [{"phase": "guest-info", "process": identity(555)}])
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            vm.admit_producer_event(event, [], identity(444), target, allow_retired=True)

    def worker_case(self, *, transfer_error=None, acknowledgment_error=False, reap_error=False):
        raw_plan, plan = self.plan()
        c = config()
        c.update({"phase": "stage-inputs", "start": time.monotonic() - 1, "end": time.monotonic() + 60,
                  "cleanup_seconds": 10, "controller": identity(111), "stage_plan_sha256": plan.sha256,
                  "stage_input_limit": 49})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel, qemu, selector = Mock(), Mock(), Mock()
        qemu.pid = 444
        qemu.poll.return_value = None
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32,
            "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        pending, sends, budgets, sessions = [], [], [], []
        selector.select.return_value = [(SimpleNamespace(fd=123, fileobj=qemu.stdout), None)]
        def sent(_channel, event, _budget, **_kwargs):
            sends.append(event)
            if event["stage"] == "stage-producer-started":
                pending.append({**event, "stage": "stage-producer-admitted"})
        def received(_channel, _budget, **_kwargs):
            if not pending:
                return gate
            item = pending.pop(0)
            return {**item, "phase": "wrong"} if acknowledgment_error else item
        def execute(argv, budget, _directory, **kwargs):
            budgets.append(budget)
            if argv[0] == c["tools"]["ssh"]["path"]:
                kwargs["on_start"](Mock(pid=555))
                return 0, vm.encode({"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                    "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}})
            return (0, b'{"format":"qcow2","virtual-size":1024}') if argv[1] == "info" else (0, b"")
        def transfer(session, phase, _config, *, extra_streams, on_start, pre_child):
            sessions.append(session)
            self.assertIs(session.budget, budgets[0])
            pre_child()
            on_start(Mock(pid=556 + self.stage.PHASES.index(phase)))
            if transfer_error:
                raise vm.Refusal(transfer_error)
            file = plan.files[session.next_phase]
            reply = self.stage.reply(vm.encode({"schema": "kubernetes-lens-owned-guest-stage-reply-v1",
                "owner": plan.owner, "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                "bytes": file.size, "sha256": file.sha256, "state": "staged"}) + b"\n", plan, phase, file)
            session.charge(file.size + len(phase) + 1)
            session.next_phase += 1
            return reply
        def reaped(process, _budget):
            if reap_error and process.pid == 556:
                raise vm.Refusal("synthetic-reap-failure")
            return True
        def read(path, *_args):
            return raw_plan if str(path).endswith("stage-plan.json") else raw
        with patch.object(vm, "read", side_effect=read), patch.object(vm, "verify_source"), \
             patch.object(vm, "worker_pre_child") as guard, patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c["controller"]), \
             patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "send", side_effect=sent), patch.object(vm, "receive", side_effect=received), \
             patch.object(vm, "run", side_effect=execute), patch.object(vm.subprocess, "Popen", return_value=qemu), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), patch.object(vm.os, "set_blocking"), \
             patch.object(vm.os, "read", return_value=b"Reached target Multi-User System\n"), \
             patch.object(vm, "reap", side_effect=reaped) as reap, \
             patch.object(vm, "authenticated_module", return_value=self.stage), \
             patch.object(self.stage, "transfer", side_effect=transfer):
            status = vm.worker("/private/config", vm.digest(raw))
        return status, sends[-1], sessions, reap.call_args_list, guard.call_args_list

    def test_worker_uses_one_original_budget_session_and_all_four_producers(self):
        status, stopped, sessions, reaps, guards = self.worker_case()
        self.assertEqual(status, 0)
        self.assertEqual(len(sessions), 3)
        self.assertTrue(all(item is sessions[0] for item in sessions))
        self.assertEqual([item["phase"] for item in stopped["producers"]], ["guest-info", *self.stage.PHASES])
        self.assertEqual(stopped["producers_reaped"], [True] * 4)
        self.assertEqual([call.args[0].pid for call in reaps], [555, 556, 557, 558, 444])
        self.assertEqual(len(guards), 6)
        self.assertEqual(stopped["staging"]["input_bytes"], 49)
        vm.validate_stage_result(stopped["staging"], sessions[0].plan, self.stage, {"stage_input_limit": 49})

    def test_registration_ack_failure_stops_all_later_transfers(self):
        status, stopped, sessions, reaps, _guards = self.worker_case(acknowledgment_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(stopped["error"], "stage-producer-acknowledgment")
        self.assertEqual(sessions, [])
        self.assertEqual([call.args[0].pid for call in reaps], [555, 444])
        self.assertEqual(stopped["producers_reaped"], [True])

    def test_first_transfer_failure_survives_later_reap_failure_no_retry(self):
        status, stopped, sessions, _reaps, _guards = self.worker_case(transfer_error="stage-reply-mismatch", reap_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(stopped["error"], "stage-reply-mismatch")
        self.assertEqual(len(sessions), 1)
        self.assertEqual(stopped["producers_reaped"], [True, False])
        self.assertIsNone(stopped["staging"])

    def test_outside_retirement_accounts_every_stage_producer_and_actual_reap(self):
        c = {**config(), "phase": "stage-inputs"}
        records = [{"phase": phase, "process": identity(555 + index)}
                   for index, phase in enumerate(("guest-info", *self.stage.PHASES))]
        stopped = {**barrier(), "producers": records, "producers_reaped": [True] * 4, "staging": None}
        inactive = {**unit(), "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "InvocationID": ""}
        def exercise(value):
            with patch.object(vm, "unit_show", side_effect=[unit(), inactive, inactive]), \
                 patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
                 patch.object(vm, "process_retired", return_value=True) as retired, \
                 patch.object(vm, "empty_cgroup", return_value="removed"), patch.object(vm.time, "sleep"):
                receipt = vm.retire(c, vm.Budget(time.monotonic() + 60, 10), "b" * 32, {"path": "/target"},
                                    identity(), identity(444), value, producers=records)
                return receipt, retired.call_args_list
        receipt, calls = exercise(stopped)
        self.assertEqual(receipt["producers"], records)
        for item in records:
            self.assertEqual(sum(call.args[0] == item["process"] for call in calls), 2)
        for flags in ([True] * 3, [True, True, False, True], [True, True, 1, True]):
            with self.assertRaisesRegex(vm.Refusal, "stage-producer-barrier-unproved"):
                exercise({**stopped, "producers_reaped": flags})
        with self.assertRaisesRegex(vm.Refusal, "stage-producer-barrier-unproved"):
            exercise({**stopped, "producers": records[:-1]})

    def test_parent_rejects_incomplete_extra_or_conformance_labeled_stage_results(self):
        raw, plan = self.plan()
        result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256, "input_bytes": 49, "replies": []}
        for phase, file in zip(self.stage.PHASES, plan.files):
            result["replies"].append({"schema": "kubernetes-lens-owned-guest-stage-reply-v1", "owner": plan.owner,
                "plan_sha256": plan.sha256, "phase": phase, "role": file.role, "bytes": file.size,
                "sha256": file.sha256, "state": "stage-reply-observed", "vm_retirement": "not-established",
                "runtime_conformance": "not-performed"})
        vm.validate_stage_result(result, plan, self.stage, {"stage_input_limit": 49})
        cases = [{**result, "input_bytes": True}, {**result, "replies": result["replies"][:-1]},
                 {**result, "extra": "unknown"}, {**result, "plan_sha256": "0" * 64}]
        changed = deepcopy(result)
        changed["replies"][0]["runtime_conformance"] = "passed"
        cases.append(changed)
        for changed in cases:
            with self.assertRaises(vm.Refusal):
                vm.validate_stage_result(changed, plan, self.stage, {"stage_input_limit": 49})

    def _parent_stage_case(self, *, drift_after=None, drift_kind="source", archive_bytes=21, guest_override=None):
        raw_plan, plan = self.plan()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            image = parent / "input.xz"
            image.write_bytes(b"fake prepared archive")
            c, tools = config(), config()["tools"]
            target = "/sys/fs/cgroup/owned/" + c["unit"]
            args = SimpleNamespace(phase="stage-inputs", deadline_seconds=120, cleanup_seconds=20,
                cpus=2, pids=256, memory_mib=4096, guest_memory_mib=2048, disk_gib=16, ssh_port=22222,
                host_tools=str(parent / "tools.json"), host_tools_sha256="a" * 64,
                image=str(image), output_parent=str(parent))
            server, probe, channel = MagicMock(), MagicMock(), Mock()
            server.accept.return_value = (channel, None)
            observed, guard_budgets = [], []
            drift = [False]
            def archive(_source, directory, _pin, _budget):
                (directory / "image.qcow2").write_bytes(b"private base")
                # The immutable reservation must remain safe if the selected
                # source is replaced/grows after all preliminary metadata.
                replacement = parent / "replacement.xz"
                replacement.write_bytes(b"larger replacement archive bytes")
                replacement.replace(image)
                if drift_after == "preparation":
                    drift[0] = True
                return {"expanded_sha256": vm.digest(b"private base"), "expanded_bytes": 12, "archive_bytes": archive_bytes}
            def source_check(_config, budget):
                guard_budgets.append(budget)
                if drift[0] and drift_kind == "source":
                    raise vm.Refusal("owning-source-drift")
            def tool_check(*_args):
                return {} if drift[0] and drift_kind == "tool" else tools
            def execute(argv, _budget, _directory, **_kwargs):
                observed.append(argv)
                if argv[0] == tools["ssh_keygen"]["path"]:
                    path = Path(argv[-1])
                    path.write_text("PRIVATE TEST KEY")
                    Path(str(path) + ".pub").write_text("ssh-ed25519 AAAA\n")
                    if drift_after == path.name:
                        drift[0] = True
                if drift_after == "show-environment" and argv[-1] == "show-environment":
                    drift[0] = True
                return 0, b""
            events, producers = [], []
            def received(_channel, budget, **_kwargs):
                index = len(events)
                if index == 0:
                    value = {"stage": "barrier", "worker": identity(), "config_sha256": "unused"}
                elif index == 1:
                    value = {"stage": "qemu-started", "qemu": identity(444)}
                elif index < 6:
                    phase = ("guest-info", *self.stage.PHASES)[index - 2]
                    process = identity(555 + index - 2)
                    producers.append({"phase": phase, "process": process})
                    value = {"stage": "stage-producer-started", "index": index - 2, "phase": phase, "ssh": process}
                else:
                    replies = []
                    for phase, file in zip(self.stage.PHASES, plan.files):
                        replies.append(self.stage.reply(vm.encode({"schema": "kubernetes-lens-owned-guest-stage-reply-v1",
                            "owner": plan.owner, "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                            "bytes": file.size, "sha256": file.sha256, "state": "staged"}) + b"\n", plan, phase, file))
                    value = {**barrier(), "guest": barrier()["guest"] if guest_override is None else guest_override,
                        "original_end": budget.end, "producers": producers,
                        "producers_reaped": [True] * 4, "staging": {"state": "stage-replies-observed",
                            "plan_sha256": plan.sha256, "input_bytes": 49, "replies": replies}}
                events.append(value)
                return value
            fake_view = Mock()
            fake_view.ParentView.return_value.attest.return_value = {"test": "parent-bound-view"}
            fake_view.ParentView.return_value.partial = {"schema": "host-view-partial", "qualification": "incomplete"}
            native = SimpleNamespace(select_profile=Mock(), Refusal=vm.Refusal)
            rows = [unit(), unit(), {**unit(), "ActiveState": "inactive", "MainPID": "0", "InvocationID": ""},
                    {**unit(), "ActiveState": "inactive", "MainPID": "0", "InvocationID": ""}]
            send = Mock()
            patches = [
                patch.object(vm, "host_view_module", return_value=fake_view),
                patch.object(vm, "validate_config_args", return_value=parent), patch.object(vm, "admit_tools", side_effect=tool_check),
                patch.object(vm, "check_source_bindings", side_effect=source_check),
                patch.object(vm, "pin_document", return_value=({"release": "44.20260928.3.2"}, "c" * 64)),
                patch.object(vm.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)),
                patch.object(vm, "boot_id", return_value="boot"), patch.object(vm.socket, "socket", side_effect=[server, probe]),
                patch.object(vm, "admit_archive", side_effect=archive), patch.object(vm, "verify_source"),
                patch.object(vm, "run", side_effect=execute), patch.object(vm, "peer_identity", return_value=identity()),
                patch.object(vm, "receive", side_effect=received),
                patch.object(vm, "attest_barrier", return_value=("b" * 32, {"path": target})),
                patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)),
                patch.object(vm, "process_cgroup", return_value=target), patch.object(vm, "unit_show", side_effect=rows),
                patch.object(vm, "send", send), patch.object(vm, "process_retired", return_value=True),
                patch.object(vm, "empty_cgroup", return_value="removed"), patch.object(vm.time, "sleep"),
                patch.object(vm, "authenticated_module", side_effect=lambda name, *_args: self.stage if name == "owned_guest_stage" else native),
                patch.object(self.stage, "admit_inputs", return_value=(raw_plan, plan, {"import": "not-performed",
                    "ledger_sha256": vm.digest(vm.read(vm.ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json", 32 * 1024**2))}))
            ]
            with ExitStack() as stack:
                for context in patches:
                    stack.enter_context(context)
                receipt, status = vm.qualify(args)
            private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
            return receipt, status, private, observed, send.call_args_list, guard_budgets

    def test_genuine_parent_stage_dispatch_reaches_only_staging_receipt_after_retirement(self):
        receipt, status, private, observed, sends, budgets = self._parent_stage_case(archive_bytes=vm.ARCHIVE_MAX)
        self.assertEqual(status, 0, receipt)
        self.assertEqual(receipt["state"], "stage-inputs-retired")
        self.assertEqual(private["guest_info"], barrier()["guest"])
        self.assertEqual(private["runtime_conformance"], "not-performed")
        self.assertEqual(len(private["retirement"]["producers"]), 4)
        self.assertEqual(len(private["retirement"]["observations"]), 2)
        self.assertEqual(sum(call.args[1].get("stage") == "stage-producer-admitted" for call in sends), 4)
        self.assertNotIn("PRIVATE TEST KEY", vm.encode(private).decode())
        storage = private["staging"]["storage"]
        self.assertEqual(storage["source_vm_archive_reserved_bytes"], vm.ARCHIVE_MAX)
        self.assertEqual(storage["overlay_max"], 16 * 1024**3 - 2 * vm.ARCHIVE_MAX - vm.EXPANDED_MAX - 4 * 1024**2 - 9)
        self.assertTrue(all(budget is budgets[0] for budget in budgets))

    def test_parent_drift_after_preparation_and_between_keys_blocks_next_native_child(self):
        expected_counts = {"preparation": 0, "client_key": 1, "host_key": 2, "stage_key": 3, "show-environment": 3}
        for kind in ("source", "tool"):
            for boundary, expected_keys in expected_counts.items():
                with self.subTest(kind=kind, boundary=boundary):
                    receipt, status, private, observed, _sends, budgets = self._parent_stage_case(drift_after=boundary, drift_kind=kind)
                    self.assertEqual(status, 1)
                    self.assertEqual(receipt["error"], "owning-source-drift" if kind == "source" else "host-tools-drift")
                    self.assertEqual(len([argv for argv in observed if argv[0] == config()["tools"]["ssh_keygen"]["path"]]), expected_keys)
                    self.assertFalse(any("--_worker" in argv for argv in observed))
                    self.assertEqual(any(argv[-1] == "show-environment" for argv in observed), boundary == "show-environment")
                    self.assertIsNone(private["guest_info"])
                    self.assertIsNone(private["retirement"])
                    self.assertTrue(all(budget is budgets[0] for budget in budgets))

    def test_archive_full_reservation_covers_replaced_and_unequal_admitted_source(self):
        for admitted_size in (1, vm.ARCHIVE_MAX):
            _receipt, status, private, _observed, _sends, _budgets = self._parent_stage_case(archive_bytes=admitted_size)
            self.assertEqual(status, 0)
            self.assertEqual(private["staging"]["storage"]["source_vm_archive_reserved_bytes"], vm.ARCHIVE_MAX)
        for admitted_size in (vm.ARCHIVE_MAX + 1, True, 0):
            receipt, status, private, observed, _sends, _budgets = self._parent_stage_case(archive_bytes=admitted_size)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["error"], "stage-storage-reservation-exceeded")
            self.assertEqual(observed, [])
            self.assertIsNone(private["guest_info"])

    def test_controller_does_not_retain_unvalidated_guest_frames(self):
        for value in ({**barrier()["guest"], "rootful": 1}, {**barrier()["guest"], "raw": "protected"}, {}):
            receipt, status, private, _observed, _sends, _budgets = self._parent_stage_case(guest_override=value)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["error"], "guest-result-unproved")
            self.assertIsNone(private["guest_info"])
            self.assertNotIn("protected", vm.encode(private).decode())


if __name__ == "__main__":
    unittest.main()
