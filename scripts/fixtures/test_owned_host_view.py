"""Pure host-view models; no services, namespaces, subprocesses or VMs start."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import errno
import os
import time
import unittest
from unittest.mock import Mock, patch

import owned_host_view as view
import owned_qemu as vm


MOUNTS = "1 0 1:1 / / ro - ext4 /dev/root ro\n2 1 0:30 / /sys/fs/cgroup ro - cgroup2 cgroup ro\n"
MAP = "1000 1000 1\n"
STATUS = "Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t1000\n" + "".join(
    name + ":\t0000000000000000\n" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) + "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
PROCESS = {"pid": 321, "start": 9, "group": 321, "session": 321}


def config():
    return {"owner": "a" * 32, "boot": "boot", "manifest_sha256": "c" * 64, "manifest": "/manifest",
            "source": {"/source": "d" * 64}, "end": 1000., "work_end": 900., "unit": "kubernetes-lens-vm-" + "a" * 32 + ".service", "directory": "/private",
            "tools": {name: {"path": "/usr/bin/python", "sha256": "b" * 64} for name in ("python", "busctl")}}


def objects():
    base = {"identity": [1, 2, 3, 4, 5], "type": 16384, "mode": 493, "uid": 0, "gid": 0}
    return {"/": dict(base), "/usr": dict(base), "/usr/bin": dict(base),
            "/usr/bin/python": {**base, "type": 32768, "sha256": "b" * 64, "capabilities_sha256": vm.digest(b"")}}


def guards(c):
    result = {name: {"type": signature, "data": deepcopy(data)} for name, (signature, data) in view.POLICY.items()}
    result["SystemCallFilter"] = {"type": "(bas)", "data": [False, list(view.DENIED)]}
    result["ReadWritePaths"] = {"type": "as", "data": [c["directory"]]}
    result["InaccessiblePaths"] = {"type": "as", "data": ["-/run/user/1000/bus", "-/run/user/1000/systemd",
                                                               "-/run/dbus/system_bus_socket", "-/run/podman", "-/run/docker.sock"]}
    return result


class Models(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def test_same_and_one_level_projection_is_exact_not_generic_overflow_acceptance(self):
        self.assertEqual(view.project(0, [[0, 0, 4294967295]], 65534), 0)
        self.assertEqual(view.project(1000, [[1000, 1000, 1]], 65534), 1000)
        self.assertEqual(view.project(0, [[1000, 1000, 1]], 65534), 65534)
        authority = objects()["/usr/bin/python"]
        local = {**authority, "uid": 65534, "gid": 65534}
        view.compare_object(authority, local, uid_map=[[1000, 1000, 1]], gid_map=[[1000, 1000, 1]],
                            overflow_uid=65534, overflow_gid=65534)
        for key, value in (("identity", [7, 2, 3, 4, 5]), ("sha256", "a" * 64), ("uid", 1000), ("mode", 511)):
            with self.subTest(key=key), self.assertRaises(vm.Refusal):
                view.compare_object(authority, {**local, key: value}, uid_map=[[1000, 1000, 1]],
                                    gid_map=[[1000, 1000, 1]], overflow_uid=65534, overflow_gid=65534)
        for uid in (65534, 1000):
            with self.assertRaisesRegex(vm.Refusal, "parent-authority"):
                view.compare_object({**authority, "uid": uid}, local)

    def test_maps_refuse_overlap_malformed_and_out_of_range(self):
        self.assertEqual(view.parse_map(MAP), [[1000, 1000, 1]])
        self.assertEqual(view.parse_map("0 0 4294967295\n"), [[0, 0, 4294967295]])
        for text in ("", "0 0 0", "0 -1 1", "0 0 4294967296", "0 0", "0 0 2\n1 4 1", "0 0 2\n4 1 1", "1 1 1\n" * 6):
            with self.subTest(text=text), self.assertRaises(vm.Refusal):
                view.parse_map(text)

    def test_every_effective_privilege_field_is_required_and_strict(self):
        expected = view.status_fields(STATUS, worker=True)
        self.assertEqual(expected["Uid"], [1000] * 4)
        for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"):
            lines = STATUS.splitlines()
            for value in ("missing", "wrong", "0000000000000001" if name.startswith("Cap") else "0"):
                changed = "\n".join(line for line in lines if not line.startswith(name + ":"))
                if value != "missing":
                    changed += "\n" + name + ":\t" + value
                with self.subTest(name=name, value=value), self.assertRaises(vm.Refusal):
                    view.status_fields(changed, worker=True)
        with self.assertRaisesRegex(vm.Refusal, "duplicate"):
            view.status_fields(STATUS + "Uid:\t1000 1000 1000 1000\n", worker=True)

    def test_topology_must_be_bounded_and_exactly_readonly(self):
        self.assertEqual(view.readonly_mount(view.mounts(MOUNTS), "/sys/fs/cgroup")["filesystem"], "cgroup2")
        for text in ("", MOUNTS + MOUNTS, MOUNTS.replace("/sys/fs/cgroup ro", "/sys/fs/cgroup rw"),
                     MOUNTS.replace(" / / ", " / /bad\\040path "), MOUNTS.replace(" ro -", " ro idmapped -")):
            with self.subTest(text=text), self.assertRaises(vm.Refusal):
                view.readonly_mount(view.mounts(text), "/sys/fs/cgroup")
        with self.assertRaises(vm.Refusal):
            view.mounts("1 0 1:1 / / ro - ext4 x ro\n" * 513)

    def test_fixed_walk_does_not_follow_any_component_or_accept_alternate_path(self):
        for path in ("relative", "/usr/../x", "/usr//bin/x", "/usr/bin/x;bad", "/usr/bin/x "):
            with self.subTest(path=path), self.assertRaises(vm.Refusal):
                view.walk(5, path, self.budget)
        with patch.object(view.os, "dup", return_value=10), patch.object(view.os, "open", side_effect=OSError(errno.ELOOP, "link")) as opened, \
             patch.object(view.os, "close"), patch.object(view, "object_record", return_value=objects()["/"]):
            with self.assertRaises(OSError):
                view.walk(5, "/usr/bin/python", self.budget)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        with patch.object(view.os, "dup", return_value=10), patch.object(view.os, "open", side_effect=OSError(errno.ELOOP, "link")) as opened, patch.object(view.os, "close"):
            with self.assertRaises(OSError):
                view.directory_at(5, "sys/fs/cgroup", self.budget)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)

    def test_manifest_admission_remains_outside_strict_and_first(self):
        with patch.object(vm, "admit_tools", side_effect=vm.Refusal("host-tool-writable")), patch.object(view.os, "open") as opened:
            with self.assertRaisesRegex(vm.Refusal, "host-tool-writable"):
                view.ParentView(config(), self.budget)
        opened.assert_not_called()

    def test_typed_constructor_policy_exact_and_no_missing_property_invention(self):
        c = config()
        expected = guards(c)
        names = [*view.POLICY, "SystemCallFilter", "ReadWritePaths", "InaccessiblePaths"]
        def run(document):
            return patch.object(vm, "run", return_value=(0, b"\n".join(vm.encode(document[name]) for name in names)))
        with patch.object(view.os, "getuid", return_value=1000), run(expected) as command:
            self.assertEqual(view.typed_guards(c, self.budget), expected)
            self.assertIs(command.call_args.args[1], self.budget)
        for name in names:
            for field, value in (("type", "unknown"), ("data", None)):
                changed = deepcopy(expected)
                changed[name][field] = value
                with self.subTest(name=name, field=field), patch.object(view.os, "getuid", return_value=1000), run(changed), self.assertRaises(vm.Refusal):
                    view.typed_guards(c, self.budget)
        for change in ([True, list(view.DENIED)], [False, [name for name in view.DENIED if name != "clone3"]], [False, [*view.DENIED, "unknown"]]):
            changed = deepcopy(expected)
            changed["SystemCallFilter"]["data"] = change
            with patch.object(view.os, "getuid", return_value=1000), run(changed), self.assertRaises(vm.Refusal):
                view.typed_guards(c, self.budget)
        with patch.object(vm, "run", return_value=(0, b"")), self.assertRaises(vm.Refusal):
            view.typed_guards(c, self.budget)

    def test_native_architecture_serialization_is_fixed(self):
        c = config()
        expected = guards(c)
        self.assertEqual(expected["SystemCallArchitectures"], {"type": "as", "data": ["native"]})
        names = [*view.POLICY, "SystemCallFilter", "ReadWritePaths", "InaccessiblePaths"]
        for architectures in (["x86-64"], ["native", "x86-64"], ["x86"], [], ["unknown"], "native"):
            changed = deepcopy(expected)
            changed["SystemCallArchitectures"]["data"] = architectures
            raw = b"\n".join(vm.encode(changed[name]) for name in names)
            with self.subTest(architectures=architectures), patch.object(vm, "run", return_value=(0, raw)), self.assertRaisesRegex(vm.Refusal, "host-view-constructor-policy"):
                view.typed_guards(c, self.budget)

    def test_manager_client_hash_is_not_server_version_proof(self):
        for value in ({"type": "s", "data": "261.5"}, {"type": "s", "data": ""}, {"type": "as", "data": ["261.4"]}):
            with patch.object(vm, "run", return_value=(0, vm.encode(value))), self.assertRaises(vm.Refusal):
                view.manager_version(config(), self.budget)
        with patch.object(vm, "run", return_value=(0, vm.encode({"type": "s", "data": "261.4"}))):
            self.assertEqual(view.manager_version(config(), self.budget), "261.4")

    def test_exact_process_unit_cgroup_and_parent_namespace_are_rechecked(self):
        p = object.__new__(view.ParentView)
        p.config, p.budget = config(), self.budget
        p.invocation, p.cgroup = "invocation", {"path": "/cgroup"}
        p.parent_proc, p.parent_ns = 10, {"user": [1, 10], "mnt": [1, 11]}
        with patch.object(vm, "boot_id", return_value="boot") as boot, \
             patch.object(vm, "process_identity", return_value=PROCESS) as process, \
             patch.object(vm, "unit_show", return_value={"MainPID": "321"}) as unit, \
             patch.object(vm, "validate_unit", return_value="invocation") as validate, \
             patch.object(vm, "process_cgroup", return_value="/cgroup") as placement, \
             patch.object(vm, "cgroup_snapshot", return_value=p.cgroup), \
             patch.object(view, "namespace", side_effect=lambda _proc, name: 31 if name == "user" else 32), \
             patch.object(view, "identity", side_effect=lambda fd: [1, 10 if fd == 31 else 11]) as namespace_id, \
             patch.object(view.os, "close"):
            p.check_process(PROCESS)
            for target, changed in ((boot, "other-boot"), (process, {**PROCESS, "start": 10}),
                                    (unit, {"MainPID": "999"}), (validate, "other-invocation"),
                                    (placement, "/other-cgroup")):
                previous = target.return_value
                target.return_value = changed
                with self.subTest(changed=changed), self.assertRaises(vm.Refusal):
                    p.check_process(PROCESS)
                target.return_value = previous
            namespace_id.side_effect = lambda _fd: [1, 99]
            with self.assertRaisesRegex(vm.Refusal, "parent-namespace-drift"):
                p.check_process(PROCESS)

    def test_fixed_kernel_scalars_and_kernel_reads_have_original_bounded_end(self):
        with patch.object(view.os, "open", return_value=10), patch.object(view.os, "close"), \
             patch.object(view.os, "read", side_effect=[b"65534\n", b"", b"65534\n", b""]):
            self.assertEqual(view.overflow_ids(self.budget), [65534, 65534])
        for chunks in ([b"9" * 33], [b"65534\n", b"trailing"], [b"4294967295", b""], [b"bad", b""]):
            with patch.object(view.os, "open", return_value=10), patch.object(view.os, "close"), \
                 patch.object(view.os, "read", side_effect=chunks), self.assertRaises(vm.Refusal):
                view.overflow_ids(self.budget)
        with patch.object(view.os, "open") as opened, self.assertRaises(vm.Refusal):
            view.kernel_at(10, "unexpected", self.budget)
        opened.assert_not_called()
        with patch.object(view.os, "open", return_value=10), patch.object(view.os, "close"), \
             patch.object(view.os, "read", return_value=b"x" * 9), self.assertRaisesRegex(vm.Refusal, "kernel-budget"):
            view.kernel_at(10, "uid_map", self.budget, maximum=8)


class BoundView(unittest.TestCase):
    setUp = Models.setUp

    def model(self, *, same=False):
        """Full parent and local adapter against closed fake kernel/control data."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        c = config()
        p = object.__new__(view.ParentView)
        p.config, p.budget, p.handles = c, self.budget, []
        p.parent_proc, p.parent_ns = 10, {"user": [1, 10], "mnt": [1, 11]}
        p.objects = objects()
        p.partial = {"schema": "kubernetes-lens-owned-host-view-partial-v1"}
        p.manager, p.kernel = "261.4", {"release": "reviewed-kernel", "machine": "x86_64"}
        child_ns = {"user": [1, 10 if same else 12], "mnt": [1, 13]}
        raw_map = "0 0 4294967295\n" if same else MAP
        self.kernel = {"uid_map": raw_map, "gid_map": raw_map, "setgroups": "allow\n" if same else "deny\n",
                       "status": STATUS, "mountinfo": MOUNTS}
        self.local = False
        def walk(*_args, **_kwargs):
            result = objects()
            if self.local and not same:
                for record in result.values():
                    record["uid"] = record["gid"] = 65534
            return result
        stack.enter_context(patch.object(view.os, "getuid", return_value=1000))
        stack.enter_context(patch.object(view.os, "getgid", return_value=1000))
        stack.enter_context(patch.object(view.os, "getpid", return_value=321))
        stack.enter_context(patch.object(view.os, "uname", return_value=SimpleNamespace(release="reviewed-kernel", machine="x86_64")))
        stack.enter_context(patch.object(vm, "process_identity", return_value=PROCESS))
        stack.enter_context(patch.object(vm, "process_cgroup", return_value="/cgroup"))
        stack.enter_context(patch.object(vm, "cgroup_snapshot", return_value={"path": "/cgroup"}))
        stack.enter_context(patch.object(vm, "boot_id", return_value="boot"))
        stack.enter_context(patch.object(view.os, "pidfd_open", return_value=20))
        stack.enter_context(patch.object(view.os, "open", return_value=21))
        stack.enter_context(patch.object(view.os, "close"))
        stack.enter_context(patch.object(view, "namespace", side_effect=lambda _proc, name: 31 if name == "user" else 32))
        stack.enter_context(patch.object(view, "identity", side_effect=lambda fd: [30, 40] if fd == 22 else p.parent_ns["user"] if fd == 99 else child_ns["user" if fd == 31 else "mnt"]))
        self.ancestry = stack.enter_context(patch.object(view.fcntl, "ioctl", return_value=99))
        stack.enter_context(patch.object(view, "kernel_at", side_effect=lambda _proc, name, _budget: self.kernel[name]))
        stack.enter_context(patch.object(view, "walk", side_effect=walk))
        stack.enter_context(patch.object(view, "object_record", return_value=objects()["/usr/bin/python"]))
        stack.enter_context(patch.object(view, "directory_at", return_value=22))
        self.fs = stack.enter_context(patch.object(view.os, "fstatvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)))
        stack.enter_context(patch.object(view.os, "fstat", return_value=SimpleNamespace(st_dev=30, st_ino=40)))
        stack.enter_context(patch.object(view.os, "stat", return_value=SimpleNamespace(st_dev=30, st_ino=40)))
        stack.enter_context(patch.object(view, "overflow_ids", return_value=[65534, 65534]))
        stack.enter_context(patch.object(view, "typed_guards", return_value=guards(c)))
        stack.enter_context(patch.object(view, "manager_version", return_value="261.4"))
        stack.enter_context(patch.object(vm, "admit_tools", return_value=c["tools"]))
        self.process_check = stack.enter_context(patch.object(p, "check_process"))
        stack.enter_context(patch.dict(vm.os.environ, {"INVOCATION_ID": "invocation"}))
        return p, c

    def frame(self, *, same=False):
        p, c = self.model(same=same)
        frame = p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))
        return p, c, frame

    def test_parent_then_worker_equivalence_for_proved_immediate_child(self):
        p, c, frame = self.frame()
        p.recheck()
        self.local = True
        view.validate_local(frame, c, self.budget)
        self.assertEqual(frame["binding"]["end"], c["end"])
        self.assertEqual(frame["constructor"]["manager"], "261.4")

    def test_self_constructor_cannot_fall_back_to_same_user_namespace(self):
        p, c = self.model(same=True)
        with self.assertRaisesRegex(vm.Refusal, "private-namespace-inconsistent"):
            p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))

    def test_denied_or_wrong_namespace_parent_refuses_before_go(self):
        p, c = self.model()
        self.ancestry.side_effect = PermissionError("denied")
        with self.assertRaises(PermissionError):
            p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))
        self.ancestry.side_effect = None
        self.ancestry.return_value = 32
        with self.assertRaisesRegex(vm.Refusal, "nested-userns"):
            p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))

    def test_multirange_projection_not_admitted_despite_valid_map_syntax(self):
        p, c = self.model()
        self.kernel["uid_map"] = "0 0 1\n1000 1000 1\n"
        with self.assertRaisesRegex(vm.Refusal, "worker-map-unsupported"):
            p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))

    def test_effective_cgroup_readonly_not_requested_property_is_mandatory(self):
        p, c = self.model()
        self.fs.return_value = SimpleNamespace(f_flag=0)
        with self.assertRaisesRegex(vm.Refusal, "cgroup-mount-writable"):
            p.attest(PROCESS, "invocation", {"path": "/cgroup"}, vm.digest(vm.encode(c)))

    def test_recheck_rejects_same_namespace_mount_or_map_drift(self):
        p, _c, _frame = self.frame()
        for name, changed in (("mountinfo", MOUNTS.replace("ext4", "xfs")), ("uid_map", "1001 1001 1\n"),
                              ("setgroups", "allow\n"), ("status", STATUS.replace("1000", "1001"))):
            previous = self.kernel[name]
            self.kernel[name] = changed
            with self.subTest(name=name), self.assertRaises(vm.Refusal):
                p.recheck()
            self.kernel[name] = previous

    def test_local_binding_replay_and_view_mutations_refuse(self):
        _p, c, frame = self.frame()
        self.local = True
        for field, value in (("owner", "foreign"), ("process", {**PROCESS, "start": 10}), ("end", 2000.),
                             ("manifest_sha256", "f" * 64), ("invocation", "foreign")):
            changed = deepcopy(frame)
            changed["binding"][field] = value
            with self.subTest(field=field), self.assertRaises(vm.Refusal):
                view.validate_local(changed, c, self.budget)
        for field, value in (("mountinfo_sha256", "f" * 64), ("uid_map", [[1001, 1001, 1]]),
                             ("setgroups", "allow"), ("overflow", [1000, 1000]),
                             ("constructor", {"manager": "future", "kernel": {}})):
            changed = deepcopy(frame)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(vm.Refusal):
                view.validate_local(changed, c, self.budget)

    def test_original_deadline_exhaustion_is_not_renewed(self):
        p, _c, _frame = self.frame()
        self.budget.work_end = time.monotonic() - 1
        # Our fake kernel adapters bypass their own remaining() deliberately;
        # the recheck's control-plane and object budget must still refuse.
        with patch.object(view, "manager_version", wraps=view.manager_version):
            with self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                p.budget.remaining()


class OwningIntegration(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def test_helper_loader_uses_authenticated_exact_bytes_and_owner_identity(self):
        path = vm.ROOT / "scripts/fixtures/owned_host_view.py"
        c = {"source": {str(path): vm.digest(path.read_bytes())}}
        module = vm.host_view_module(c, self.budget)
        self.assertIs(module.vm, vm)
        self.assertIs(module.vm.Refusal, vm.Refusal)
        vm.CANCELLED = 15
        self.assertEqual(module.vm.CANCELLED, 15)
        vm.CANCELLED = 0
        with patch.object(vm, "read", return_value=b"raise AssertionError('must not execute')"), patch.object(vm.types, "ModuleType") as create:
            with self.assertRaisesRegex(vm.Refusal, "helper-source-drift"):
                vm.host_view_module(c, self.budget)
        create.assert_not_called()

    def test_each_native_guard_checks_source_and_manifest_before_loading_helper(self):
        events = []
        module = Mock()
        module.validate_local.side_effect = lambda *_args: events.append("view")
        c = {"manifest": "/manifest", "manifest_sha256": vm.digest(b"manifest")}
        with patch.object(vm, "check_source_bindings", side_effect=lambda *_args: events.append("source")), \
             patch.object(vm, "read", side_effect=lambda *_args: events.append("manifest") or b"manifest"), \
             patch.object(vm, "host_view_module", side_effect=lambda *_args: events.append("load") or module):
            vm.worker_pre_child(c, self.budget, {"bound": "frame"})
        self.assertEqual(events, ["source", "manifest", "load", "view"])
        module.validate_local.assert_called_once_with({"bound": "frame"}, c, self.budget)
        self.assertEqual(self.budget.commands_left, 128)

    def test_refusal_at_any_native_guard_check_never_loads_unadmitted_code(self):
        c = {"manifest": "/manifest", "manifest_sha256": vm.digest(b"manifest")}
        for source_bad in (True, False):
            with patch.object(vm, "check_source_bindings", side_effect=vm.Refusal("source") if source_bad else None), \
                 patch.object(vm, "read", return_value=b"drifted"), patch.object(vm, "host_view_module") as load:
                with self.assertRaises(vm.Refusal):
                    vm.worker_pre_child(c, self.budget, {})
                load.assert_not_called()

    def test_worker_equivalence_does_not_call_relaxed_or_strict_local_root_admission(self):
        c = {"input_files": {}}
        frame = {"bound": "frame"}
        with patch.object(vm, "check_source_bindings"), patch.object(vm, "worker_pre_child") as guard, patch.object(vm, "admit_tools") as admit:
            vm.verify_source(c, self.budget, host_view=frame)
        guard.assert_called_once_with(c, self.budget, frame)
        admit.assert_not_called()

    def test_direct_worker_main_alias_shares_exception_budget_and_cancellation_state(self):
        # Execute the real owning module's definitions with its final CLI entry
        # suppressed. No worker, subprocess, service or compiler is invoked.
        import ast
        import types
        source = Path(vm.__file__).read_text()
        tree = ast.parse(source, vm.__file__)
        self.assertIsInstance(tree.body[-1], ast.If)
        tree.body.pop()
        module = types.ModuleType("__main__")
        module.__file__ = vm.__file__
        with patch.dict(vm.sys.modules, {"__main__": module, "owned_qemu": vm}):
            exec(compile(tree, vm.__file__, "exec"), module.__dict__)
            path = vm.ROOT / "scripts/fixtures/owned_host_view.py"
            c = {"source": {str(path): vm.digest(path.read_bytes())}}
            loaded = module.host_view_module(c, self.budget)
            self.assertIs(loaded.vm, module)
            self.assertIs(loaded.vm.Refusal, module.Refusal)
            module.CANCELLED = 2
            self.assertEqual(loaded.vm.CANCELLED, 2)


if __name__ == "__main__":
    unittest.main()
