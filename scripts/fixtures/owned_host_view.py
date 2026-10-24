"""Conditional parent-authority equivalence under a trusted systemd constructor.

Not generic BPF, idmapped-mount or whole-OS attestation. This finite Linux-amd64
profile trusts the installed manager/kernel/loader to implement its closed
policy; independently checked objects, maps, status and mounts remain mandatory.
The parent never enters a worker namespace or relaxes its host-root admission.
"""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

import owned_qemu as vm

MAX_KERNEL = 65536
MAX_MOUNTS = 512
MAX_OBJECTS = 64
NS_GET_PARENT = 0xb702
DENIED = ("chroot", "clone3", "fsconfig", "fsmount", "fsopen", "fspick", "mount",
          "mount_setattr", "move_mount", "open_tree", "pivot_root", "setns", "umount2", "unshare")
TRUST = "trusted-systemd-constructor-v1"
# Fixed historical constructor profile, not an operational tool installer/pin.
# Exact selected-policy normalization remains runtime qualification evidence.
MANAGER_VERSION = "261.4"
POLICY = {
    "NoNewPrivileges": ("b", True), "RestrictNamespaces": ("t", 0),
    "CapabilityBoundingSet": ("t", 0), "AmbientCapabilities": ("t", 0),
    "SystemCallArchitectures": ("as", ["native"]), "SystemCallErrorNumber": ("i", 38),
    "DynamicUser": ("b", False), "PrivateUsersEx": ("s", "self"), "ProtectSystem": ("s", "strict"),
    "ProtectHome": ("s", "read-only"), "ReadOnlyPaths": ("as", ["/sys/fs/cgroup"]),
    "RootDirectory": ("s", ""), "RootImage": ("s", ""),
    "RootEphemeral": ("b", False), "RootDirectoryStartOnly": ("b", False),
    "RootMStack": ("s", ""), "MountAPIVFS": ("b", False), "MountFlags": ("t", 0),
    "RootImageOptions": ("a(ss)", []), "BindLogSockets": ("b", False),
    "PrivateTmpEx": ("s", "no"), "PrivateDevices": ("b", False), "PrivateMounts": ("b", True),
    "PrivateNetwork": ("b", False), "PrivateIPC": ("b", False), "PrivatePIDs": ("s", "no"),
    "ProtectKernelTunables": ("b", False), "ProtectKernelModules": ("b", False),
    "ProtectKernelLogs": ("b", False), "ProtectClock": ("b", False),
    "ProtectControlGroupsEx": ("s", "no"), "ProtectHostnameEx": ("(ss)", ["no", ""]),
    "ProtectProc": ("s", "default"), "ProcSubset": ("s", "all"),
    "UserNamespacePath": ("s", ""), "NetworkNamespacePath": ("s", ""), "IPCNamespacePath": ("s", ""),
    "LogNamespace": ("s", ""),
    "StateDirectorySymlink": ("a(sst)", []), "CacheDirectorySymlink": ("a(sst)", []),
    "LogsDirectorySymlink": ("a(sst)", []), "RuntimeDirectorySymlink": ("a(sst)", []),
    "BindPaths": ("a(ssbt)", []), "BindReadOnlyPaths": ("a(ssbt)", []),
    "MountImages": ("a(ssba(ss))", []), "ExtensionImages": ("a(sba(ss))", []),
    "ExtensionDirectories": ("as", []), "TemporaryFileSystem": ("a(ss)", []),
    "StateDirectory": ("as", []), "CacheDirectory": ("as", []),
    "LogsDirectory": ("as", []), "RuntimeDirectory": ("as", []), "ConfigurationDirectory": ("as", []),
}


def kernel_at(directory, name, budget, maximum=MAX_KERNEL):
    vm.require(name in {"uid_map", "gid_map", "setgroups", "status", "mountinfo"}, "host-view-kernel-name")
    budget.remaining()
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    try:
        result = bytearray()
        while len(result) <= maximum:
            budget.remaining()
            raw = os.read(descriptor, min(4096, maximum + 1 - len(result)))
            if not raw:
                break
            result.extend(raw)
        vm.require(len(result) <= maximum, "host-view-kernel-budget")
        return bytes(result).decode("ascii")
    finally:
        os.close(descriptor)


def identity(descriptor):
    info = os.fstat(descriptor)
    return [info.st_dev, info.st_ino]


def namespace(directory, name):
    vm.require(name in {"user", "mnt"}, "host-view-namespace-name")
    # Namespace entries are intentional nsfs handles, not generic path inputs.
    return os.open("ns/" + name, os.O_RDONLY, dir_fd=directory)


def overflow_ids(budget):
    result = []
    for name in ("overflowuid", "overflowgid"):
        budget.remaining()
        descriptor = os.open("/proc/sys/kernel/" + name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            raw = os.read(descriptor, 33)
            vm.require(0 < len(raw) <= 32 and not os.read(descriptor, 1), "host-view-overflow-budget")
            text = raw.decode("ascii").strip()
            vm.require(re.fullmatch(r"[0-9]{1,10}", text) and int(text) < 4294967295,
                       "host-view-overflow-schema")
            result.append(int(text))
        finally:
            os.close(descriptor)
    return result


def parse_map(text):
    rows = []
    vm.require(0 < len(text) <= 4096 and 0 < len(text.splitlines()) <= 5, "host-view-map-budget")
    for line in text.splitlines():
        values = line.split()
        vm.require(len(values) == 3 and all(re.fullmatch(r"[0-9]+", value) for value in values), "host-view-map-schema")
        inside, outside, count = map(int, values)
        vm.require(count > 0 and inside + count <= 4294967295 and outside + count <= 4294967295,
                   "host-view-map-range")
        for old_inside, old_outside, old_count in rows:
            vm.require(inside >= old_inside + old_count or old_inside >= inside + count, "host-view-map-overlap")
            vm.require(outside >= old_outside + old_count or old_outside >= outside + count, "host-view-map-overlap")
        rows.append([inside, outside, count])
    return rows


def project(host_id, mapping, overflow):
    vm.require(type(host_id) is int and host_id >= 0 and type(overflow) is int and 0 <= overflow < 4294967295,
               "host-view-projection-input")
    for inside, outside, count in mapping:
        if outside <= host_id < outside + count:
            return inside + host_id - outside
    return overflow


def status_fields(text, *, worker=False):
    wanted = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"}
    result = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in wanted:
            vm.require(name not in result, "host-view-status-duplicate")
            result[name] = value.strip()
    vm.require(set(result) == wanted, "host-view-status-incomplete")
    for name in ("Uid", "Gid"):
        values = result[name].split()
        vm.require(len(values) == 4 and all(re.fullmatch(r"[0-9]+", value) for value in values), "host-view-credential-schema")
        result[name] = [int(value) for value in values]
    groups = result["Groups"].split()
    vm.require(len(groups) <= 64 and all(re.fullmatch(r"[0-9]+", value) for value in groups), "host-view-groups-budget")
    result["Groups"] = [int(value) for value in groups]
    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        vm.require(re.fullmatch(r"[0-9a-f]{1,16}", result[name]), "host-view-capability-schema")
        result[name] = int(result[name], 16)
    for name in ("NoNewPrivs", "Seccomp", "Seccomp_filters"):
        vm.require(re.fullmatch(r"[0-9]+", result[name]), "host-view-status-number")
        result[name] = int(result[name])
    if worker:
        vm.require(all(result[name] == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                   and result["NoNewPrivs"] == 1 and result["Seccomp"] == 2 and result["Seccomp_filters"] > 0,
                   "host-view-effective-guards")
    return result


def mounts(text):
    vm.require(len(text) <= MAX_KERNEL and 0 < len(text.splitlines()) <= MAX_MOUNTS, "host-view-mount-budget")
    result = []
    seen = set()
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        vm.require(separator and len(left) >= 6 and len(right) == 3
                   and all(re.fullmatch(r"[0-9]+", value) for value in left[:2])
                   and re.fullmatch(r"[0-9]+:[0-9]+", left[2]), "host-view-mount-schema")
        vm.require(left[0] not in seen, "host-view-mount-duplicate")
        seen.add(left[0])
        # This profile supports literal ASCII path components. Escaped spaces,
        # unusual optional fields and visible ID-map indications are refused.
        vm.require(all("\\" not in value for value in (left[3], left[4]))
                   and all(re.fullmatch(r"(?:shared|master|propagate_from):[0-9]+|unbindable", value)
                           for value in left[6:]), "host-view-mount-layout-unsupported")
        result.append({"id": int(left[0]), "root": left[3], "path": left[4], "options": left[5].split(","),
                       "filesystem": right[0]})
    return result


def readonly_mount(records, path):
    choices = [record for record in records if path == record["path"] or path.startswith(record["path"].rstrip("/") + "/")]
    vm.require(bool(choices), "host-view-mount-missing")
    length = max(len(record["path"]) for record in choices)
    selected = [record for record in choices if len(record["path"]) == length]
    vm.require(len(selected) == 1 and "ro" in selected[0]["options"] and "rw" not in selected[0]["options"],
               "host-view-mount-not-readonly")
    return selected[0]


def capabilities(descriptor):
    try:
        raw = os.getxattr(descriptor, "security.capability")
    except OSError as error:
        vm.require(error.errno in (errno.ENODATA, errno.ENOTSUP), "host-view-capability-unavailable")
        raw = b""
    vm.require(not raw, "host-view-file-capabilities")
    return vm.digest(raw)


def object_record(descriptor, *, executable=False, budget=None):
    before = os.fstat(descriptor)
    vm.require(stat.S_ISREG(before.st_mode) if executable else stat.S_ISDIR(before.st_mode), "host-view-object-type")
    record = {"identity": vm.file_id(before), "type": stat.S_IFMT(before.st_mode),
              "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid}
    if executable:
        vm.require(before.st_size <= 128 * 1024**2 and before.st_mode & 0o111 and not before.st_mode & 0o6000,
                   "host-view-executable-budget")
        hasher, count = hashlib.sha256(), 0
        magic = b""
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            budget.remaining()
            block = os.read(descriptor, 65536)
            if not block:
                break
            if not magic:
                magic = block[:4]
            count += len(block)
            vm.require(count <= 128 * 1024**2, "host-view-executable-budget")
            hasher.update(block)
        vm.require(count == before.st_size and magic == b"\x7fELF", "host-view-executable-format")
        record.update({"sha256": hasher.hexdigest(), "capabilities_sha256": capabilities(descriptor)})
    vm.require(vm.file_id(os.fstat(descriptor)) == record["identity"], "host-view-object-drift")
    return record


def walk(root, path, budget, *, readonly=False):
    vm.require(isinstance(path, str) and re.fullmatch(r"/[A-Za-z0-9_./+-]+", path)
               and str(Path(path)) == path == os.path.normpath(path) and ".." not in Path(path).parts, "host-view-fixed-path")
    result, current = {}, os.dup(root)
    try:
        result["/"] = object_record(current)
        if readonly:
            vm.require(os.fstatvfs(current).f_flag & os.ST_RDONLY, "host-view-object-mount-writable")
        prefix = ""
        parts = Path(path).parts[1:]
        vm.require(0 < len(parts) <= 16, "host-view-path-budget")
        for index, component in enumerate(parts):
            budget.remaining()
            final = index == len(parts) - 1
            child = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            | (0 if final else os.O_DIRECTORY), dir_fd=current)
            os.close(current)
            current = child
            prefix += "/" + component
            result[prefix] = object_record(current, executable=final, budget=budget)
            if readonly:
                vm.require(os.fstatvfs(current).f_flag & os.ST_RDONLY, "host-view-object-mount-writable")
        return result
    finally:
        os.close(current)


def compare_object(authority, observed, *, uid_map=None, gid_map=None, overflow_uid=None, overflow_gid=None):
    expected = dict(authority)
    vm.require(authority["uid"] == 0 and not authority["mode"] & 0o022, "host-view-parent-authority")
    if uid_map is not None:
        expected["uid"] = project(authority["uid"], uid_map, overflow_uid)
        expected["gid"] = project(authority["gid"], gid_map, overflow_gid)
    vm.require(expected == observed, "host-view-object-not-equivalent")


def binding(config, config_sha, process, invocation, cgroup):
    return {"owner": config["owner"], "boot": config["boot"], "config_sha256": config_sha,
            "manifest_sha256": config["manifest_sha256"], "source_sha256": vm.digest(vm.encode(config["source"])),
            "end": config["end"], "work_end": config["work_end"], "unit": config["unit"],
            "process": process, "invocation": invocation, "cgroup": cgroup}


def typed_guards(config, budget):
    names = [*POLICY, "SystemCallFilter", "ReadWritePaths", "InaccessiblePaths"]
    timeout = str(max(1, int(min(5, budget.remaining()) * 1000000))) + "us"
    status, raw = vm.run([config["tools"]["busctl"]["path"], "--user", "--no-pager", "--timeout=" + timeout, "--json=short",
                          "get-property", "org.freedesktop.systemd1", vm.unit_object_path(config),
                          "org.freedesktop.systemd1.Service", *names], budget, config["directory"], manager=True)
    vm.require(status == 0 and len(raw.splitlines()) == len(names), "host-view-typed-guards-unavailable")
    values = {}
    for name, line in zip(names, raw.splitlines()):
        item = vm.strict_json(line)
        vm.require(type(item) is dict and set(item) == {"type", "data"}, "host-view-guard-schema")
        values[name] = item
    for name, (signature, expected) in POLICY.items():
        vm.require(values[name] == {"type": signature, "data": expected}
                   and type(values[name]["data"]) is type(expected), "host-view-constructor-policy")
    filter_value = values["SystemCallFilter"]
    vm.require(filter_value["type"] == "(bas)" and type(filter_value["data"]) is list
               and len(filter_value["data"]) == 2 and filter_value["data"][0] is False
               and type(filter_value["data"][1]) is list and sorted(filter_value["data"][1]) == sorted(DENIED),
               "host-view-syscall-policy")
    vm.require(values["ReadWritePaths"] == {"type": "as", "data": [config["directory"]]}, "host-view-write-policy")
    expected_inaccessible = [f"-/run/user/{os.getuid()}/bus", f"-/run/user/{os.getuid()}/systemd",
                             "-/run/dbus/system_bus_socket", "-/run/podman", "-/run/docker.sock"]
    vm.require(values["InaccessiblePaths"] == {"type": "as", "data": expected_inaccessible}, "host-view-socket-policy")
    return values


def manager_version(config, budget):
    timeout = str(max(1, int(min(5, budget.remaining()) * 1000000))) + "us"
    status, raw = vm.run([config["tools"]["busctl"]["path"], "--user", "--no-pager", "--timeout=" + timeout,
                          "--json=short", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                          "org.freedesktop.systemd1.Manager", "Version"], budget, config["directory"], manager=True)
    vm.require(status == 0 and vm.strict_json(raw) == {"type": "s", "data": MANAGER_VERSION},
               "host-view-manager-version")
    return MANAGER_VERSION


def directory_at(root, path, budget):
    """No intermediate symlink crossing, including the effective cgroup path."""
    current = os.dup(root)
    try:
        for component in path.split("/"):
            vm.require(re.fullmatch(r"[A-Za-z0-9_-]+", component), "host-view-directory-path")
            budget.remaining()
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


class ParentView:
    """Exact retained parent namespace authority and worker-view lease."""
    def __init__(self, config, budget):
        self.config, self.budget, self.handles = config, budget, []
        self.worker = None
        self.partial = {"schema": "kubernetes-lens-owned-host-view-partial-v1", "trust": TRUST,
                        "qualification": "incomplete"}
        try:
            vm.require(vm.admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-view-parent-tools")
            self.manager = manager_version(config, budget)
            self.kernel = {"release": os.uname().release, "machine": os.uname().machine}
            vm.require(self.kernel["machine"] == "x86_64", "host-view-native-architecture")
            self.parent_proc = self.keep(os.open("/proc/self", os.O_RDONLY | os.O_DIRECTORY))
            self.parent_ns = {name: identity(self.keep(namespace(self.parent_proc, name))) for name in ("user", "mnt")}
            vm.require(parse_map(kernel_at(self.parent_proc, "uid_map", budget)) == [[0, 0, 4294967295]]
                       and parse_map(kernel_at(self.parent_proc, "gid_map", budget)) == [[0, 0, 4294967295]],
                       "host-view-parent-map-unsupported")
            root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.objects = {}
                for tool in config["tools"].values():
                    for path, item in walk(root, tool["path"], budget).items():
                        vm.require(item["uid"] == 0 and not item["mode"] & 0o022, "host-view-parent-authority")
                        if path in self.objects:
                            vm.require(self.objects[path] == item, "host-view-parent-object-drift")
                        self.objects[path] = item
                    vm.require(self.objects[tool["path"]]["sha256"] == tool["sha256"]
                               and self.objects[tool["path"]]["identity"] == tool["file_identity"], "host-view-parent-tool-drift")
                vm.require(len(self.objects) <= MAX_OBJECTS, "host-view-object-count")
            finally:
                os.close(root)
        except BaseException:
            self.close()
            raise

    def keep(self, descriptor):
        self.handles.append(descriptor)
        vm.require(len(self.handles) <= 10, "host-view-fd-budget")
        return descriptor

    def close(self):
        for descriptor in reversed(self.handles):
            os.close(descriptor)
        self.handles.clear()

    def check_process(self, process):
        vm.require(vm.boot_id() == self.config["boot"] and vm.process_identity(process["pid"]) == process,
                   "host-view-process-drift")
        row = vm.unit_show(self.config, self.budget)
        vm.require(vm.validate_unit(row, self.config, invocation=self.invocation) == self.invocation
                   and int(row["MainPID"]) == process["pid"], "host-view-unit-drift")
        vm.require(vm.process_cgroup(process["pid"]) == self.cgroup["path"]
                   and vm.cgroup_snapshot(self.cgroup["path"], self.config) == self.cgroup, "host-view-cgroup-drift")
        for name, expected in self.parent_ns.items():
            descriptor = namespace(self.parent_proc, name)
            try:
                vm.require(identity(descriptor) == expected, "host-view-parent-namespace-drift")
            finally:
                os.close(descriptor)

    def attest(self, process, invocation, cgroup, config_sha):
        self.cgroup, self.invocation = cgroup, invocation
        self.partial.update({"binding": binding(self.config, config_sha, process, invocation, cgroup),
                             "constructor": {"manager": self.manager, "kernel": self.kernel}})
        self.check_process(process)
        self.worker = process
        self.pidfd = self.keep(os.pidfd_open(process["pid"], 0))
        proc = self.keep(os.open("/proc/" + str(process["pid"]), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        self.proc = proc
        namespaces = {}
        for name in ("user", "mnt"):
            descriptor = self.keep(namespace(proc, name))
            namespaces[name] = identity(descriptor)
            self.partial["namespaces"] = dict(namespaces)
            if name == "user" and namespaces[name] != self.parent_ns[name]:
                parent = fcntl.ioctl(descriptor, NS_GET_PARENT)
                try:
                    vm.require(identity(parent) == self.parent_ns["user"], "host-view-nested-userns-unsupported")
                finally:
                    os.close(parent)
        uid_map = parse_map(kernel_at(proc, "uid_map", self.budget))
        gid_map = parse_map(kernel_at(proc, "gid_map", self.budget))
        self.partial.update({"uid_map": uid_map, "gid_map": gid_map})
        vm.require(namespaces["user"] != self.parent_ns["user"]
                   and namespaces["mnt"] != self.parent_ns["mnt"], "host-view-private-namespace-inconsistent")
        vm.require(uid_map == [[os.getuid(), os.getuid(), 1]]
                   and gid_map == [[os.getgid(), os.getgid(), 1]],
                   "host-view-worker-map-unsupported")
        setgroups = kernel_at(proc, "setgroups", self.budget).strip()
        vm.require(setgroups == "deny", "host-view-setgroups-policy")
        status = status_fields(kernel_at(proc, "status", self.budget), worker=True)
        self.partial.update({"status": status, "setgroups": setgroups})
        vm.require(status["Uid"] == [os.getuid()] * 4 and status["Gid"] == [os.getgid()] * 4,
                   "host-view-parent-credentials")
        guards = typed_guards(self.config, self.budget)
        self.partial["guards"] = guards
        mountinfo = kernel_at(proc, "mountinfo", self.budget)
        records = mounts(mountinfo)
        self.partial["mountinfo_sha256"] = vm.digest(mountinfo.encode())
        cgroup_mount = readonly_mount(records, "/sys/fs/cgroup")
        vm.require(cgroup_mount["filesystem"] == "cgroup2" and cgroup_mount["root"] == "/",
                   "host-view-cgroup-filesystem")
        # This is the sole deliberate proc-root magic-link crossing. Every
        # subsequent fixed path component is opened relative with NOFOLLOW.
        root = self.keep(os.open("root", os.O_RDONLY | os.O_DIRECTORY, dir_fd=proc))
        self.root = root
        observed = {}
        self.partial["objects"] = observed
        for tool in self.config["tools"].values():
            for path, item in walk(root, tool["path"], self.budget, readonly=True).items():
                observed[path] = item
                compare_object(self.objects[path], item)
                readonly_mount(records, path)
        cgroup_fd = directory_at(root, "sys/fs/cgroup", self.budget)
        try:
            vm.require(os.fstatvfs(cgroup_fd).f_flag & os.ST_RDONLY, "host-view-cgroup-mount-writable")
            cgroup_root = identity(cgroup_fd)
            host_root = os.stat("/sys/fs/cgroup", follow_symlinks=False)
            vm.require(cgroup_root == [host_root.st_dev, host_root.st_ino], "host-view-cgroup-filesystem-identity")
        finally:
            os.close(cgroup_fd)
        executable = os.open("exe", os.O_RDONLY, dir_fd=proc)
        try:
            compare_object(self.objects[self.config["tools"]["python"]["path"]],
                           object_record(executable, executable=True, budget=self.budget))
        finally:
            os.close(executable)
        self.check_process(process)
        vm.require(kernel_at(proc, "mountinfo", self.budget) == mountinfo
                   and status_fields(kernel_at(proc, "status", self.budget), worker=True) == status
                   and parse_map(kernel_at(proc, "uid_map", self.budget)) == uid_map
                   and parse_map(kernel_at(proc, "gid_map", self.budget)) == gid_map
                   and typed_guards(self.config, self.budget) == guards, "host-view-observation-drift")
        for name, expected in namespaces.items():
            descriptor = namespace(proc, name)
            try:
                vm.require(identity(descriptor) == expected, "host-view-worker-namespace-drift")
            finally:
                os.close(descriptor)
        overflow = overflow_ids(self.budget)
        frame = {"schema": "kubernetes-lens-owned-host-view-v1", "trust": TRUST, "nonce": uuid.uuid4().hex,
                 "binding": binding(self.config, config_sha, process, invocation, cgroup),
                 "namespaces": namespaces, "uid_map": uid_map, "gid_map": gid_map, "setgroups": setgroups,
                 "status": status, "constructor": {"manager": self.manager, "kernel": self.kernel}, "mountinfo_sha256": vm.digest(mountinfo.encode()), "objects": observed,
                 "overflow": overflow, "guards": guards, "cgroup_root": cgroup_root}
        vm.require(len(vm.encode(frame)) <= vm.META_MAX, "host-view-frame-budget")
        self.frame, self.mountinfo = frame, mountinfo
        return frame

    def recheck(self):
        """Final outside-authority check immediately before authenticated GO."""
        self.check_process(self.worker)
        vm.require(manager_version(self.config, self.budget) == self.manager, "host-view-manager-drift")
        vm.require(vm.admit_tools(self.config["manifest"], self.config["manifest_sha256"]) == self.config["tools"],
                   "host-view-parent-tools-drift")
        for name, expected in self.frame["namespaces"].items():
            descriptor = namespace(self.proc, name)
            try:
                vm.require(identity(descriptor) == expected, "host-view-final-namespace-drift")
            finally:
                os.close(descriptor)
        vm.require(kernel_at(self.proc, "mountinfo", self.budget) == self.mountinfo
                   and parse_map(kernel_at(self.proc, "uid_map", self.budget)) == self.frame["uid_map"]
                   and parse_map(kernel_at(self.proc, "gid_map", self.budget)) == self.frame["gid_map"]
                   and kernel_at(self.proc, "setgroups", self.budget).strip() == self.frame["setgroups"]
                   and status_fields(kernel_at(self.proc, "status", self.budget), worker=True) == self.frame["status"]
                   and typed_guards(self.config, self.budget) == self.frame["guards"], "host-view-final-observation-drift")
        for tool in self.config["tools"].values():
            for path, item in walk(self.root, tool["path"], self.budget, readonly=True).items():
                compare_object(self.objects[path], item)
        descriptor = directory_at(self.root, "sys/fs/cgroup", self.budget)
        try:
            vm.require(os.fstatvfs(descriptor).f_flag & os.ST_RDONLY
                       and identity(descriptor) == self.frame["cgroup_root"], "host-view-final-cgroup-writable")
        finally:
            os.close(descriptor)
        self.check_process(self.worker)


def validate_local(frame, config, budget):
    expected_keys = {"schema", "trust", "nonce", "binding", "namespaces", "uid_map", "gid_map", "setgroups",
                     "status", "constructor", "mountinfo_sha256", "objects", "overflow", "guards", "cgroup_root"}
    vm.require(type(frame) is dict and set(frame) == expected_keys
               and frame["schema"] == "kubernetes-lens-owned-host-view-v1" and frame["trust"] == TRUST
               and re.fullmatch(r"[0-9a-f]{32}", frame["nonce"]), "host-view-frame-schema")
    vm.require(frame["constructor"] == {"manager": MANAGER_VERSION,
               "kernel": {"release": os.uname().release, "machine": os.uname().machine}}
               and set(frame["namespaces"]) == {"user", "mnt"}, "host-view-constructor-drift")
    process = vm.process_identity(os.getpid())
    expected = binding(config, vm.digest(vm.encode(config)), process, os.environ.get("INVOCATION_ID"),
                       vm.cgroup_snapshot(vm.process_cgroup(os.getpid()), config))
    vm.require(frame["binding"] == expected and vm.boot_id() == config["boot"], "host-view-frame-binding")
    proc = os.open("/proc/self", os.O_RDONLY | os.O_DIRECTORY)
    root = None
    try:
        for name, expected_ns in frame["namespaces"].items():
            descriptor = namespace(proc, name)
            try:
                vm.require(identity(descriptor) == expected_ns, "host-view-local-namespace-drift")
            finally:
                os.close(descriptor)
        # Parent-opened and self maps agree only under this explicitly proved
        # immediate-parent profile; same/nested layouts are not fallbacks.
        vm.require(parse_map(kernel_at(proc, "uid_map", budget)) == frame["uid_map"]
                   and parse_map(kernel_at(proc, "gid_map", budget)) == frame["gid_map"]
                   and kernel_at(proc, "setgroups", budget).strip() == frame["setgroups"], "host-view-local-map-drift")
        status = status_fields(kernel_at(proc, "status", budget), worker=True)
        projected = dict(frame["status"])
        projected["Uid"] = [project(value, frame["uid_map"], frame["overflow"][0]) for value in projected["Uid"]]
        projected["Gid"] = [project(value, frame["gid_map"], frame["overflow"][1]) for value in projected["Gid"]]
        projected["Groups"] = [project(value, frame["gid_map"], frame["overflow"][1]) for value in projected["Groups"]]
        vm.require(status == projected, "host-view-local-credentials-drift")
        mountinfo = kernel_at(proc, "mountinfo", budget)
        vm.require(vm.digest(mountinfo.encode()) == frame["mountinfo_sha256"], "host-view-local-mount-drift")
        records = mounts(mountinfo)
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        observed = {}
        for tool in config["tools"].values():
            for path, item in walk(root, tool["path"], budget, readonly=True).items():
                vm.require(path in frame["objects"], "host-view-local-object-unknown")
                compare_object(frame["objects"][path], item, uid_map=frame["uid_map"], gid_map=frame["gid_map"],
                               overflow_uid=frame["overflow"][0], overflow_gid=frame["overflow"][1])
                readonly_mount(records, path)
                observed[path] = item
        vm.require(set(observed) == set(frame["objects"]), "host-view-local-object-incomplete")
        descriptor = directory_at(root, "sys/fs/cgroup", budget)
        try:
            cgroup_mount = readonly_mount(records, "/sys/fs/cgroup")
            vm.require(cgroup_mount["filesystem"] == "cgroup2" and cgroup_mount["root"] == "/"
                       and identity(descriptor) == frame["cgroup_root"], "host-view-local-cgroup-filesystem")
            vm.require(os.fstatvfs(descriptor).f_flag & os.ST_RDONLY, "host-view-local-cgroup-writable")
        finally:
            os.close(descriptor)
        vm.require(vm.digest(kernel_at(proc, "mountinfo", budget).encode()) == frame["mountinfo_sha256"]
                   and vm.process_identity(os.getpid()) == process, "host-view-local-observation-drift")
    finally:
        if root is not None:
            os.close(root)
        os.close(proc)
