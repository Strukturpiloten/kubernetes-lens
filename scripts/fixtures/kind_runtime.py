#!/usr/bin/env python3
"""Explicit external, disposable kind-on-Podman readiness; never library acquisition.

The internal provider accepts only the fixed kind profiles' finite command surface.
All operational identities come from the existing capability ledger or explicit inputs.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
import unittest
import uuid

LEDGER = Path(__file__).resolve().parents[2] / "schemas/capabilities/kubernetes-1.20-1.37.json"
LABEL = "io.kubernetes-lens.issue2.owner"
PREFIX = "kubernetes-lens-issue2-"
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_BINARY = 128 * 1024 * 1024
MAX_METADATA = 32 * 1024 * 1024
CANCELLED = 0
REQUIRED_HELPERS = frozenset({"newuidmap", "newgidmap", "crun", "conmon", "netavark", "aardvark-dns", "pasta", "rootlessport"})
OPTIONAL_HELPERS = frozenset({"catatonit", "iptables", "ip6tables", "nft"})


class Refusal(Exception):
    def __init__(self, code, state="failed"):
        super().__init__(code)
        self.code, self.state = code, state


def require(value, code, state="failed"):
    if not value:
        raise Refusal(code, state)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, limit, admit=None, account=None):
    admit = (lambda: None) if admit is None else admit
    admit()
    path = Path(path)
    require(path.is_absolute(), "absolute-path-required", "unavailable")
    path = _metadata_path(path)
    # Each lstat/open/fstat is one metadata event; content reads retain their byte window.
    for part in [path, *path.parents]:
        require(not _metadata_access(part.is_symlink, admit=admit, account=account), "symlink-input", "unavailable")
    fd = _metadata_access(os.open, path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          admit=admit, account=account)
    try:
        info = _metadata_access(os.fstat, fd, admit=admit, account=account)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "file-budget", "unavailable")
        data = bytearray()
        while len(data) <= limit:
            admit()
            block = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
            admit()
            if not block:
                break
            data.extend(block)
        require(len(data) == info.st_size, "file-changed", "unavailable")
        admit()
        return bytes(data)
    finally:
        os.close(fd)

def read_json(path):
    return json.loads(regular(path, MAX_METADATA))


def write_json(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    temporary = Path(str(path) + ".new." + str(os.getpid()) + "." + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def secure_host_path(path):
    """Host helpers stay privileged where necessary, without writable PATH ancestors."""
    require(Path(path).is_absolute(), "helper-absolute-path-required", "unavailable")
    for part in [Path(path), *Path(path).parents]:
        require(not part.is_symlink(), "helper-canonical-path-required", "unavailable")
        info = part.stat()
        require(info.st_uid == 0 and not (info.st_mode & 0o022), "helper-host-path-writable", "unavailable")


def helper_capability(path):
    try:
        return sha(os.getxattr(path, "security.capability", follow_symlinks=False))
    except OSError as error:
        require(error.errno in {errno.ENODATA, errno.ENOTSUP}, "helper-capability-unavailable", "unavailable")
        return sha(b"")


def helper_file_identity(expected):
    path = Path(expected["path"])
    secure_host_path(path)
    before = path.stat()
    data = regular(path, MAX_BINARY)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "helper-changed-during-authentication", "unavailable")
    require(data.startswith(b"\x7fELF") and after.st_mode & 0o111, "helper-native-executable-required", "unavailable")
    observed = {"path": str(path), "sha256": sha(data), "bytes": len(data), "uid": after.st_uid, "gid": after.st_gid,
                "mode": f"{stat.S_IMODE(after.st_mode):04o}", "capability_sha256": helper_capability(path)}
    require(all(observed[key] == expected[key] for key in observed), "helper-identity-drift", "unavailable")
    return {**observed, "device": after.st_dev, "inode": after.st_ino}


def load_helper_closure(path, expected_sha256):
    raw = regular(path, 64 * 1024)
    require(isinstance(expected_sha256, str) and HEX.fullmatch(expected_sha256) and sha(raw) == expected_sha256,
            "helper-manifest-integrity", "unavailable")
    document = json.loads(raw)
    require(set(document) == {"schema", "helpers"} and document["schema"] == "podman-host-helper-closure-v1"
            and isinstance(document["helpers"], dict), "helper-manifest-schema", "unavailable")
    supplied = document["helpers"]
    require(REQUIRED_HELPERS <= set(supplied) <= REQUIRED_HELPERS | OPTIONAL_HELPERS, "helper-catalogue", "unavailable")
    identities = {}
    for name, record in supplied.items():
        require(isinstance(record, dict) and set(record) == {"path", "sha256", "bytes", "uid", "gid", "mode", "capability_sha256"}, "helper-record-schema", "unavailable")
        require(type(record["uid"]) is int and record["uid"] == 0 and type(record["gid"]) is int and record["gid"] >= 0
                and type(record["bytes"]) is int and 0 < record["bytes"] <= MAX_BINARY
                and isinstance(record["mode"], str) and re.fullmatch(r"[0-7]{4}", record["mode"])
                and isinstance(record["sha256"], str) and HEX.fullmatch(record["sha256"])
                and isinstance(record["capability_sha256"], str) and HEX.fullmatch(record["capability_sha256"]), "helper-record-identity", "unavailable")
        identities[name] = helper_file_identity(record)
    return {"manifest_sha256": expected_sha256, "helpers": identities}


def install_helper_links(directory, closure):
    for name, item in closure["helpers"].items():
        for subdirectory in ["bin", "helpers"]:
            (directory / subdirectory / name).symlink_to(item["path"])


def authenticate_helpers(policy):
    closure = policy["helper_closure"]
    directory = Path(policy["directory"])
    for name, item in closure["helpers"].items():
        observed = helper_file_identity(item)
        require(observed == item, "helper-host-inode-drift", "unavailable")
        for subdirectory in ["bin", "helpers"]:
            link = directory / subdirectory / name
            require(link.is_symlink() and os.readlink(link) == item["path"], "helper-private-link-drift", "unavailable")
    for name, expected in policy["configuration_sha256"].items():
        require(sha(regular(directory / name, 64 * 1024)) == expected, "private-configuration-drift", "unavailable")
    # These system defaults can otherwise inject host bind mounts, including credentials.
    for path in [Path("/etc/containers/mounts.conf"), Path("/usr/share/containers/mounts.conf")]:
        if path.exists():
            require(all(not line.strip() or line.lstrip().startswith("#") for line in regular(path, 64 * 1024).decode("utf-8").splitlines()),
                    "implicit-host-mounts-refused", "unavailable")


def select_profile(ledger, profile_id, owner_bytes):
    profiles = [p for p in ledger["runtime_profiles"] if p["id"] == profile_id]
    require(len(profiles) == 1, "unknown-runtime-profile", "unavailable")
    profile = profiles[0]
    require(re.fullmatch(r"kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}", profile["node_image"]), "unpinned-image", "unavailable")
    tools = {}
    for name in ["kind", "kubectl"]:
        selected = [p for p in ledger["tool_profiles"] if p["id"] == profile[name + "_profile"]]
        require(len(selected) == 1, "unknown-tool-profile", "unavailable")
        item = selected[0]
        if "sha256" in item:
            require(item["platform"] == "linux-amd64", "tool-platform", "unavailable")
            expected = item["sha256"]
        else:
            owner = ledger["canonical_tool_owner"]
            require(owner_bytes is not None and sha(owner_bytes) == owner["sha256"], "canonical-owner-integrity", "unavailable")
            text = owner_bytes.decode("utf-8")
            versions = re.findall(r'^readonly ' + re.escape(item["version_variable"]) + r'="([0-9.]+)"$', text, re.M)
            require(versions == [item["version"]], "canonical-owner-version", "unavailable")
            blocks = re.findall(r"  x86_64\)(.*?)    ;;", text, re.S)
            require(len(blocks) == 1, "canonical-owner-architecture", "unavailable")
            checksums = re.findall(r'    readonly ' + name + r'_checksum="([0-9a-f]{64})"', blocks[0])
            require(len(checksums) == 1, "canonical-owner-checksum", "unavailable")
            expected = checksums[0]
        require(HEX.fullmatch(expected), "tool-checksum", "unavailable")
        tools[name] = {"version": item["version"], "sha256": expected}
    return profile, tools


def limits_valid(limits):
    require(300 <= limits["seconds"] <= 1800 and 60 <= limits["cleanup_seconds"] <= 300
            and limits["cleanup_seconds"] * 2 < limits["seconds"], "deadline-budget", "unavailable")
    require(1 <= limits["cpus"] <= 8 and 2 * 1024**3 <= limits["memory_bytes"] <= 16 * 1024**3
            and 1024 <= limits["pids"] <= 65536 and limits["nodes"] == 1, "resource-budget", "unavailable")
    require(8 * 1024**3 <= limits["store_bytes"] <= 32 * 1024**3
            and 65536 <= limits["output_bytes"] <= 16 * 1024**2
            and 16 <= limits["commands"] <= 512, "io-budget", "unavailable")


def cgroup_limits(path, limits, current_text=None):
    path = Path(path)
    require(path.is_absolute() and str(path).startswith("/sys/fs/cgroup/") and path.name.endswith(".slice")
            and path.name.startswith(PREFIX), "task-slice-required", "unavailable")
    for part in [path, *path.parents]:
        require(not part.is_symlink(), "cgroup-symlink", "unavailable")
    current_text = Path("/proc/self/cgroup").read_text() if current_text is None else current_text
    values = [line[3:] for line in current_text.splitlines() if line.startswith("0::")]
    relative = "/" + str(path.relative_to("/sys/fs/cgroup"))
    require(len(values) == 1 and (values[0] == relative or values[0].startswith(relative + "/")), "caller-outside-task-slice", "unavailable")
    try:
        memory = int((path / "memory.max").read_text())
        pids = int((path / "pids.max").read_text())
        swap = int((path / "memory.swap.max").read_text())
        quota, period = map(int, (path / "cpu.max").read_text().split())
    except (OSError, ValueError) as error:
        raise Refusal("finite-cgroup-limits-required", "unavailable") from error
    require(0 < memory <= limits["memory_bytes"] and 0 < pids <= limits["pids"] and swap == 0
            and period > 0 and 0 < quota <= limits["cpus"] * period, "cgroup-cap-mismatch", "unavailable")
    require({"cpu", "memory", "pids"} <= set((path / "cgroup.controllers").read_text().split()), "cgroup-delegation-required", "unavailable")
    return {"memory": memory, "pids": pids, "cpu": [quota, period], "swap": swap}


METADATA_PATH_PARTS = 64


def _metadata_path(path):
    path = Path(path)
    require(path.is_absolute() and len(path.parts) <= METADATA_PATH_PARTS,
            'retirement-metadata-path-depth', 'unavailable')
    return path


def _metadata_access(function, *args, admit=None, account=None, **kwargs):
    """Debit 256 surface accounting bytes per admitted metadata operation.

    This interface debit is not physical filesystem I/O, Python heap usage,
    native source Work or a claim about kernel metadata representation size.
    """
    check = admit if admit is not None else (lambda: None)
    charge = account if account is not None else (lambda _amount: None)
    check()
    charge(256)
    check()
    try:
        return function(*args, **kwargs)
    finally:
        check()


def store_limit(path, maximum, admit=None, account=None, maximum_accesses=None):
    """Measured store budget, explicitly not a filesystem quota.

    Controller callers supply original-time admission and cumulative credit.
    Pure/native callers retain the same measurement without a controller meter.
    """
    check = admit if admit is not None else (lambda: None)
    charge = account if account is not None else (lambda _amount: None)

    accesses = 0
    def access(function, *args, **kwargs):
        nonlocal accesses
        check()
        require(maximum_accesses is None or accesses < maximum_accesses, 'retirement-store-metadata-window')
        accesses += 1
        return _metadata_access(function, *args, admit=check, account=charge, **kwargs)

    check()
    root = _metadata_path(path)
    require(not any(access(part.is_symlink) for part in [root, *root.parents]), "store-symlink", "unavailable")
    require(root.is_absolute() and access(root.is_dir) and not access(root.is_symlink), "private-store-required", "unavailable")
    require(access(root.stat).st_uid == os.geteuid() and stat.S_IMODE(access(root.stat).st_mode) == 0o700, "private-store-mode-required", "unavailable")
    total, entries, pending = 0, 0, [root]
    while pending:
        directory = _metadata_path(pending.pop())
        iterator = access(os.scandir, directory)
        try:
            while True:
                try:
                    entry = access(next, iterator)
                except StopIteration:
                    break
                _metadata_path(entry.path)
                info = access(entry.stat, follow_symlinks=False)
                entries += 1
                total += info.st_blocks * 512
                require(entries <= 250000 and total <= maximum, "measured-store-budget")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
        finally:
            # Descriptor release consumes no new metadata or publication credit.
            iterator.close()
        check()
    free = access(os.statvfs, root)
    require(free.f_bavail * free.f_frsize >= min(maximum, 1024**3), "store-free-space", "unavailable")
    check()
    return {"allocated_bytes": total, "entries": entries, "disk_enforcement": "measured-not-quota"}


def image_reference(profile):
    return "docker.io/kindest/node@" + profile["node_image"].split("@", 1)[1]


def image_identity(profile, rows):
    require(isinstance(rows, list) and len(rows) == 1, "image-inspect-count")
    row = rows[0]
    require(image_reference(profile) in row.get("RepoDigests", []) and row.get("Architecture") == "amd64"
            and row.get("Os") == "linux", "profile-image-digest-or-platform-mismatch")
    identity = row.get("Id", "").removeprefix("sha256:")
    require(HEX.fullmatch(identity), "image-id-required")
    return identity


def check_cancel():
    require(not CANCELLED, "cancelled")
    if PROXY_CONTROL is not None:
        with selectors.PollSelector() as selector:
            selector.register(PROXY_CONTROL, selectors.EVENT_READ)
            if selector.select(0):
                require(os.read(PROXY_CONTROL, 1), "provider-parent-cancelled")
        record = state_read(PROXY_POLICY).get("proxies", {}).get(PROXY_LEASE)
        require(isinstance(record, dict) and not record.get("cancel"), "provider-parent-cancelled")


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**3, 8 * 1024**3))
    _soft, inherited_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    hard = 524288 if inherited_hard == resource.RLIM_INFINITY else min(524288, inherited_hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))


def cleanup_end(policy):
    return policy["end"] - policy.get("retirement", {}).get("finalization_seconds", 0)


class Budget:
    """A single original monotonic end, including setup and reserved cleanup."""
    def __init__(self, policy, cleanup=False, clock=time.monotonic):
        self.policy, self.cleanup, self.clock = policy, cleanup, clock

    def remaining(self):
        end = cleanup_end(self.policy) if self.cleanup else self.policy["end"] - self.policy["limits"]["cleanup_seconds"]
        value = end - self.clock()
        require(value > 0, "cleanup-deadline" if self.cleanup else "operation-deadline")
        return value


def live_group(group, proc_root=Path("/proc")):
    members, charged = [], 0
    for entry in proc_root.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # A zombie thread-group leader does not prove all its threads retired.
            for task in (entry / "task").iterdir():
                if not task.name.isdecimal():
                    continue
                charged += 1
                require(charged <= 250000, "process-census-budget")
                try:
                    text = (task / "stat").read_text()
                    fields = text[text.rfind(")") + 2:].split()
                    if len(fields) >= 3 and int(fields[2]) == group and fields[0] != "Z":
                        members.append(int(task.name))
                except (FileNotFoundError, ProcessLookupError):
                    continue
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


class DuplexBuffers:
    """Finite byte queues independent of process lifetime and OS readiness ordering."""
    def __init__(self, maximum, interactive=False, forward=False, charge=None):
        self.maximum, self.charge = maximum, charge
        self.input_total = self.output_total = 0
        self.input_eof = not interactive
        self.output_eof = [False, False]
        self.input_pending = bytearray()
        self.output_pending = [bytearray(), bytearray()]
        self.captured = [bytearray(), bytearray()]
        self.forward = forward

    def input(self, data):
        require(not self.input_eof and len(self.input_pending) + len(data) <= 65536, "stdin-pending-budget")
        require(self.input_total + len(data) <= self.maximum, "subprocess-input-budget")
        if self.charge and data:
            self.charge("input", len(data))
        self.input_total += len(data)
        self.input_pending.extend(data)
        if not data:
            self.input_eof = True

    def output(self, channel, data):
        require(channel in [0, 1] and not self.output_eof[channel], "output-after-eof")
        require(self.output_total + len(data) <= self.maximum, "subprocess-output-budget")
        require(not self.forward or len(self.output_pending[channel]) + len(data) <= 65536, "output-pending-budget")
        if self.charge and data:
            self.charge("output", len(data))
        self.output_total += len(data)
        self.captured[channel].extend(data)
        if self.forward:
            self.output_pending[channel].extend(data)
        if not data:
            self.output_eof[channel] = True

    def sent_input(self, count):
        require(0 < count <= len(self.input_pending), "stdin-write-progress")
        del self.input_pending[:count]

    def sent_output(self, channel, count):
        require(0 < count <= len(self.output_pending[channel]), "stdout-write-progress")
        del self.output_pending[channel][:count]


def pump_child(process, budget, maximum, io_spec, charge):
    """Forward both directions before EOF, with bounded queues and backpressure."""
    source = io_spec.get("stdin_fd")
    targets = [io_spec["stdout_fd"], io_spec["stderr_fd"]]
    buffers = DuplexBuffers(maximum, interactive=source is not None, forward=True, charge=charge)
    pipes = [process.stdout, process.stderr]
    changed = {}
    input_closed = source is None
    descriptors = [*targets, *[p.fileno() for p in pipes]]
    if source is not None:
        descriptors.extend([source, process.stdin.fileno()])
    try:
        for descriptor in set(descriptors):
            changed[descriptor] = os.get_blocking(descriptor)
            os.set_blocking(descriptor, False)
        with selectors.PollSelector() as selector:
            while True:
                check_cancel()
                remaining = budget.remaining()
                if source is not None and buffers.input_eof and not buffers.input_pending and not input_closed:
                    process.stdin.close()  # EOF only after every queued byte was delivered.
                    input_closed = True
                wanted = {}
                for channel, pipe in enumerate(pipes):
                    if not buffers.output_eof[channel] and len(buffers.output_pending[channel]) < 65536:
                        wanted[pipe.fileno()] = (selectors.EVENT_READ, ("output", channel))
                    if buffers.output_pending[channel]:
                        wanted[targets[channel]] = (selectors.EVENT_WRITE, ("forward", channel))
                if source is not None and not input_closed:
                    if not buffers.input_eof and len(buffers.input_pending) < 65536:
                        wanted[source] = (selectors.EVENT_READ, ("input", 0))
                    if buffers.input_pending:
                        wanted[process.stdin.fileno()] = (selectors.EVENT_WRITE, ("deliver", 0))
                for descriptor in list(selector.get_map()):
                    if descriptor not in wanted:
                        selector.unregister(descriptor)
                for descriptor, (event, tag) in wanted.items():
                    if descriptor not in selector.get_map():
                        selector.register(descriptor, event, tag)
                    else:
                        selector.modify(descriptor, event, tag)
                if not wanted:
                    break
                for key, _event in selector.select(min(0.1, remaining)):
                    action, channel = key.data
                    try:
                        if action == "input":
                            buffers.input(os.read(key.fd, min(65536, 65536 - len(buffers.input_pending))))
                        elif action == "output":
                            buffers.output(channel, os.read(key.fd, min(65536, 65536 - len(buffers.output_pending[channel]))))
                        elif action == "deliver":
                            buffers.sent_input(os.write(key.fd, buffers.input_pending))
                        else:
                            buffers.sent_output(channel, os.write(key.fd, buffers.output_pending[channel]))
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError as error:
                        raise Refusal("stdin-not-consumed" if action == "deliver" else "forwarding-consumer-closed") from error
        return bytes(buffers.captured[0]), bytes(buffers.captured[1]), buffers.input_total
    finally:
        for descriptor, blocking in changed.items():
            try:
                os.set_blocking(descriptor, blocking)
            except OSError:
                pass


PROXY_CONTROL = None
PROXY_POLICY = None
PROXY_LEASE = None


def process_identity(pid, proc_root=Path("/proc")):
    text = (proc_root / str(pid) / "stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    require(len(fields) >= 20, "process-identity-unavailable")
    return {"pid": pid, "group": int(fields[2]), "session": int(fields[3]), "start": int(fields[19])}


def register_proxy(policy, process, nonce):
    identity = process_identity(process.pid)
    require(identity["group"] == process.pid and identity["session"] == process.pid, "proxy-private-session-required")
    with state_lock(policy):
        state = state_read(policy)
        proxies = state.setdefault("proxies", {})
        require(nonce not in proxies and len(proxies) < policy["limits"]["commands"], "proxy-lease-budget")
        proxies[nonce] = {**identity, "cancel": False, "retired": False}
        state_write(policy, state)


def await_proxy_gate(policy, nonce, descriptor):
    # No native effect precedes this one-byte gate. EOF before registration grants nothing.
    with selectors.PollSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        require(selector.select(min(2, Budget(policy).remaining())), "proxy-gate-timeout")
        require(os.read(descriptor, 1) == b"G", "proxy-gate-closed")
    record = state_read(policy).get("proxies", {}).get(nonce)
    require(isinstance(record, dict) and all(record.get(key) == value for key, value in process_identity(os.getpid()).items()), "proxy-lease-identity-drift")


def finish_proxy(policy, nonce):
    with state_lock(policy):
        state = state_read(policy)
        record = state.get("proxies", {}).get(nonce)
        if record is not None:
            require(all(record.get(key) == value for key, value in process_identity(os.getpid()).items()), "proxy-lease-identity-drift")
            record["retired"] = not state.get("retirement_unproved", False)
            state_write(policy, state)


def provider_front(policy_path, expected, arguments):
    raw = regular(Path(policy_path), MAX_METADATA)
    require(sha(raw) == expected, "provider-policy-integrity")
    policy = json.loads(raw)
    require(sha(regular(Path(__file__).resolve(), MAX_METADATA)) == policy["source_sha256"], "provider-source-integrity")
    read_fd, write_fd = os.pipe()
    nonce = uuid.uuid4().hex
    process = None
    try:
        # Backend inherits the exact kind pipes. Front death closes only the control writer.
        process = subprocess.Popen(["/usr/bin/python3", str(Path(__file__).resolve()), "--podman-proxy", policy_path,
                                    expected, str(read_fd), nonce, *arguments],
                                   stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, env=policy["environment"],
                                   cwd=policy["environment"]["HOME"], pass_fds=(read_fd,), start_new_session=True, preexec_fn=child_limits)
        os.close(read_fd)
        read_fd = None
        register_proxy(policy, process, nonce)
        os.write(write_fd, b"G")
        return process.wait(timeout=Budget(policy).remaining())
    finally:
        if read_fd is not None:
            os.close(read_fd)
        os.close(write_fd)
        # Do not kill a backend that may own child sessions: control EOF requests retirement.
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=min(2, max(0.01, policy["end"] - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass  # Active manifest lease makes the controller quarantine, never pass cleanup.


def retire_proxies(policy, clock=time.monotonic, sleep=time.sleep):
    with state_lock(policy):
        state = state_read(policy)
        for record in state.get("proxies", {}).values():
            if not record.get("retired"):
                record["cancel"] = True
        state_write(policy, state)
    end = min(cleanup_end(policy), clock() + 5)
    while True:
        pending = [record for record in state_read(policy).get("proxies", {}).values() if not record.get("retired")]
        if not pending:
            return []
        if clock() >= end:
            break
        for record in pending:
            try:
                observed = process_identity(record["pid"])
                require(all(observed.get(key) == record.get(key) for key in observed), "proxy-identity-drift")
            except (OSError, Refusal):
                with state_lock(policy):
                    state = state_read(policy)
                    state["retirement_unproved"] = True
                    state_write(policy, state)
                return ["proxy-retirement-unproved"]
        sleep(min(0.05, max(0, end - clock())))
    with state_lock(policy):
        state = state_read(policy)
        state["retirement_unproved"] = True
        state_write(policy, state)
    return ["proxy-retirement-unproved"]


def bounded_run(argv, env, budget, maximum, new_session=True, io_spec=None, charge=None):
    """Retain the unreaped group leader until bounded group retirement is proved."""
    if not budget.cleanup:
        check_cancel()
    budget.remaining()
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "sigchld-default-required", "unavailable")
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if io_spec and io_spec.get("stdin_fd") is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, cwd=env["HOME"], start_new_session=new_session, preexec_fn=child_limits)
    chunks, failure = [bytearray(), bytearray()], None
    try:
        if io_spec:
            out, err, input_count = pump_child(process, budget, maximum, io_spec, charge)
            chunks = [bytearray(out), bytearray(err)]
            io_spec["input_bytes"] = input_count
        else:
            with selectors.DefaultSelector() as selector:
                for index, pipe in enumerate([process.stdout, process.stderr]):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, index)
                while selector.get_map():
                    if not budget.cleanup:
                        check_cancel()
                    remaining = budget.remaining()
                    for key, _ in selector.select(min(0.1, remaining)):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        else:
                            if charge:
                                charge("output", len(data))
                            chunks[key.data].extend(data)
                            require(sum(map(len, chunks)) <= maximum, "subprocess-output-budget")
        result = None
        while result is None:
            if not budget.cleanup:
                check_cancel()
            budget.remaining()
            result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is None:
                time.sleep(min(0.01, budget.remaining()))
        status = result.si_status if result.si_code == os.CLD_EXITED else -result.si_status
        return status, bytes(chunks[0]), bytes(chunks[1])
    except BaseException as caught:
        failure = caught
        raise
    finally:
        retired = True
        try:
            if new_session:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                end = min(time.monotonic() + 2, budget.policy["end"])
                while live_group(process.pid) and time.monotonic() < end:
                    time.sleep(0.01)
                retired = not live_group(process.pid)
            else:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            if retired:
                process.wait(timeout=min(2, max(0.01, budget.policy["end"] - time.monotonic())))
        except (OSError, Refusal, subprocess.TimeoutExpired):
            retired = False
        for pipe in [process.stdout, process.stderr, getattr(process, "stdin", None)]:
            if pipe is not None:
                pipe.close()
        if not retired:
            if failure is not None:
                failure.retirement_unproved = True
            else:
                error = Refusal("child-retirement-unproved")
                error.retirement_unproved = True
                raise error


@contextmanager
def state_lock(policy):
    fd = os.open(Path(policy["directory"]) / "lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def state_read(policy):
    value = read_json(Path(policy["directory"]) / "ownership.json")
    require(value["owner"] == policy["owner"] and value["cluster"] == policy["cluster"], "ownership-manifest-drift")
    return value


def state_write(policy, state):
    write_json(Path(policy["directory"]) / "ownership.json", state)


def authenticate_tool(policy, name):
    item = policy["tools"][name]
    require(sha(regular(item["path"], MAX_BINARY)) == item["sha256"], "tool-integrity-drift")
    return item["path"]


def tool(policy, name, arguments, cleanup=False, session=True, io_spec=None):
    budget = Budget(policy, cleanup)
    budget.remaining()
    cgroup_limits(policy["cgroup"], policy["limits"])
    authenticate_helpers(policy)
    store_limit(policy["store"], _worker_store_limit(policy))
    info = Path(policy["store"]).stat()
    require([info.st_dev, info.st_ino] == policy["store_identity"], "store-identity-drift")
    with state_lock(policy):
        state = state_read(policy)
        state["commands"] += 1
        ceiling = policy["limits"]["commands"] + (32 if cleanup else 0)
        require(state["commands"] <= ceiling, "command-budget")
        maximum = (1024 * 1024 if cleanup else policy["limits"]["output_bytes"]) - state["cleanup_output" if cleanup else "output"]
        require(maximum > 0, "aggregate-output-budget")
        state_write(policy, state)
    argv = [authenticate_tool(policy, name), *arguments]
    if name == "podman":
        argv = [argv[0], "--root", str(Path(policy["store"]) / "graph"), "--runroot", str(Path(policy["store"]) / "run"),
                "--storage-driver", "vfs", "--cgroup-manager", "systemd",
                "--runtime", policy["helper_closure"]["helpers"]["crun"]["path"],
                "--conmon", policy["helper_closure"]["helpers"]["conmon"]["path"],
                "--hooks-dir", str(Path(policy["directory"]) / "hooks"), *arguments]
    def charge(direction, count):
        with state_lock(policy):
            state = state_read(policy)
            key = "input" if direction == "input" else "cleanup_output" if cleanup else "output"
            ceiling = 1024 * 1024 if cleanup else policy["limits"]["output_bytes"]
            require(state.get(key, 0) + count <= ceiling, "aggregate-" + direction + "-budget")
            state[key] = state.get(key, 0) + count
            state_write(policy, state)
    try:
        # Every actual child has a private session, including children of streaming backends.
        status, out, err = bounded_run(argv, policy["environment"], budget, min(maximum, 1024 * 1024), True, io_spec, charge)
    except BaseException as caught:
        if getattr(caught, "retirement_unproved", False):
            with state_lock(policy):
                state = state_read(policy)
                state["retirement_unproved"] = True
                state_write(policy, state)
        raise
    with state_lock(policy):
        state = state_read(policy)
        key = "cleanup_output" if cleanup else "output"
        state.setdefault("results", []).append({"tool": name, "status": status, "stdout_bytes": len(out), "stderr_bytes": len(err), "stdout_sha256": sha(out), "stderr_sha256": sha(err), "stdin_bytes": io_spec.get("input_bytes", 0) if io_spec else 0})
        require(state[key] <= (1024 * 1024 if cleanup else policy["limits"]["output_bytes"]), "aggregate-output-budget")
        state_write(policy, state)
    return status, out, err


def checked(policy, name, arguments, cleanup=False, session=True):
    status, out, _ = tool(policy, name, arguments, cleanup, session)
    require(status == 0, "tool-nonzero-" + name + "-" + str(status))
    return out


def json_command(policy, args, cleanup=False, session=True):
    try:
        return json.loads(checked(policy, "podman", args, cleanup, session))
    except (UnicodeError, ValueError) as error:
        raise Refusal("invalid-podman-json") from error


def inspect_owned(policy, kind, identity, cleanup=False, session=True):
    require(HEX.fullmatch(identity) is not None if kind != "volume" else identity == policy["volume"], "invalid-owned-id")
    rows = json_command(policy, [kind, "inspect", identity], cleanup, session)
    require(isinstance(rows, list) and len(rows) == 1, "ownership-inspect-count")
    row = rows[0]
    labels = row.get("Config", {}).get("Labels", {}) if kind == "container" else row.get("Labels", row.get("labels", {}))
    actual = row.get("Id", row.get("ID", row.get("id", row.get("Name"))))
    require(actual == identity and labels.get(LABEL) == policy["owner"], "ownership-drift")
    if kind == "network":
        require(row.get("Name", row.get("name")) == "kind", "foreign-network")
    if kind == "volume":
        expected = state_read(policy).get("volume_fingerprint")
        require(expected is None or expected == volume_fingerprint(row), "volume-identity-drift")
    if kind == "container":
        require(row.get("Name", "").lstrip("/") == policy["node"] and labels.get("io.x-k8s.kind.cluster") == policy["cluster"], "foreign-container")
    return row


def creation_cidfile(policy):
    return Path(policy["directory"]) / "node.cid"


def read_creation_cid(policy):
    path = creation_cidfile(policy)
    info = path.stat(follow_symlinks=False)
    require(info.st_uid == os.geteuid() and not (info.st_mode & 0o077), "cidfile-private-owner-required")
    raw = regular(path, 128)
    require(re.fullmatch(rb"[0-9a-f]{64}\n?", raw), "cidfile-invalid")
    return raw.rstrip(b"\n").decode("ascii")


def creation_file_record(policy):
    path = creation_cidfile(policy)
    before = path.stat(follow_symlinks=False)
    identity = read_creation_cid(policy)
    after = path.stat(follow_symlinks=False)
    fields = ["st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"]
    require(all(getattr(before, key) == getattr(after, key) for key in fields), "cidfile-changed-during-authentication")
    return {"cid": identity, **{key: getattr(after, key) for key in fields}}


def claim_creation(policy):
    path = creation_cidfile(policy)
    require(not path.exists() and not path.is_symlink(), "cidfile-preexisting-refused")
    with state_lock(policy):
        state = state_read(policy)
        require(state["prepared"], "prepared-image-required", "unavailable")
        require(not state["run_attempted"] and state.get("creation") is None, "second-node-refused")
        state["run_attempted"] = True
        state["creation"] = {"owner": policy["owner"], "cidfile": str(path), "started": False,
                             "returned": False, "status": None, "cid": None, "cid_identity": None, "outcome": "claimed", "removed": False}
        state_write(policy, state)


def start_creation(policy):
    with state_lock(policy):
        state = state_read(policy)
        creation = state["creation"]
        require(creation["outcome"] == "claimed" and not creation["started"] and not creation["returned"], "creation-intent-reused")
        creation["started"], creation["outcome"] = True, "outcome-unproved"
        state_write(policy, state)


def complete_creation(policy, result):
    status, output, _error = result
    with state_lock(policy):
        state = state_read(policy)
        creation = state["creation"]
        require(creation["started"] and not creation["returned"], "creation-result-reused")
        creation["returned"], creation["status"], creation["outcome"] = True, status, "result-unverified"
        state_write(policy, state)
    require(type(status) is int and status >= 0, "creation-interrupted-quarantined")
    cid_record = creation_file_record(policy)
    identity = cid_record["cid"]
    with state_lock(policy):
        state = state_read(policy)
        state["creation"]["cid"] = identity
        state["creation"]["cid_identity"] = cid_record
        state_write(policy, state)
    require(status != 0 or output.strip() == identity.encode(), "creation-result-cid-mismatch")
    inspect_owned(policy, "container", identity, session=False)
    with state_lock(policy):
        state = state_read(policy)
        require(not state["container"] and state["creation"]["cid"] == identity, "creation-result-drift")
        state["container"] = [identity]
        state["creation"]["outcome"] = "verified"
        state_write(policy, state)


def creation_guard(policy, state):
    creation = state.get("creation")
    if not state["run_attempted"]:
        require(creation is None and not state["container"], "missing-creation-intent")
        return
    require(isinstance(creation, dict) and creation.get("owner") == policy["owner"]
            and creation.get("cidfile") == str(creation_cidfile(policy)), "creation-intent-drift")
    if not creation.get("started"):
        require(creation.get("outcome") == "claimed" and not creation.get("returned") and not state["container"], "creation-intent-drift")
        return
    # A later cidfile can never promote an interrupted or absent original result.
    require(creation.get("returned") and type(creation.get("status")) is int and creation["status"] >= 0
            and creation.get("outcome") == "verified", "creation-outcome-unproved")
    identity = creation.get("cid")
    require(isinstance(identity, str) and HEX.fullmatch(identity), "creation-cid-missing")
    if creation.get("removed"):
        require(not state["container"], "removed-container-drift")
        return
    require(state["container"] == [identity] and creation_file_record(policy) == creation.get("cid_identity"), "creation-cid-drift")


def quarantine_creation(policy, code):
    with state_lock(policy):
        state = state_read(policy)
        state["quarantine"] = code
        try:
            state["late_cid_evidence_only"] = read_creation_cid(policy)
        except (Refusal, OSError, ValueError):
            state["late_cid_evidence_only"] = None
        state_write(policy, state)


def volume_fingerprint(row):
    return sha(json.dumps({key: row.get(key) for key in ["Name", "CreatedAt", "Mountpoint"]}, sort_keys=True).encode())


def effect_result(policy, kind, result):
    with state_lock(policy):
        state = state_read(policy)
        state[kind + "_result"] = {"returned": True, "status": result[0], "identity": None}
        state_write(policy, state)
    require(type(result[0]) is int and result[0] == 0, kind + "-create-nonzero-" + str(result[0]))


def record_created(policy, kind, identity):
    row = inspect_owned(policy, kind, identity, session=False)
    if kind == "volume":
        require(isinstance(row.get("CreatedAt"), str) and 0 < len(row["CreatedAt"]) <= 128
                and row.get("Mountpoint") == str(Path(policy["store"]) / "graph/volumes" / policy["volume"] / "_data"), "volume-creation-evidence")
    with state_lock(policy):
        state = state_read(policy)
        require(not state[kind] or state[kind] == [identity], "owned-resource-count")
        state[kind] = [identity]
        state[kind + "_result"]["identity"] = identity
        if kind == "volume":
            state["volume_fingerprint"] = volume_fingerprint(row)
        state_write(policy, state)


def argument_value(arguments, flag):
    values = []
    for index, value in enumerate(arguments):
        if value == flag:
            require(index + 1 < len(arguments), "provider-argument")
            values.append(arguments[index + 1])
        elif value.startswith(flag + "="):
            values.append(value[len(flag) + 1:])
    require(len(values) == 1, "provider-argument")
    return values[0]


def node_arguments(policy, arguments):
    require(arguments[0] == "run", "provider-command")
    normalized = ["run"]
    for item in arguments[1:]:
        if item.startswith("--volume="):
            normalized.extend(["--volume", item.split("=", 1)[1]])
        else:
            normalized.append(item)
    arguments = normalized
    booleans = {"--privileged", "--detach", "--tty", "--init", "-d", "-t"}
    valued = {"--name", "--hostname", "--label", "--userns", "--cgroupns", "--net", "--network", "--volume", "--tmpfs", "--publish", "--security-opt", "--env", "-e", "--ulimit", "--device"}
    index = 1
    while index < len(arguments) - 1:
        item = arguments[index]
        flag, equal, value = item.partition("=")
        if flag in booleans:
            require(not equal, "provider-boolean-option")
            index += 1
            continue
        require(flag in valued, "provider-run-option-unavailable", "unavailable")
        if not equal:
            index += 1
            require(index < len(arguments) - 1, "provider-run-option-value")
            value = arguments[index]
        if flag in {"--net", "--network"}:
            require(value == "kind", "provider-foreign-network")
        elif flag == "--hostname":
            require(value == policy["node"], "provider-foreign-hostname")
        elif flag == "--publish":
            require(re.fullmatch(r"127\.0\.0\.1:[0-9]{0,5}:6443(?:/[tT][cC][pP])?", value), "provider-public-listener")
        elif flag == "--userns":
            require(value == "host", "provider-user-namespace")
        elif flag == "--cgroupns":
            require(value == "private", "provider-cgroup-namespace")
        elif flag == "--tmpfs":
            require(value.split(":", 1)[0] in {"/tmp", "/run"}, "provider-tmpfs")
        elif flag in {"--env", "-e"}:
            require(value in {"container=podman", "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER", "KUBECONFIG=/etc/kubernetes/admin.conf"}, "provider-node-env")
        elif flag == "--device":
            require(value == "/dev/fuse", "provider-device-unavailable", "unavailable")
        elif flag == "--ulimit":
            require(value in {"nofile=65536:65536", "nofile=524288:524288"}, "provider-ulimit-unavailable", "unavailable")
            required = int(value.rsplit(":", 1)[1])
            hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            require(hard == resource.RLIM_INFINITY or required <= hard, "host-nofile-prerequisite", "unavailable")
        index += 1
    require(argument_value(arguments, "--name") == policy["node"], "foreign-node-name")
    require(arguments[-1] in {policy["profile"]["node_image"], image_reference(policy["profile"])}, "profile-image-mismatch")
    # Kind's node command has no shell command after the pinned node image.
    labels = [v for v in arguments if v.startswith("--label=")]
    labels += [arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value == "--label"]
    require("io.x-k8s.kind.cluster=" + policy["cluster"] in [v.removeprefix("--label=") for v in labels], "foreign-cluster-label")
    require("io.x-k8s.kind.role=control-plane" in [v.removeprefix("--label=") for v in labels], "foreign-node-role")
    forbidden = ["--memory", "--memory-swap", "--cpus", "--cpu-quota", "--cpu-period", "--pids-limit", "--cgroup-parent", "--cgroups", "--pull", "--log-driver", "--log-opt", "--cidfile", "--replace", "--pod", "--root", "--runroot"]
    require(not any(value == flag or value.startswith(flag + "=") for flag in forbidden for value in arguments), "provider-cap-override")
    require(not any(LABEL in value for value in arguments), "provider-owner-override")
    replaced, mounts = [], 0
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in ["--volume", "-v"]:
            require(index + 1 < len(arguments), "provider-volume")
            mount = arguments[index + 1]
            if mount == policy["volume"] + ":/var:suid,exec,dev":
                mounts += 1
            else:
                require(mount == "/lib/modules:/lib/modules:ro", "provider-host-mount")
            replaced.extend([value, mount])
            index += 2
        elif value.startswith("--volume="):
            raise Refusal("provider-volume-form")
        else:
            require(not value.startswith("--mount"), "provider-host-mount")
            replaced.append(value)
            index += 1
    require(mounts == 1, "provider-volume-count")
    replaced[-1] = image_reference(policy["profile"])
    limits = policy["limits"]
    return ["run", "--memory", str(limits["memory_bytes"]), "--memory-swap", str(limits["memory_bytes"]),
            "--cpus", str(limits["cpus"]), "--pids-limit", str(limits["pids"]), "--cgroup-parent", Path(policy["cgroup"]).name, "--cgroups=no-conmon", "--image-volume=ignore",
            "--cidfile", str(creation_cidfile(policy)), "--pull=never", "--log-driver=k8s-file", "--log-opt=max-size=1048576", "--label", LABEL + "=" + policy["owner"], *replaced[1:]]


def owned_target(policy, target):
    state = state_read(policy)
    require(len(state["container"]) == 1 and target in [policy["node"], state["container"][0]], "foreign-container-target")
    inspect_owned(policy, "container", state["container"][0], session=False)
    return state["container"][0]


def stream_spec(interactive=False):
    return {"stdin_fd": 0 if interactive else None, "stdout_fd": 1, "stderr_fd": 2}


def streaming_tool(policy, arguments, interactive=False):
    status, _out, _err = tool(policy, "podman", arguments, io_spec=stream_spec(interactive))
    return status, b"", b""  # Already delivered live; never duplicate protected output.


def write_reply(policy, output, error):
    pending = {1: bytearray(output), 2: bytearray(error)}
    original = {fd: os.get_blocking(fd) for fd in pending}
    try:
        for fd in pending:
            os.set_blocking(fd, False)
        with selectors.PollSelector() as selector:
            for fd, data in pending.items():
                if data:
                    selector.register(fd, selectors.EVENT_WRITE)
            while selector.get_map():
                check_cancel()
                for key, _event in selector.select(min(0.1, Budget(policy).remaining())):
                    try:
                        count = os.write(key.fd, pending[key.fd][:65536])
                        require(count > 0, "reply-write-progress")
                        del pending[key.fd][:count]
                        if not pending[key.fd]:
                            selector.unregister(key.fd)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError as caught:
                        raise Refusal("forwarding-consumer-closed") from caught
    finally:
        for fd, blocking in original.items():
            os.set_blocking(fd, blocking)


def create_provider_volume(policy, arguments):
    require(arguments == ["volume", "create", "--label", policy["node"] + "=true"], "provider-volume-catalogue")
    with state_lock(policy):
        state = state_read(policy)
        require(not state["volume_attempted"], "second-volume-refused")
        state["volume_attempted"] = True
        state_write(policy, state)
    result = tool(policy, "podman", [*arguments, "--label", LABEL + "=" + policy["owner"], policy["volume"]])
    effect_result(policy, "volume", result)
    require(result[1].strip() == policy["volume"].encode(), "volume-create-result-mismatch")
    record_created(policy, "volume", policy["volume"])
    return result


def validate_fuse_device():
    path = Path("/dev/fuse")
    require(not path.is_symlink(), "rootless-fuse-device-unavailable", "unavailable")
    info = path.stat()
    require(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 10 and os.minor(info.st_rdev) == 229
            and os.access(path, os.R_OK | os.W_OK), "rootless-fuse-device-unavailable", "unavailable")


def exec_arguments(policy, arguments):
    index, interactive = 1, False
    while index < len(arguments) and arguments[index].startswith("-"):
        item = arguments[index]
        if item == "--privileged":
            index += 1
        elif item == "-i" and not interactive:
            interactive = True
            index += 1
        elif item in ["-e", "--env"]:
            require(index + 1 < len(arguments) and arguments[index + 1] in {
                "container=podman", "KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER", "KUBECONFIG=/etc/kubernetes/admin.conf"}, "provider-exec-env")
            index += 2
        else:
            raise Refusal("provider-exec-option-unavailable", "unavailable")
    require(index + 1 < len(arguments), "provider-exec-target")
    identity = owned_target(policy, arguments[index])
    return [*arguments[:index], identity, *arguments[index + 1:]], interactive


def provider(policy, arguments):
    """No arbitrary Podman verbs; every mutation is task-owned and bounded."""
    require(arguments, "provider-command")
    require(policy.get("phase") == "run", "provider-not-authorized-for-execution", "unavailable")
    if arguments in [["--version"], ["-v"]]:
        return tool(policy, "podman", arguments)
    require(not arguments[0].startswith("-"), "provider-global-option")
    verb = arguments[0]
    if arguments[:2] == ["volume", "create"]:
        return create_provider_volume(policy, arguments)
    if verb == "run":
        transformed = node_arguments(policy, arguments)
        state = state_read(policy)
        require(not state["run_attempted"], "second-node-refused")
        require(state["volume"] == [policy["volume"]] and state.get("volume_result", {}).get("identity") == policy["volume"], "prepared-volume-required")
        inspect_owned(policy, "volume", policy["volume"])
        if "--device" in arguments or any(a.startswith("--device=") for a in arguments):
            validate_fuse_device()
        claim_creation(policy)
        start_creation(policy)
        result = tool(policy, "podman", transformed, session=False)
        complete_creation(policy, result)
        reconcile(policy, session=False)
        return result
    if arguments[:2] == ["network", "create"]:
        require(arguments[-1] == "kind", "foreign-network")
        with state_lock(policy):
            state = state_read(policy)
            require(not state["network_attempted"], "second-network-refused")
            state["network_attempted"] = True
            state_write(policy, state)
        require(not any(LABEL in a for a in arguments), "provider-owner-override")
        result = tool(policy, "podman", ["network", "create", "--label", LABEL + "=" + policy["owner"], *arguments[2:]], session=False)
        effect_result(policy, "network", result)
        rows = json_command(policy, ["network", "inspect", "kind"], session=False)
        require(isinstance(rows, list) and len(rows) == 1, "network-create-inspect-count")
        identity = rows[0].get("id", rows[0].get("ID", rows[0].get("Id")))
        require(isinstance(identity, str) and HEX.fullmatch(identity) and result[1].strip() in {b"kind", identity.encode()}, "network-create-result-mismatch")
        record_created(policy, "network", identity)
        reconcile(policy, session=False)
        return result
    # Read-only provider surface used by the frozen kind clients.
    if verb in ["info", "version", "ps", "inspect"] or arguments[:2] in [["image", "inspect"], ["network", "inspect"], ["network", "ls"]]:
        return tool(policy, "podman", arguments, session=False)
    if verb == "logs":
        require(len(arguments) in [2, 3] and (len(arguments) == 2 or arguments[1] == "-f"), "provider-logs-catalogue")
        identity = owned_target(policy, arguments[-1])
        return streaming_tool(policy, [*arguments[:-1], identity])
    if verb == "exec":
        command, interactive = exec_arguments(policy, arguments)
        return streaming_tool(policy, command, interactive)
    if verb == "cp":
        require(len(arguments) == 3, "provider-cp-arguments")
        # Only export kubeconfig from this node to the private run directory.
        source, destination = arguments[1:]
        require(source == policy["node"] + ":/etc/kubernetes/admin.conf", "provider-cp-source")
        require(Path(destination).is_absolute() and Path(destination).parent == Path(policy["directory"]), "provider-cp-destination")
        identity = owned_target(policy, policy["node"])
        return tool(policy, "podman", ["cp", identity + ":/etc/kubernetes/admin.conf", destination], session=False)
    # Kind cleanup is refused. The parent alone cleans recorded exact IDs after group retirement.
    raise Refusal("provider-command-unavailable", "unavailable")


def reconcile(policy, cleanup=False, session=True):
    """Recheck recorded command/CID identities only; labels never discover authority."""
    state = state_read(policy)
    creation_guard(policy, state)
    for kind in ["container", "network", "volume"]:
        identities = state[kind]
        require(len(identities) <= 1, "owned-resource-count")
        intent = "run_attempted" if kind == "container" else kind + "_attempted"
        require(not identities or state[intent], "missing-creation-intent")
        if kind != "container" and state[intent]:
            result = state.get(kind + "_result")
            require(isinstance(result, dict) and result.get("returned") and type(result.get("status")) is int and result.get("status") == 0
                    and len(identities) == 1 and result.get("identity") == identities[0], kind + "-creation-outcome-unproved")
        for identity in identities:
            inspect_owned(policy, kind, identity, cleanup, session)


def cleanup_resources(policy, keep_image=False):
    errors = retire_proxies(policy) if state_read(policy).get("proxies") else []
    if errors:
        return errors
    if state_read(policy).get("retirement_unproved"):
        return ["child-retirement-unproved"]
    if state_read(policy).get("pull_attempted") and not state_read(policy)["image"] and not state_read(policy)["prepared"]:
        errors.append("partial-image-preparation-quarantined")
    try:
        reconcile(policy, cleanup=True)
    except (Refusal, OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        code = error.code if isinstance(error, Refusal) else "cleanup-reconciliation-failed"
        quarantine_creation(policy, code)
        return [*errors, code]
    for kind in (["container", "volume", "network"] if keep_image else ["container", "volume", "network", "image"]):
        for identity in state_read(policy)[kind]:
            try:
                if kind == "image":
                    rows = json_command(policy, ["image", "inspect", identity], cleanup=True)
                    require(len(rows) == 1 and rows[0].get("Id", "").removeprefix("sha256:") == identity
                            and image_reference(policy["profile"]) in rows[0].get("RepoDigests", []), "image-ownership-drift")
                    args = ["image", "rm", identity]
                else:
                    inspect_owned(policy, kind, identity, cleanup=True)
                    args = ["rm", "--force", "--time", "0", identity] if kind == "container" else [kind, "rm", identity]
                checked(policy, "podman", args, cleanup=True)
                with state_lock(policy):
                    state = state_read(policy)
                    state[kind] = []
                    if kind == "container":
                        state["creation"]["removed"] = True
                    state_write(policy, state)
            except (Refusal, OSError, ValueError, TypeError, AttributeError, KeyError) as error:
                errors.append(error.code if isinstance(error, Refusal) else "cleanup-tool-failed")
    return errors


def version_evidence(document, expected):
    require(isinstance(document, dict) and document.get("gitVersion") == "v" + expected, "server-version-mismatch")
    major, minor, _ = expected.split(".")
    require(document.get("major") == major and document.get("minor") == minor, "server-version-components")
    require(re.fullmatch(r"[0-9a-f]{40}", document.get("gitCommit", "")) and document.get("platform") == "linux/amd64", "server-build-evidence")
    return {key: document.get(key) for key in ["gitVersion", "major", "minor", "gitCommit", "platform"]}


def validate_kubeconfig(policy, document, row):
    clusters, contexts, users = [document.get(key, []) for key in ["clusters", "contexts", "users"]]
    require(len(clusters) == len(contexts) == len(users) == 1, "kubeconfig-cardinality")
    context = contexts[0]
    expected = "kind-" + policy["cluster"]
    require(context.get("name") == expected and context.get("context") == {"cluster": expected, "user": expected}
            and clusters[0].get("name") == expected and users[0].get("name") == expected, "kubeconfig-context")
    ports = row.get("NetworkSettings", {}).get("Ports", {}).get("6443/tcp", [])
    require(len(ports) == 1 and ports[0].get("HostIp") == "127.0.0.1" and isinstance(ports[0].get("HostPort"), str) and ports[0]["HostPort"].isdecimal(), "owned-api-listener")
    cluster, user = clusters[0].get("cluster", {}), users[0].get("user", {})
    require(set(cluster) == {"server", "certificate-authority-data"} and cluster["server"] == "https://127.0.0.1:" + ports[0]["HostPort"], "kubeconfig-server")
    require(set(user) == {"client-certificate-data", "client-key-data"}, "kubeconfig-implicit-credentials")
    for value in [cluster["certificate-authority-data"], user["client-certificate-data"], user["client-key-data"]]:
        require(isinstance(value, str) and 0 < len(value) <= 65536, "kubeconfig-credential-budget")
        try:
            require(base64.b64decode(value, validate=True), "kubeconfig-credential-encoding")
        except ValueError as error:
            raise Refusal("kubeconfig-credential-encoding") from error


def readiness(policy, row):
    kube = policy["environment"]["KUBECONFIG"]
    require(stat.S_IMODE(Path(kube).stat().st_mode) == 0o600, "private-kubeconfig-required")
    regular(Path(kube), 256 * 1024)
    document = json.loads(checked(policy, "kubectl", ["--kubeconfig", kube, "config", "view", "--raw", "-o", "json"]))
    validate_kubeconfig(policy, document, row)
    common = ["--kubeconfig", kube, "--context", "kind-" + policy["cluster"], "--request-timeout=5s"]
    version = version_evidence(json.loads(checked(policy, "kubectl", [*common, "get", "--raw=/version"])), policy["profile"]["server_patch"])
    for _attempt in range(30):
        status, ready, _ = tool(policy, "kubectl", [*common, "get", "--raw=/readyz"])
        if status == 0 and ready.strip() == b"ok":
            nodes = json.loads(checked(policy, "kubectl", [*common, "get", "nodes", "-o", "json"]))
            rows = nodes.get("items", [])
            require(len(rows) == 1 and rows[0].get("metadata", {}).get("name") == policy["node"], "node-count-or-name")
            require(rows[0].get("status", {}).get("nodeInfo", {}).get("kubeletVersion") == "v" + policy["profile"]["server_patch"], "node-version-mismatch")
            conditions = rows[0].get("status", {}).get("conditions", [])
            if any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
                return version
        time.sleep(min(1, Budget(policy).remaining()))
    raise Refusal("server-or-node-not-ready")


def verify_node_limits(policy, row, process_cgroup=None):
    host, limits = row.get("HostConfig", {}), policy["limits"]
    require(host.get("Memory") == limits["memory_bytes"] and host.get("PidsLimit") == limits["pids"]
            and host.get("MemorySwap") == limits["memory_bytes"]
            and host.get("CgroupParent") == Path(policy["cgroup"]).name, "node-cap-inspect-mismatch")
    nano, quota, period = host.get("NanoCpus", 0), host.get("CpuQuota", 0), host.get("CpuPeriod", 0)
    require((0 < nano <= limits["cpus"] * 10**9) or (0 < quota and 0 < period and quota <= limits["cpus"] * period), "node-cpu-cap-mismatch")
    pid = row.get("State", {}).get("Pid")
    require(type(pid) is int and pid > 0, "node-live-pid-required")
    text = Path("/proc") .joinpath(str(pid), "cgroup").read_text() if process_cgroup is None else process_cgroup
    paths = [line[3:] for line in text.splitlines() if line.startswith("0::")]
    parent = "/" + str(Path(policy["cgroup"]).relative_to("/sys/fs/cgroup"))
    require(len(paths) == 1 and paths[0].startswith(parent + "/"), "node-outside-capped-slice")


def kernel_text(path, maximum=4096, admit=None, account=None):
    """Procfs/cgroup files report size zero; read one bounded content window."""
    admit = (lambda: None) if admit is None else admit
    admit()
    path = _metadata_path(path)
    fd = _metadata_access(os.open, path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          admit=admit, account=account)
    try:
        result = bounded_kernel_read(fd, maximum, admit, account).decode("ascii")
        admit()
        return result
    finally:
        os.close(fd)

def bounded_kernel_read(fd, maximum=4096, admit=None, account=None):
    admit = (lambda: None) if admit is None else admit
    admit()
    _metadata_access(os.lseek, fd, 0, os.SEEK_SET, admit=admit, account=account)
    data = bytearray()
    while len(data) <= maximum:
        admit()
        block = os.read(fd, maximum + 1 - len(data))
        admit()
        if not block:
            break
        data.extend(block)
    require(len(data) <= maximum, "retirement-kernel-read-budget")
    return bytes(data)

def boot_identity(io=None):
    value = (io.kernel_text("/proc/sys/kernel/random/boot_id") if io else kernel_text("/proc/sys/kernel/random/boot_id")).strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "retirement-boot-unavailable")
    return value


def member_of_slice(cgroup, text):
    values = [line[3:] for line in text.splitlines() if line.startswith("0::")]
    require(len(values) == 1, "retirement-cgroup-membership-unavailable")
    relative = "/" + str(Path(cgroup).relative_to("/sys/fs/cgroup"))
    return values[0] == relative or values[0].startswith(relative + "/")


def retirement_process(pid, io=None):
    path = "/proc/" + str(pid) + "/stat"
    text = io.kernel_text(path) if io else kernel_text(path)
    fields = text[text.rfind(")") + 2:].split()
    require(len(fields) >= 20, "retirement-process-identity-unavailable")
    return {"pid": pid, "group": int(fields[2]), "session": int(fields[3]), "start": int(fields[19])}


def check_retirement_process(record, cgroup, inside, allow_absent=False, io=None):
    require(set(record) == {"pid", "group", "session", "start"}
            and all(type(value) is int and value > 0 for value in record.values()), "retirement-process-record")
    try:
        require((retirement_process(record["pid"], io=io) if io else retirement_process(record["pid"])) == record, "retirement-process-identity-drift")
    except FileNotFoundError:
        require(allow_absent, "retirement-process-missing")
        return False
    path = "/proc/" + str(record["pid"]) + "/cgroup"
    text = io.kernel_text(path) if io else kernel_text(path)
    require(member_of_slice(cgroup, text) == inside, "retirement-process-placement-drift")
    require((retirement_process(record["pid"], io=io) if io else retirement_process(record["pid"])) == record, "retirement-process-identity-drift")
    return True


# Format bounds restrict metadata; none grants extra invocation resource credit.
CONTROLLER_RECORD = 65536
CONTROLLER_ARM = 16384
CONTROLLER_POLICY = 65536
CONTROLLER_RECORD_KEYS = {
    'state', 'runtime', 'runtime_conformance', 'api_acceptance', 'policy_sha256',
    'server', 'error', 'cleanup', 'cleanup_errors', 'original_state', 'evidence_scope',
    'cleanup_scope', 'detached-helper-retirement', 'scoped_retirement', 'disk_enforcement',
    'store_after', 'store_before', 'store_error', 'provider_diagnostics', 'profile',
    'owner', 'ledger_sha256', 'producer_barrier', 'helper_containment',
    'retirement_error', 'runtime_object_cleanup', 'resource_envelope',
}


def _record_bound(value, maximum, allowed=None):
    """Validate finite shape and precharge a conservative ASCII JSON size."""
    if allowed is not None:
        require(type(value) is dict and len(value) <= 128 and set(value) <= allowed, 'retirement-record-fields')
    if allowed is CONTROLLER_RECORD_KEYS:
        nested = {'store_before', 'store_after', 'server', 'producer_barrier',
                  'provider_diagnostics', 'cleanup_errors', 'helper_containment',
                  'scoped_retirement', 'resource_envelope'}
        require(all(type(item) is str and len(item) <= 4096 for key, item in value.items()
                    if key not in nested), 'retirement-receipt-scalar-fields')
        if 'cleanup_errors' in value:
            require(type(value['cleanup_errors']) is list and len(value['cleanup_errors']) <= 512
                    and all(type(item) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', item)
                            for item in value['cleanup_errors']), 'retirement-cleanup-error-fields')
        if 'resource_envelope' in value:
            require(type(value['resource_envelope']) is dict and set(value['resource_envelope']) ==
                    {'cgroup', 'cgroup_identity', 'memory', 'pids', 'swap', 'cpu'},
                    'retirement-receipt-envelope-fields')
        if 'scoped_retirement' in value:
            require(type(value['scoped_retirement']) is dict and set(value['scoped_retirement']) <= {
                'state', 'boundary', 'cgroup_identity', 'boot_id', 'unit', 'unit_identity_source',
                'policy_sha256', 'owner', 'original_end', 'producer_barrier_at', 'observed_at',
                'populated', 'coverage'}, 'retirement-receipt-scoped-fields')
        for name in ('store_before', 'store_after'):
            if name in value:
                require(type(value[name]) is dict and len(value[name]) == 3 and set(value[name]) == {'allocated_bytes', 'entries', 'disk_enforcement'}
                        and all(type(value[name][key]) is int and value[name][key] >= 0 for key in ('allocated_bytes', 'entries'))
                        and value[name]['disk_enforcement'] == 'measured-not-quota',
                        'retirement-receipt-store-fields')
        if 'server' in value:
            require(type(value['server']) is dict and len(value['server']) == 5 and set(value['server']) ==
                    {'gitVersion', 'major', 'minor', 'gitCommit', 'platform'}
                    and all(type(item) is str for item in value['server'].values()), 'retirement-receipt-server-fields')
        if 'producer_barrier' in value:
            barrier = value['producer_barrier']
            require(type(barrier) is dict and len(barrier) == 4 and set(barrier) == {'policy_sha256', 'at', 'cancelled', 'gates'}
                    and type(barrier['gates']) is dict and len(barrier['gates']) == 3 and set(barrier['gates']) ==
                    {'objects', 'proxies', 'client_groups'}, 'retirement-receipt-barrier-fields')
        diagnostics = value.get('provider_diagnostics', [])
        require(type(diagnostics) is list and len(diagnostics) <= 512, 'retirement-diagnostic-count')
        for diagnostic in diagnostics:
            require(type(diagnostic) is dict and len(diagnostic) == 2 and set(diagnostic) == {'code', 'state'}
                    and type(diagnostic['code']) is str
                    and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', diagnostic['code'])
                    and diagnostic['state'] in {'failed', 'unavailable'}, 'retirement-diagnostic-fields')
    nodes = 0
    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        require(nodes <= 4096 and depth <= 12, 'retirement-record-shape')
        if item is None or type(item) is bool:
            return 5
        if type(item) is int:
            require(-(2**63) <= item < 2**64, 'retirement-record-integer')
            return 21
        if type(item) is float:
            require(math.isfinite(item), 'retirement-record-number')
            return 32
        if type(item) is str:
            require(len(item) <= 4096, 'retirement-record-string')
            return 2 + 12 * len(item)
        if type(item) is list:
            require(len(item) <= 512, 'retirement-record-count')
            return 2 + len(item) + sum(visit(child, depth + 1) for child in item)
        require(type(item) is dict and len(item) <= 128
                and all(type(key) is str for key in item), 'retirement-record-object')
        return 2 + 2 * len(item) + sum(visit(key, depth + 1) + visit(child, depth + 1)
                                    for key, child in item.items())
    amount = visit(value, 0) + 1
    require(amount <= maximum, 'retirement-record-bytes')
    return amount


def _json_shape(raw):
    """Bound JSON structure before json.loads allocates its container tree."""
    depth = tokens = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            tokens += 1
        elif byte in (91, 123):
            depth += 1
            tokens += 1
            require(depth <= 12, 'retirement-record-shape')
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, 'retirement-record-shape')
        elif byte in (44, 58):
            tokens += 1
        require(tokens <= 4096, 'retirement-record-shape')
    require(depth == 0 and not quoted, 'retirement-record-shape')


class ControllerIO:
    """One original end and explicit partitions, never a second full budget."""
    def __init__(self, start, seconds, output, store, reserved_output, reserved_store,
                 clock=time.monotonic):
        require(type(seconds) is int and 300 <= seconds <= 1800, 'retirement-startup-duration')
        require(type(output) is int and 65536 <= output <= 16 * 1024**2
                and type(store) is int and 8 * 1024**3 <= store <= 32 * 1024**3,
                'retirement-startup-original-limits')
        require(type(reserved_output) is int and 0 < reserved_output <= output
                and type(reserved_store) is int and 0 < reserved_store < store,
                'retirement-reservation-partition')
        require(type(start) in {int, float} and math.isfinite(start), 'retirement-original-start-required')
        self.start, self.end, self.clock = start, start + seconds, clock
        self.original = {'seconds': seconds, 'output_bytes': output, 'store_bytes': store}
        self.reservation = {'output_bytes': reserved_output, 'store_bytes': reserved_store}
        self.used, self.stored = 0, 0
        self.output_share, self.store_share = reserved_output, reserved_store
        self.directory = None
        self.contract_name = None
        self.check()

    def check(self):
        return retirement_time(self.end, self.clock)

    def stage(self, function, *args, **kwargs):
        self.check()
        result = function(*args, **kwargs)
        self.check()
        return result

    def charge(self, amount):
        self.check()
        require(type(amount) is int and amount >= 0
                and self.used + amount <= self.output_share,
                'retirement-controller-output-budget')
        self.used += amount

    def read(self, path, maximum):
        self.charge(1)
        path = _metadata_path(path)
        info = self.metadata(path.stat)
        require(0 <= info.st_size <= maximum, 'retirement-controller-input-size')
        self.charge(info.st_size + 1)
        try:
            return self.stage(regular, path, min(maximum, info.st_size), self.check, self.charge)
        except FileNotFoundError:
            # Only the earlier outer-stat absence is a retryable single-stat poll.
            raise Refusal('retirement-input-disappeared') from None

    def decode(self, raw, maximum, allowed=None):
        self.check()
        require(type(raw) is bytes and len(raw) <= maximum, 'retirement-controller-input-size')
        self.stage(_json_shape, raw)
        def unique_pairs(pairs):
            result = {}
            for key, item in pairs:
                require(key not in result, 'retirement-duplicate-field')
                result[key] = item
            return result
        value = self.stage(json.loads, raw, object_pairs_hook=unique_pairs)
        self.stage(_record_bound, value, maximum * 12 + 1, allowed)
        return value

    def kernel_read(self, fd, maximum=4096):
        self.charge(maximum + 1)
        return self.stage(bounded_kernel_read, fd, maximum, self.check, self.charge)

    def kernel_text(self, path, maximum=4096):
        self.charge(maximum + 1)
        return self.stage(kernel_text, path, maximum, self.check, self.charge)

    def process(self, function, *args, **kwargs):
        # Each underlying bounded read charges itself; no opaque per-call fee.
        return self.stage(function, *args, io=self, **kwargs)

    def metadata(self, function, *args, **kwargs):
        return _metadata_access(function, *args, admit=self.check, account=self.charge, **kwargs)

    def measure_store(self, path, maximum, maximum_accesses=None):
        return self.stage(store_limit, path, maximum, self.check, self.charge, maximum_accesses)

    def handoff_measure(self):
        self.check()
        require(self.directory is not None, 'retirement-handoff-unbound')
        _metadata_path(self.directory)
        total = self.metadata(self.directory.stat).st_blocks * 512
        count = 0
        iterator = self.metadata(os.scandir, self.directory)
        try:
            while True:
                try:
                    entry = self.metadata(next, iterator)
                except StopIteration:
                    break
                count += 1
                require(count <= 16, 'retirement-handoff-count')
                require(entry.name in {self.contract_name, 'controller.claim', 'armed.json', 'worker.json',
                        'gate.json', 'provisional.json', 'final.json'}, 'retirement-handoff-entry')
                _metadata_path(self.directory / entry.name)
                info = self.metadata(entry.stat, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode), 'retirement-handoff-entry')
                total += info.st_blocks * 512
        finally:
            # Releasing a held descriptor produces no metadata/publication credit.
            iterator.close()
        require(total <= self.reservation['store_bytes'], 'retirement-controller-store-budget')
        self.check()
        return total

    def reserve_store(self, amount):
        self.check()
        _metadata_path(self.directory)
        block = self.metadata(os.statvfs, self.directory).f_frsize
        require(0 < block <= CONTROLLER_RECORD, 'retirement-store-block-size')
        # Atomic replacement can overlap the complete old and new backing.
        requested = 2 * ((amount + block - 1) // block) * block
        require(self.stored + requested <= self.store_share,
                'retirement-controller-store-budget')
        self.stored += requested
        self.handoff_measure()

    def _serialize_precharged(self, value, bound):
        text = self.stage(json.dumps, value, sort_keys=True, separators=(',', ':'), allow_nan=False)
        raw = self.stage(text.encode)
        self.check()
        raw += b'\n'
        self.check()
        require(len(raw) <= bound, 'retirement-serialized-bound')
        return raw

    def encode(self, value, allowed=None, maximum=CONTROLLER_RECORD):
        bound = self.stage(_record_bound, value, maximum, allowed)
        self.charge(bound)
        return self._serialize_precharged(value, bound)

    def write(self, path, value, allowed=None, maximum=CONTROLLER_RECORD):
        path = _metadata_path(path)
        bound = self.stage(_record_bound, value, maximum, allowed)
        # Both partitions are admitted before serialization or file allocation.
        self.charge(bound)
        self.reserve_store(bound)
        raw = self._serialize_precharged(value, bound)
        temporary = Path(str(path) + '.new.' + str(os.getpid()) + '.' + uuid.uuid4().hex)
        fd = self.metadata(os.open, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                self.stage(output.write, raw)
                self.stage(output.flush)
                self.metadata(os.fsync, output.fileno())
            self.metadata(os.replace, temporary, path)
            directory = self.metadata(os.open, Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.metadata(os.fsync, directory)
            finally:
                os.close(directory)
            self.handoff_measure()
        finally:
            # Expiry grants no extra mutation allowance, even for a temp file.
            if self.end > self.clock() and not CANCELLED:
                self.metadata(temporary.unlink, missing_ok=True)

    def publish(self, receipt):
        raw = self.encode(receipt, CONTROLLER_RECORD_KEYS)
        text = self.stage(raw.decode, 'ascii')
        self.stage(sys.stdout.write, text)
        self.check()
        return exit_status(receipt, CANCELLED)


def _worker_io_reservation(source_bytes):
    require(type(source_bytes) is int and 0 <= source_bytes <= MAX_METADATA, "retirement-source-window")
    # This entire finite role share is reserved by the controller before claim/arm.
    # Seven regular reads: contract/source/arm/policy/gate/final-policy/ownership.
    # Each read has <=64 ancestor probes plus stat/open/fstat = 67 effects.
    # Kernel rows have 17 content windows; each path opens once and seeks once.
    # Contract extras: path+parent stat and <=68 private-store probes.
    # Three writes each have <=2*35 handoff effects, statvfs and six file effects.
    # Gate polling: <=257 attempts = one read window plus <=256 failed stats.
    # Final store walk stops before metadata effect 257; no role window can grow.
    effects = {'source_stat': 1, 'reads': 7 * (METADATA_PATH_PARTS + 3),
               'contract': 2 + METADATA_PATH_PARTS + 4, 'kernel': 17 * 2,
               'replay': 4, 'lease': 2, 'writes': 3 * (2 * 35 + 1 + 6),
               'store': 256, 'polls': 256}
    rows = {'contract': 16386, 'arm': 16386, 'source': source_bytes + 2,
            'boot': 4097, 'controller_two_checks': 6 * 4097, 'shell_check': 3 * 4097,
            'own_stat': 4097, 'own_check': 3 * 4097, 'policy_digest': 65538,
            'final_policy_digest': 65538, 'ownership_receipt': 65538,
            'worker_record': 16384, 'gate_record': 16386,
            'controller_gate_check': 3 * 4097, 'private_receipt': 65536,
            'provisional_record': 65536, 'missing_gate_polls': 512,
            'metadata': 256 * sum(effects.values())}
    return {'output_bytes': sum(rows.values()), 'store_bytes': 6 * CONTROLLER_RECORD,
            'windows': rows, 'metadata_operations': effects}


def _worker_budget_counters(state, retirement):
    state['commands'], state['cleanup_output'], state['input'] = 0, 0, 0
    state['output'] = retirement['controller_reservation']['output_bytes'] if retirement else 0


def _worker_store_limit(policy):
    reservation = policy.get('retirement', {}).get('controller_reservation', {})
    maximum = policy['limits']['store_bytes'] - reservation.get('store_bytes', 0)
    require(maximum > 0, 'retirement-worker-store-partition')
    return maximum


def _selected_helper_profile_admission():
    # No caller field or receipt can authorize the known escaping helper cone.
    raise Refusal('unsupported-selected-helper-containment', 'unavailable')


def retirement_time(end, clock=time.monotonic):
    check_cancel()
    now = clock()
    require(type(end) in {int, float} and math.isfinite(end)
            and type(now) in {int, float} and math.isfinite(now), "retirement-clock")
    value = end - now
    require(value > 0, "retirement-deadline")
    return value


def retirement_contract(path, expected, io=None):
    require(HEX.fullmatch(expected or ""), "retirement-contract-digest")
    path = Path(path)
    raw = io.read(path, 16384) if io else regular(path, 16384)
    require(sha(raw) == expected, "retirement-contract-integrity")
    access = io.metadata if io else (lambda function, *args, **kwargs: function(*args, **kwargs))
    info, parent = access(path.stat), access(path.parent.stat)
    require(info.st_uid == parent.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1 and stat.S_IMODE(parent.st_mode) == 0o700, "retirement-private-handoff-required")
    value = io.decode(raw, 16384) if io else json.loads(raw)
    require(set(value) == {"schema", "owner", "cgroup", "cgroup_identity", "unit", "boot_id",
        "source_sha256", "phase", "limits", "store", "store_identity", "launch_shell", "envelope",
        "controller_reservation"}, "retirement-contract-schema")
    if io:
        require(value["controller_reservation"] == io.reservation
                and all(value["limits"][key] == amount for key, amount in io.original.items()),
                "retirement-original-partition-drift")
        io.check()
    require(value["schema"] == 1 and re.fullmatch(r"[0-9a-f]{32}", value["owner"]), "retirement-contract-schema")
    cgroup = Path(value["cgroup"])
    require(value["cgroup"] == str(cgroup) and cgroup.is_absolute() and str(cgroup).startswith("/sys/fs/cgroup/")
            and str(cgroup) == os.path.normpath(str(cgroup)) and ".." not in cgroup.parts
            and cgroup.name.startswith(PREFIX) and cgroup.name.endswith(".slice"), "retirement-full-task-slice-required")
    require(value["unit"]["name"] == cgroup.name and value["unit"]["transient"] is True
            and re.fullmatch(r"[0-9a-f]{32}", value["unit"]["invocation_id"]), "retirement-unit-attestation-required")
    require(value["boot_id"] == (io.process(boot_identity) if io else boot_identity()), "retirement-boot-drift")
    require(value["source_sha256"] == sha(io.read(_metadata_path(__file__), MAX_METADATA) if io else regular(Path(__file__).resolve(), MAX_METADATA)), "retirement-source-drift")
    require(value["phase"] in {"preflight", "prepare-image", "run"}, "retirement-phase")
    require(type(value['limits']) is dict and set(value['limits']) == {
        'seconds', 'cleanup_seconds', 'cpus', 'memory_bytes', 'pids', 'nodes',
        'store_bytes', 'output_bytes', 'commands'}, 'retirement-contract-limit-fields')
    require(type(value['controller_reservation']) is dict and set(value['controller_reservation']) ==
            {'output_bytes', 'store_bytes'}, 'retirement-reservation-fields')
    require(type(value['unit']) is dict and set(value['unit']) ==
            {'name', 'transient', 'invocation_id'}, 'retirement-unit-fields')
    require(type(value['envelope']) is dict and set(value['envelope']) ==
            {'cgroup', 'cgroup_identity', 'memory', 'pids', 'swap', 'cpu'}, 'retirement-envelope-fields')
    require(type(value['launch_shell']) is dict and set(value['launch_shell']) ==
            {'pid', 'group', 'session', 'start'}, 'retirement-process-record')
    limits_valid(value["limits"])
    store = Path(value["store"])
    require(len(store.parts) <= 64 and len(cgroup.parts) <= 64, 'retirement-path-depth')
    require(store.is_absolute() and str(store) == os.path.normpath(str(store))
            and not access(store.is_symlink) and stat.S_IMODE(access(store.stat).st_mode) == 0o700
            and access(store.stat).st_uid == os.geteuid(), "retirement-store-required")
    for part in store.parents:
        require(not access(part.is_symlink), "retirement-store-symlink")
    require(value["store_identity"] == [access(store.stat).st_dev, access(store.stat).st_ino], "retirement-store-drift")
    require(path.parent != store and store not in path.parent.parents and path.parent not in store.parents,
            "retirement-separate-handoff-required")
    if io:
        io.check()
    return value, path.parent


def nofollow_directory(path, admit=None, account=None):
    """Bound ancestry before opening root, then meter each no-follow component."""
    check = admit or (lambda: None)
    check()
    path = _metadata_path(path)
    fd = _metadata_access(os.open, "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          admit=check, account=account)
    try:
        for part in path.parts[1:]:
            child = _metadata_access(os.open, part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=fd, admit=check, account=account)
            os.close(fd)
            fd = child
        check()
        return fd
    except BaseException:
        os.close(fd)
        raise


class ControllerEnvelope:
    """Existing kernel bounds cover controller and target from their first read."""
    def __init__(self, path, io=None):
        self.path, self.fd, self.io = path, None, io

    def snapshot(self):
        def value(name):
            fd = self.metadata(os.open, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            try:
                return (self.io.kernel_read(fd, 128) if self.io else bounded_kernel_read(fd, 128)).decode("ascii").strip()
            finally:
                os.close(fd)
        info = self.metadata(os.fstat, self.fd)
        memory, pids, swap = int(value("memory.max")), int(value("pids.max")), int(value("memory.swap.max"))
        quota, period = map(int, value("cpu.max").split())
        require(0 < memory <= 16 * 1024**3 and 0 < pids <= 65536 and swap == 0
                and period > 0 and 0 < quota <= 8 * period, "retirement-envelope-finite-caps-required")
        return {"cgroup": self.path, "cgroup_identity": [info.st_dev, info.st_ino], "memory": memory,
                "pids": pids, "swap": swap, "cpu": [quota, period]}

    def stage(self, function, *args, **kwargs):
        return self.io.stage(function, *args, **kwargs) if self.io else function(*args, **kwargs)

    def metadata(self, function, *args, **kwargs):
        return self.io.metadata(function, *args, **kwargs) if self.io else function(*args, **kwargs)

    def __enter__(self):
        path = Path(self.path)
        require(path.is_absolute() and self.path == str(path) and ".." not in path.parts
                and self.path.startswith("/sys/fs/cgroup/") and path.name.startswith(PREFIX)
                and path.name.endswith(".slice"), "retirement-explicit-task-envelope-required")
        try:
            self.fd = self.stage(nofollow_directory, self.path, self.io.check if self.io else None, self.io.charge if self.io else None)
            self.record = self.snapshot()
            self.validate()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def validate(self):
        text = self.io.kernel_text("/proc/self/cgroup") if self.io else kernel_text("/proc/self/cgroup")
        relative = "/" + str(Path(self.path).relative_to("/sys/fs/cgroup"))
        require(member_of_slice(self.path, text) and "0::" + relative not in text.splitlines(),
                "retirement-controller-outside-envelope")
        current = self.stage(nofollow_directory, self.path, self.io.check if self.io else None, self.io.charge if self.io else None)
        try:
            require([self.metadata(os.fstat, current).st_dev, self.metadata(os.fstat, current).st_ino] == self.record["cgroup_identity"]
                    and self.snapshot() == self.record, "retirement-envelope-drift")
        finally:
            os.close(current)


class RetirementBoundary:
    """Invocation-local outside controller; no runtime commands or unit operations."""
    def __init__(self, contract, envelope=None, io=None):
        self.contract, self.envelope, self.io = contract, envelope, io
        self.directory = self.events = None

    def stage(self, function, *args, **kwargs):
        return self.io.stage(function, *args, **kwargs) if self.io else function(*args, **kwargs)

    def metadata(self, function, *args, **kwargs):
        return self.io.metadata(function, *args, **kwargs) if self.io else function(*args, **kwargs)

    def __enter__(self):
        try:
            self.directory = self.stage(nofollow_directory, self.contract["cgroup"], self.io.check if self.io else None, self.io.charge if self.io else None)
            info = self.metadata(os.fstat, self.directory)
            require(self.contract["cgroup_identity"] == [info.st_dev, info.st_ino], "retirement-slice-identity-drift")
            self.events = self.metadata(os.open, "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory)
            self.events_identity = [self.metadata(os.fstat, self.events).st_dev, self.metadata(os.fstat, self.events).st_ino]
            self.validate()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args):
        for fd in [self.events, self.directory]:
            if fd is not None:
                os.close(fd)
        self.events = self.directory = None

    def validate(self):
        if self.envelope is not None:
            self.envelope.validate()
        boot = self.io.process(boot_identity) if self.io else boot_identity()
        text = self.io.kernel_text("/proc/self/cgroup") if self.io else kernel_text("/proc/self/cgroup")
        require(boot == self.contract["boot_id"], "retirement-boot-drift")
        require(not member_of_slice(self.contract["cgroup"], text), "retirement-controller-inside-slice")
        current = self.stage(nofollow_directory, self.contract["cgroup"], self.io.check if self.io else None, self.io.charge if self.io else None)
        try:
            identity = self.contract["cgroup_identity"]
            require(identity == [self.metadata(os.fstat, current).st_dev, self.metadata(os.fstat, current).st_ino]
                    == [self.metadata(os.fstat, self.directory).st_dev, self.metadata(os.fstat, self.directory).st_ino], "retirement-slice-identity-drift")
            event = self.metadata(os.stat, "cgroup.events", dir_fd=current, follow_symlinks=False)
            require(stat.S_ISREG(event.st_mode) and [event.st_dev, event.st_ino] == self.events_identity,
                    "retirement-events-identity-drift")
        finally:
            os.close(current)

    def populated(self):
        self.validate()
        data = self.io.kernel_read(self.events) if self.io else bounded_kernel_read(self.events)
        lines = data.decode("ascii").splitlines()
        values = {}
        for line in lines:
            fields = line.split()
            require(len(fields) == 2 and fields[0] in {"populated", "frozen"}
                    and fields[0] not in values and fields[1] in {"0", "1"}, "retirement-malformed-events")
            values[fields[0]] = fields[1]
        require("populated" in values and data.endswith(b"\n"), "retirement-malformed-events")
        self.validate()
        return int(values["populated"])


def wait_retirement_record(path, end, clock=time.monotonic, sleep=time.sleep,
                           io=None, maximum=CONTROLLER_RECORD, allowed=None, maximum_attempts=None):
    attempts = 0
    while True:
        require(maximum_attempts is None or attempts < maximum_attempts, "retirement-record-attempt-window")
        attempts += 1
        retirement_time(end, clock)
        try:
            if io is None:
                raw = regular(path, maximum)
                retirement_time(end, clock)
                _json_shape(raw)
                result = json.loads(raw)
                _record_bound(result, maximum * 12 + 1, allowed)
                retirement_time(end, clock)
                return result
            raw = io.read(path, maximum)
            return io.decode(raw, maximum, allowed)
        except FileNotFoundError:
            if io is not None:
                # Missing-record polls still spend finite original metadata credit.
                io.charge(1)
            sleep(min(0.05, retirement_time(end, clock)))


def worker_retirement(args):
    # Explicit original start/end prevent a worker bootstrap clock renewal.
    start = args.retirement_original_start
    require(type(start) in {int, float} and math.isfinite(start), 'retirement-original-start-required')
    io = ControllerIO(start, args.seconds, args.output_bytes, args.store_bytes,
                      args.controller_output_bytes, args.controller_store_bytes)
    require(args.retirement_original_end == io.end, 'retirement-original-end-drift')
    prepaid = _worker_io_reservation(io.metadata(_metadata_path(__file__).stat).st_size)
    require(prepaid['output_bytes'] <= io.reservation['output_bytes']
            and prepaid['store_bytes'] <= io.reservation['store_bytes'], 'retirement-worker-share')
    io.output_share, io.store_share = prepaid['output_bytes'], prepaid['store_bytes']
    contract, directory = retirement_contract(args.retirement_contract, args.retirement_contract_sha256, io=io)
    require(contract['phase'] == args.phase and contract['cgroup'] == args.cgroup and contract['store'] == args.store
            and contract['limits'] == {key: getattr(args, key) for key in contract['limits']},
            'retirement-worker-context-drift')
    io.directory, io.contract_name = directory, Path(args.retirement_contract).name
    arm_raw = io.read(directory / 'armed.json', CONTROLLER_ARM)
    arm = io.decode(arm_raw, CONTROLLER_ARM, {'contract_sha256', 'boot_id', 'owner', 'controller',
        'start', 'end', 'envelope', 'controller_reservation', 'worker_io'})
    require(arm['contract_sha256'] == args.retirement_contract_sha256 and arm['boot_id'] == contract['boot_id']
            and arm['envelope'] == contract['envelope'] and contract['cgroup'].startswith(contract['envelope']['cgroup'] + '/')
            and arm['owner'] == contract['owner'] and arm['start'] == start and arm['end'] == io.end
            and arm['controller_reservation'] == io.reservation and arm['worker_io'] == prepaid,
            'retirement-arm-drift')
    retirement_time(io.end - contract['limits']['cleanup_seconds'])
    io.process(check_retirement_process, arm['controller'], contract['cgroup'], False)
    io.process(check_retirement_process, arm['controller'], contract['envelope']['cgroup'], True)
    io.process(check_retirement_process, contract['launch_shell'], contract['cgroup'], True)
    worker = io.process(retirement_process, os.getpid())
    require(worker['pid'] not in {arm['controller']['pid'], contract['launch_shell']['pid']},
            'retirement-distinct-producers-required')
    io.process(check_retirement_process, worker, contract['cgroup'], True)
    require(not any(io.metadata((directory / name).exists) for name in ['worker.json', 'gate.json', 'provisional.json', 'final.json']),
            'retirement-handoff-replay')
    record = {'contract': contract, 'contract_path': args.retirement_contract,
        'contract_sha256': args.retirement_contract_sha256, 'handoff': str(directory),
        'arm_sha256': sha(arm_raw), 'controller': arm['controller'], 'worker': worker,
        'end': arm['end'], 'controller_reservation': io.reservation, 'worker_io': prepaid,
        'finalization_seconds': min(30, contract['limits']['cleanup_seconds'] // 2)}
    return record, io


def retirement_binding(policy):
    raw = regular(Path(policy["directory"]) / "policy.json", MAX_METADATA)
    require(json.loads(raw) == policy, "retirement-policy-drift")
    return sha(raw)


def worker_native_gate(policy, io=None):
    require(type(io) is ControllerIO, 'retirement-worker-io-required')
    record = policy['retirement']
    binding = sha(io.read(Path(policy['directory']) / 'policy.json', CONTROLLER_POLICY))
    directory = Path(record['handoff'])
    worker = {'policy_sha256': binding, 'worker': record['worker'], 'arm_sha256': record['arm_sha256']}
    io.write(directory / 'worker.json', worker, set(worker), CONTROLLER_ARM)
    gate = wait_retirement_record(directory / 'gate.json', policy['end'] - policy['limits']['cleanup_seconds'],
                                  io=io, maximum=CONTROLLER_ARM,
                                  allowed={'policy_sha256', 'arm_sha256', 'controller'}, maximum_attempts=257)
    require(gate == {'policy_sha256': binding, 'arm_sha256': record['arm_sha256'],
                     'controller': record['controller']}, 'retirement-native-gate-drift')
    io.process(check_retirement_process, record['controller'], policy['cgroup'], False)
    retirement_time(policy['end'] - policy['limits']['cleanup_seconds'])


def scoped_final_receipt(provisional, evidence, failure=None):
    _record_bound(provisional, CONTROLLER_RECORD, CONTROLLER_RECORD_KEYS)
    _record_bound(evidence, CONTROLLER_RECORD)
    receipt = {key: item for key, item in provisional.items()
               if key not in {'scoped_retirement', 'helper_containment', 'detached-helper-retirement', 'resource_envelope'}}
    receipt["scoped_retirement"] = evidence
    receipt["helper_containment"] = {"state": "not-established", "reason": "unsupported-selected-helper-containment",
                                     "coverage": "no-reviewed-complete-helper-containment-provider"}
    receipt["detached-helper-retirement"] = "not-established"
    if receipt.get("state") == "readiness-passed":
        receipt["state"] = "readiness-observed-pending-retirement"
    if failure:
        receipt["original_state"] = receipt.get("state")
        receipt["state"] = "failed"
        receipt["retirement_error"] = failure
        receipt["runtime_object_cleanup"] = receipt.get("cleanup", "not-established")
        receipt["cleanup"] = "incomplete-quarantined"
    return receipt


def observe_scoped_retirement(boundary, policy, provisional, clock=time.monotonic, sleep=time.sleep, io=None):
    record = policy["retirement"]
    barrier = provisional["producer_barrier"]
    binding = sha(io.read(Path(policy["directory"]) / "policy.json", CONTROLLER_POLICY)) if io else retirement_binding(policy)
    require(barrier["policy_sha256"] == binding
            and barrier["gates"] == {"objects": True, "proxies": True, "client_groups": True}
            and provisional["cleanup"] == "complete" and barrier["cancelled"] == 0,
            "retirement-producer-barrier-incomplete")
    require(type(barrier["at"]) in {int, float} and math.isfinite(barrier["at"])
            and barrier["at"] <= cleanup_end(policy), "retirement-producer-barrier-late")
    while True:
        retirement_time(policy["end"], clock)
        boundary.validate()
        worker_live = (io.process(check_retirement_process, record["worker"], policy["cgroup"], True, allow_absent=True) if io else check_retirement_process(record["worker"], policy["cgroup"], True, allow_absent=True))
        shell_live = (io.process(check_retirement_process, record["contract"]["launch_shell"], policy["cgroup"], True, allow_absent=True) if io else check_retirement_process(record["contract"]["launch_shell"], policy["cgroup"], True, allow_absent=True))
        if not worker_live and not shell_live and boundary.populated() == 0:
            observed = clock()
            require(observed >= barrier["at"], "retirement-observation-order")
            # A second direct read catches repopulation during the witness window.
            require(boundary.populated() == 0, "retirement-repopulation")
            retirement_time(policy["end"], clock)
            return {"state": "subtree-empty-observed", "boundary": record["contract"]["cgroup"],
                    "cgroup_identity": record["contract"]["cgroup_identity"], "boot_id": record["contract"]["boot_id"],
                    "unit": record["contract"]["unit"], "unit_identity_source": "operator-attestation-bound-to-kernel-identity",
                    "policy_sha256": barrier["policy_sha256"], "owner": policy["owner"], "original_end": policy["end"],
                    "producer_barrier_at": barrier["at"], "observed_at": observed, "populated": 0,
                    "coverage": "exact-full-slice-subtree-at-observation-only"}
        sleep(min(0.05, retirement_time(policy["end"], clock)))


def retirement_controller(path, expected, envelope_path, clock=time.monotonic,
                          startup=None):
    start = clock()
    require(type(startup) is dict and set(startup) == {
        'seconds', 'output_bytes', 'store_bytes', 'controller_output_bytes', 'controller_store_bytes'},
        'retirement-startup-partition-required')
    io = ControllerIO(start, startup['seconds'], startup['output_bytes'], startup['store_bytes'],
                      startup['controller_output_bytes'], startup['controller_store_bytes'], clock)
    require(sys.platform == 'linux' and os.geteuid() != 0, 'retirement-rootless-linux-required')
    with ControllerEnvelope(envelope_path, io) as envelope:
        io.check()
        return controlled_retirement(path, expected, envelope, start, clock, io)


def controlled_retirement(path, expected, envelope, start, clock=time.monotonic, io=None):
    require(type(io) is ControllerIO and io.start == start, 'retirement-startup-partition-required')
    io.check()
    contract, directory = retirement_contract(path, expected, io=io)
    io.check()
    require(contract['controller_reservation'] == io.reservation
            and all(contract['limits'][key] == value for key, value in io.original.items()),
            'retirement-original-partition-drift')
    end = io.end
    require(contract['envelope'] == envelope.record
            and contract['cgroup'].startswith(envelope.path + '/')
            and envelope.record['memory'] <= contract['limits']['memory_bytes']
            and envelope.record['pids'] <= contract['limits']['pids']
            and envelope.record['cpu'][0] <= contract['limits']['cpus'] * envelope.record['cpu'][1],
            'retirement-aggregate-envelope-drift')
    io.directory, io.contract_name = directory, Path(path).name
    io.stored = io.handoff_measure()
    retirement_time(end - contract['limits']['cleanup_seconds'], clock)
    # Reserve worker handoff/readonly metadata share before the one-shot claim.
    worker_io = _worker_io_reservation(io.metadata(_metadata_path(__file__).stat).st_size)
    io.charge(worker_io['output_bytes'])
    require(io.stored + worker_io['store_bytes'] <= io.reservation['store_bytes'],
            'retirement-controller-store-budget')
    io.stored += worker_io['store_bytes']
    io.reserve_store(1)
    claim = io.metadata(os.open, directory / 'controller.claim',
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(claim)
    require(not any(io.metadata((directory / name).exists) for name in
                    ['armed.json', 'worker.json', 'gate.json', 'provisional.json', 'final.json']),
            'retirement-handoff-replay')
    provisional = {'state': 'failed', 'cleanup': 'not-established'}
    evidence = {'state': 'not-established', 'boundary': contract['cgroup'], 'original_end': end}
    failure = None
    try:
        with RetirementBoundary(contract, envelope, io) as boundary:
            controller = io.process(retirement_process, os.getpid())
            io.process(check_retirement_process, contract['launch_shell'], contract['cgroup'], True)
            arm = {'contract_sha256': expected, 'boot_id': contract['boot_id'], 'owner': contract['owner'],
                   'controller': controller, 'start': start, 'end': end, 'envelope': envelope.record,
                   'controller_reservation': io.reservation, 'worker_io': worker_io}
            io.write(directory / 'armed.json', arm, set(arm), CONTROLLER_ARM)
            worker = wait_retirement_record(directory / 'worker.json',
                end - contract['limits']['cleanup_seconds'], clock=clock, io=io,
                maximum=CONTROLLER_ARM, allowed={'policy_sha256', 'worker', 'arm_sha256',
                                                'state', 'error', 'contract_sha256'})
            if worker.get('state') == 'refused':
                require(set(worker) == {'state', 'error', 'contract_sha256', 'arm_sha256'}
                        and worker['error'] == 'unsupported-selected-helper-containment'
                        and worker.get('contract_sha256') == expected
                        and worker.get('arm_sha256') == sha(io.read(directory / 'armed.json', CONTROLLER_ARM)),
                        'retirement-worker-refusal-drift')
                raise Refusal(worker['error'], 'unavailable')
            policy_raw = io.read(Path(contract['store']) / 'control/policy.json', CONTROLLER_POLICY)
            policy = io.decode(policy_raw, CONTROLLER_POLICY, {'schema', 'phase', 'store_before', 'owner', 'cluster', 'node', 'volume', 'directory', 'store', 'store_identity', 'cgroup', 'limits', 'end', 'profile', 'tools', 'helper_closure', 'configuration_sha256', 'environment', 'ledger_sha256', 'source_sha256', 'retirement'})
            record = policy['retirement']
            ownership = io.decode(io.read(Path(contract['store']) / 'control/ownership.json', CONTROLLER_POLICY),
                                  CONTROLLER_POLICY)
            require(ownership['owner'] == policy['owner'] and ownership['cluster'] == policy['cluster']
                    and ownership['commands'] == 0 and ownership['output'] == io.reservation['output_bytes']
                    and ownership['input'] == 0, 'retirement-worker-output-precharge')
            require(io.measure_store(contract['store'], contract['limits']['store_bytes'] -
                             io.reservation['store_bytes'])['allocated_bytes'] <= contract['limits']['store_bytes'] -
                    io.reservation['store_bytes'], 'retirement-worker-store-partition')
            require(worker['policy_sha256'] == sha(policy_raw) and record['contract'] == contract
                    and record['contract_sha256'] == expected and record['handoff'] == str(directory)
                    and record['arm_sha256'] == sha(io.read(directory / 'armed.json', CONTROLLER_ARM))
                    and worker['arm_sha256'] == record['arm_sha256'] and worker['worker'] == record['worker']
                    and record['controller'] == controller and record['end'] == policy['end'] == end
                    and policy['owner'] == contract['owner'] and policy['phase'] == contract['phase']
                    and policy['store_identity'] == contract['store_identity'] and policy['cgroup'] == contract['cgroup']
                    and policy['limits'] == contract['limits'] and policy['source_sha256'] == contract['source_sha256']
                    and record['controller_reservation'] == io.reservation and record['worker_io'] == worker_io
                    and record['finalization_seconds'] == min(30, contract['limits']['cleanup_seconds'] // 2),
                    'retirement-worker-binding-drift')
            io.process(check_retirement_process, record['worker'], contract['cgroup'], True)
            io.stage(boundary.validate)
            retirement_time(end - contract['limits']['cleanup_seconds'], clock)
            gate = {'policy_sha256': sha(policy_raw), 'arm_sha256': record['arm_sha256'], 'controller': controller}
            io.write(directory / 'gate.json', gate, set(gate), CONTROLLER_ARM)
            provisional = wait_retirement_record(directory / 'provisional.json', end, clock=clock,
                io=io, allowed=CONTROLLER_RECORD_KEYS)
            require(retirement_contract(path, expected, io=io)[0] == contract, 'retirement-contract-drift')
            evidence = io.stage(observe_scoped_retirement, boundary, policy, provisional, clock=clock, io=io)
    except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError) as caught:
        failure = caught.code if isinstance(caught, Refusal) else 'retirement-evidence-unavailable'
    # Expiry/cancellation/credit exhaustion authorize no extra diagnostic publication.
    io.check()
    receipt = io.stage(scoped_final_receipt, provisional, evidence, failure)
    receipt['resource_envelope'] = envelope.record
    io.write(directory / 'final.json', receipt, CONTROLLER_RECORD_KEYS)
    io.check()
    return io.publish(receipt)


def make_policy(args, start, retirement=None):
    require(sys.platform == "linux" and os.uname().machine == "x86_64" and os.geteuid() != 0, "rootless-linux-amd64-required", "unavailable")
    limits = {key: getattr(args, key) for key in ["seconds", "cleanup_seconds", "cpus", "memory_bytes", "pids", "nodes", "store_bytes", "output_bytes", "commands"]}
    limits_valid(limits)
    cgroup_limits(args.cgroup, limits)
    before = store_limit(args.store, limits["store_bytes"] - (retirement["controller_reservation"]["store_bytes"] if retirement else 0))
    store = Path(args.store)
    require(stat.S_IMODE(store.stat().st_mode) == 0o700, "private-store-mode-required", "unavailable")
    ledger_bytes = regular(LEDGER, MAX_METADATA)
    owner_bytes = regular(args.canonical_owner, 1024 * 1024) if args.canonical_owner else None
    profile, selected = select_profile(json.loads(ledger_bytes), args.profile, owner_bytes)
    # All binaries are authenticated before the first tool execution, then private snapshots are used.
    binaries = {}
    for name in ["kind", "kubectl", "podman"]:
        data = regular(getattr(args, name), MAX_BINARY)
        expected = args.podman_sha256 if name == "podman" else selected[name]["sha256"]
        require(HEX.fullmatch(expected) and sha(data) == expected, name + "-binary-integrity", "unavailable")
        require(data.startswith(b"\x7fELF"), "native-executable-required", "unavailable")
        binaries[name] = (data, expected)
    helper_closure = load_helper_closure(Path(args.helper_manifest), args.helper_manifest_sha256)
    if args.phase == "run":
        return resume_policy(args, start, limits, profile, binaries, ledger_bytes, helper_closure, retirement)
    require(not list(store.iterdir()), "empty-owned-store-required", "unavailable")
    bus = Path("/run/user") / str(os.geteuid()) / "bus"
    require(bus.exists() and stat.S_ISSOCK(bus.stat().st_mode) and bus.stat().st_uid == os.geteuid(), "explicit-user-systemd-bus-required", "unavailable")
    owner = retirement["contract"]["owner"] if retirement else uuid.uuid4().hex
    cluster = PREFIX + owner
    directory = store / "control"
    directory.mkdir(mode=0o700)
    for name in ["home", "bin", "helpers", "hooks", "cdi", "networks", "tmp", "xdg", "config"]:
        (directory / name).mkdir(mode=0o700)
    (directory / "lock").touch(mode=0o600)
    tools = {}
    for name, (data, expected) in binaries.items():
        path = directory / "bin" / ("real-podman" if name == "podman" else name)
        path.write_bytes(data)
        path.chmod(0o500)
        tools[name] = {"path": str(path), "sha256": expected}
    install_helper_links(directory, helper_closure)
    (directory / "auth.json").write_text('{"auths":{}}\n')
    (directory / "auth.json").chmod(0o600)
    config = ('[containers]\nmounts=[]\n[engine]\ncgroup_manager="systemd"\n'
              + 'helper_binaries_dir=' + json.dumps([str(directory / "helpers")]) + '\n'
              + 'hooks_dir=' + json.dumps([str(directory / "hooks")]) + '\n'
              + 'cdi_spec_dirs=' + json.dumps([str(directory / "cdi")]) + '\n'
              + '[network]\nnetwork_backend="netavark"\ndefault_rootless_network_cmd="pasta"\nrootless_port_forwarder="rootlessport"\n'
              + 'network_config_dir=' + json.dumps(str(directory / "networks")) + '\n')
    (directory / "containers.conf").write_text(config)
    (directory / "registries.conf").write_text('unqualified-search-registries=[]\n')
    (directory / "storage.conf").write_text('[storage]\ndriver="vfs"\n')
    (directory / "kubeconfig").touch(mode=0o600)
    environment = {"HOME": str(directory / "home"), "PATH": str(directory / "bin"), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                   "TMPDIR": str(directory / "tmp"), "XDG_RUNTIME_DIR": str(directory / "xdg"), "XDG_CONFIG_HOME": str(directory / "config"),
                   "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(bus), "KUBECONFIG": str(directory / "kubeconfig"), "REGISTRY_AUTH_FILE": str(directory / "auth.json"),
                   "CONTAINERS_CONF": str(directory / "containers.conf"), "CONTAINERS_REGISTRIES_CONF": str(directory / "registries.conf"),
                   "CONTAINERS_STORAGE_CONF": str(directory / "storage.conf"), "KIND_EXPERIMENTAL_PROVIDER": "podman",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    policy = {"schema": 1, "phase": args.phase, "store_before": before, "owner": owner, "cluster": cluster, "node": cluster + "-control-plane", "volume": cluster + "-var",
              "directory": str(directory), "store": str(store), "store_identity": [store.stat().st_dev, store.stat().st_ino], "cgroup": str(args.cgroup), "limits": limits, "end": start + limits["seconds"],
              "profile": profile, "tools": tools, "helper_closure": helper_closure,
              "configuration_sha256": {name: sha(regular(directory / name, 64 * 1024)) for name in ["auth.json", "containers.conf", "registries.conf", "storage.conf"]}, "environment": environment, "ledger_sha256": sha(ledger_bytes), "source_sha256": sha(regular(Path(__file__).resolve(), MAX_METADATA))}
    if retirement:
        policy["retirement"], policy["end"] = retirement, retirement["end"]
    state = {"owner": owner, "cluster": cluster, "commands": 0, "output": 0, "cleanup_output": 0, "run_attempted": False, "network_attempted": False, "volume_attempted": False, "pull_attempted": False, "prepared": False,
             "container": [], "network": [], "volume": [], "image": [], "input": 0, "proxies": {}, "creation": None, "volume_result": None, "network_result": None, "volume_fingerprint": None}
    _worker_budget_counters(state, retirement)
    state_write(policy, state)
    install_launcher(policy)
    return policy


def install_launcher(policy):
    directory = Path(policy["directory"])
    policy_path = directory / "policy.json"
    write_json(policy_path, policy)
    policy_path.chmod(0o400)
    launcher = directory / "bin/podman"
    if launcher.exists():
        launcher.chmod(0o600)
    launcher.write_text('#!/usr/bin/python3\nimport os,sys\nos.execv("/usr/bin/python3", ["/usr/bin/python3", ' + repr(str(Path(__file__).resolve()))
                        + ', "--podman-front", ' + repr(str(policy_path)) + ', ' + repr(sha(policy_path.read_bytes())) + ', *sys.argv[1:]])\n')
    launcher.chmod(0o500)


def resume_policy(args, start, limits, profile, binaries, ledger_bytes, helper_closure, retirement=None):
    policy_path = Path(args.store) / "control/policy.json"
    raw = regular(policy_path, MAX_METADATA)
    require(HEX.fullmatch(args.prepared_policy_sha256) and sha(raw) == args.prepared_policy_sha256, "prepared-policy-integrity", "unavailable")
    policy = json.loads(raw)
    require(policy.get("phase") == "prepare-image", "prepared-phase-required", "unavailable")
    require(policy["profile"] == profile and policy["limits"] == limits and policy["cgroup"] == str(args.cgroup)
            and policy["store"] == str(Path(args.store)) and policy["directory"] == str(Path(args.store) / "control")
            and policy["ledger_sha256"] == sha(ledger_bytes) and policy["source_sha256"] == sha(regular(Path(__file__).resolve(), MAX_METADATA)), "prepared-policy-context-drift", "unavailable")
    require(policy["store_identity"] == [Path(args.store).stat().st_dev, Path(args.store).stat().st_ino], "prepared-store-replaced", "unavailable")
    require(re.fullmatch(r"[0-9a-f]{32}", policy["owner"]) and policy["cluster"] == PREFIX + policy["owner"]
            and policy["node"] == policy["cluster"] + "-control-plane" and policy["volume"] == policy["cluster"] + "-var", "prepared-ownership-drift", "unavailable")
    for name, (_, expected) in binaries.items():
        require(policy["tools"][name]["sha256"] == expected, "prepared-tool-profile-drift", "unavailable")
        authenticate_tool(policy, name)
    require(policy["helper_closure"] == helper_closure, "prepared-helper-closure-drift", "unavailable")
    authenticate_helpers(policy)
    state = state_read(policy)
    require(state["prepared"] and not any(state[k] for k in ["container", "network", "volume"])
            and not state["run_attempted"] and not state["network_attempted"] and not state["volume_attempted"], "used-or-unprepared-store-refused", "unavailable")
    if retirement:
        require(policy["owner"] == retirement["contract"]["owner"]
                and policy.get("retirement", {}).get("contract_sha256") != retirement["contract_sha256"], "retirement-prepared-replay")
        prior = read_json(Path(policy["retirement"]["handoff"]) / "final.json")
        require(prior["state"] == "image-prepared-only" and prior["cleanup"] == "complete"
                and prior["scoped_retirement"]["state"] == "subtree-empty-observed"
                and prior["scoped_retirement"]["policy_sha256"] == args.prepared_policy_sha256
                and prior["owner"] == policy["owner"], "retirement-prepared-finalization-required")
        policy["retirement"] = retirement
    policy["end"] = retirement["end"] if retirement else start + limits["seconds"]
    policy["phase"] = "run"
    policy["store_before"] = store_limit(args.store, limits["store_bytes"] - retirement["controller_reservation"]["store_bytes"])
    _worker_budget_counters(state, retirement)
    state_write(policy, state)
    install_launcher(policy)
    return policy


def verify_helper_selection(policy, host):
    closure = policy["helper_closure"]["helpers"]
    backend = host.get("networkBackendInfo", {})
    require(host.get("networkBackend") == "netavark" and backend.get("backend") == "netavark", "helper-network-backend-mismatch", "unavailable")
    reported = {"conmon": host.get("conmon", {}).get("path"), "crun": host.get("ociRuntime", {}).get("path"),
                "netavark": backend.get("path"), "aardvark-dns": backend.get("dns", {}).get("path"),
                "pasta": host.get("pasta", {}).get("executable")}
    for name, path in reported.items():
        allowed = {closure[name]["path"], str(Path(policy["directory"]) / "helpers" / name), str(Path(policy["directory"]) / "bin" / name)}
        require(path in allowed, "helper-reported-path-mismatch", "unavailable")


def preflight(policy):
    info = json_command(policy, ["info", "--format", "json"])
    host = info.get("host", {})
    require(host.get("security", {}).get("rootless") is True and host.get("cgroupVersion") == "v2"
            and host.get("cgroupManager") == "systemd" and host.get("serviceIsRemote") is False, "rootless-cgroupv2-systemd-required", "unavailable")
    store = info.get("store", {})
    require(store.get("graphRoot") == str(Path(policy["store"]) / "graph") and store.get("runRoot") == str(Path(policy["store"]) / "run"), "podman-store-mismatch", "unavailable")
    require(json_command(policy, ["ps", "--all", "--format", "json"]) == [], "preexisting-container-refused", "unavailable")
    require(json_command(policy, ["volume", "ls", "--format", "json"]) == [], "preexisting-volume-refused", "unavailable")
    networks = json_command(policy, ["network", "ls", "--format", "json"])
    require(not any(row.get("name", row.get("Name")) == "kind" for row in networks), "preexisting-kind-network-refused", "unavailable")
    verify_helper_selection(policy, host)
    version = checked(policy, "kind", ["version"]).decode("ascii").split()
    selected = {p["id"]: p for p in json.loads(regular(LEDGER, MAX_METADATA))["tool_profiles"]}
    require(len(version) >= 2 and version[:2] == ["kind", "v" + selected[policy["profile"]["kind_profile"]]["version"]], "kind-version-mismatch", "unavailable")
    kubectl = json.loads(checked(policy, "kubectl", ["version", "--client", "-o", "json"]))
    require(kubectl.get("clientVersion", {}).get("gitVersion") == "v" + selected[policy["profile"]["kubectl_profile"]]["version"], "kubectl-version-mismatch", "unavailable")


def execute(policy, args):
    preflight(policy)
    if args.phase == "preflight":
        return {"state": "preflight-only", "runtime": "pending"}
    if args.phase == "prepare-image":
        require(args.allow_public_image_pull, "explicit-public-image-pull-consent-required", "unavailable")
        with state_lock(policy):
            state = state_read(policy)
            state["pull_attempted"] = True
            state_write(policy, state)
        checked(policy, "podman", ["pull", "--authfile", policy["environment"]["REGISTRY_AUTH_FILE"], image_reference(policy["profile"])])
        rows = json_command(policy, ["image", "inspect", image_reference(policy["profile"])])
        identity = image_identity(policy["profile"], rows)
        with state_lock(policy):
            state = state_read(policy)
            state["image"] = [identity]
            state["prepared"] = True
            state_write(policy, state)
        return {"state": "image-prepared-only", "runtime": "pending", "policy_sha256": sha(regular(Path(policy["directory"]) / "policy.json", MAX_METADATA))}
    require(args.execute_owned_cluster, "explicit-execution-consent-required", "unavailable")
    require(state_read(policy)["prepared"], "prepared-image-required", "unavailable")
    images = json_command(policy, ["image", "inspect", image_reference(policy["profile"])])
    require(state_read(policy)["image"] == [image_identity(policy["profile"], images)], "prepared-image-drift")
    config = Path(policy["directory"]) / "kind.yaml"
    config.write_text('---\nkind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n  - role: control-plane\n')
    checked(policy, "kind", ["create", "cluster", "--name", policy["cluster"], "--image", policy["profile"]["node_image"],
                            "--config", str(config), "--kubeconfig", policy["environment"]["KUBECONFIG"], "--retain", "--wait", str(min(120, int(Budget(policy).remaining()))) + "s"])
    reconcile(policy)
    state = state_read(policy)
    require(len(state["container"]) == 1, "owned-node-required")
    row = inspect_owned(policy, "container", state["container"][0])
    verify_node_limits(policy, row)
    return {"state": "readiness-observed-pending-retirement", "server": readiness(policy, row), "runtime_conformance": "pending", "api_acceptance": "pending"}


def join_receipt(receipt, error, cleanup):
    if error:
        receipt = {"state": error.state, "error": error.code, "runtime": "pending"}
    if cleanup:
        receipt["original_state"] = receipt.get("state")
        receipt["state"] = "failed"
        receipt["cleanup_errors"] = cleanup
    receipt["cleanup"] = "incomplete-quarantined" if cleanup else "complete"
    return receipt


def exit_status(receipt, cancelled=0):
    # There is no independently reviewed complete helper-containment provider yet.
    # Receipt fields supplied by callers cannot manufacture that authority.
    return (128 + cancelled) if cancelled else (2 if receipt["state"] in ["unavailable", "preflight-only", "image-prepared-only"] else 1)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-output-bytes", type=int)
    parser.add_argument("--controller-store-bytes", type=int)
    parser.add_argument("--retirement-original-start", type=float)
    parser.add_argument("--retirement-original-end", type=float)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--phase", choices=["preflight", "prepare-image", "run"])
    parser.add_argument("--execute-owned-cluster", action="store_true")
    parser.add_argument("--allow-public-image-pull", action="store_true")
    for name in ["profile", "kind", "kubectl", "podman", "podman-sha256", "canonical-owner", "helper-manifest", "helper-manifest-sha256", "cgroup", "store", "prepared-policy-sha256", "retirement-contract", "retirement-contract-sha256"]:
        parser.add_argument("--" + name)
    for name in ["seconds", "cleanup-seconds", "cpus", "memory-bytes", "pids", "nodes", "store-bytes", "output-bytes", "commands"]:
        parser.add_argument("--" + name, type=int)
    return parser, parser.parse_args()


def main():
    global CANCELLED, PROXY_CONTROL, PROXY_POLICY, PROXY_LEASE
    if len(sys.argv) > 1 and sys.argv[1] == "--owned-vm":
        import owned_qemu
        return owned_qemu.main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == '--retirement-controller':
        parser = argparse.ArgumentParser()
        parser.add_argument('--retirement-controller', required=True)
        parser.add_argument('contract_sha256')
        parser.add_argument('--controller-envelope', required=True)
        for name in ('seconds', 'output-bytes', 'store-bytes', 'controller-output-bytes', 'controller-store-bytes'):
            parser.add_argument('--' + name, type=int, required=True)
        args = parser.parse_args()
        previous = {}
        def controller_cancelled(signum, _frame):
            global CANCELLED
            if not CANCELLED:
                CANCELLED = signum
        os.umask(0o077)
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, controller_cancelled)
        try:
            startup = {name: getattr(args, name) for name in ('seconds', 'output_bytes', 'store_bytes',
                       'controller_output_bytes', 'controller_store_bytes')}
            return retirement_controller(args.retirement_controller, args.contract_sha256,
                                         args.controller_envelope, startup=startup)
        except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError):
            # No uncharged bootstrap/expired failure receipt or fresh timeout.
            return 128 + CANCELLED if CANCELLED else 1
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if len(sys.argv) >= 4 and sys.argv[1] == "--podman-front":
        try:
            _selected_helper_profile_admission()
        except Refusal:
            return 1
        try:
            return provider_front(sys.argv[2], sys.argv[3], sys.argv[4:])
        except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
            return 1
    if len(sys.argv) >= 6 and sys.argv[1] == "--podman-proxy":
        try:
            _selected_helper_profile_admission()
        except Refusal:
            return 1
        policy = None
        try:
            raw = regular(Path(sys.argv[2]), MAX_METADATA)
            require(sha(raw) == sys.argv[3], "provider-policy-integrity")
            policy = json.loads(raw)
            require(sha(regular(Path(__file__).resolve(), MAX_METADATA)) == policy["source_sha256"], "provider-source-integrity")
            PROXY_CONTROL, PROXY_POLICY, PROXY_LEASE = int(sys.argv[4]), policy, sys.argv[5]
            await_proxy_gate(policy, PROXY_LEASE, PROXY_CONTROL)
            status, out, err = provider(policy, sys.argv[6:])
            write_reply(policy, out, err)
            return status
        except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as caught:
            if policy is not None:
                try:
                    with state_lock(policy):
                        state = state_read(policy)
                        code = caught.code if isinstance(caught, Refusal) else "provider-unavailable"
                        if code not in {"provider-parent-cancelled", "forwarding-consumer-closed"}:
                            state.setdefault("provider_diagnostics", []).append({"code": code, "state": caught.state if isinstance(caught, Refusal) else "failed"})
                            state_write(policy, state)
                except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError):
                    pass
            return 1  # Fixed status only: no protected command body or child diagnostic is logged.
        finally:
            if policy is not None:
                try:
                    finish_proxy(policy, PROXY_LEASE)
                except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError):
                    pass  # Missing retirement acknowledgement forces controller quarantine.
    parser, args = arguments()
    if args.self_test:
        require(len(sys.argv) == 2, "self-test-isolation")
        import test_kind_runtime
        import test_owned_qemu
        import test_owned_host_view
        import test_owned_guest_stage
        import test_owned_guest_receiver
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module)
                                   for module in (test_kind_runtime, test_owned_qemu, test_owned_host_view, test_owned_guest_stage, test_owned_guest_receiver))
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    required = ["phase", "profile", "kind", "kubectl", "podman", "podman_sha256", "helper_manifest", "helper_manifest_sha256", "cgroup", "store", "seconds", "cleanup_seconds", "cpus", "memory_bytes", "pids", "nodes", "store_bytes", "output_bytes", "commands", "retirement_contract", "retirement_contract_sha256", "controller_output_bytes", "controller_store_bytes", "retirement_original_start", "retirement_original_end"]
    if any(getattr(args, name) is None for name in required) or (args.phase == "run" and (not args.prepared_policy_sha256 or not args.execute_owned_cluster)):
        parser.error("explicit phase, tool paths/digests, resource limits and run consent/prepared-policy are required")
    os.umask(0o077)
    start = time.monotonic()
    policy, error, receipt = None, None, {}
    native_started = False
    retirement = worker_io = None
    lease = None
    previous = {}
    def cancelled(signum, _frame):
        global CANCELLED
        if not CANCELLED:
            CANCELLED = signum
    for signum in [signal.SIGINT, signal.SIGTERM]:
        previous[signum] = signal.signal(signum, cancelled)
    try:
        retirement, worker_io = worker_retirement(args)
        lease = worker_io.metadata(os.open, _metadata_path(args.store), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            worker_io.metadata(fcntl.flock, lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as caught:
            raise Refusal("store-already-in-use", "unavailable") from caught
        try:
            _selected_helper_profile_admission()
        except Refusal as refusal:
            value = {'state': 'refused', 'error': refusal.code,
                     'contract_sha256': retirement['contract_sha256'], 'arm_sha256': retirement['arm_sha256']}
            worker_io.write(Path(retirement['handoff']) / 'worker.json', value, set(value), CONTROLLER_ARM)
            return 1
        policy = make_policy(args, start, retirement)
        worker_native_gate(policy, worker_io)
        native_started = True
        receipt = execute(policy, args)
    except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as caught:
        error = caught if isinstance(caught, Refusal) else Refusal("invalid-or-unavailable-prerequisite", "unavailable" if policy is None else "failed")
    finally:
        try:
            cleanup = cleanup_resources(policy, keep_image=error is None and args.phase == "prepare-image") if policy and native_started else []
        except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as caught:
            cleanup = [caught.code if isinstance(caught, Refusal) else "cleanup-unavailable"]
        if lease is not None:
            os.close(lease)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if policy is None:
        return 128 + CANCELLED if CANCELLED else 1
    try:
        worker_io.check()
    except Refusal:
        return 128 + CANCELLED if CANCELLED else 1
    try:
        receipt = join_receipt(receipt, error, cleanup)
        receipt["evidence_scope"] = "external-readiness-only"
        receipt["cleanup_scope"] = "recorded-runtime-objects-and-leased-client-groups"
        receipt["detached-helper-retirement"] = "not-established"
        receipt["scoped_retirement"] = {"state": "pending-outside-finalization" if policy else "not-established"}
        receipt["disk_enforcement"] = "measured-not-quota"
        if policy:
            try:
                receipt["store_after"] = worker_io.measure_store(policy["store"], _worker_store_limit(policy), maximum_accesses=256)
            except (Refusal, OSError) as caught:
                receipt["state"] = "failed"
                receipt["store_error"] = caught.code if isinstance(caught, Refusal) else "store-measurement-unavailable"
            receipt["store_before"] = policy["store_before"]
            current = worker_io.decode(worker_io.read(Path(policy['directory']) / 'ownership.json', CONTROLLER_POLICY), CONTROLLER_POLICY)
            require(current['owner'] == policy['owner'] and current['cluster'] == policy['cluster'], 'ownership-manifest-drift')
            receipt["provider_diagnostics"] = current.get("provider_diagnostics", [])
            receipt.update({"profile": policy["profile"]["id"], "owner": policy["owner"], "ledger_sha256": policy["ledger_sha256"]})
            receipt["producer_barrier"] = {"policy_sha256": sha(worker_io.read(Path(policy["directory"]) / "policy.json", CONTROLLER_POLICY)), "at": time.monotonic(), "cancelled": CANCELLED,
                "gates": {"objects": native_started and receipt["cleanup"] == "complete" and not any(current[key] for key in ["container", "network", "volume"])
                          and (args.phase == "prepare-image" or not current["image"]),
                          "proxies": all(record.get("retired") is True for record in current.get("proxies", {}).values()),
                          "client_groups": not current.get("retirement_unproved", False)}}
            worker_io.write(Path(policy["directory"]) / "receipt.json", receipt, CONTROLLER_RECORD_KEYS)
            require(type(worker_io) is ControllerIO, 'retirement-worker-io-required')
            try:
                worker_io.write(Path(policy['retirement']['handoff']) / 'provisional.json', receipt,
                                CONTROLLER_RECORD_KEYS)
            except (Refusal, OSError, ValueError, TypeError):
                return 128 + CANCELLED if CANCELLED else 1
    except (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError):
        return 128 + CANCELLED if CANCELLED else 1
    # Only the accounted outside controller may publish an external final receipt.
    return 128 + CANCELLED if CANCELLED else 1


if __name__ == "__main__":
    sys.exit(main())
