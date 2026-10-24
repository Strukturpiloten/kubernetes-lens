#!/usr/bin/env python3
"""Explicit owned-VM prerequisite qualification, not Kubernetes conformance.

The outside owner alone publishes success after retiring its private user service.
The service worker cannot start QEMU until the owner authenticates its kernel and
systemd identity and actual finite limits. All subprocess argument lists are fixed.
"""
import argparse
import base64
import errno
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import re
import resource
import select
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import types
import uuid

# The worker runs this file as __main__; share one Refusal/CANCELLED/Budget
# identity with the tightly coupled host-view module.
if __name__ == "__main__":
    sys.modules["owned_qemu"] = sys.modules[__name__]

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / "scripts/kind-vm-image.json"
ROLES = {"qemu", "qemu_img", "ssh", "ssh_keygen", "systemctl", "systemd_run", "busctl", "python"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
ARCHIVE_MAX = 2 * 1024**3
EXPANDED_MAX = 4 * 1024**3
META_MAX = 65536
OUTPUT_MAX = 2 * 1024**2
FIXED_COMMAND = ("/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin "
                 "/usr/bin/podman --remote=false info --format=json")
EXPECTED_PODMAN = "5.8.7"  # Historical prerequisite profile, not an operational tool pin.
CANCELLED = 0


class Refusal(Exception):
    """Fixed diagnostic; raw subprocess/guest text is never returned."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: require(False, "nonfinite-json"))
    except (ValueError, RecursionError) as error:
        raise Refusal("invalid-json") from error


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(path), "absolute-canonical-path-required")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symlink-path-refused")
    return path


def read(path, maximum=META_MAX):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "regular-file-budget")
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        require(file_id(before) == file_id(after) and len(raw) == before.st_size, "file-identity-drift")
        return bytes(raw)
    finally:
        os.close(fd)


def file_id(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def write(path, data):
    require(len(data) <= META_MAX, "metadata-budget")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


class Budget:
    def __init__(self, end, cleanup_seconds, *, output=OUTPUT_MAX, commands=128):
        require(type(end) in (int, float) and math.isfinite(end), "invalid-original-end")
        self.end, self.work_end = end, end - cleanup_seconds
        self.output_left, self.commands_left = output, commands

    def remaining(self, cleanup=False):
        require(cleanup or not CANCELLED, "cancelled")
        result = (self.end if cleanup else self.work_end) - time.monotonic()
        require(result > 0, "original-deadline-expired")
        return result

    def charge(self, count):
        self.output_left -= count
        require(self.output_left >= 0, "output-budget")


def child_limits(seconds, file_bytes, address_bytes=512 * 1024**2):
    def apply():
        os.umask(0o077)
        for which, limit in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64),
                             (resource.RLIMIT_FSIZE, file_bytes),
                             (resource.RLIMIT_CPU, max(1, math.ceil(seconds))),
                             (resource.RLIMIT_AS, address_bytes)):
            inherited = resource.getrlimit(which)[1]
            if inherited != resource.RLIM_INFINITY:
                limit = min(limit, inherited)
            resource.setrlimit(which, (limit, limit))
    return apply


def clean_environment(directory):
    return {"PATH": "/usr/bin:/usr/sbin", "HOME": str(directory), "LANG": "C", "LC_ALL": "C",
            "TMPDIR": str(directory), "XDG_CONFIG_HOME": str(directory),
            "XDG_CACHE_HOME": str(directory), "XDG_DATA_HOME": str(directory)}


def command_remaining(budget, cleanup=False, deadline=None):
    remaining = budget.remaining(cleanup)
    if deadline is not None:
        require(type(deadline) in (int, float) and math.isfinite(deadline), "invalid-command-deadline")
        remaining = min(remaining, deadline - time.monotonic())
        require(remaining > 0, "command-deadline-expired")
    return remaining


def run(argv, budget, directory, *, cleanup=False, maximum=META_MAX, file_bytes=META_MAX, manager=False, extra_streams=(), on_start=None, deadline=None):
    """One bounded command; no shell, inherited agent, config or raw error receipt."""
    def remaining():
        return command_remaining(budget, cleanup, deadline)
    seconds = remaining()
    budget.commands_left -= 1
    require(budget.commands_left >= 0, "command-budget")
    environment = clean_environment(directory)
    if manager:
        environment.update({"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
                            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus"})
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                               env=environment,
                               preexec_fn=child_limits(seconds, file_bytes))
    result = bytearray()
    selector = selectors.DefaultSelector()
    pending = {process.stdout, process.stderr}
    try:
        if on_start:
            on_start(process)
        for stream in (process.stdout, process.stderr, *extra_streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while pending:
            remaining()
            for key, _ in selector.select(min(0.1, remaining())):
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    pending.discard(key.fileobj)
                    continue
                budget.charge(len(raw))
                if key.fileobj is process.stdout:
                    result.extend(raw)
                    require(len(result) <= maximum, "command-output-budget")
        while process.poll() is None:
            time.sleep(min(0.01, remaining()))
        return process.returncode, bytes(result)
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Never acquire a new timeout after cancellation or expiry.
            try:
                process.wait(timeout=max(0, budget.end - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise Refusal("control-child-retirement-unproved") from None
        process.stdout.close()
        process.stderr.close()


def admit_tools(path, expected):
    raw = read(path)
    require(isinstance(expected, str) and HEX.fullmatch(expected) and digest(raw) == expected,
            "host-tools-manifest-integrity")
    document = strict_json(raw)
    require(type(document) is dict and set(document) == {"schema", "tools"}
            and document["schema"] == "kubernetes-lens-owned-vm-tools-v1"
            and type(document["tools"]) is dict and set(document["tools"]) == ROLES,
            "host-tools-manifest-schema")
    result = {}
    for role, record in document["tools"].items():
        require(type(record) is dict and set(record) == {"path", "bytes", "sha256", "owner", "mode", "version"},
                "host-tool-record-schema")
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= 128 * 1024**2
                and record["owner"] == 0 and type(record["owner"]) is int
                and isinstance(record["sha256"], str) and HEX.fullmatch(record["sha256"])
                and isinstance(record["mode"], str) and re.fullmatch(r"0[0-7]{3}", record["mode"])
                and isinstance(record["version"], str) and 0 < len(record["version"]) <= 128,
                "host-tool-record-identity")
        target = canonical(record["path"])
        for part in (target, *target.parents):
            info = part.stat()
            require(info.st_uid == 0 and not info.st_mode & 0o022, "host-tool-writable")
        before = target.stat()
        try:
            require(not os.getxattr(target, "security.capability", follow_symlinks=False), "host-tool-capabilities-refused")
        except OSError as error:
            require(error.errno in (errno.ENODATA, errno.ENOTSUP), "host-tool-capability-unavailable")
        data = read(target, 128 * 1024**2)
        after = target.stat()
        require(file_id(before) == file_id(after) and data.startswith(b"\x7fELF")
                and before.st_mode & 0o111 and not before.st_mode & 0o6000
                and len(data) == record["bytes"] and digest(data) == record["sha256"]
                and f"{stat.S_IMODE(before.st_mode):04o}" == record["mode"], "host-tool-identity-drift")
        result[role] = {**record, "file_identity": file_id(after)}
    require(Path(result["python"]["path"]) == Path(sys.executable).resolve(), "host-python-identity")
    return result


def pin_document(path=PIN):
    raw = read(path)
    item = strict_json(raw)
    require(type(item) is dict and set(item) == {"schema", "release", "archive_sha256"}
            and item["schema"] == "kubernetes-lens-owned-vm-image-v1"
            and isinstance(item["release"], str) and re.fullmatch(r"[0-9]{2}\.[0-9]{8}\.[0-9]+\.[0-9]+", item["release"])
            and isinstance(item["archive_sha256"], str) and HEX.fullmatch(item["archive_sha256"]),
            "image-pin-schema")
    return item, digest(raw)


def official_url(pin):
    release = pin["release"]
    return ("https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/" + release
            + "/x86_64/fedora-coreos-" + release + "-qemu.x86_64.qcow2.xz")


def admit_archive(source, directory, pin, budget):
    """Copy/hash once before decoding; no downloader or caller-selected digest."""
    source = canonical(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    copied = Path(directory) / "image.qcow2.xz"
    hasher, count = hashlib.sha256(), 0
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= ARCHIVE_MAX, "archive-file-budget")
        out = os.open(copied, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, "wb") as output:
            while True:
                budget.remaining()
                block = os.read(fd, 65536)
                if not block:
                    break
                count += len(block)
                require(count <= ARCHIVE_MAX, "archive-byte-budget")
                hasher.update(block)
                output.write(block)
        require(file_id(before) == file_id(os.fstat(fd)) and count == before.st_size,
                "archive-source-drift")
        require(hasher.hexdigest() == pin["archive_sha256"], "archive-integrity")
    finally:
        os.close(fd)
    expanded = Path(directory) / "image.qcow2"
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024**2)
    total, expanded_hash = 0, hashlib.sha256()
    try:
        with copied.open("rb") as compressed, expanded.open("xb") as output:
            while not decoder.eof:
                budget.remaining()
                block = compressed.read(65536) if decoder.needs_input else b""
                require(bool(block) or not decoder.needs_input, "truncated-xz")
                raw = decoder.decompress(block, max_length=65536)
                total += len(raw)
                require(total <= EXPANDED_MAX, "expanded-image-budget")
                expanded_hash.update(raw)
                output.write(raw)
            require(not decoder.unused_data and not compressed.read(1), "trailing-xz-data")
    except lzma.LZMAError as error:
        raise Refusal("invalid-xz") from error
    require(total >= 104, "qcow2-header")
    with expanded.open("rb") as image:
        header = image.read(104)
    require(header[:4] == b"QFI\xfb" and struct.unpack_from(">I", header, 4)[0] == 3
            and struct.unpack_from(">Q", header, 8)[0] == 0
            and struct.unpack_from(">I", header, 16)[0] == 0
            and struct.unpack_from(">I", header, 32)[0] == 0
            and struct.unpack_from(">Q", header, 72)[0] == 0,
            "qcow2-external-or-unsupported-features")
    expanded.chmod(0o400)
    copied.unlink()
    return {"archive_sha256": hasher.hexdigest(), "archive_bytes": count,
            "expanded_sha256": expanded_hash.hexdigest(), "expanded_bytes": total,
            "official_url": official_url(pin)}


def ignition(client_public, host_private, host_public, *, stage_public=None, stage_files=None):
    require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: ?[^\r\n]*)?\n?", client_public)
            and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: ?[^\r\n]*)?\n?", host_public),
            "ssh-key-format")
    def file(path, value, mode):
        return {"path": path, "mode": mode,
                "contents": {"source": "data:;base64," + base64.b64encode(value.encode()).decode()}}
    key = 'restrict,command="' + FIXED_COMMAND + '" ' + client_public.strip()
    config = ("HostKey /etc/ssh/ssh_host_ed25519_key\nPasswordAuthentication no\n"
              "KbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers core\n"
              "AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\n"
              "PermitTunnel no\nPermitTTY no\n")
    result = {"ignition": {"version": "3.4.0"},
            "passwd": {"users": [{"name": "core", "sshAuthorizedKeys": [key]}]},
            "storage": {"files": [file("/etc/ssh/ssh_host_ed25519_key", host_private, 0o600),
                                    file("/etc/ssh/ssh_host_ed25519_key.pub", host_public, 0o644),
                                    file("/etc/ssh/sshd_config.d/00-kubernetes-lens.conf", config, 0o600)]},
            "systemd": {"units": [{"name": "zincati.service", "mask": True}]}}

    if stage_public is not None:
        require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: ?[^\r\n]*)?\n?", stage_public)
                and type(stage_files) is dict, "stage-ignition-contract")
        stage = authenticated_module("owned_guest_stage")
        result["passwd"]["users"][0]["sshAuthorizedKeys"].append(
            'restrict,command="' + stage.RECEIVER_COMMAND + '" ' + stage_public.strip())
        result["storage"]["directories"] = [{"path": "/var/lib/kubernetes-lens-stage", "mode": 0o700}]
        for path, (raw, mode) in stage_files.items():
            result["storage"]["files"].append({"path": path, "mode": mode,
                "contents": {"source": "data:;base64," + base64.b64encode(raw).decode("ascii")}})
    require(len(encode(result)) <= META_MAX, "ignition-budget")
    return result


def process_identity(pid):
    require(type(pid) is int and pid > 0, "process-pid")
    text = Path(f"/proc/{pid}/stat").read_text()
    tail = text[text.rfind(")") + 2:].split()
    require(len(tail) >= 20, "process-stat")
    return {"pid": pid, "group": int(tail[2]), "session": int(tail[3]), "start": int(tail[19])}


def process_cgroup(pid):
    raw = Path(f"/proc/{pid}/cgroup").read_text()
    rows = [line[3:] for line in raw.splitlines() if line.startswith("0::")]
    require(len(rows) == 1 and rows[0].startswith("/"), "process-cgroup")
    return "/sys/fs/cgroup" + rows[0]


def boot_id():
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "host-boot-identity")
    return value


def cgroup_snapshot(path, config):
    path = canonical(path)
    require(str(path).startswith("/sys/fs/cgroup/") and path.name == config["unit"], "unit-cgroup-path")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "unit-cgroup-owner")
    def number(name):
        raw = (path / name).read_text().strip()
        require(re.fullmatch(r"[0-9]+", raw), "unit-limit-unbounded")
        return int(raw)
    cpu = (path / "cpu.max").read_text().split()
    require(len(cpu) == 2 and all(re.fullmatch(r"[0-9]+", item) for item in cpu)
            and int(cpu[0]) > 0 and int(cpu[1]) > 0
            and int(cpu[0]) <= config["cpus"] * int(cpu[1]), "unit-cpu-limit")
    memory, pids, swap = number("memory.max"), number("pids.max"), number("memory.swap.max")
    require(memory == config["memory_bytes"] and pids == config["pids"] and swap == 0,
            "unit-memory-pid-swap-limit")
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino,
            "cpu_max": " ".join(cpu), "memory_max": memory, "pids_max": pids, "swap_max": swap}


SHOW_FIELDS = ("Id", "Description", "LoadState", "ActiveState", "SubState", "Transient", "MainPID",
               "InvocationID", "ControlGroup", "Restart", "KillMode", "RemainAfterExit", "Triggers",
               "TriggeredBy", "UpheldBy", "NRestarts", "ExecMainStartTimestampMonotonic",
               "RuntimeMaxUSec", "TimeoutStopUSec", "ExecStop", "ExecStopPost", "Job", "OnFailure", "OnSuccess",
               "FailureAction", "SuccessAction", "StartLimitAction", "RuntimeRandomizedExtraUSec")
STOP_FIELDS = ("ExecStop", "ExecStopPost")
SIMPLE_FIELDS = tuple(name for name in SHOW_FIELDS if name not in STOP_FIELDS)
STOP_COMMAND_TYPE = "a(sasbttttuii)"


def unit_object_path(config):
    owner = config["owner"]
    require(isinstance(owner, str) and re.fullmatch(r"[0-9a-f]{32}", owner)
            and config["unit"] == "kubernetes-lens-vm-" + owner + ".service", "unit-object-path-identity")
    # The admitted name starts with a letter and contains only ASCII
    # alphanumerics, '-' and '.'. systemd encodes each non-alphanumeric byte
    # as an underscore followed by its two lowercase hexadecimal digits.
    encoded = "".join(character if character.isascii() and character.isalnum()
                      else "_" + format(ord(character), "02x") for character in config["unit"])
    return "/org/freedesktop/systemd1/unit/" + encoded


def prove_no_stop_commands(config, budget, *, cleanup=False, deadline=None):
    remaining = command_remaining(budget, cleanup, deadline)
    microseconds = int(min(5.0, remaining) * 1000000)
    require(microseconds > 0, "unit-property-deadline")
    timeout = "5s" if microseconds == 5000000 else str(microseconds) + "us"
    status, raw = run([config["tools"]["busctl"]["path"], "--user", "--no-pager",
                       "--timeout=" + timeout, "--json=short", "get-property", "org.freedesktop.systemd1",
                       unit_object_path(config), "org.freedesktop.systemd1.Service", *STOP_FIELDS],
                      budget, config["directory"], cleanup=cleanup, manager=True, deadline=deadline)
    require(status == 0, "unit-stop-properties-unavailable")
    lines = raw.splitlines()
    require(len(lines) == len(STOP_FIELDS), "unit-stop-properties-count")
    for line in lines:
        value = strict_json(line)
        require(type(value) is dict and set(value) == {"type", "data"}
                and value["type"] == STOP_COMMAND_TYPE and type(value["data"]) is list,
                "unit-stop-properties-schema")
        require(not value["data"], "unit-stop-command-present")


def duration_seconds(value):
    units = {"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600, "d": 86400}
    if value == "0":
        return 0
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h|d)", value)
    require(parts and " ".join(number + unit for number, unit in parts) == value, "unit-timer-unbounded")
    return sum(float(number) * units[unit] for number, unit in parts)


def simple_unit_show(config, budget, *, cleanup=False, deadline=None):
    status, raw = run([config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "show", config["unit"],
                       "--property=" + ",".join(SIMPLE_FIELDS)], budget, config["directory"], cleanup=cleanup, manager=True, deadline=deadline)
    result = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in SIMPLE_FIELDS and key not in result, "unit-state-schema")
        result[key] = value
    require(set(result) == set(SIMPLE_FIELDS), "unit-state-incomplete")
    require(status == 0 or status in (1, 4) and result["LoadState"] == "not-found", "unit-state-unavailable")
    require(result["Id"] == config["unit"], "unit-state-name")
    return result


def unit_show(config, budget, *, cleanup=False, deadline=None):
    result = simple_unit_show(config, budget, cleanup=cleanup, deadline=deadline)
    if result["LoadState"] == "not-found":
        require(result["ActiveState"] == "inactive" and result["MainPID"] == "0"
                and result["Job"] in ("", "0") and not result["InvocationID"] and not result["ControlGroup"],
                "unit-not-found-state-inconsistent")
        # No loaded service definition: report only the simple not-found
        # observation. It does NOT establish support or empty values for the
        # two complex service properties, and they are intentionally absent.
        return result
    prove_no_stop_commands(config, budget, cleanup=cleanup, deadline=deadline)
    after = simple_unit_show(config, budget, cleanup=cleanup, deadline=deadline)
    identity_and_policy = ("Id", "Description", "LoadState", "Transient", "InvocationID", "Restart",
                           "KillMode", "RemainAfterExit", "NRestarts", "Triggers", "TriggeredBy", "UpheldBy",
                           "OnFailure", "OnSuccess", "FailureAction", "SuccessAction", "StartLimitAction")
    require(all(after[name] == result[name] for name in identity_and_policy), "unit-changed-during-stop-proof")
    # MainPID and state may naturally advance as the genuine worker exits.
    # Return the later observation, never a stale pre-property live identity.
    result = after
    # These semantic empty values exist only after typed, successful readback.
    result.update(dict.fromkeys(STOP_FIELDS, ""))
    return result


def validate_unit(row, config, *, live=True, invocation=None):
    require(row["Id"] == config["unit"] and row["Description"] == "KubernetesLens owned VM " + config["owner"]
            and row["LoadState"] == "loaded" and row["Transient"] == "yes"
            and row["Restart"] == "no" and row["KillMode"] == "control-group"
            and row["RemainAfterExit"] == "yes" and row["NRestarts"] == "0"
            and not any(row[key] for key in ("Triggers", "TriggeredBy", "UpheldBy", "ExecStop", "ExecStopPost", "OnFailure", "OnSuccess"))
            and all(row[key] == "none" for key in ("FailureAction", "SuccessAction", "StartLimitAction")),
            "unit-ownership-or-respawn-policy")
    require(re.fullmatch(r"[0-9a-f]{32}", row["InvocationID"])
            and (invocation is None or row["InvocationID"] == invocation), "unit-invocation-drift")
    if live:
        require(row["ActiveState"] == "active" and row["SubState"] == "running"
                and re.fullmatch(r"[1-9][0-9]*", row["MainPID"])
                and row["Job"] in ("", "0"), "unit-worker-not-running")
        require(re.fullmatch(r"[1-9][0-9]*", row["ExecMainStartTimestampMonotonic"]), "unit-start-clock")
        runtime = duration_seconds(row["RuntimeMaxUSec"])
        require(runtime > 0 and int(row["ExecMainStartTimestampMonotonic"]) / 1000000 + runtime <= config["work_end"]
                and duration_seconds(row["TimeoutStopUSec"]) <= 1
                and duration_seconds(row["RuntimeRandomizedExtraUSec"]) == 0, "unit-original-runtime-guard")
    return row["InvocationID"]


def unit_arguments(config, config_path, config_sha, manager_keys):
    tools = config["tools"]
    memory, cpus = config["memory_bytes"], config["cpus"]
    seconds = math.floor(config["work_end"] - time.monotonic()) - 2
    require(seconds >= 1, "unit-activation-deadline")
    properties = {
        "Description": "KubernetesLens owned VM " + config["owner"], "Restart": "no",
        "KillMode": "control-group", "SendSIGKILL": "yes", "TimeoutStopSec": "1s",
        "RuntimeMaxSec": str(seconds), "RuntimeRandomizedExtraSec": "0", "RemainAfterExit": "yes", "CPUQuota": str(cpus * 100) + "%",
        "MemoryMax": str(memory), "MemorySwapMax": "0", "TasksMax": str(config["pids"]),
        "UMask": "0077", "LimitNOFILE": "64", "LimitCORE": "0",
        "LimitFSIZE": str(config["overlay_max"]), "LimitAS": str(memory + 4 * 1024**3),
        "LimitCPU": str(math.ceil(config["end"] - config["start"]) * cpus),
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "read-only",
        "ReadOnlyPaths": "/sys/fs/cgroup", "ReadWritePaths": config["directory"],
        "PrivateUsers": "self", "PrivateMounts": "yes", "DynamicUser": "no", "RestrictNamespaces": "yes",
        "SystemCallArchitectures": "native", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
        "SystemCallFilter": "~chroot clone3 fsconfig fsmount fsopen fspick mount mount_setattr move_mount open_tree pivot_root setns umount2 unshare",
        "SystemCallErrorNumber": "ENOSYS",
        "RestrictSUIDSGID": "yes", "LockPersonality": "yes", "RestrictRealtime": "yes",
        "StandardInput": "null", "StandardOutput": "null", "StandardError": "null",
        "InaccessiblePaths": (f"-/run/user/{os.getuid()}/bus -/run/user/{os.getuid()}/systemd "
                              "-/run/dbus/system_bus_socket -/run/podman -/run/docker.sock"),
    }
    environment = clean_environment(config["directory"])
    removals = set(manager_keys) - set(environment)
    removals.update({"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "SSH_AUTH_SOCK",
                     "SSH_AGENT_PID", "DBUS_SESSION_BUS_ADDRESS", "CONTAINER_HOST", "CONTAINER_CONNECTION"})
    properties["UnsetEnvironment"] = " ".join(sorted(removals))
    argv = [tools["systemd_run"]["path"], "--user", "--no-block", "--unit=" + config["unit"],
            "--service-type=exec"]
    for key, value in properties.items():
        argv.append("--property=" + key + "=" + value)
    for key, value in environment.items():
        argv.append("--setenv=" + key + "=" + value)
    return argv + [tools["python"]["path"], "-I", "-B", str(Path(__file__).resolve()),
                   "--_worker", str(config_path), config_sha]


def qemu_arguments(config):
    directory = Path(config["directory"])
    return [config["tools"]["qemu"]["path"], "-no-user-config", "-nodefaults", "-display", "none",
            "-monitor", "none", "-serial", "stdio", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-smp", str(config["cpus"]), "-m", str(config["guest_memory_mib"]), "-no-reboot",
            "-name", config["owner"], "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-drive", "file=" + str(directory / "overlay.qcow2") + ",if=virtio,format=qcow2,cache=none",
            "-fw_cfg", "name=opt/com.coreos/config,file=" + str(directory / "ignition.json"),
            "-nic", "user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:" + str(config["port"]) + "-:22"]


def ssh_arguments(config):
    directory = Path(config["directory"])
    options = {"BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
               "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(directory / "known_hosts"),
               "GlobalKnownHostsFile": "/dev/null", "HostKeyAlgorithms": "ssh-ed25519",
               "PubkeyAcceptedAlgorithms": "ssh-ed25519", "PasswordAuthentication": "no",
               "KbdInteractiveAuthentication": "no", "PreferredAuthentications": "publickey",
               "ControlMaster": "no", "ControlPath": "none", "ProxyCommand": "none", "ProxyJump": "none",
               "ClearAllForwardings": "yes", "ForwardAgent": "no", "ForwardX11": "no",
               "PermitLocalCommand": "no", "RequestTTY": "no", "ConnectionAttempts": "1",
               "ConnectTimeout": "15", "ServerAliveInterval": "5", "ServerAliveCountMax": "2",
               "UpdateHostKeys": "no", "EscapeChar": "none", "LogLevel": "ERROR"}
    argv = [config["tools"]["ssh"]["path"], "-F", "/dev/null", "-T", "-n", "-i", str(directory / "client_key"),
            "-p", str(config["port"])]
    for key, value in options.items():
        argv += ["-o", key + "=" + value]
    return argv + ["core@127.0.0.1", FIXED_COMMAND]


def guest_info(raw):
    require(len(raw) <= META_MAX, "guest-info-budget")
    value = strict_json(raw)
    try:
        host, version = value["host"], value["version"]
        require(host["security"]["rootless"] is False and host["serviceIsRemote"] is False
                and host["cgroupVersion"] == "v2" and host["os"] == "linux" and host["arch"] == "amd64"
                and version["Version"] == EXPECTED_PODMAN, "guest-prerequisite-mismatch")
    except (KeyError, TypeError) as error:
        raise Refusal("guest-info-schema") from error
    return {"rootful": True, "local": True, "cgroup_version": "v2", "podman_version": EXPECTED_PODMAN}


def send(channel, value, budget, *, cleanup=False):
    raw = encode(value)
    require(len(raw) <= META_MAX, "channel-message-budget")
    channel.settimeout(min(1, budget.remaining(cleanup)))
    channel.sendall(struct.pack(">I", len(raw)) + raw)


def receive(channel, budget, *, cleanup=False):
    def exact(count):
        result = bytearray()
        while len(result) < count:
            channel.settimeout(min(0.1, budget.remaining(cleanup)))
            try:
                raw = channel.recv(count - len(result))
            except socket.timeout:
                continue
            require(bool(raw), "worker-channel-closed")
            budget.charge(len(raw))
            result.extend(raw)
        return bytes(result)
    length = struct.unpack(">I", exact(4))[0]
    require(0 < length <= META_MAX, "worker-message-budget")
    return strict_json(exact(length))


def peer_identity(channel):
    pid, uid, _gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == os.getuid(), "worker-peer-owner")
    return process_identity(pid)


def verify_source(config, budget, *, host_view=None):
    check_source_bindings(config, budget)
    if host_view is None:
        require(admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-tools-drift")
    else:
        worker_pre_child(config, budget, host_view)
    for name, expected in config["input_files"].items():
        target = canonical(Path(config["directory"]) / name)
        if name != "image.qcow2":
            require(digest(read(target)) == expected["sha256"], "private-input-drift")
            continue
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and file_id(info) == expected["identity"]
                    and info.st_size <= EXPANDED_MAX, "expanded-input-identity")
            hasher, count = hashlib.sha256(), 0
            while True:
                budget.remaining()
                block = os.read(fd, 65536)
                if not block:
                    break
                count += len(block)
                require(count <= EXPANDED_MAX, "expanded-input-budget")
                hasher.update(block)
            require(file_id(os.fstat(fd)) == file_id(info) and count == info.st_size
                    and hasher.hexdigest() == expected["sha256"], "expanded-input-integrity")
        finally:
            os.close(fd)


def check_source_bindings(config, budget):
    require(boot_id() == config["boot"], "host-boot-changed")
    for name, expected in config["source"].items():
        budget.remaining()
        maximum = 32 * 1024**2 if name == str(ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json") else 4 * 1024**2
        require(digest(read(name, maximum)) == expected, "owning-source-drift")


def host_view_module(config, budget):
    """Execute exactly authenticated helper bytes; never search ambient sys.path.

    In the -I direct worker, the owning module is aliased to __main__ above, so
    helper exceptions and cancellation checks use that same owner instance.
    """
    budget.remaining()
    path = str(ROOT / "scripts/fixtures/owned_host_view.py")
    raw = read(path, 4 * 1024**2)
    require(config["source"].get(path) == digest(raw), "host-view-helper-source-drift")
    module = types.ModuleType("owned_host_view")
    module.__file__ = path
    exec(compile(raw, path, "exec"), module.__dict__)
    require(module.vm is sys.modules[__name__], "host-view-owner-module-identity")
    return module


def authenticated_module(name, config=None, budget=None):
    require(name in ("owned_guest_stage", "kind_runtime"), "owned-helper-catalogue")
    path = str(ROOT / "scripts/fixtures" / (name + ".py"))
    raw = read(path, 4 * 1024**2)
    if config is not None:
        budget.remaining()
        require(config["source"].get(path) == digest(raw), "owned-helper-source-drift")
    # dataclasses resolve defining modules via sys.modules. Keep one owner/module
    # identity, authenticate bytes before execution, and never ambient-import it.
    existing = sys.modules.get(name)
    if existing is not None and hasattr(existing, "_admitted_source_sha256"):
        require(getattr(existing, "__file__", None) == path
                and existing._admitted_source_sha256 == digest(raw), "owned-helper-module-identity")
        return existing
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module
    try:
        exec(compile(raw, path, "exec"), module.__dict__)
        module._admitted_source_sha256 = digest(raw)
        if name == "owned_guest_stage":
            require(module.vm is sys.modules[__name__], "stage-owner-module-identity")
        return module
    except BaseException:
        del sys.modules[name]
        raise


def worker_pre_child(config, budget, frame):
    check_source_bindings(config, budget)
    require(digest(read(config["manifest"])) == config["manifest_sha256"], "host-tools-manifest-drift")
    host_view_module(config, budget).validate_local(frame, config, budget)
    if config.get("phase") == "stage-inputs":
        for name, expected in config["input_files"].items():
            budget.remaining()
            target = canonical(Path(config["directory"]) / name)
            if name == "image.qcow2":
                require(file_id(target.stat()) == expected["identity"], "expanded-input-identity")
            else:
                require(digest(read(target)) == expected["sha256"], "private-input-drift")


def reap(process, budget):
    if process is None:
        return True
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        while process.poll() is None and time.monotonic() < min(budget.end - 0.5, budget.work_end + 1):
            time.sleep(0.01)
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=budget.remaining(cleanup=True))
    except subprocess.TimeoutExpired as error:
        raise Refusal("worker-child-reap-unproved") from error
    return True


def worker(path, expected):
    """Internal unit endpoint. No API accepts arbitrary guest or host commands."""
    raw = read(path)
    require(digest(raw) == expected, "worker-config-integrity")
    config = strict_json(raw)
    budget = Budget(config["end"], config["cleanup_seconds"])
    require(time.monotonic() >= config["start"] and config["work_end"] == budget.work_end, "worker-original-deadline")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    qemu = None
    selector = None
    outcome, failure, qemu_record, ssh_record = None, None, None, None
    producers, producer_records, stage_result = [], [], None
    is_stage = config.get("phase") == "stage-inputs"
    try:
        channel.settimeout(min(1, budget.remaining()))
        channel.connect(str(Path(config["directory"]) / "control.sock"))
        require(peer_identity(channel) == config["controller"], "controller-peer-identity")
        identity = process_identity(os.getpid())
        send(channel, {"stage": "barrier", "worker": identity, "config_sha256": expected}, budget)
        gate = receive(channel, budget)
        require(type(gate) is dict and set(gate) == {"stage", "config_sha256", "invocation", "cgroup", "host_view", "host_view_sha256"}
                and gate["stage"] == "go" and gate["config_sha256"] == expected, "worker-gate-schema")
        require(cgroup_snapshot(process_cgroup(os.getpid()), config) == gate["cgroup"], "worker-gate-cgroup")
        require(os.environ.get("INVOCATION_ID") == gate["invocation"], "worker-invocation-identity")
        require(digest(encode(gate["host_view"])) == gate["host_view_sha256"], "worker-host-view-integrity")
        verify_source(config, budget, host_view=gate["host_view"])
        directory = Path(config["directory"])
        status, raw_info = run([config["tools"]["qemu_img"]["path"], "info", "--output=json", "-f", "qcow2",
                                str(directory / "image.qcow2")], budget, directory)
        require(status == 0, "qemu-image-inspection-failed")
        image = strict_json(raw_info)
        require(image.get("format") == "qcow2" and type(image.get("virtual-size")) is int
                and 0 < image["virtual-size"] <= 32 * 1024**3
                and not any(key in image for key in ("backing-filename", "full-backing-filename", "encrypted")),
                "qemu-image-profile")
        worker_pre_child(config, budget, gate["host_view"])
        status, _ = run([config["tools"]["qemu_img"]["path"], "create", "-f", "qcow2", "-F", "qcow2", "-b",
                         str(directory / "image.qcow2"), str(directory / "overlay.qcow2")], budget, directory,
                        file_bytes=config["overlay_max"])
        require(status == 0, "overlay-create-failed")
        budget.remaining()
        worker_pre_child(config, budget, gate["host_view"])
        qemu = subprocess.Popen(qemu_arguments(config), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True, env=clean_environment(directory),
                                preexec_fn=child_limits(budget.remaining() * config["cpus"], config["overlay_max"],
                                                       config["memory_bytes"] + 4 * 1024**3))
        qemu_record = process_identity(qemu.pid)
        require(process_cgroup(qemu.pid) == gate["cgroup"]["path"], "qemu-placement")
        send(channel, {"stage": "qemu-started", "qemu": qemu_record}, budget)
        selector = selectors.DefaultSelector()
        for stream in (qemu.stdout, qemu.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        serial = bytearray()
        while True:
            budget.remaining()
            require(qemu.poll() is None, "qemu-exited-before-guest-check")
            for key, _ in selector.select(min(0.1, budget.remaining())):
                block = os.read(key.fd, 65536)
                require(bool(block), "qemu-console-closed")
                budget.charge(len(block))
                if key.fileobj is qemu.stdout:
                    serial.extend(block)
                    if len(serial) > 65536:
                        del serial[:-65536]
            # A boot marker is merely permission for our one authenticated SSH
            # attempt; it is not guest identity or prerequisite evidence.
            plain = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", bytes(serial))
            if re.search(rb"Reached target[^\r\n]*Multi-User System|Startup finished in", plain):
                break
        def producer_started(process, phase):
            # Retain the actual child before any identity, placement or channel
            # failure; worker finally reaps it even when registration fails.
            producers.append(process)
            record = process_identity(process.pid)
            producer_records.append({"phase": phase, "process": record})
            require(process_cgroup(process.pid) == gate["cgroup"]["path"], "ssh-placement")
            event = {"stage": "stage-producer-started", "index": len(producer_records) - 1,
                     "phase": phase, "ssh": record}
            send(channel, event, budget)
            acknowledgment = receive(channel, budget)
            require(acknowledgment == {"stage": "stage-producer-admitted", "index": event["index"],
                                       "phase": phase, "ssh": record}, "stage-producer-acknowledgment")
        def ssh_started(process):
            nonlocal ssh_record
            if is_stage:
                producer_started(process, "guest-info")
            else:
                ssh_record = process_identity(process.pid)
                require(process_cgroup(process.pid) == gate["cgroup"]["path"], "ssh-placement")
                send(channel, {"stage": "ssh-started", "ssh": ssh_record}, budget)
        worker_pre_child(config, budget, gate["host_view"])
        status, raw_info = run(ssh_arguments(config), budget, directory, extra_streams=(qemu.stdout, qemu.stderr), on_start=ssh_started)
        require(status == 0, "authenticated-guest-check-failed")
        outcome = guest_info(raw_info)
        if is_stage:
            stage = authenticated_module("owned_guest_stage", config, budget)
            plan_raw = read(directory / "stage-plan.json")
            plan = stage.parse_plan(plan_raw, config["stage_plan_sha256"])
            session = stage.Session(plan, budget, config["stage_input_limit"])
            results = []
            for phase in stage.PHASES:
                # The authenticated mapped worker view is required here. Parent
                # root ownership checks may not be rerun inside a user mapping.
                results.append(stage.transfer(session, phase, config,
                    extra_streams=(qemu.stdout, qemu.stderr),
                    on_start=lambda process, selected=phase: producer_started(process, selected),
                    pre_child=lambda: worker_pre_child(config, budget, gate["host_view"])))
            require(session.next_phase == 3 and not session.failed
                    and session.input_sent == config["stage_input_limit"], "stage-cumulative-proof")
            stage_result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256,
                            "input_bytes": session.input_sent, "replies": results}
        require(qemu.poll() is None and process_identity(qemu.pid) == qemu_record, "qemu-identity-before-retirement")
    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        failure = str(error) if isinstance(error, Refusal) else "worker-prerequisite-unavailable"
    finally:
        try:
            producer_reaped = []
            for process in producers:
                try:
                    producer_reaped.append(reap(process, budget))
                except (Refusal, OSError, subprocess.SubprocessError):
                    producer_reaped.append(False)
                    failure = failure or "worker-stage-producer-reap-unproved"
            try:
                reaped = reap(qemu, budget)
            except (Refusal, OSError, subprocess.SubprocessError):
                reaped = False
                failure = failure or "worker-qemu-reap-unproved"
            if selector:
                selector.close()
            if qemu:
                qemu.stdout.close()
                qemu.stderr.close()
            barrier = {"stage": "producer-stopped", "error": failure, "guest": outcome,
                       "qemu": qemu_record, "ssh": ssh_record, "qemu_reaped": reaped,
                       "ssh_reaped": True, "original_end": config["end"]}
            if is_stage:
                barrier.update({"producers": producer_records, "producers_reaped": producer_reaped,
                                "staging": stage_result})
            send(channel, barrier, budget, cleanup=True)
        finally:
            channel.close()

    return 1 if failure else 0


def validate_config_args(args):
    require(60 <= args.deadline_seconds <= 1800 and 10 <= args.cleanup_seconds <= 120
            and 2 * args.cleanup_seconds < args.deadline_seconds, "deadline-budget")
    require(1 <= args.cpus <= 8 and 2048 <= args.memory_mib <= 16384
            and 1024 <= args.guest_memory_mib <= args.memory_mib - 1024
            and 64 <= args.pids <= 1024 and 8 <= args.disk_gib <= 32, "vm-resource-budget")
    require(1024 <= args.ssh_port <= 65535, "loopback-port-budget")
    parent = canonical(args.output_parent)
    # QEMU's file= suboptions and systemd path-list properties have their own
    # delimiters. Do not reinterpret a caller path as configuration syntax.
    require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(parent)), "private-output-parent-syntax")
    control_path = parent / ("kubernetes-lens-vm-" + "0" * 32) / "control.sock"
    require(len(os.fsencode(control_path)) <= 107, "private-control-socket-path-budget")
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "private-output-parent-required")
    require(os.getuid() != 0 and sys.platform == "linux" and os.uname().machine == "x86_64", "host-profile-unavailable")
    require(stat.S_ISCHR(Path("/dev/kvm").stat().st_mode) and os.access("/dev/kvm", os.R_OK | os.W_OK), "kvm-unavailable")
    return parent


def attest_barrier(row, hello, peer, config, config_sha):
    invocation = validate_unit(row, config)
    require(type(hello) is dict and set(hello) == {"stage", "worker", "config_sha256"}
            and hello["stage"] == "barrier" and hello["config_sha256"] == config_sha
            and hello["worker"] == peer and int(row["MainPID"]) == peer["pid"], "worker-barrier-identity")
    require(process_identity(peer["pid"]) == peer, "worker-process-drift")
    target = "/sys/fs/cgroup" + row["ControlGroup"]
    require(process_cgroup(peer["pid"]) == target and process_cgroup(os.getpid()) != target
            and not process_cgroup(os.getpid()).startswith(target + "/"), "outside-controller-placement")
    snapshot = cgroup_snapshot(target, config)
    require(process_identity(peer["pid"]) == peer and boot_id() == config["boot"], "barrier-kernel-drift")
    return invocation, snapshot


def await_worker_connection(server, config, budget):
    """A short activation cutoff, always inside the original execution end.

    No receipt, ownership permission or runtime credit comes from a manager
    health poll. Only the subsequent authenticated barrier grants native work.
    """
    startup_end = min(budget.work_end, time.monotonic() + 10)
    next_poll = time.monotonic()
    while True:
        remaining = min(budget.remaining(), startup_end - time.monotonic())
        require(remaining > 0, "owned-worker-startup-cutoff")
        server.settimeout(min(0.1, remaining))
        try:
            channel, _ = server.accept()
            return channel
        except socket.timeout:
            pass
        if time.monotonic() >= next_poll:
            row = unit_show(config, budget, deadline=startup_end)
            require(row["Id"] == config["unit"]
                    and row["Description"] == "KubernetesLens owned VM " + config["owner"]
                    and row["LoadState"] == "loaded" and row["Transient"] == "yes",
                    "owned-worker-startup-unit-identity")
            require(row["ActiveState"] not in ("failed", "inactive", "deactivating")
                    and not (row["ActiveState"] == "active" and row["SubState"] == "exited"),
                    "owned-worker-exited-before-barrier")
            next_poll = time.monotonic() + 0.5


def process_retired(record):
    if record is None:
        return True
    try:
        current = process_identity(record["pid"])
    except FileNotFoundError:
        return True
    require(current == record, "retirement-pid-reused")
    return False


def empty_cgroup(snapshot, config):
    path = Path(snapshot["path"])
    try:
        require(cgroup_snapshot(path, config) == snapshot, "retirement-cgroup-drift")
        events = dict(line.split() for line in (path / "cgroup.events").read_text().splitlines())
        require(events.get("populated") == "0" and not (path / "cgroup.procs").read_text().strip(),
                "retirement-cgroup-populated")
        # Kernel populated=0 covers all descendants; direct membership alone does not.
        return "held-empty"
    except FileNotFoundError:
        require(not path.exists(), "retirement-partial-cgroup-disappearance")
        return "removed"


def retire(config, budget, invocation, snapshot, worker_record, qemu_record, barrier, ssh_record=None, producers=None):
    """Outside the whole target: no worker-supplied booleans establish retirement."""
    producers = [] if producers is None else producers
    row = unit_show(config, budget, cleanup=True)
    validate_unit(row, config, live=False, invocation=invocation)
    # Prevent manager-driven production first; no restart/timer/dependency surface
    # is admitted. Only our exact invocation can be stopped.
    status, _ = run([config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "stop", "--no-block", config["unit"]],
                    budget, config["directory"], cleanup=True, manager=True)
    require(status == 0, "unit-stop-failed")
    empty = []
    while len(empty) < 2:
        budget.remaining(cleanup=True)
        require(boot_id() == config["boot"], "retirement-host-boot-drift")
        row = unit_show(config, budget, cleanup=True)
        if row["LoadState"] == "not-found":
            require(row["ActiveState"] == "inactive" and row["MainPID"] == "0", "unit-unloaded-active")
        else:
            # systemd may clear InvocationID on stop. A different nonempty one
            # always quarantines; the exact pre-stop identity is retained.
            if row["InvocationID"]:
                require(row["InvocationID"] == invocation, "retirement-new-invocation")
            require(row["Restart"] == "no" and row["NRestarts"] == "0"
                    and not any(row[key] for key in ("Triggers", "TriggeredBy", "UpheldBy")), "retirement-respawn-policy")
        inactive = row["ActiveState"] in ("inactive", "failed") and row["MainPID"] == "0" and row["Job"] in ("", "0")
        if (inactive and process_retired(worker_record) and process_retired(qemu_record) and process_retired(ssh_record)
                and all(process_retired(item["process"]) for item in producers)):
            empty.append({"at": time.monotonic(), "cgroup": empty_cgroup(snapshot, config)})
        else:
            empty.clear()
        if len(empty) < 2:
            time.sleep(min(0.1, budget.remaining(cleanup=True)))
    fields = {"stage", "error", "guest", "qemu", "ssh", "qemu_reaped", "ssh_reaped", "original_end"}
    if config.get("phase") == "stage-inputs":
        fields |= {"producers", "producers_reaped", "staging"}
        require(type(barrier) is dict and barrier.get("producers") == producers
                and len(barrier.get("producers_reaped", [])) == len(producers)
                and all(value is True for value in barrier["producers_reaped"]), "stage-producer-barrier-unproved")
    require(type(barrier) is dict and set(barrier) == fields
            and barrier["stage"] == "producer-stopped" and barrier["original_end"] == config["end"]
            and barrier["qemu"] == qemu_record and barrier["ssh"] == ssh_record and barrier["qemu_reaped"] is True
            and barrier["ssh_reaped"] is True, "producer-barrier-unproved")
    return {"state": "retired", "observations": empty, "invocation": invocation,
            "worker": worker_record, "qemu": qemu_record, "ssh": ssh_record, "cgroup": snapshot, "boot": config["boot"],
            **({"producers": producers} if config.get("phase") == "stage-inputs" else {})}


def admit_producer_event(event, records, qemu, snapshot, *, allow_retired=False):
    phases = ("guest-info", "stage-kind", "stage-kubectl", "stage-node-oci")
    require(type(event) is dict and set(event) == {"stage", "index", "phase", "ssh"}
            and event["stage"] == "stage-producer-started" and type(event["index"]) is int
            and event["index"] == len(records) < len(phases) and event["phase"] == phases[len(records)]
            and qemu is not None, "stage-producer-event-schema")
    record = event["ssh"]
    require(type(record) is dict and set(record) == {"pid", "group", "session", "start"}
            and all(type(value) is int and value > 0 for value in record.values())
            and record["group"] == record["session"] == record["pid"]
            and all(item["process"]["pid"] != record["pid"] for item in records), "stage-producer-identity-schema")
    # Retain structurally valid identity even if placement readback fails; it can
    # never become a positive admission, but outside retirement must account it.
    records.append({"phase": event["phase"], "process": record})
    try:
        require(process_identity(record["pid"]) == record and process_cgroup(record["pid"]) == snapshot["path"],
                "stage-producer-external-identity")
    except FileNotFoundError:
        require(allow_retired, "stage-producer-disappeared-before-admission")


def validate_stage_result(result, plan, stage, config):
    require(type(result) is dict and set(result) == {"state", "plan_sha256", "input_bytes", "replies"}
            and result["state"] == "stage-replies-observed" and result["plan_sha256"] == plan.sha256
            and type(result["input_bytes"]) is int and result["input_bytes"] == config["stage_input_limit"]
            and type(result["replies"]) is list and len(result["replies"]) == 3, "stage-result-schema")
    for phase, file, observed in zip(stage.PHASES, plan.files, result["replies"]):
        expected = {"schema": "kubernetes-lens-owned-guest-stage-reply-v1", "owner": plan.owner,
                    "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                    "bytes": file.size, "sha256": file.sha256, "state": "stage-reply-observed",
                    "vm_retirement": "not-established", "runtime_conformance": "not-performed"}
        require(type(observed) is dict and type(observed.get("bytes")) is int and observed == expected,
                "stage-result-reply-mismatch")


def parent_pre_child(config, budget):
    """Fresh strict parent source/tool authority, even before private inputs exist."""
    check_source_bindings(config, budget)
    require(admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-tools-drift")
    budget.remaining()


def validated_guest_summary(value):
    """Return only a newly constructed closed summary after strict equality."""
    expected = {"rootful": True, "local": True, "cgroup_version": "v2", "podman_version": EXPECTED_PODMAN}
    require(type(value) is dict and set(value) == set(expected) and value == expected
            and value["rootful"] is True and value["local"] is True, "guest-result-unproved")
    return expected


def qualify(args, *, start=None):
    start = time.monotonic() if start is None else start
    parent = validate_config_args(args)
    budget = Budget(start + args.deadline_seconds, args.cleanup_seconds)
    tools = admit_tools(args.host_tools, args.host_tools_sha256)
    pin, pin_sha = pin_document()
    owner = uuid.uuid4().hex
    directory = parent / ("kubernetes-lens-vm-" + owner)
    directory.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel, invocation, snapshot, worker_record, qemu_record, ssh_record, barrier = None, None, None, None, None, None, None
    error, cleanup_error, retirement = None, None, None
    attempted = False
    view, view_frame = None, None
    config = {"owner": owner, "unit": "kubernetes-lens-vm-" + owner + ".service",
              "directory": str(directory), "start": start, "end": budget.end, "work_end": budget.work_end,
              "cleanup_seconds": args.cleanup_seconds, "cpus": args.cpus, "pids": args.pids,
              "memory_bytes": args.memory_mib * 1024**2, "guest_memory_mib": args.guest_memory_mib,
              "disk_bytes": args.disk_gib * 1024**3,
              "overlay_max": args.disk_gib * 1024**3 - ARCHIVE_MAX - EXPANDED_MAX - 4 * 1024**2,
              "port": args.ssh_port, "tools": tools, "manifest": str(canonical(args.host_tools)),
              "manifest_sha256": args.host_tools_sha256, "controller": process_identity(os.getpid()),
              "boot": boot_id(), "source": {str(Path(__file__).resolve()): digest(read(Path(__file__).resolve(), 4 * 1024**2)),
                                             str(ROOT / "scripts/fixtures/kind_runtime.py"): digest(read(ROOT / "scripts/fixtures/kind_runtime.py", 4 * 1024**2)),
                                             str(PIN): pin_sha,
                                             str(ROOT / "scripts/fixtures/owned_host_view.py"): digest(read(ROOT / "scripts/fixtures/owned_host_view.py", 4 * 1024**2))}}
    image_evidence, stage_evidence, guest_summary = None, None, None
    producer_records = []
    is_stage = getattr(args, "phase", "qualify-vm") == "stage-inputs"
    try:
        if is_stage:
            config["phase"] = "stage-inputs"
            for name in ("owned_guest_stage.py", "owned_guest_receiver.sh"):
                path = ROOT / "scripts/fixtures" / name
                config["source"][str(path)] = digest(read(path, 4 * 1024**2))
            ledger_path = ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json"
            config["source"][str(ledger_path)] = digest(read(ledger_path, 32 * 1024**2))
            stage = authenticated_module("owned_guest_stage", config, budget)
            native = authenticated_module("kind_runtime", config, budget)
            try:
                plan_raw, plan, stage_evidence = stage.admit_inputs(args, owner, budget, native.select_profile)
            except native.Refusal as caught:
                raise Refusal(caught.code) from caught
            require(stage_evidence["ledger_sha256"] == config["source"][str(ledger_path)], "stage-ledger-source-drift")
            payload_bytes = sum(file.size for file in plan.files)
            # Existing immutable inputs + one capped overlay + metadata share
            # the original disk envelope. Guest staging has no other disk/share.
            # Reserve the full immutable admitted ceiling, never a preliminary
            # stat that can name a different object from admit_archive below.
            source_archive_bytes = ARCHIVE_MAX
            require(payload_bytes + source_archive_bytes + META_MAX < config["overlay_max"], "stage-storage-budget")
            config["overlay_max"] -= payload_bytes + source_archive_bytes
            config["stage_plan_sha256"] = plan.sha256
            config["stage_input_limit"] = payload_bytes + 40
            stage_evidence["storage"] = {"source_payload_bytes": payload_bytes, "source_vm_archive_reserved_bytes": source_archive_bytes,
                "guest_payload_bytes": payload_bytes,
                "overlay_max": config["overlay_max"], "host_total_max": config["disk_bytes"],
                "guest_storage_in_overlay": True}
            write(directory / "stage-plan.json", plan_raw)
        image_evidence = admit_archive(args.image, directory, pin, budget)
        if is_stage:
            require(type(image_evidence.get("archive_bytes")) is int
                    and 0 < image_evidence["archive_bytes"] <= ARCHIVE_MAX, "stage-storage-reservation-exceeded")
        # Reserve the explicit listener before boot. Releasing it creates a port
        # race, but a foreign endpoint cannot pass the per-run host-key check.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", args.ssh_port))
        for name in (("client_key", "host_key", "stage_key") if is_stage else ("client_key", "host_key")):
            parent_pre_child(config, budget)
            status, _ = run([tools["ssh_keygen"]["path"], "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(directory / name)], budget, directory)
            require(status == 0, "task-key-generation-failed")
        client_public = read(directory / "client_key.pub").decode("ascii")
        host_public = read(directory / "host_key.pub").decode("ascii")
        stage_options = {}
        if is_stage:
            receiver_path = ROOT / "scripts/fixtures/owned_guest_receiver.sh"
            receiver = read(receiver_path)
            require(digest(receiver) == config["source"][str(receiver_path)], "stage-receiver-source-drift")
            stage_options = {"stage_public": read(directory / "stage_key.pub").decode("ascii"),
                             "stage_files": stage.guest_files(plan_raw, receiver)}
        write(directory / "ignition.json", encode(ignition(client_public, read(directory / "host_key").decode("ascii"), host_public, **stage_options)))
        write(directory / "known_hosts", ("[127.0.0.1]:" + str(args.ssh_port) + " " + host_public.strip() + "\n").encode())
        # Ignition retains the host private key; remove its redundant host copy.
        (directory / "host_key").unlink()
        (directory / "host_key.pub").unlink()
        config["input_files"] = {name: {"sha256": digest(read(directory / name))}
                                 for name in (("ignition.json", "client_key", "client_key.pub", "known_hosts", "stage_key", "stage_key.pub", "stage-plan.json")
                                              if is_stage else ("ignition.json", "client_key", "client_key.pub", "known_hosts"))}
        config["input_files"]["image.qcow2"] = {"sha256": image_evidence["expanded_sha256"],
                                                 "identity": file_id((directory / "image.qcow2").stat())}
        config_path = directory / "config.json"
        raw_config = encode(config)
        write(config_path, raw_config)
        config_sha = digest(raw_config)
        server.bind(str(directory / "control.sock"))
        server.listen(1)
        parent_pre_child(config, budget)
        status, manager_environment = run([tools["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "show-environment"], budget, directory, manager=True)
        require(status == 0, "user-manager-unavailable")
        manager_keys = []
        for line in manager_environment.decode("utf-8").splitlines():
            key = line.partition("=")[0]
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key), "user-manager-environment-schema")
            manager_keys.append(key)
        verify_source(config, budget)
        view = host_view_module(config, budget).ParentView(config, budget)
        parent_pre_child(config, budget)
        attempted = True
        status, _ = run(unit_arguments(config, config_path, config_sha, manager_keys), budget, directory, manager=True)
        require(status == 0, "owned-unit-start-failed")
        channel = await_worker_connection(server, config, budget)
        worker_record = peer_identity(channel)
        hello = receive(channel, budget)
        row = unit_show(config, budget)
        invocation, snapshot = attest_barrier(row, hello, worker_record, config, config_sha)
        verify_source(config, budget)
        view_frame = view.attest(worker_record, invocation, snapshot, config_sha)
        view.recheck()
        send(channel, {"stage": "go", "config_sha256": config_sha, "invocation": invocation, "cgroup": snapshot,
                       "host_view": view_frame if view_frame is not None else view.partial if view is not None else None, "host_view_sha256": digest(encode(view_frame))}, budget)
        while True:
            event = receive(channel, budget)
            if event.get("stage") == "qemu-started":
                require(qemu_record is None and set(event) == {"stage", "qemu"}, "qemu-start-event-schema")
                qemu_record = event["qemu"]
                require(process_identity(qemu_record["pid"]) == qemu_record
                        and process_cgroup(qemu_record["pid"]) == snapshot["path"], "qemu-external-identity")
            elif is_stage and event.get("stage") == "stage-producer-started":
                admit_producer_event(event, producer_records, qemu_record, snapshot)
                send(channel, {"stage": "stage-producer-admitted", "index": event["index"],
                               "phase": event["phase"], "ssh": event["ssh"]}, budget)
            elif not is_stage and event.get("stage") == "ssh-started":
                require(ssh_record is None and set(event) == {"stage", "ssh"} and qemu_record is not None, "ssh-start-event-schema")
                ssh_record = event["ssh"]
                try:
                    require(process_identity(ssh_record["pid"]) == ssh_record
                            and process_cgroup(ssh_record["pid"]) == snapshot["path"], "ssh-external-identity")
                except FileNotFoundError:
                    pass
            else:
                break
        barrier = event
        require(event.get("stage") == "producer-stopped", "producer-stage")
        if event.get("error"):
            raise Refusal(event["error"])
        guest_summary = validated_guest_summary(event.get("guest"))
        if is_stage:
            validate_stage_result(event.get("staging"), plan, stage, config)
            require(len(producer_records) == 4, "stage-producer-count")
    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:
        error = str(caught) if isinstance(caught, Refusal) else "vm-prerequisite-unavailable"
    finally:
        server.close()
        if view is not None:
            view.close()
        if attempted:
            try:
                # Even failure before GO may leave a waiting worker. Adopt only
                # this uniquely described transient invocation, never a caller unit.
                if invocation is None:
                    row = unit_show(config, budget, cleanup=True)
                    invocation = validate_unit(row, config)
                    worker_record = process_identity(int(row["MainPID"]))
                    snapshot = cgroup_snapshot("/sys/fs/cgroup" + row["ControlGroup"], config)
                if channel is not None and barrier is None:
                    row = unit_show(config, budget, cleanup=True)
                    validate_unit(row, config, live=False, invocation=invocation)
                    status, _ = run([tools["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "kill", "--kill-whom=main", "--signal=SIGTERM", config["unit"]],
                                    budget, directory, cleanup=True, manager=True)
                    require(status == 0, "worker-cancellation-unavailable")
                    for _ in range(6 if is_stage else 3):
                        event = receive(channel, budget, cleanup=True)
                        if event.get("stage") == "producer-stopped":
                            barrier = event
                            break
                        if event.get("stage") == "qemu-started" and qemu_record is None:
                            qemu_record = event["qemu"]
                        elif event.get("stage") == "ssh-started" and ssh_record is None and qemu_record is not None:
                            ssh_record = event["ssh"]
                        elif is_stage and event.get("stage") == "stage-producer-started":
                            # Cancellation never authorizes more payload. Retain
                            # identity for outside retirement; no GO is sent.
                            admit_producer_event(event, producer_records, qemu_record, snapshot, allow_retired=True)
                        else:
                            raise Refusal("cancellation-event-order")
                retirement = retire(config, budget, invocation, snapshot, worker_record, qemu_record, barrier, ssh_record, producer_records)
            except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:
                cleanup_error = str(caught) if isinstance(caught, Refusal) else "outside-retirement-unavailable"
        if channel:
            channel.close()
        # No target was started: removal is safe. Once started, uncertainty keeps
        # the private lease/evidence and forbids a positive receipt or deletion.
        if not attempted or retirement is not None:
            try:
                budget.remaining(cleanup=True)
                shutil.rmtree(directory)
            except (OSError, Refusal):
                cleanup_error = cleanup_error or "private-artifact-retirement-unproved"
    if CANCELLED:
        error = error or "cancelled"
    success = error is None and cleanup_error is None and retirement is not None
    private = {"schema": "kubernetes-lens-owned-vm-receipt-v1", "owner": owner,
               "state": ("stage-inputs-retired" if is_stage else "vm-qualified-retired") if success else "failed-quarantined" if cleanup_error else "failed-retired",
               "error": error, "retirement_error": cleanup_error, "boot": config["boot"],
               "unit": config["unit"], "source": config["source"], "tools": tools, "image": image_evidence,
               "guest_info": guest_summary,
               "start": start, "original_end": budget.end, "finished": time.monotonic(), "retirement": retirement,
               "control_plane": {"commands_remaining": budget.commands_left, "output_bytes_remaining": budget.output_left,
                                 "target_limits_cover_controller": False},
               "host_view": view_frame if view_frame is not None else view.partial if view is not None else None,
               "runtime_conformance": "not-performed", "kubernetes_readiness": "not-performed"}
    if is_stage:
        private["staging"] = stage_evidence
        private["stage_result"] = barrier.get("staging") if type(barrier) is dict else None
    # The receipt contains identities, never key material, raw guest JSON or logs.
    receipt_path = parent / ("kubernetes-lens-vm-" + owner + ".receipt.json")
    budget.remaining(cleanup=True)
    write(receipt_path, encode(private))
    try:
        budget.remaining(cleanup=True)
    except Refusal:
        receipt_path.unlink()
        raise
    return {"state": private["state"], "owner": owner, "error": error, "retirement_error": cleanup_error,
            "receipt_sha256": digest(encode(private)), "runtime_conformance": "not-performed"}, 0 if success else 1


def publish_receipt(value, end, *, descriptor=1):
    """Never block final publication or leave buffered output for interpreter exit."""
    raw = encode(value) + b"\n"
    require(len(raw) <= META_MAX, "public-receipt-budget")
    offset = 0
    try:
        previous_blocking = os.get_blocking(descriptor)
        os.set_blocking(descriptor, False)
    except OSError:
        return False
    try:
        while offset < len(raw):
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            try:
                written = os.write(descriptor, raw[offset:])
            except BlockingIOError:
                try:
                    select.select([], [descriptor], [], min(0.1, remaining))
                except InterruptedError:
                    pass
                except OSError:
                    return False
                continue
            except InterruptedError:
                continue
            except OSError:
                return False
            if written <= 0:
                return False
            offset += written
        return time.monotonic() <= end
    finally:
        # No Python buffered write is used; restore the inherited descriptor's
        # mode without leaving an interpreter-exit flush to wait on a full pipe.
        try:
            os.set_blocking(descriptor, previous_blocking)
        except OSError:
            pass


def main(argv=None):
    global CANCELLED
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--self-test"]:
        import unittest
        import test_owned_qemu
        import test_owned_host_view
        import test_owned_guest_stage
        import test_owned_guest_receiver
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module)
                                   for module in (test_owned_qemu, test_owned_host_view, test_owned_guest_stage, test_owned_guest_receiver))
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    if argv and argv[0] == "--_worker":
        require(len(argv) == 3, "worker-argument-schema")
        previous = {}
        def cancelled(number, _frame):
            global CANCELLED
            CANCELLED = CANCELLED or number
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, cancelled)
        try:
            return worker(argv[1], argv[2])
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["qualify-vm", "stage-inputs"], required=True)
    for name in ("image", "host-tools", "host-tools-sha256", "output-parent"):
        parser.add_argument("--" + name, required=True)
    for name in ("cpus", "memory-mib", "guest-memory-mib", "pids", "disk-gib", "deadline-seconds", "cleanup-seconds", "ssh-port"):
        parser.add_argument("--" + name, required=True, type=int)
    for name in ("profile", "kind", "kubectl", "canonical-owner", "node-parent", "node-manifest", "node-config", "node-archive"):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    selected = (args.profile, args.kind, args.kubectl, args.node_parent, args.node_manifest, args.node_config, args.node_archive)
    if args.phase == "stage-inputs" and not all(selected):
        parser.error("stage-inputs requires exact profile, kind/kubectl and node parent/manifest/config/archive paths")
    if args.phase == "qualify-vm" and (any(selected) or args.canonical_owner):
        parser.error("staging options require explicit stage-inputs phase")
    start = time.monotonic()
    # Invalid options never start native work; even their refusal publication is
    # bounded. Valid invocations share this exact end with qualify and cleanup.
    end = start + (args.deadline_seconds if 60 <= args.deadline_seconds <= 1800 else 1)
    os.umask(0o077)
    # Own the outside control-plane process as well as each of its bounded
    # subprocesses. These limits are not represented as target-cgroup proof.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (EXPANDED_MAX, EXPANDED_MAX))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    previous = {}
    def cancelled(number, _frame):
        global CANCELLED
        CANCELLED = CANCELLED or number
    for number in (signal.SIGTERM, signal.SIGINT):
        previous[number] = signal.signal(number, cancelled)
    try:
        try:
            receipt, status = qualify(args, start=start)
        except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
            receipt, status = {"state": "unavailable", "error": str(error) if isinstance(error, Refusal) else "prerequisite-unavailable"}, 1
        published = publish_receipt(receipt, end)
        return 128 + CANCELLED if CANCELLED else status if published else 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.exit(main())
