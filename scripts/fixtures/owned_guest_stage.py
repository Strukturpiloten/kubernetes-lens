"""Finite source-bound staging into one explicitly owned disposable guest.

Admission, receiver and outside retirement remain separate from native conformance.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import re
import zlib
import subprocess
import threading
import time
from types import MappingProxyType

import owned_qemu as vm

CHUNK = 65536
CLIENT_MAX = 128 * 1024**2
ARCHIVE_MAX = 2 * 1024**3
LAYER_EXPANDED_MAX = 2 * 1024**3
EXPANDED_TOTAL_MAX = 4 * 1024**3
PHASES = ("stage-kind", "stage-kubectl", "stage-node-oci")
ROLES = ("kind", "kubectl", "node-oci")
GUEST_NAMES = MappingProxyType({"kind": "kind", "kubectl": "kubectl", "node-oci": "node.oci.tar"})
MAX_INPUT = 2 * CLIENT_MAX + ARCHIVE_MAX + sum(len(phase) + 1 for phase in PHASES)
RECEIVER_COMMAND = ("/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin "
                    "/var/lib/kubernetes-lens-stage/receiver")


class StageRefusal(vm.Refusal):
    def __init__(self, code, retirement_error=None):
        super().__init__(code)
        self.code = code
        self.retirement_error = retirement_error


@dataclass(frozen=True)
class FilePlan:
    role: str
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Plan:
    owner: str
    profile: str
    files: tuple
    sha256: str


def parse_plan(raw, expected_sha256):
    """Identity admission only; caller must establish ledger/OCI provenance."""
    vm.require(type(raw) is bytes and len(raw) <= vm.META_MAX, "stage-plan-budget")
    vm.require(isinstance(expected_sha256, str) and vm.HEX.fullmatch(expected_sha256)
               and vm.digest(raw) == expected_sha256, "stage-plan-integrity")
    item = vm.strict_json(raw)
    vm.require(type(item) is dict and set(item) == {"schema", "owner", "profile", "files"}
               and item["schema"] == "kubernetes-lens-owned-guest-stage-plan-v1"
               and isinstance(item["owner"], str) and len(item["owner"]) == 32
               and all(character in "0123456789abcdef" for character in item["owner"])
               and item["profile"] in ("legacy-1.20.15", "modern-1.37.0")
               and type(item["files"]) is dict and set(item["files"]) == set(ROLES), "stage-plan-schema")
    files = []
    for role in ROLES:
        record = item["files"][role]
        vm.require(type(record) is dict and set(record) == {"path", "bytes", "sha256"}, "stage-file-schema")
        vm.require(isinstance(record["path"], str) and len(record["path"]) <= 4096
                   and "\x00" not in record["path"], "stage-file-path")
        path = Path(record["path"])
        vm.require(path.is_absolute() and str(path) == os.path.normpath(record["path"]), "stage-file-path")
        maximum = ARCHIVE_MAX if role == "node-oci" else CLIENT_MAX
        vm.require(type(record["bytes"]) is int and 0 < record["bytes"] <= maximum
                   and isinstance(record["sha256"], str) and vm.HEX.fullmatch(record["sha256"]), "stage-file-identity")
        files.append(FilePlan(role, str(path), record["bytes"], record["sha256"]))
    return Plan(item["owner"], item["profile"], tuple(files), expected_sha256)


class Session:
    """Single caller-owned, non-concurrent phase cursor and cumulative input cap.

    This object supplies no VM ownership or native authority. Never reconstruct
    it to retry an ambiguous phase; any failed exchange poisons this session.
    """
    def __init__(self, plan, budget, input_limit):
        vm.require(type(plan) is Plan and type(budget) is vm.Budget, "stage-original-budget-required")
        total = sum(file.size + len(phase) + 1 for file, phase in zip(plan.files, PHASES))
        vm.require(type(input_limit) is int and total <= input_limit <= MAX_INPUT, "stage-cumulative-input-cap")
        self.plan, self.budget = plan, budget
        self.input_limit, self.input_sent = input_limit, 0
        self.next_phase, self.failed, self.busy = 0, False, False
        self._lock = threading.Lock()

    def charge(self, count):
        vm.require(type(count) is int and 0 <= count <= self.input_limit - self.input_sent, "stage-input-budget")
        self.input_sent += count


def open_source(file):
    """Walk each component by directory FD with O_NOFOLLOW, retaining the parent."""
    parts = Path(file.path).parts
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        source = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(source)
            vm.require(stat.S_ISREG(info.st_mode) and info.st_size == file.size, "stage-source-regular-size")
            return source, parent, parts[-1], vm.file_id(info)
        except BaseException:
            os.close(source)
            raise
    except BaseException:
        os.close(parent)
        raise


def source_identity(source, parent, name, identity):
    vm.require(vm.file_id(os.fstat(source)) == identity
               and vm.file_id(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
               "stage-source-identity-drift")


def hash_source(source, parent, name, identity, file, budget):
    hasher, count = hashlib.sha256(), 0
    while True:
        budget.remaining()
        raw = os.read(source, min(CHUNK, file.size + 1 - count))
        if not raw:
            break
        count += len(raw)
        vm.require(count <= file.size, "stage-source-growth")
        hasher.update(raw)
    source_identity(source, parent, name, identity)
    vm.require(count == file.size and hasher.hexdigest() == file.sha256, "stage-source-integrity")
    os.lseek(source, 0, os.SEEK_SET)


def ssh_arguments(config):
    """Reuse reviewed isolation options; replace only DEVNULL/one fixed command."""
    argv = vm.ssh_arguments(config)
    vm.require(argv.count("-n") == 1 and argv[-2:] == ["core@127.0.0.1", vm.FIXED_COMMAND],
               "stage-ssh-command-contract")
    argv.remove("-n")
    argv[-1] = RECEIVER_COMMAND
    index = argv.index("-i")
    argv[index + 1] = str(Path(config["directory"]) / "stage_key")
    return argv


def reply(raw, plan, phase, file):
    vm.require(len(raw) <= vm.META_MAX and raw.endswith(b"\n") and len(raw.splitlines()) == 1,
               "stage-reply-framing")
    item = vm.strict_json(raw)
    expected = {"schema": "kubernetes-lens-owned-guest-stage-reply-v1", "owner": plan.owner,
                "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                "bytes": file.size, "sha256": file.sha256, "state": "staged"}
    vm.require(type(item) is dict and type(item.get("bytes")) is int and item == expected, "stage-reply-mismatch")
    return {**expected, "state": "stage-reply-observed", "vm_retirement": "not-established",
            "runtime_conformance": "not-performed"}


def transfer(session, phase, config, *, extra_streams=(), on_start, pre_child=None):
    vm.require(type(session) is Session, "stage-session-unavailable")
    vm.require(session._lock.acquire(blocking=False), "stage-session-busy")
    try:
        return _transfer(session, phase, config, extra_streams=extra_streams, on_start=on_start, pre_child=pre_child)
    finally:
        session._lock.release()


def _transfer(session, phase, config, *, extra_streams, on_start, pre_child):
    """One finite role exchange under an existing admitted worker's exact Budget.

    on_start must register the SSH child with the owning VM producer; its caller
    and receiver are bound by the separate explicitly selected VM caller.
    """
    vm.require(type(session) is Session and not session.busy and not session.failed,
               "stage-session-unavailable")
    vm.require(session.next_phase < len(PHASES) and phase == PHASES[session.next_phase], "stage-phase-order")
    vm.require(callable(on_start) and len(extra_streams) <= 2
               and len({stream.fileno() for stream in extra_streams}) == len(extra_streams), "stage-peer-contract")
    budget, plan = session.budget, session.plan
    file = plan.files[session.next_phase]
    vm.require(config["owner"] == plan.owner and config["end"] == budget.end
               and config["work_end"] == budget.work_end and config["stage_plan_sha256"] == plan.sha256
               and str(Path(__file__).resolve()) in config["source"], "stage-caller-binding")
    session.busy = True
    source = parent = None
    process = selector = None
    stdin_closed = False
    original_blocking = []
    failure, retirement_error, result = None, None, None
    try:
        header = phase.encode("ascii") + b"\n"
        vm.require(file.size + len(header) <= session.input_limit - session.input_sent, "stage-input-budget")
        source, parent, name, identity = open_source(file)
        hash_source(source, parent, name, identity, file, budget)
        (pre_child if pre_child is not None else lambda: vm.verify_source(config, budget))()
        seconds = budget.remaining()
        budget.commands_left -= 1
        vm.require(budget.commands_left >= 0, "command-budget")
        process = subprocess.Popen(ssh_arguments(config), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                                   env=vm.clean_environment(config["directory"]),
                                   preexec_fn=vm.child_limits(seconds, vm.META_MAX))
        selector = selectors.DefaultSelector()
        on_start(process)
        for stream in (process.stdin, process.stdout, process.stderr, *extra_streams):
            if stream in extra_streams:
                info = os.fstat(stream.fileno())
                original_blocking.append((stream.fileno(), os.get_blocking(stream.fileno()), (info.st_dev, info.st_ino)))
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if stream is process.stdin else selectors.EVENT_READ)
        output_pending = {process.stdout, process.stderr}
        response = bytearray()
        pending, is_payload = header, False
        read_count, written_count = 0, 0
        sent_hash = hashlib.sha256()

        def close_stdin():
            nonlocal stdin_closed
            if not stdin_closed:
                selector.unregister(process.stdin)
                stdin_closed = True
                process.stdin.close()

        while output_pending or not stdin_closed:
            budget.remaining()
            for key, _events in selector.select(min(0.1, budget.remaining())):
                if key.fileobj is process.stdin:
                    if not pending:
                        if read_count == file.size:
                            vm.require(not os.read(source, 1), "stage-source-growth")
                            vm.require(written_count == file.size and sent_hash.hexdigest() == file.sha256,
                                       "stage-transmitted-integrity")
                            source_identity(source, parent, name, identity)
                            close_stdin()
                            continue
                        pending = os.read(source, min(CHUNK, file.size - read_count))
                        vm.require(bool(pending), "stage-source-truncated")
                        read_count += len(pending)
                        is_payload = True
                    vm.require(len(pending) <= CHUNK and len(pending) <= session.input_limit - session.input_sent,
                               "stage-input-budget")
                    try:
                        count = os.write(key.fd, pending)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except BrokenPipeError as error:
                        raise StageRefusal("stage-stdin-broken-pipe") from error
                    vm.require(0 < count <= len(pending), "stage-stdin-zero-write")
                    session.charge(count)
                    if is_payload:
                        written_count += count
                        sent_hash.update(pending[:count])
                    pending = pending[count:]
                else:
                    try:
                        raw = os.read(key.fd, CHUNK)
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not raw:
                        selector.unregister(key.fileobj)
                        output_pending.discard(key.fileobj)
                        continue
                    budget.charge(len(raw))
                    if key.fileobj is process.stdout:
                        response.extend(raw)
                        vm.require(len(response) <= vm.META_MAX, "stage-reply-budget")
        while process.poll() is None:
            time.sleep(min(0.01, budget.remaining()))
        vm.require(process.returncode == 0, "stage-ssh-failed")
        budget.remaining()
        result = reply(bytes(response), plan, phase, file)
    except (vm.Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        failure = error if isinstance(error, vm.Refusal) else StageRefusal("stage-unavailable")
    except BaseException:
        session.failed = True
        raise
    finally:
        if process is not None:
            if not stdin_closed:
                try:
                    process.stdin.close()
                except OSError:
                    retirement_error = "stage-stdin-closure-unproved"
                stdin_closed = True
            if selector:
                try:
                    selector.close()
                except OSError:
                    retirement_error = retirement_error or "stage-selector-retirement-unproved"
            try:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=max(0, budget.end - time.monotonic()))
                budget.remaining(cleanup=True)
            except (vm.Refusal, OSError, subprocess.SubprocessError):
                retirement_error = "stage-ssh-retirement-unproved"
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    retirement_error = retirement_error or "stage-stream-retirement-unproved"
        for descriptor, blocking, identity in original_blocking:
            # Only caller-owned QEMU streams survive the helper. Never touch a
            # recycled descriptor belonging to a now-closed SSH pipe.
            try:
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) != identity:
                    retirement_error = retirement_error or "stage-stream-restoration-unproved"
                else:
                    os.set_blocking(descriptor, blocking)
            except OSError:
                retirement_error = retirement_error or "stage-stream-restoration-unproved"
        if source is not None:
            os.close(source)
        if parent is not None:
            os.close(parent)
        session.busy = False
        if failure or retirement_error:
            session.failed = True
    if failure or retirement_error:
        raise StageRefusal(str(failure) if failure else "stage-transport-retirement-failed", retirement_error)
    session.next_phase += 1
    return result


def descriptor(value, *, media=None):
    vm.require(type(value) is dict and set(value) == {"mediaType", "size", "digest"}
               and type(value["size"]) is int and 0 < value["size"] <= ARCHIVE_MAX
               and isinstance(value["digest"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
               and (media is None or value["mediaType"] in media), "stage-oci-descriptor")
    return value


def admit_oci(path, parent_raw, manifest_raw, config_raw, profile, budget):
    """No extraction/import: authenticate exact bounded regular USTAR OCI members.

    The original selected raw OCI or frozen Docker schema2 manifest must be
    preserved. The local OCI index is a selection envelope, not the upstream
    parent. Carrying Docker media bytes proves no importer interoperability.
    """
    parent, manifest, config = (vm.strict_json(raw) for raw in (parent_raw, manifest_raw, config_raw))
    vm.require(vm.digest(parent_raw) == profile["node_image"].split("@sha256:")[1]
               and type(parent) is dict and set(parent) == {"schemaVersion", "mediaType", "manifests"}
               and parent["schemaVersion"] == 2 and type(parent["schemaVersion"]) is int
               and parent["mediaType"] in ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
               and type(parent["manifests"]) is list and 0 < len(parent["manifests"]) <= 8, "stage-oci-parent")
    selected = []
    for item in parent["manifests"]:
        vm.require(type(item) is dict and set(item) == {"mediaType", "size", "digest", "platform"}
                   and type(item["platform"]) is dict, "stage-oci-platform")
        record = descriptor({key: item[key] for key in ("mediaType", "size", "digest")})
        if item["platform"].get("architecture") == "amd64" and item["platform"].get("os") == "linux":
            vm.require(item["platform"] == {"architecture": "amd64", "os": "linux"}, "stage-oci-platform-variant")
            selected.append(record)
    vm.require(len(selected) == 1, "stage-oci-amd64-ambiguous")
    chosen = selected[0]
    vm.require(len(manifest_raw) == chosen["size"] and vm.digest(manifest_raw) == chosen["digest"][7:]
               and type(manifest) is dict and set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
               and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 2
               and manifest["mediaType"] == chosen["mediaType"]
               and manifest["mediaType"] in ("application/vnd.oci.image.manifest.v1+json",
                                              "application/vnd.docker.distribution.manifest.v2+json"),
               "stage-oci-preserved-manifest-unavailable")
    docker = manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json"
    config_media = "application/vnd.docker.container.image.v1+json" if docker else "application/vnd.oci.image.config.v1+json"
    layer_media = "application/vnd.docker.image.rootfs.diff.tar.gzip" if docker else "application/vnd.oci.image.layer.v1.tar+gzip"
    cfg = descriptor(manifest["config"], media={config_media})
    vm.require(vm.digest(config_raw) == cfg["digest"][7:] and len(config_raw) == cfg["size"]
               and type(config) is dict and config.get("architecture") == "amd64" and config.get("os") == "linux"
               and "variant" not in config and type(config.get("rootfs")) is dict
               and set(config["rootfs"]) == {"type", "diff_ids"} and config["rootfs"]["type"] == "layers",
               "stage-oci-config")
    layers = manifest["layers"]
    vm.require(type(layers) is list and 0 < len(layers) <= 8, "stage-oci-layers")
    layers = [descriptor(item, media={layer_media}) for item in layers]
    diffs = config["rootfs"]["diff_ids"]
    vm.require(type(diffs) is list and len(diffs) == len(layers)
               and all(isinstance(item, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in diffs),
               "stage-oci-diffids")
    expected = {"blobs/sha256/" + chosen["digest"][7:]: (len(manifest_raw), chosen["digest"][7:], manifest_raw, None),
                "blobs/sha256/" + cfg["digest"][7:]: (len(config_raw), cfg["digest"][7:], config_raw, None)}
    for item, diff in zip(layers, diffs):
        name = "blobs/sha256/" + item["digest"][7:]
        vm.require(name not in expected, "stage-oci-duplicate-blob")
        expected[name] = (item["size"], item["digest"][7:], None, diff[7:])
    # Only this closed index shape is admitted; labels/URLs/annotations do not
    # supply an alternate identity. JSON whitespace itself remains harmless.
    expected_index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                      "manifests": [{**chosen, "platform": {"architecture": "amd64", "os": "linux"}}]}
    vm.require(sum(item[0] for item in expected.values()) <= ARCHIVE_MAX - vm.META_MAX, "stage-oci-total-budget")
    file = FilePlan("node-oci", str(vm.canonical(path)), Path(path).stat().st_size, "0" * 64)
    vm.require(0 < file.size <= ARCHIVE_MAX and file.size % 512 == 0, "stage-oci-archive-size")
    source, parent_fd, name, identity = open_source(file)
    archive_hash, count, expanded_total, catalogue = hashlib.sha256(), 0, 0, {}
    def exact(length):
        nonlocal count
        raw = bytearray()
        while len(raw) < length:
            budget.remaining()
            block = os.read(source, min(CHUNK, length - len(raw)))
            vm.require(bool(block), "stage-oci-truncated")
            count += len(block)
            vm.require(count <= file.size, "stage-oci-growth")
            archive_hash.update(block)
            raw.extend(block)
        return bytes(raw)
    def octal(raw):
        vm.require(re.fullmatch(rb"[0-7]+\x00? *", raw) is not None, "stage-oci-tar-octal")
        return int(raw.rstrip(b"\x00 "), 8)
    try:
        while True:
            header = exact(512)
            if header == bytes(512):
                vm.require(exact(512) == bytes(512), "stage-oci-tar-end")
                while count < file.size:
                    vm.require(not any(exact(min(CHUNK, file.size - count))), "stage-oci-trailing-data")
                break
            vm.require(header[257:263] == b"ustar\x00" and header[263:265] == b"00"
                       and header[156:157] in (b"0", b"\x00") and not any(header[157:257])
                       and not any(header[345:512]) and octal(header[148:156]) == sum(header[:148] + b" " * 8 + header[156:]),
                       "stage-oci-tar-header")
            raw_name = header[:100].split(b"\x00", 1)[0]
            vm.require(header[:100] == raw_name.ljust(100, b"\x00"), "stage-oci-tar-name")
            member = raw_name.decode("ascii")
            vm.require(member not in catalogue and (member in expected or member in ("index.json", "oci-layout")), "stage-oci-tar-catalogue")
            size = octal(header[124:136])
            vm.require(0 < size <= ARCHIVE_MAX and (size == expected[member][0] if member in expected else size <= vm.META_MAX), "stage-oci-member-size")
            hasher, small = hashlib.sha256(), bytearray()
            diff = expected.get(member, (None, None, None, None))[3]
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if diff else None
            expanded_hash, expanded = hashlib.sha256(), 0
            remaining = size
            while remaining:
                block = exact(min(CHUNK, remaining))
                remaining -= len(block)
                hasher.update(block)
                if decoder:
                    pending = block
                    while pending:
                        budget.remaining()
                        output = decoder.decompress(pending, CHUNK)
                        pending = decoder.unconsumed_tail
                        expanded += len(output)
                        expanded_total += len(output)
                        vm.require(expanded <= LAYER_EXPANDED_MAX and expanded_total <= EXPANDED_TOTAL_MAX,
                                   "stage-oci-inflation-budget")
                        expanded_hash.update(output)
                    vm.require(not decoder.unused_data, "stage-oci-gzip-trailing")
                elif member in ("index.json", "oci-layout") or expected[member][2] is not None:
                    vm.require(len(small) + len(block) <= vm.META_MAX, "stage-oci-json-budget")
                    small.extend(block)
            vm.require(not any(exact((-size) % 512)), "stage-oci-padding")
            if member in expected:
                vm.require(hasher.hexdigest() == expected[member][1], "stage-oci-blob-integrity")
                if decoder:
                    vm.require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
                               and expanded_hash.hexdigest() == diff, "stage-oci-diffid-integrity")
                else:
                    vm.require(bytes(small) == expected[member][2], "stage-oci-manifest-bytes")
            else:
                wanted = expected_index if member == "index.json" else {"imageLayoutVersion": "1.0.0"}
                vm.require(vm.strict_json(bytes(small)) == wanted, "stage-oci-layout")
            catalogue[member] = {"bytes": size, "sha256": hasher.hexdigest()}
        vm.require(set(catalogue) == set(expected) | {"index.json", "oci-layout"} and not os.read(source, 1), "stage-oci-incomplete-catalogue")
        source_identity(source, parent_fd, name, identity)
    except (zlib.error, UnicodeError) as error:
        raise StageRefusal("stage-oci-invalid") from error
    finally:
        os.close(source)
        os.close(parent_fd)
    return FilePlan("node-oci", file.path, file.size, archive_hash.hexdigest()), {
        "parent_sha256": vm.digest(parent_raw), "manifest_sha256": vm.digest(manifest_raw),
        "config_sha256": vm.digest(config_raw), "expanded_bytes_hashed": expanded_total,
        "archive_sha256": archive_hash.hexdigest(), "archive_bytes": file.size,
        "catalogue": catalogue, "source_manifest_media_type": manifest["mediaType"],
        "transport": "source-preserved-docker-manifest" if docker else "source-preserved-oci-manifest",
        "archive_index_is_original_parent": False, "import": "not-performed",
        "repo_digest_behavior": "unavailable", "runtime": "not-performed"}


def admit_inputs(args, owner, budget, select_profile):
    """Use the existing frozen ledger/canonical source as sole tool-pin owner."""
    ledger_path = vm.ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json"
    ledger_raw = vm.read(ledger_path, 32 * 1024**2)
    ledger = vm.strict_json(ledger_raw)
    owner_bytes = vm.read(vm.canonical(args.canonical_owner), 1024**2) if args.canonical_owner else None
    profile, tools = select_profile(ledger, args.profile, owner_bytes)
    files = {}
    for role in ROLES[:2]:
        path = vm.canonical(getattr(args, role))
        file = FilePlan(role, str(path), path.stat().st_size, tools[role]["sha256"])
        vm.require(0 < file.size <= CLIENT_MAX, "stage-client-budget")
        source, parent_fd, name, identity = open_source(file)
        try:
            vm.require(os.read(source, 4) == b"\x7fELF", "stage-client-elf")
            os.lseek(source, 0, os.SEEK_SET)
            hash_source(source, parent_fd, name, identity, file, budget)
        finally:
            os.close(source)
            os.close(parent_fd)
        files[role] = {"path": file.path, "bytes": file.size, "sha256": file.sha256}
    parent_raw = vm.read(vm.canonical(args.node_parent), vm.META_MAX)
    manifest_raw = vm.read(vm.canonical(args.node_manifest), vm.META_MAX)
    config_raw = vm.read(vm.canonical(args.node_config), vm.META_MAX)
    archive, evidence = admit_oci(args.node_archive, parent_raw, manifest_raw, config_raw, profile, budget)
    files["node-oci"] = {"path": archive.path, "bytes": archive.size, "sha256": archive.sha256}
    raw = vm.encode({"schema": "kubernetes-lens-owned-guest-stage-plan-v1", "owner": owner,
                     "profile": profile["id"], "files": files})
    plan = parse_plan(raw, vm.digest(raw))
    evidence.update({"ledger_sha256": vm.digest(ledger_raw), "tool_profiles": tools,
                     "canonical_owner_sha256": vm.digest(owner_bytes) if owner_bytes is not None else None})
    return raw, plan, evidence


def guest_files(plan_raw, receiver_raw):
    """Closed root-only Ignition payload, never generated from network input."""
    plan = parse_plan(plan_raw, vm.digest(plan_raw))
    root = "/var/lib/kubernetes-lens-stage"
    table = ("kubernetes-lens-owned-guest-table-v1\n" + plan.owner + "\n" + plan.profile + "\n" + plan.sha256 + "\n"
             + "".join(f"{file.role} {file.size} {file.sha256}\n" for file in plan.files)).encode("ascii")
    files = {root + "/plan.json": (plan_raw, 0o400), root + "/table": (table, 0o400),
             root + "/lock": (b"", 0o600),
             "/var/lib/kubernetes-lens-stage/receiver": (receiver_raw, 0o500)}
    for phase in PHASES:
        files[root + "/" + phase + ".header"] = ((phase + "\n").encode("ascii"), 0o400)
    checks = "".join(vm.digest(raw) + "  " + path + "\n" for path, (raw, _) in files.items() if path != root + "/lock")
    files[root + "/checks.sha256"] = (checks.encode("ascii"), 0o400)
    return files
