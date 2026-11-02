#!/usr/bin/env python3
"""Explicit owned-VM prerequisite qualification, not Kubernetes conformance.

The outside owner alone publishes success after retiring its private user service.
The service worker cannot start QEMU until the owner authenticates its kernel and
systemd identity and actual finite limits. All subprocess argument lists are fixed.
"""
import argparse
import base64
import errno
import gzip
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
DIAGNOSTIC_CREDIT_PROFILE = "host-view-diagnostic-credit-v1"
DIAGNOSTIC_CREDIT_BYTES = 2053
DIAGNOSTIC_FRAME_BYTES = 2052
DIAGNOSTIC_BODY_BYTES = 2048
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


HOST_VIEW_MISMATCH_SCHEMA = "kubernetes-lens-host-view-mismatch-v3"
HOST_VIEW_MISMATCH_SITES = {"parent-attest", "parent-recheck", "worker-local"}
HOST_VIEW_MISMATCH_OBJECTS = {"root", "usr", "bin", "tool-busctl", "tool-python", "tool-qemu",
                              "tool-qemu_img", "tool-ssh", "tool-ssh_keygen", "tool-systemctl", "tool-systemd_run"}
HOST_VIEW_IDENTITY_MEMBERS = {"dev", "ino", "size", "mtime_ns", "ctime_ns"}
HOST_VIEW_MISMATCH_FIELDS = {"identity", "type", "mode", "uid", "gid", "sha256"}


def validated_host_view_mismatch(value):
    """Return a closed, bounded private mismatch record or refuse it."""
    require(type(value) is dict and set(value) == {"schema", "site", "object", "differences"}
            and value["schema"] == HOST_VIEW_MISMATCH_SCHEMA
            and type(value["site"]) is str and value["site"] in HOST_VIEW_MISMATCH_SITES
            and type(value["object"]) is str and value["object"] in HOST_VIEW_MISMATCH_OBJECTS
            and type(value["differences"]) is list and 1 <= len(value["differences"]) <= 11,
            "host-view-mismatch-schema")
    differences = []
    previous = None
    for row in value["differences"]:
        require(type(row) is dict and type(row.get("field")) is str
                and row["field"] in HOST_VIEW_MISMATCH_FIELDS,
                "host-view-mismatch-difference-schema")
        field = row["field"]
        if field == "identity":
            require(set(row) == {"field", "member", "expected", "observed"}
                    and type(row["member"]) is str and row["member"] in HOST_VIEW_IDENTITY_MEMBERS,
                    "host-view-mismatch-identity-schema")
            member = row["member"]
            low, high = (0, 2**64 - 1) if member in ("dev", "ino", "size") else (-(2**63), 2**63 - 1)
        else:
            require(set(row) == {"field", "expected", "observed"},
                    "host-view-mismatch-value-schema")
            member = ""
            low, high = None, None
        expected, observed = row["expected"], row["observed"]
        require(expected != observed, "host-view-mismatch-equal-values")
        if field == "identity" or field in ("mode", "uid", "gid"):
            require(type(expected) is int and type(observed) is int, "host-view-mismatch-integer")
            if field == "mode":
                low, high = 0, 0o7777
            elif field in ("uid", "gid"):
                low, high = 0, 2**32 - 1
            require(low <= expected <= high and low <= observed <= high, "host-view-mismatch-integer-range")
        elif field == "type":
            require(type(expected) is str and type(observed) is str
                    and expected in ("directory", "regular") and observed in ("directory", "regular"),
                    "host-view-mismatch-type")
        elif field == "sha256":
            require(type(expected) is str and type(observed) is str
                    and HEX.fullmatch(expected) and HEX.fullmatch(observed), "host-view-mismatch-digest")
        key = (field, member)
        require(previous is None or previous < key, "host-view-mismatch-order")
        previous = key
        differences.append({"field": field, **({"member": member} if field == "identity" else {}),
                            "expected": expected, "observed": observed})
    result = {"schema": HOST_VIEW_MISMATCH_SCHEMA, "site": value["site"],
              "object": value["object"], "differences": differences}
    try:
        require(len(encode(result)) <= 2048, "host-view-mismatch-budget")
    except (TypeError, ValueError, RecursionError) as error:
        raise Refusal("host-view-mismatch-budget") from error
    return result


def with_optional_host_view_mismatch(envelope, value):
    """Preflight optional private detail against the existing single-message cap."""
    if type(envelope) is not dict or "host_view_mismatch" in envelope or value is None:
        return envelope
    try:
        detail = validated_host_view_mismatch(value)
        candidate = {**envelope, "host_view_mismatch": detail}
        if len(encode(candidate)) <= META_MAX:
            return candidate
    except (Refusal, TypeError, ValueError, RecursionError):
        pass
    return envelope


def diagnostic_credit_profile(config):
    keys = {"host_view_diagnostic_profile", "host_view_diagnostic_credit_bytes"}
    present = keys.intersection(config)
    if not present:
        return None
    require(present == keys and config["host_view_diagnostic_profile"] == DIAGNOSTIC_CREDIT_PROFILE
            and type(config["host_view_diagnostic_credit_bytes"]) is int
            and config["host_view_diagnostic_credit_bytes"] == DIAGNOSTIC_CREDIT_BYTES,
            "host-view-diagnostic-profile")
    return DIAGNOSTIC_CREDIT_PROFILE


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


def write(path, data, *, maximum=META_MAX):
    require(type(maximum) is int and 0 < maximum <= 256 * 1024 and len(data) <= maximum, "metadata-budget")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


class Budget:
    def __init__(self, end, cleanup_seconds, *, output=OUTPUT_MAX, commands=128):
        require(type(end) in (int, float) and math.isfinite(end), "invalid-original-end")
        self.end, self.work_end = end, end - cleanup_seconds
        self.cleanup_seconds = cleanup_seconds
        self.output_left, self.commands_left = output, commands

    def remaining(self, cleanup=False):
        require(cleanup or not CANCELLED, "cancelled")
        result = (min(self.end, getattr(self, "retirement_end", self.end)) if cleanup else self.work_end) - time.monotonic()
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



def command_outcome():
    """Fresh unavailable summary; hashes describe successfully charged prefixes."""
    return {"schema": "kubernetes-lens-command-outcome-v1", "classification": "incomplete",
            "returncode": None, **{name: {"charged_bytes": 0, "charged_sha256": digest(b""), "eof": False}
                                   for name in ("stdout", "stderr")}}


def validated_command_outcome(value):
    require(type(value) is dict and set(value) == {"schema", "classification", "returncode", "stdout", "stderr"}
            and value["schema"] == "kubernetes-lens-command-outcome-v1", "command-outcome-schema")
    result = {"schema": value["schema"]}
    total = 0
    for name in ("stdout", "stderr"):
        record = value[name]
        require(type(record) is dict and set(record) == {"charged_bytes", "charged_sha256", "eof"}
                and type(record["charged_bytes"]) is int and 0 <= record["charged_bytes"] <= OUTPUT_MAX
                and type(record["charged_sha256"]) is str and HEX.fullmatch(record["charged_sha256"])
                and type(record["eof"]) is bool, "command-outcome-stream")
        require(record["charged_bytes"] != 0 or record["charged_sha256"] == digest(b""), "command-outcome-empty-digest")
        total += record["charged_bytes"]
        result[name] = {key: record[key] for key in ("charged_bytes", "charged_sha256", "eof")}
    require(total <= OUTPUT_MAX, "command-outcome-output-bound")
    status = value["returncode"]
    require(status is None or type(status) is int and -64 <= status <= 255, "command-outcome-returncode")
    complete = status is not None and result["stdout"]["eof"] and result["stderr"]["eof"]
    classification = "signal" if complete and status < 0 else "exit" if complete else "incomplete"
    require(type(value["classification"]) is str and value["classification"] == classification,
            "command-outcome-completion")
    require(not complete or result["stdout"]["charged_bytes"] <= META_MAX, "command-outcome-complete-stdout")
    result.update(returncode=status, classification=classification)
    return result


def validated_guest_info_command(value, producers):
    """Bind private diagnostics to the actual first admitted SSH producer only."""
    if value is None:
        return None
    require(type(value) is dict and set(value) == {"phase", "process", "outcome"}
            and value["phase"] == "guest-info" and type(producers) is list and len(producers) > 0,
            "guest-info-command-schema")
    record = value["process"]
    require(type(record) is dict and set(record) == {"pid", "group", "session", "start"}
            and all(type(number) is int and 0 < number < 2**63 for number in record.values())
            and record["pid"] < 2**31 and record["group"] == record["session"] == record["pid"]
            and producers[0] == {"phase": "guest-info", "process": record}, "guest-info-command-binding")
    return {"phase": "guest-info", "process": {key: record[key] for key in ("pid", "group", "session", "start")},
            "outcome": validated_command_outcome(value["outcome"])}


# Historical fixture-content binding, not an operational software/update pin.
PREREQUISITE_RECEIVER_SHA256 = '145ea71ea21376b2f0385320a7799259ebd0c99168c9eec03d1c9144733872f1'
PREREQUISITE_STDERR_PATTERNS = {
    (25, "8e648fa8c89eb6f12a37533e2ea8764bdcc729391df5098c258538296219e354"): None,
    (60, "019cf68157ab8ae0c0355953c3e9c9f54dc6bbf61230759128ed21e9381348cc"): "entry",
    (61, "0fd9ab1572f1e6e95d3d4ba78900c4a5a40438453b25d05284a55dcbdf3c6f42"): "source",
    (60, "3d6ac096bc81a7121a4afbd9d477d602cc7a4fb6a0c928681a5d0541925550cf"): "paths",
    (63, "e1dc204830438ac626ff778dbd0e65ac79f10273e54e693b92e99935e462646f"): "packages",
    (67, "2b290d947a164b44f91e21611d0375aaa04c54d880797f76a47765a94454aa16"): "exec-closure",
    (58, "e9c55235d3916107cb784fb3f296ba006a321be76212e3043173b7b89f68ac34"): "eof",
    (66, "134faedbfa9751175fb8b57e09cabdbbc7023fc0d14ad975aa54293c26c9a721"): "fresh-state",
    (65, "8911191d1bca60e48ebdf323634f10981c0cf78cf375e476d86330ad5c708a57"): "pid-limits",
    (64, "78d7b35e5eac28bbfa99c70ad250cd51da259278317cfa640943c7aa22fda18d"): "namespace",
    (60, "218e5c0637f39f492d6d1a973eab713e6e08c468b5bdccd05d05de31aaaf98a3"): "mount",
    (61, "2ffcebceb8b6d31b41d9fad69fd2cb8b21652ccf9ab7d7179821b7431a37bd1e"): "memory",
    (60, "6a20ef468874f776e43ab5ccdbe19fc8dd226de65ae3dc6d7f41be46155d5452"): "block",
    (61, "666a92fb4be2b02c89c7878b0145de9590afa0bef88fddef6ea9fd108a079ebf"): "mapper",
    (65, "cabdc0917721642b740b8616f7407ad48e07dc845c8b5acf98c04bb4a1039cc8"): "filesystem",
    (64, "3447254791c0300709e7be3136a873a7bc8aed9826d7aaa2595954d55dd25744"): "inventory",
    (66, "74cc830e660c923f8fd385b298d02dd88c4af010be77144b4144f8ed44f55d14"): "podman-info",
    (69, "52b029e5fa532783466cb2833603716a6987b9ae91b97e24e08008462cd78679"): "podman-profile",
    (65, "4f7ee21a33407f5a22b5e566b9e00120817eb166e3e7a5c9c21b14b81cbf9a3a"): "pkg-jq-ver",
    (65, "d96ed047e7fff32541096b8b8734139f7307e29f38694db6d0a1d94670afdf97"): "pkg-sd-ver",
    (65, "d20739d40c735c558d72cb139774c54770ba9ac7f0d76a0e4cc832407b588fdb"): "pkg-kernel",
    (64, "44908099aae210be9fa718a4064bd091327bad030ac673a6d781600d109ef4a1"): "rpm-shape",
    (63, "ae2f943129b6f4cbca75f36ef51e7d6a9bea16d65ba1beba5237dc45732ea2fb"): "rpm-bash",
    (61, "bf9ff98e27549e71cfb6afdedab3a897bdabaa683ec60fa576cdc36731a13b49"): "rpm-jq",
    (68, "a2f2e0d2aa7f07e811e0bd749dfc2bc53fa8d14bc87970d973273d43055d1917"): "rpm-coreutils",
    (66, "079a1539f4729fc9550b01a5ec206d3ddc97519d6c8ab5a7ef94fb963fb6359f"): "rpm-systemd",
    (65, "9d13201496e5dec9e48af2483658f9be25e3363ac449f9929944f9f204496c9e"): "rpm-podman",
    (65, "18509327e8b36cf58fc345905bb4060eb2c7492a749c4db0735b7f00a45e7fd0"): "rpm-skopeo",
    (63, "4032048a3558e147fb0d49e7e700f3c759b5995c8997fca9bb4897d385efc6ec"): "rpm-crun",
    (65, "3b8d1cbf9bb2c31088ca212aa42fdb7fa569c7db4d5ad53b7c7a61a941f5881a"): "rpm-conmon",
    (67, "a59848d433090c3cc058c34ab01579a686c0626e86c6847f7746515fbe42e9fd"): "rpm-netavark",
    (67, "65a41b6500ff15d88c839cf4394ec6284770616c253445449ac20baaf106b2d6"): "rpm-aardvark",
    (69, "a9d8682c49e8be663c239200fda88460314783a22d0b4a7aa3b420c375916570"): "rpm-util-linux",
    (65, "9bee5e4cd051edfd3d69620d10965a8976e6d45a527873b2baa8936ed943513f"): "rpm-libcap",
    (67, "808363753ca8c105b3849cb4545f9a333b54dc9d008f6184b08d34bd13cc45ac"): "pkg-sd-query",
    (64, "b594df95e761623a544f880e39d6732c19e6093a32c40b307bf39934929f3198"): "pkg-sd-q1",
    (64, "bd034c8c0686c166ad2da482b75bae2f7c93032b7de9e0584b2342e025f51c56"): "pkg-sd-q2",
    (64, "22493410c9a8b49413f26234ada4ac601dd66ee8504c1d4bf4f4b4ae471d07f9"): "pkg-sd-q3",
    (64, "0fdfb0c8bf2700cc78c4946aab5c5a018b0b998d9409a8d8c7827fc738c96137"): "pkg-sd-q4",
    (64, "1a6486e2e6ff1a1ff50a63656e9d6d859c741d03f2a09e39bbe8b1a5723e28ab"): "pkg-sd-q5",
    (64, "6071b8e3ef7f02f0e7eacbc21787f1978ad9180438a62fa42bf06af85df10ed5"): "pkg-sd-q6",
    (64, "150a5a6851c5921cdde6c6a401f8547f2319cb68caa1090a87d080e3286cbf21"): "pkg-sd-q7",
    (64, "33d9fb330ea6ea4cdc170b8e906432652a90377b638eff3c06f1f9ce9a92fbd6"): "pkg-sd-q8",
    (64, "7e5ead50880f6677b7d3d1619d05616725ba6a5077fd4113858f6a56f81f6f31"): "pkg-sd-q9",
    (65, "215a6304af8ef3f2121eaaef6635637fee04443b1aeac53867112697dc74a4e3"): "pkg-sd-q10",
    (65, "d580d26d23ecc691004453b30d2fc6ef61f16f26ac462ecf6f5cabf53348c134"): "pkg-sd-q11",
    (65, "b6c3c3be16214b0cab444cc34821f672ced71d3a809b0f840b5899b51d1588fc"): "pkg-sd-q12",
    (65, "8db28283a6bb3bd37148e6b32129b5cd73105b606daab09fefd121fdd3bdd30b"): "pkg-sd-q13",
    (65, "f9176e34ae1d1b45fa456c41a8eb46ad23bbf99c83f12e2a113b456e6caf0d29"): "pkg-sd-q14",
    (65, "139eaecdd5db935854c2591e37fd040f2d12f70301dd13459ed1f0f95f0fe268"): "pkg-sd-q15",
    (65, "9344e5da3f258e7ed2e2147338ad4f30ba4a8554fc031c345eb771100f8e2d8c"): "pkg-sd-q16",
    (65, "61c239a1caed1753650ce2983db54198bd736eccad978b416a0388fb1a2a6e13"): "pkg-sd-q17",
    (65, "8c588915a330615a5810f8ab5e75d4039989424ffd431e0c7c6c1c5d508ed8bc"): "pkg-sd-q18",
    (65, "65922af0d7e7a89882bbea44d00071ec7ec0aa4e135882d746c3d5942e4d4928"): "pkg-sd-q19",
    (65, "705d4f2765a790cfdc22489e1ba8e0fd143c4171028d73ac46a4211beeb4e8e9"): "pkg-sd-q20",
    (65, "1c672cc3b9369fe961334cd4750bba2bde8006c9eef9e484ac4038862b038cb2"): "pkg-sd-q21",
    (65, "2895281cbf0f8366ee14451198abef2bc2c21438f9778c9e7add4fc535f6b353"): "pkg-sd-q22",
    (65, "36969e3fd84136ff3381a83912eaba792662fcb66a61cb09f20ea9690bcbd3f6"): "pkg-sd-q23",
    (65, "1d7d446094632a0985636eb0a1e48220937f4dff5b38f34ca41d1ae9d67a7344"): "pkg-sd-q24",
    (65, "683b8b1e198b769316608e6881ad17fc2f4edcefb902108f00f63ad2e393c2f5"): "pkg-sd-q25",
    (65, "47a1a71311bddff4334b6c83072bcee8361100bb6d3f4046e4525147376208c7"): "pkg-sd-q26",
    (65, "4df104393d968f6f69547e72af8b9e3963adb81bdba8f8b4c320a99632e89a39"): "pkg-sd-q27",
    (65, "1132303ca2611f5585b96f0d746b5d3483e1a8546da46aaa1014963252d05811"): "pkg-sd-q28",
    (65, "aabd895219b2934eb19c9db551c22376a7b54bffc7be62999dcd2d75cd8a09b7"): "pkg-sd-q29",
    (65, "d8e4f8a857a87b137d05e4aa03a5b06ce740b85ea3857853a5e22c1e6fe530a5"): "pkg-sd-q30",
    (65, "8336377b6569f75be0855e7865a98b1ee7700daae07f0aea0fc435167121b327"): "pkg-sd-q31",
    (65, "c2695836505578409cef5288c8930c71c26fe0c5b14eb89770a33ad4dc99c5eb"): "pkg-sd-q32",
    (65, "4889381f2cd48983fe36ff8eae575f1e0b1570ee0e16038dc823b541fd054ac1"): "pkg-sd-q33",
    (65, "b2ae082e1f710da3802444aa3172772d1ecc34152217e840915bf82689e600b6"): "pkg-sd-q34",
    (65, "916c9ae54c48701dabcdd4a044a8f6e0d8f17e6e5c69a4c4673b2571fc8b374d"): "pkg-sd-q35",
    (65, "efe7df960470ef04fef5d94646d6d46181aa942ac1b583db2962eaa70efec277"): "pkg-sd-q36",
    (65, "0fe6b385be04fdfdcf0ee3901038eeab6fef06e14cbbe0c73541f585d97d6852"): "pkg-sd-q37",
    (65, "1cced4ceb922a33319da6608f4626820d3b031724fd470d1a48d535845c08dc3"): "pkg-sd-q38",
    (65, "f32776f4329cf5e54009b2df6b09d1feec04ccbd30f300f7091382c10e9ee8dd"): "pkg-sd-q39",
    (65, "45815bc513fd6fb1ffdda12bdb0ae00d864037355ac1f836c5d17b112d3d97a7"): "pkg-sd-q40",
    (65, "220d5b1db53ed33a07ed93d267fe523b2ed475986bea4805d46f88a71da00934"): "pkg-sd-q41",
    (65, "33ee625aa088507f7739546899d21d2426720942465e269774344bfd8228dccd"): "pkg-sd-q42",
    (65, "78bdf73b72532768bcae4cce1fd59074f9f2c56d5f6cc7e7c079360ebcf499c2"): "pkg-sd-q43",
    (65, "9a9b867a0e5d132f9fe5699028ad7d43d24c04e026ff378e3a380fe51e5112a2"): "pkg-sd-q44",
    (65, "c4d9a59a9bf1adb0aa0645d493af90857c51acd17643c34db153a597ed385684"): "pkg-sd-q45",
    (65, "3613a2635125bd045cb0564234fe7c1bec7b22a3ebe22362f7fb43b7690e6e70"): "pkg-sd-q46",
    (65, "b75af74c9293c1cb4daa0232e557c195c1e57493636cb109d7fefec0ec9d9c8c"): "pkg-sd-q47",
    (65, "59718bbc9593e5df56308e0baad441496324a483979e24e07dd639c2aea7d87f"): "pkg-sd-q48",
    (65, "ef705445e9d4073bd44e25aa59637246f931b0a7d6efbaf5615c20d3623f6031"): "pkg-sd-q49",
    (65, "51ccf6b1a72727ca007cb4099bb61d3b9d8b70c558ecf6ae4941b5a755d64a04"): "pkg-sd-q50",
    (65, "b3bb2fd684e114179d6a9ad4781b4648e06ad17406d49e0949e05ae242ac2a68"): "pkg-sd-q51",
    (65, "3f5766f77ade444e0679e8128c3de0e0065d6e1e829899cf2674e06d0171c8bb"): "pkg-sd-q52",
    (65, "6711c0801099a12d157cda50b0d7e5c5fc1b64b880b6993cf30e46d759f63bcb"): "pkg-sd-q53",
    (65, "bbb8619d822fdd98bed634ffe3715248d2d755b792c110d204d12c88a63b0aec"): "pkg-sd-q54",
    (65, "7d64a343df5af5b47add49c19d375c659369fb4e6208e877a0e4774815d2f527"): "pkg-sd-q55",
    (65, "c3c895059a93f85c9d524865353a5e05432a2806938da8725d0cfd57b97a55a4"): "pkg-sd-q56",
    (65, "b85439ae1a7cd804b579dc41af49998de461d03d641f43770a2ca174ceb6e698"): "pkg-sd-q57",
    (65, "4d9e48f0da80c3fe651423824949f0b8ec892a9f1eae3d3ddd821831a577d797"): "pkg-sd-q58",
    (65, "c3f76f62dbed3f15271d735dc9fd72ff70101037521252ec769f4f30baaf07f6"): "pkg-sd-q59",
    (65, "f9988ddead390cc1a8cb33e650cd143416442003427fd8d1e427db2b81ec7df6"): "pkg-sd-q60",
    (65, "ef348760bb5295ad3271c5fb46970f688f4cc08fbad11efaa451937068a9e324"): "pkg-sd-q61",
    (65, "7614eaa5f350a4fd6d7f81974f42358483721d397e84957e892ac854b1022523"): "pkg-sd-q62",
    (65, "2f20359f614dce9ffb597547498a981927c19eb25da9e119654632ae0a657293"): "pkg-sd-q63",
    (65, "89fb2e1092e7c00271646a5d7ff784f47ea436ad19898b021f044ff6f8842076"): "pkg-sd-q64",
    (65, "52607176c5d24e80704dcb3b01025bd809014a6a29aa5abe27ba86df69025ce1"): "pkg-sd-q65",
    (65, "b68a818c0e83d68e5a92298d4184d4285613e3bc427b5feb8a4d7e7763db742a"): "pkg-sd-q66",
    (65, "f01aebdf5bd363961d0230f76dc4a1f4b5482fa47cd0f46d1fffcc4a854fdd4a"): "pkg-sd-q67",
    (65, "d9130f2e861a00c66c26e223519dbb64782d4aa3c9936b8c7eac920e7947ade8"): "pkg-sd-q68",
    (65, "26a9b07faf0129fcebf22f33c2a090b52977f8d5cbb9b36c120bb85cffdead60"): "pkg-sd-q69",
    (65, "a3c0d0ab55bb0e08692c8a2956c1a887bbf105862068812b0d481e2139b4ae33"): "pkg-sd-q70",
    (65, "750d60104de85729f9185a6aaaf8ff67eccd3d59c8ed0c045c099ba634095623"): "pkg-sd-q71",
    (65, "18b48417236a6e868f998e2a8a5320dfbb0b61594174d65b8b590f0ba3d2102c"): "pkg-sd-q72",
    (65, "b1eec0b879b07282f67d1c255ef23a669651bdba58498a7280ad64315a4425c1"): "pkg-sd-q73",
    (65, "ef260c0d214ed35e9da0dbc39ae3b52b6aedb7483b907fceae3af134f9a6af54"): "pkg-sd-q74",
    (65, "441168341ca1fd3b4c604dc0c97be21644f53dba9117aa8e931baccd8722fb86"): "pkg-sd-q75",
    (65, "14c1d578e6701d8d1e5e53b0fdf5e9084be0f1208bd414724ec7ac29f82e2b7c"): "pkg-sd-q76",
    (65, "a602aca5ddb615b8acb2043d2fd2d4f0d52296baafa7913b0016fef26e6fe1ce"): "pkg-sd-q77",
    (65, "43573818f253ceea013bffa2cb6571c35374068088d94273c68331b7e428d203"): "pkg-sd-q78",
    (65, "907829cd62f1719fca9dc92371a972b9a46452fdbfb627f4f962b9227c0821e1"): "pkg-sd-q79",
    (65, "f7af1603c4b04a38871b20adb392406ad5c24389aa0fc81df187ea8bf7f643dd"): "pkg-sd-q80",
    (65, "836f0710cded43523e928db50240b6196080cf3aa7f063742e3056631c79fb0d"): "pkg-sd-q81",
    (65, "b2097829b41eb471c4ba57c0df5c32960b15ab0c30954a9822b28f1f3d76f19c"): "pkg-sd-q82",
    (65, "621e7b4aa3e0fe155019f7c7bb1b8fefbb684a43e6d6d14dac9a3691ec801303"): "pkg-sd-q83",
    (65, "5b983db06af210c73f1746fde111424e597052c8308d7a7d24cfdecedb5ec35f"): "pkg-sd-q84",
    (65, "4e17b897927c8a585f7ca8aa178731ace5052b0ab9fd3f9db4da20eff10a484d"): "pkg-sd-q85",
    (65, "29b78ed204394a689d237902f8c266b0dfc24d0ad1814ff75e5767ec2d736d04"): "pkg-sd-q86",
    (65, "127283260eb4f375adf5b35b019adc0dbd800e5f10dbf44671d7001a6263fcf1"): "pkg-sd-q87",
    (65, "25ef113d1bde8238ca01148fefd228c029b29d673a660024d195835a35726db2"): "pkg-sd-q88",
    (65, "412e36effc78cdd8832814138c0c1b5524cade9602f0bde7166c63109d5163e0"): "pkg-sd-q89",
    (65, "e0787610bf94ea5d72f246075cb713a1c5b5a294ead049b2e0639e07a191fd31"): "pkg-sd-q90",
    (65, "8b8ff1a750333a5bc070c7c39b5b3a1ce47832a7b3088ade319c4730412fecab"): "pkg-sd-q91",
    (65, "5897041ea8d455b3237cf405c1d84c7053e84e8a0bb72cd92e10b6f23cfe8126"): "pkg-sd-q92",
    (65, "73eb3b38119bca0611401935d16c230f93496f2740cabbe9e0f67709a430cb68"): "pkg-sd-q93",
    (65, "75e15d6a7429180c6b23d4adeeb98febd2e1c33baab69085db0cf6cb09e066c7"): "pkg-sd-q94",
    (65, "a3fed8f5d5294c8bd33cb97002c6a2906859128d43c072e206e2758e87504543"): "pkg-sd-q95",
    (65, "0315ec0a8d5595c69dcf542c73540e8bcb8727dc6f0ec275dbb26d678dd667ed"): "pkg-sd-q96",
    (65, "517479cfb787edf4dd3044dbb6e344ccdffe462c738502c2d56dc22eb4600868"): "pkg-sd-q97",
    (65, "3b163fbbf1fe792f2bdf1981e28a856bcee366217c19abf6256e98dd94c54469"): "pkg-sd-q98",
    (65, "a1cd36494419a30b4a64caa2a1188bdefb2c121ea7c5febf9d4d88fb19e3fc2f"): "pkg-sd-q99",
    (66, "5a8833a67545c581fafb68fc006366b610130122b7503a593449503325350d7b"): "pkg-sd-q100",
    (66, "0ae82244db736fd0ff8e91c2ee1a6bbbf26796a5b62f0cb9348b7cce15c374dc"): "pkg-sd-q101",
    (66, "75057a671052c97e11cc8c9347af31b3c7daafb9f2571c8f5c6738b5c4008886"): "pkg-sd-q102",
    (66, "661b02fc3ac41c2caea945e0bc21ad57ead6e411ad769e8b3b8f5ece74d09ac7"): "pkg-sd-q103",
    (66, "5e3481fec1c55afdd16c454c36af27d136aa161942127c494c8489b186058944"): "pkg-sd-q104",
    (66, "af07854172170b3eb82ade16861f6a5cf9956e981db7ad5d0baa6ce1ac4022c8"): "pkg-sd-q105",
    (66, "9cd06aca95c6a2c7a0f3c93cdca9db2b1df10fb313c49037f1582b8a4a46156a"): "pkg-sd-q106",
    (66, "90af1714f13ce4d9fd2449d0e89c4e48e9e186ab4dbb0985754307f5579d90ed"): "pkg-sd-q107",
    (66, "feca651ab1f915926fcba4a5dabd5638a5a75a7be3640f79d3400047536c7d27"): "pkg-sd-q108",
    (66, "d61b6784fb8ec9bab9a7c7be1e9dd903c09af89a621e1851fca518246913144f"): "pkg-sd-q109",
    (66, "d310fce4be59375d13a3aa40150900a0388ea1d7f28c7ac463732a9941418740"): "pkg-sd-q110",
    (66, "ef3b57baee59c532430f898620221e9ff2622eeece4a7ecf3e869288c9586b6f"): "pkg-sd-q111",
    (66, "0474c421eb1f344ce75d62ae1f613215def3d2bb1ddabf65c97aa206eb7fdf63"): "pkg-sd-q112",
    (66, "613e87f56762cc231ae2710652e9c1d23831891aec8ef04fd243ac157748e3dc"): "pkg-sd-q113",
    (66, "d3160f52dd89813413665574f1aa3b2a5b754e363e5c4eb814f2a05f63dd8b00"): "pkg-sd-q114",
    (66, "833e19dfcf9127044b5d5add6d7f0c69094347f31d5e4eabd84663a43cccdc0e"): "pkg-sd-q115",
    (66, "ce99cfdba43bb7d2b96763cc2b295b33a85c20881b1f059747b3921964e1d4d1"): "pkg-sd-q116",
    (66, "c5754f87f851260ac896c177dd041fe3cce643bab1f25495f5dc444a36dae082"): "pkg-sd-q117",
    (66, "e6c08aeb84dafbb8e85bb82e14aac983efbf2a431b4cc8cda6058f56e69303a6"): "pkg-sd-q118",
    (66, "919fdb85ec9fc2a47c0abb0b9f65ebf276b392340b170c83435c0c7734d7aada"): "pkg-sd-q119",
    (66, "e5c35e7567d84dc50f0f1bc31cffbb6dbb8d4c6ef17c873bd1e781aaa725b9c9"): "pkg-sd-q120",
    (66, "5e96ae57107df22783e8adf4f79acdcd55ac1449c534c42fd1045dd2e2de84a8"): "pkg-sd-q121",
    (66, "f81bbe2fb60c75841a36db11a47745d78ef39fb4b7cf0ad883a403b1fe8e28e5"): "pkg-sd-q122",
    (66, "09e787da51647cb2165137d084345088103801484cb8c7e4adc4d9bf26a134c5"): "pkg-sd-q123",
    (66, "06ff58463a5782f90a38cb797cb4301d69890e90acab948134b85cec79d403f3"): "pkg-sd-q124",
    (66, "5f886da8c7f9b1bb0b89b2e2d6d1c1495fe24485e4cfa6a5513c72b379804176"): "pkg-sd-q125",
    (66, "664e83ae39c01db620f9aedf0596aef3f4d76d193cfbc436975be260a17224a9"): "pkg-sd-q126",
    (66, "102a5be400cfa5a0f4b30e2689149139198b2fcd49ffeb05a34e8cf80595a27f"): "pkg-sd-q127",
    (66, "15db7c72517b3212d65ada76cca78a79fa2ca04fe011fa1870de306be809ff07"): "pkg-sd-q128",
    (66, "54e9b1e48ab8aee2d85684dfa230f067361ed653879e6973602946fcf1de378b"): "pkg-sd-q129",
    (66, "f2da6c169970a86ba2093448df311ff63d94a574efebca90f5d4fda27e2aa71c"): "pkg-sd-q130",
    (66, "49af94215214e3764976c00c9f0dccbb85f20b897a7cecf18a291032d24a7131"): "pkg-sd-q131",
    (66, "a5034046716a9b31e763ca3dd6037695e9738a771a3b9aee2ef55760fa6bda08"): "pkg-sd-q132",
    (66, "0f45a9ee13e6bf20c048c1705d2b8eba5d06dc74f5f21c4ab7f4df0b406df804"): "pkg-sd-q133",
    (66, "b605f5a6f4fcad6eefb2b1c32ac8d83fbe4ef8a868bff2f2aae1226f817e8211"): "pkg-sd-q134",
    (66, "27256c04af921b008ff68c74c31c611999b044c44f6c056f130aff478958be8f"): "pkg-sd-q135",
    (66, "6edcb302de40ef45f8297e2fe70cad6eeda3e06bab5d9ff23cfc6582a8c75dc6"): "pkg-sd-q136",
    (66, "ee703376382e4ef8a9174fa8d2e80f611abb0962b0fae9dca447ad2ebd4c4759"): "pkg-sd-q137",
    (66, "4463128d464984c94f8bc5150eea80f3576551149f3d6f95c3e1fa5307c1f0d5"): "pkg-sd-q138",
    (66, "46b2b193b0c0837419a5ed512fa55969a6a0e50b8f3b63c302d49b868400cefe"): "pkg-sd-q139",
    (66, "9a021c24e60bd02f5decb6e2fd5c011319d7217ad8eebecb74a9e0a22d1bc221"): "pkg-sd-q140",
    (66, "af4244372dd20f109fd60f04b727458cd0dd538ef9f58ccee940a42c30056252"): "pkg-sd-q141",
    (66, "0dc0f09bcf693cbe7d535dcf785ec56132402f61f089348a2371c29582ff4501"): "pkg-sd-q142",
    (66, "70a8e5e5626b64dc0df25c3842d89fbe67aff827b6a536068d904b464f403dbf"): "pkg-sd-q143",
    (66, "01633645efdd2a6b9a781775e031aab55bcd1182c2aa1c0c809643b87d222a4c"): "pkg-sd-q144",
    (66, "4da39241f0b2b9f49ee0c9eaf1398b3ecdb05c73c6fcaeaa71409c6b63ae2c34"): "pkg-sd-q145",
    (66, "105df18c1e8290fbd9ebb7688208d475addcd6be2d8e9a3335d8fb27c9d1386b"): "pkg-sd-q146",
    (66, "c0ac1fae42aa115ff4243073ea53af46950518d815da7e69732b136c9a5c5f26"): "pkg-sd-q147",
    (66, "b3eb69dbc25b7737cfb35caa3b6312464c5932587a71d17294ad5684321d3912"): "pkg-sd-q148",
    (66, "c629022bf6d6d9b60f62d2c42041d0b2e5f33446e91b32474d93392e6499a1b8"): "pkg-sd-q149",
    (66, "5d6b263e1f0f6844f917529f85728fe65440b346917e255abec754385c31bbb1"): "pkg-sd-q150",
    (66, "8df3fd615ff3824c0deafc859a4bfbd4525fad1b333759a8a0ef4d2def1bac4d"): "pkg-sd-q151",
    (66, "382ca35129f71ba33f9c5da858f40d1246bcc18f71baded0d060327386f35bb8"): "pkg-sd-q152",
    (66, "c380b790834206d25650c8925907b4c2c3f1101278d42c0e1ee137e3fb2444e4"): "pkg-sd-q153",
    (66, "42ef71babf87b30bd281c5e6ce60178bb7b059eea8afa2d68b87921af13585f2"): "pkg-sd-q154",
    (66, "ba1478a7d3d196742296e10a8e39d8b159f0fafaa83f5fc56819fee6f2e9dc51"): "pkg-sd-q155",
    (66, "dea9c1bb123e0bbc662e0e311ffc13c0fda802218a0b429489ac14b7ce96d6fa"): "pkg-sd-q156",
    (66, "69f74dddd0ef3515787e464030f52be476d973181725c6266823dd02de5d1655"): "pkg-sd-q157",
    (66, "6271dcac48b50cbbe337d1193ea22fa31226702883673c66edcab2b4df1d50eb"): "pkg-sd-q158",
    (66, "1202930cd737d3dbd36a5a4e30119a214a4c2b317ddc5030bca49a38e57c90c5"): "pkg-sd-q159",
    (66, "0a4b8e2344a8a3497708fa4c825410478fc3daa9c752f661eff17be1de70eb9f"): "pkg-sd-q160",
    (66, "33e790d8c0beaddd5e8bc8dd5f14ad618bd8f22a77ac451e5119023000e87789"): "pkg-sd-q161",
    (66, "fe1477888e91884cf99e3f297621e00dd873bc8e48000d43364dfa46a6e3136c"): "pkg-sd-q162",
    (66, "72110b2f085809b4a8184895ce5337645f8c2248d46e481ad783857337d62dab"): "pkg-sd-q163",
    (66, "ed5c984ee9a16f1bed7450452b97625e6032aeea10655f71b6e7ccc4696f3284"): "pkg-sd-q164",
    (66, "59416faa6910f823f69387d139e8f1e2ccf403bfe9eba9f6355b04928114e77d"): "pkg-sd-q165",
    (66, "c91986bc11e95cd2da45dc9bb5b09f948ec6108a398f3596b2de1b2117a3e595"): "pkg-sd-q166",
    (66, "74ce86bde7aa29329efc5bfeaf19f632cee8a6961f746ce8f70950e76e370833"): "pkg-sd-q167",
    (66, "9709519b5d0dc51c83d2c5319cd0fd6efd9d6845ab2e8e16b007384c019c0acd"): "pkg-sd-q168",
    (66, "aaf723394997c3d7d9dd319cfd22d15fb6b7a9c3ea1fa8853b77029c8d9adb50"): "pkg-sd-q169",
    (66, "70614ab43efb7683882c3a7a5648f304659b4d17ccce5083dbfb5e908426a146"): "pkg-sd-q170",
    (66, "2c5f23cb8243e51cd13564de459988db9998f7d306ead8cd6e3770b0ed0082a9"): "pkg-sd-q171",
    (66, "c9ddfa5f6133bb753fb37af2c1d1861049fb9b8dfe56a3e432cd56b599d44531"): "pkg-sd-q172",
    (66, "292bf2a329673a7e613c3769cda8ad946b4095d36dd49fa915a97bb481f75fec"): "pkg-sd-q173",
    (66, "f99133d0436b14c0c2ef71e7f74a89d8c004cb9f2db4e04bc977357a986012b4"): "pkg-sd-q174",
    (66, "48262113aadecc110c95943d03018f0320a8afac5b73405b03b3cb75f1eb2e52"): "pkg-sd-q175",
    (66, "7b92064d6eedf6eba58e5f9f29709405c7c169c559c12b6637dd4af6d37c2e7c"): "pkg-sd-q176",
    (66, "ccf9166942f58a7e0f79cda18aea9b555c93e93c0a6bd37fd0b6a3d10aed6165"): "pkg-sd-q177",
    (66, "cf7b6e43dafa1af2f53ac508d5c6e0505d07c57db0b90f0a7ed3d51cbb00b84d"): "pkg-sd-q178",
    (66, "9003c5fef51bac5af91dd0bb15e2bfda8817afdfbf39d3fc08bd4ba861c256b4"): "pkg-sd-q179",
    (66, "f796f4e40dbc6e840053b98c24aa4d78e378d3afb68ba9a5c9a88b2968a60e6e"): "pkg-sd-q180",
    (66, "b63537b75f7dcd41f0cd2f8c576292c6520c61dac496d1cdb882759da51347e3"): "pkg-sd-q181",
    (66, "728c78fb0357583bdc0f5d6118c2fe88a22836ec371eede6e2e04474aaec1928"): "pkg-sd-q182",
    (66, "57ac5cccd87d8e3cad8397831b450f2920971c8305ecc8fa56d764cf1abb437b"): "pkg-sd-q183",
    (66, "5052354d65f37992e3248ba22e47a378f20055a900e905333aaa3353446de68d"): "pkg-sd-q184",
    (66, "7a0900de601e8a884d3dc94b1c50ac7ae90ff18caf274711b0a7b89fac6ff5e7"): "pkg-sd-q185",
    (66, "28b3cf105a47c4feb8ea9b320134d2657b2c98ef4d193aad82493d2028bb3c3d"): "pkg-sd-q186",
    (66, "331bfe051529439351e8c1535258dca071f4f07779f68f4da4f34f1d899404bc"): "pkg-sd-q187",
    (66, "43b8c1954657262e8385d2e2b23e6b8c14ea4b6969cfe35f32cbf0868c935742"): "pkg-sd-q188",
    (66, "76f47c4ac653d70b28ab84530593866db17eb0e1cd5176a25d534eac5432221b"): "pkg-sd-q189",
    (66, "c8f33780c957324b091518956740247abe5bdfcdab2efc77242e68b2da92788a"): "pkg-sd-q190",
    (66, "d3b9385b439932230ebf97af3341257ac4678efa52d383292e66e37d559bd926"): "pkg-sd-q191",
    (66, "93414d59884658700a10d127dc09bc0bb1cfc667df5904f29e2a9ae9740548e5"): "pkg-sd-q192",
    (66, "e0f272661cccc29a128a40254b4bdf339fb3ebb2a5175b09c7eca0a112478267"): "pkg-sd-q193",
    (66, "6bf52a1eaa6d127948d47869f97942d64b5188aa6fc3bba2719e411999deb216"): "pkg-sd-q194",
    (66, "e357fc53112489399cde0ba9e41cd90dde00d919404fcc2c4ac8bd0a9f497501"): "pkg-sd-q195",
    (66, "d778251d41e503e3fcd4170b0fb83e644e7913f8fb1ed967a664610cb257b61a"): "pkg-sd-q196",
    (66, "b31b071806649defb801be8266454b336d5837fc1656bbaa63953c31ef56fe28"): "pkg-sd-q197",
    (66, "075bba4841ae814f0e4502c1dc3717945b7c603bc233b1da2a5b485758804846"): "pkg-sd-q198",
    (66, "ef51e6f292fcdeebab8a827d85a72e8656535463acd62195b1173cc03de7a4f7"): "pkg-sd-q199",
    (66, "ab4a9748837ddb7d88d0ca3b6b4cdb0ef7b69a03a72313e00decdebb64ff24d4"): "pkg-sd-q200",
    (66, "8c9a3d6a787f215e140be07df37b2b8b8161c314f41cb3d34b3e70d454dbb76a"): "pkg-sd-q201",
    (66, "3ae1b1b6758db5075fc6b7e3c1aedad37b90539f6dafcbce0ad3f772af33a61d"): "pkg-sd-q202",
    (66, "ee766514b45db2d352e5fa3bc41e8990c1f904af2e323d9084580ed1051ec091"): "pkg-sd-q203",
    (66, "fd1c345dbe9522dd83e21e07e72d79993affb0911447520c2f2d5e2bd208d57e"): "pkg-sd-q204",
    (66, "853f611754742c7632fd1b4cd224835405ca4daab7e000d9b8072b5a44e48f15"): "pkg-sd-q205",
    (66, "a83aa46a520f090c9dec7855a0942c5863ee6b147c12143cdb7dd87b340f170d"): "pkg-sd-q206",
    (66, "e64a9d8835cbef0951b5f7d0e791cb2d716f3c3290dab0198e63d8dac3a2c3dc"): "pkg-sd-q207",
    (66, "bd9350979211edc0c535bea6922deec311d899c69b32c5f0ad2dac863fccdc64"): "pkg-sd-q208",
    (66, "f6d200d816756afee20f302e264fb95af9fee38b3ebe553dd1d2a38954abbdb9"): "pkg-sd-q209",
    (66, "33b3d4dd8ef4035de28e6b0a6d78d47028a41fbb1446f027254de0d263a6dae5"): "pkg-sd-q210",
    (66, "daac161158e9c2c28eee401c9a87624d39da357dda7e2f2e6432d09c1a931857"): "pkg-sd-q211",
    (66, "3a233bd110cdddb5859e759b6bea2840c5d263b312be41e77b139b6b6065ab4a"): "pkg-sd-q212",
    (66, "3dedc23948be8f9f1748d4ec4aa6d086afddd05fd93ea8e205882f7cf859bab7"): "pkg-sd-q213",
    (66, "2c9a51c31920dfd2eb6532bd5160c1b907bd67fc7a6360d7236428a5d4fec8da"): "pkg-sd-q214",
    (66, "f2ad422becd94702c4f89aa998273c18b7c36544a22a2ad0019448fc7ccbdbb1"): "pkg-sd-q215",
    (66, "2edbde79ca7b8e33dd03553110e1232539613e5ca3622993d8f0d0985ba5cecd"): "pkg-sd-q216",
    (66, "89b8ba1af7146aad3d1703fb08cdbedddb2669431c970bda7bb4548aa09ea0b1"): "pkg-sd-q217",
    (66, "1f4bedf43dfc2baef469a9fba5f9043949e0f787873d88bc1d55f1530fb418e9"): "pkg-sd-q218",
    (66, "d9488badc8a03a41f554dfae6bc9b98f6d0ec5cb737b1f694b70d14b24f34b11"): "pkg-sd-q219",
    (66, "8c867069efc62f172f96a1ee7746d29ad5efddbc3f08de21993b0ec056974376"): "pkg-sd-q220",
    (66, "19fe54147aa488b4d6ce3b026c384c34954c4a3da5c8679a5c685bf203c77771"): "pkg-sd-q221",
    (66, "3effb7542c72ceb36b25c2675e0d297962766e100280964ad09f532fe8ec71ac"): "pkg-sd-q222",
    (66, "347ff168ae60cb404d4b1dd3d6e48dc51304eb579cb7bd1e7c9ea63cf2e5dee0"): "pkg-sd-q223",
    (66, "fdc32ee283c84c93ceb3017f8f4d84f1285c764b75a16e71a79b6859f95b39bb"): "pkg-sd-q224",
    (66, "6a6f9b0fffa9ac623501f5ab813176ddffa582a8bcf08bacc20a7c8f75e57b1e"): "pkg-sd-q225",
    (66, "1fbd7f0ea34444913a2ce074a705eabaa6a851470f3dc141747e8763332d75ca"): "pkg-sd-q226",
    (66, "ffc422606fefb3c3fadb048a207046b5dcd7867dec1f3492583bb350985b18b9"): "pkg-sd-q227",
    (66, "d677f8ae6d45efc190410bc3e13d0f8472bfcb2a7eb6e002857956248a0d844f"): "pkg-sd-q228",
    (66, "00adaeb5ddeb1c358e6e02ba938df48ac387cf3671428e07e28fc628a141ea5f"): "pkg-sd-q229",
    (66, "3b8da221194ae0e50b261e87739e8129d1bd1145d5b6fa67059c2331c7840e0c"): "pkg-sd-q230",
    (66, "e1dafdef9267e8bb681a9757b0019b8a7251bf2ba5f52e511caa54abc0c9c8e6"): "pkg-sd-q231",
    (66, "15dfdc9175a58373415d99c003c4a519f194354fd85c1189c27ed15ba03e5026"): "pkg-sd-q232",
    (66, "f9aca852dd6857b43ca40a70855898e710e51befa49ced3b5fe051e5583c341f"): "pkg-sd-q233",
    (66, "65d7acc6f05fc6e3aaea07edd6cc5083ee5181384c5c94fbf7d7186382eb86b0"): "pkg-sd-q234",
    (66, "56a26e1d0cfab9a3c7f6a7532dc91b1efee504e5a397016473bf2e6581ba5a63"): "pkg-sd-q235",
    (66, "937e84617651f11623cab67de6f6133b9651a779ed5f13919baa48589482c199"): "pkg-sd-q236",
    (66, "7fa5ccd24ba9735f1e38dfa1f302806e1276983ccc9985a037ff85884e5af8e1"): "pkg-sd-q237",
    (66, "45060a178392a5e939c7ad523185802a8ed5c72453ce92a78d9ad69e53bb51d3"): "pkg-sd-q238",
    (66, "3e046a99061d35103ac6e6c36456ae424c22bd94d5d2b2cbf0aa1952e192784c"): "pkg-sd-q239",
    (66, "7532ece06b9748cdf96aaf7052c99b3f4f81db149ac6b6e29e35cc4942be4c01"): "pkg-sd-q240",
    (66, "5a21aaa828b3b7729db2fc4e49be71866d5ed754c1a7483d7e1a28d88460a232"): "pkg-sd-q241",
    (66, "0cd53e7d1d8043854db7b3881532b39c9fc9bb6fcdf73b4d4c3c0771dff1b6ae"): "pkg-sd-q242",
    (66, "b77751364ae837d5b56354e115cd86dde425accad6ba654e49cf972951353d5d"): "pkg-sd-q243",
    (66, "3ae0e38592ca47bc21d25d1298ff271fe2082b64cd4c94075e6016f8b8e97236"): "pkg-sd-q244",
    (66, "4c5248b33b43fd112bf7f92d56562e6226f0639cf07b5400761ae377fea48484"): "pkg-sd-q245",
    (66, "56d94debfb1260205f77d102ef9384125706b1f0cca56f7ebaec255ab8d9d70c"): "pkg-sd-q246",
    (66, "1eb121b2cdd060a42a8ef540156a9a7d1acd350a605130e12ee2b2a5aecec6fd"): "pkg-sd-q247",
    (66, "c35c2b49a5403190ba4830d73c4c00c1d91ca45da5e8f6b3d93cd29eb727efd1"): "pkg-sd-q248",
    (66, "95da21af0189cd33a61d47c8b73adf585832444ba3fb06ebadd6eae672a760ba"): "pkg-sd-q249",
    (66, "b722892dbfaaf71bcbcf4ffb8a863a045009446899cf77157da384335587677e"): "pkg-sd-q250",
    (66, "e59e049c5a02704279412779d343475a2072a52fcda5cc88fb241be1af1c3921"): "pkg-sd-q251",
    (66, "0cd3b220b886377c19dafa7c223db9b6971e6c97bda6261becbd73c7b916ff6e"): "pkg-sd-q252",
    (66, "2133a828d0436cd459744a2b1e99a0e7fe6c5779952110adeffd2c23d24c6c36"): "pkg-sd-q253",
    (66, "232e998debcf3c371efb2fa2980f71e97fd99c8144fa1e81ab58f5138948e6d6"): "pkg-sd-q254",
    (66, "f53502c06788bba43e290eea7c12a88f5685677004cb8180e3f33b23a0fbbfe8"): "pkg-sd-q255",
    (62, "ed7dd548fe0a427d533aa5a29d356d5e16f0d032b8ed92fb36a0ef8497c0699f"): "pid-max",
    (67, "9373669b25591775d765b3c9ef02c77f07eb21822c51a6bb181e66f679b49570"): "nr-open-form",
    (68, "65a7e29b6697188a8da63fdc0f3e655a786f915e77d7564b6bd0bce207a84488"): "nr-open-range",
    (65, "a1a6465be9ba0e68eb04c46d5c1df3c48dfaecec8e946a0d92c71e51fbdb2c9c"): "mount-both",
    (65, "8a3ccd933078010605579af4cf1b5573210a78a2ec96750a731cd40e98a48b5d"): "mount-proc",
    (65, "95966c9b4d45756da13347a8a6ccd0d8d982162a8bf4eb21d3b84d0efce62806"): "mount-root",
    (68, "c0df55c53e9ec11bfbfdf303046636d12f5132451c40258e438b120a1b43f587"): "inv-pid-range",
    (68, "572b0336c99cab8d5d548884c81185731237e5e57c16ac8ade56c45c54700ed7"): "inv-proc-task",
    (68, "8a0df6b6456b64e654d24d9e34cb0b5c15e330d6b24b8eff8992f5915ef99039"): "inv-proc-read",
    (67, "e34cc656b3cac6738579ef10f0b12855e2fdc5dc71d21928f8af40b61b6c4164"): "inv-proc-pid",
    (68, "7350a5ef84389c2690736f4e39ab99e170f93c35b4ac3655f8f230b3f4c26fe1"): "inv-proc-form",
    (69, "cb993014c1a216faf5dd509660b7258a6ac2be1a35f36c18e8b96e51880eae0a"): "inv-task-empty",
    (68, "d3b3bb96396cfa368c12630c966a83736e316cbabc44343dc844534984086489"): "inv-tid-count",
    (68, "33e594fe97f64caf2732dc71ac4a693ce146f4b11979b9ca3bcdfa183fde6911"): "inv-task-read",
    (67, "1b243974896c009a84aff3fd3850be1cfd093716e67af0022ba8f65fd0a6d6fb"): "inv-task-tid",
    (68, "8c6984cc4a856563529a36fabd9fa5b52e1e0a5302b5612d48fa05b84e5aab55"): "inv-task-form",
    (66, "02d06defa097d42c0f27d212242b6a6bee5260e2194bfa3f873e339e0c9b069e"): "inv-nf-form",
    (67, "77eac6aeaecf3fffe764ef83389c1a582d6ff2987375fa5cef3c6c7c0226bf8a"): "inv-nf-range",
    (68, "81cf868c966e0b98099e80a47d4a13d75845fc033d35dfb3ffb04ff6e88f353f"): "inv-fd-access",
    (66, "620a20c3e0f4c91b9d85606835ac06cb7cfd80a910bebfc6ac04b1eb9cbbbd70"): "inv-fd-form",
    (67, "8e1c2b928ac4eb027e7449e3f28e7163b75b7573c5f057f57aca2c8310ea81b5"): "inv-fd-range",
    (68, "3d1f9e08209b30e5089529213e9ca6199af2bc4c5f49080fde7f8d0264482b9c"): "inv-snap-size",
    (64, "370750f0c30ea1873248433e8cd77b09dfeb31210824daa4653e0e44776faeef"): "inv-empty",
    (64, "6a8dbc09f114ad9fd61a9ed1ea34e015e38641d9f7e3c71fb120905361ed5a9d"): "inv-drift",
}


def validated_guest_info_stderr_pattern(value):
    """Closed byte-pattern report, never authentication or receiver evidence."""
    require(type(value) is dict and set(value) == {"schema", "source_sha256", "classification", "code"}
            and value["schema"] == "kubernetes-lens-guest-info-stderr-pattern-v1", "guest-info-pattern-schema")
    source, classification, code = value["source_sha256"], value["classification"], value["code"]
    require(source is None or type(source) is str and HEX.fullmatch(source), "guest-info-pattern-source")
    require(type(classification) is str and classification in
            ("not-established", "unrecognized", "legacy-refusal-bytes", "prerequisite-code-bytes"),
            "guest-info-pattern-classification")
    require(classification == "not-established" or source == PREREQUISITE_RECEIVER_SHA256,
            "guest-info-pattern-source-binding")
    require((classification == "prerequisite-code-bytes" and type(code) is str
             and code in PREREQUISITE_STDERR_PATTERNS.values())
            or (classification != "prerequisite-code-bytes" and code is None), "guest-info-pattern-code")
    return {"schema": value["schema"], "source_sha256": source, "classification": classification, "code": code}


def guest_info_stderr_pattern(command, receiver_sha256):
    """Match only complete source-bound whole streams; never inspect raw bytes."""
    source = receiver_sha256 if type(receiver_sha256) is str and HEX.fullmatch(receiver_sha256) else None
    result = {"schema": "kubernetes-lens-guest-info-stderr-pattern-v1", "source_sha256": source,
              "classification": "not-established", "code": None}
    if command is None or source != PREREQUISITE_RECEIVER_SHA256:
        return validated_guest_info_stderr_pattern(result)
    outcome = validated_command_outcome(command["outcome"])
    if outcome["classification"] == "incomplete":
        return validated_guest_info_stderr_pattern(result)
    result["classification"] = "unrecognized"
    stdout, stderr = outcome["stdout"], outcome["stderr"]
    key = stderr["charged_bytes"], stderr["charged_sha256"]
    if stdout["charged_bytes"] == 0 and key in PREREQUISITE_STDERR_PATTERNS:
        result["code"] = PREREQUISITE_STDERR_PATTERNS[key]
        result["classification"] = "legacy-refusal-bytes" if result["code"] is None else "prerequisite-code-bytes"
    return validated_guest_info_stderr_pattern(result)


def run(argv, budget, directory, *, cleanup=False, maximum=META_MAX, file_bytes=META_MAX, manager=False, extra_streams=(), on_start=None, deadline=None, input_bytes=None, input_account=None, outcome_capture=None, stdout_capture=None):
    """One bounded command; no shell, inherited agent, config or raw error receipt."""
    require(stdout_capture is None or callable(stdout_capture), "command-stdout-capture")
    if manager:
        deadline = min(time.monotonic() + 5.0, budget.end if deadline is None else deadline)
    def remaining():
        return command_remaining(budget, cleanup, deadline)
    require(input_bytes is None or type(input_bytes) is bytes and 0 < len(input_bytes) <= META_MAX, "command-input-budget")
    require(input_bytes is None and input_account is None or input_bytes is not None and type(input_account) is dict
            and set(input_account) == {"limit", "written"} and type(input_account["limit"]) is int
            and type(input_account["written"]) is int and input_account["written"] == 0
            and 0 < len(input_bytes) <= input_account["limit"] <= 4096, "command-input-reservation")
    if outcome_capture is not None:
        require(validated_command_outcome(outcome_capture) == command_outcome(), "command-outcome-not-fresh")
    hashes = {name: hashlib.sha256() for name in ("stdout", "stderr")} if outcome_capture is not None else None
    observed_status = None
    seconds = remaining()
    budget.commands_left -= 1
    require(budget.commands_left >= 0, "command-budget")
    environment = clean_environment(directory)
    if manager:
        environment.update({"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
                            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus"})
    result = bytearray()
    input_offset = 0
    selector = None
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
                               env=environment,
                               preexec_fn=child_limits(seconds, file_bytes))
    try:
        selector = selectors.DefaultSelector()
        pending = {process.stdout, process.stderr}
        if on_start:
            on_start(process)
        if input_bytes is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
        for stream in (process.stdout, process.stderr, *extra_streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while pending:
            remaining()
            for key, _ in selector.select(min(0.1, remaining())):
                if input_bytes is not None and key.fileobj is process.stdin:
                    try:
                        count = os.write(key.fd, input_bytes[input_offset:])
                    except (BlockingIOError, InterruptedError):
                        continue
                    require(count > 0, "command-stdin-zero-write")
                    input_offset += count
                    input_account["written"] += count
                    require(input_account["written"] <= input_account["limit"], "command-input-budget")
                    if input_offset == len(input_bytes):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                    continue
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    pending.discard(key.fileobj)
                    if outcome_capture is not None and key.fileobj in (process.stdout, process.stderr):
                        outcome_capture["stdout" if key.fileobj is process.stdout else "stderr"]["eof"] = True
                    continue
                budget.charge(len(raw))
                if outcome_capture is not None and key.fileobj in (process.stdout, process.stderr):
                    name = "stdout" if key.fileobj is process.stdout else "stderr"
                    hashes[name].update(raw)
                    outcome_capture[name]["charged_bytes"] += len(raw)
                if stdout_capture is not None and key.fileobj is process.stdout:
                    stdout_capture(raw)
                if key.fileobj is process.stdout:
                    result.extend(raw)
                    require(len(result) <= maximum, "command-output-budget")
        while (observed_status := process.poll()) is None:
            time.sleep(min(0.01, remaining()))
        require(input_bytes is None or input_offset == len(input_bytes), "command-input-incomplete")
        return process.returncode, bytes(result)
    finally:
        try:
            cleanup_error = None
            try:
                if selector is not None:
                    selector.close()
            except BaseException as error:
                cleanup_error = error
            try:
                final_status = process.poll()
                if observed_status is None and type(final_status) is int:
                    observed_status = final_status
                if final_status is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    # Never acquire a new timeout after cancellation or expiry.
                    try:
                        waited_status = process.wait(timeout=max(0, budget.end - time.monotonic()))
                        if observed_status is None and type(waited_status) is int:
                            observed_status = waited_status
                    except subprocess.TimeoutExpired:
                        raise Refusal("control-child-retirement-unproved") from None
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            # Unwinding must attempt every owned pipe, even when selector
            # retirement, child reaping or an earlier close has failed.
            for index, stream in enumerate((process.stdin, process.stdout, process.stderr)):
                try:
                    if stream is not None and (index != 0 or not stream.closed):
                        stream.close()
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
            if cleanup_error is not None:
                raise cleanup_error
        finally:
            if outcome_capture is not None:
                for name in ("stdout", "stderr"):
                    outcome_capture[name]["charged_sha256"] = hashes[name].hexdigest()
                outcome_capture["returncode"] = observed_status
                complete = observed_status is not None and all(outcome_capture[name]["eof"] for name in ("stdout", "stderr"))
                outcome_capture["classification"] = "signal" if complete and observed_status < 0 else "exit" if complete else "incomplete"


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


def ignition(client_public, host_private, host_public, *, stage_public=None, stage_files=None, rootful_files=None):
    require(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: ?[^\r\n]*)?\n?", client_public)
            and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: ?[^\r\n]*)?\n?", host_public),
            "ssh-key-format")
    def file(path, value, mode):
        return {"path": path, "mode": mode,
                "contents": {"source": "data:;base64," + base64.b64encode(value.encode()).decode()}}
    command = authenticated_module('owned_guest_rootful').COMMAND if rootful_files is not None else FIXED_COMMAND
    key = 'restrict,command="' + command + '" ' + client_public.strip()
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
        stage_command = stage.ROOTFUL_RECEIVER_COMMAND if rootful_files is not None else stage.RECEIVER_COMMAND
        result["passwd"]["users"][0]["sshAuthorizedKeys"].append(
            'restrict,command="' + stage_command + '" ' + stage_public.strip())
        result["storage"]["directories"] = [{"path": "/var/lib/kubernetes-lens-stage", "mode": 0o700}]
        for path, (raw, mode) in stage_files.items():
            result["storage"]["files"].append({"path": path, "mode": mode,
                "contents": {"source": "data:;base64," + base64.b64encode(raw).decode("ascii")}})
    if rootful_files is not None:
        root = "/var/lib/kubernetes-lens-rootful"
        result["kernelArguments"] = {"shouldExist": ["ostree.prepare-root.composefs=0"]}
        require(type(rootful_files) is dict and stage_public is not None, "rootful-ignition-contract")
        receiver = rootful_files.get(root + "/receiver")
        require(type(receiver) is tuple and len(receiver) == 2 and type(receiver[0]) is bytes
                and 0 < len(receiver[0]) <= META_MAX and type(receiver[1]) is int and receiver[1] == 0o500,
                "rootful-ignition-receiver-contract")
        result["storage"]["directories"].extend({"path": path, "mode": 0o700} for path in
            (root, root + "/bin", root + "/state", root + "/state/credits", root + "/captures"))
        for path, (raw, mode) in rootful_files.items():
            contents = {}
            if path == root + "/receiver":
                # Ignition3.4 decodes this representation into the exact source
                # bytes already bound above. Old qualify/stage files stay plain.
                raw = gzip.compress(raw, mtime=0)
                contents["compression"] = "gzip"
            contents["source"] = "data:;base64," + base64.b64encode(raw).decode("ascii")
            result["storage"]["files"].append({"path": path, "mode": mode, "contents": contents})
        result["storage"]["files"].append(file("/etc/sysctl.d/99-kubernetes-lens.conf", "kernel.pid_max=32768\nfs.nr_open=1073741816\n", 0o600))
    require(len(encode(result)) <= META_MAX, "ignition-budget")
    return result


def process_identity(pid, *, evidence=None):
    require(type(pid) is int and pid > 0, "process-pid")
    if evidence is None:
        return _process_stat(pid, Path(f"/proc/{pid}/stat").read_bytes())
    raw, event = evidence.kernel_bytes("process", f"/proc/{pid}/stat", pid=pid)
    return evidence.parsed(event, _process_stat(pid, raw))


def process_cgroup(pid, *, evidence=None):
    if evidence is None:
        return _process_cgroup(Path(f"/proc/{pid}/cgroup").read_bytes())
    raw, event = evidence.kernel_bytes("process-cgroup", f"/proc/{pid}/cgroup", pid=pid)
    return evidence.parsed(event, _process_cgroup(raw))


def boot_id(*, evidence=None):
    path = "/proc/sys/kernel/random/boot_id"
    if evidence is None:
        return _boot_identity(Path(path).read_bytes())
    raw, event = evidence.kernel_bytes("boot", path)
    return evidence.parsed(event, _boot_identity(raw))


def cgroup_snapshot(path, config, *, evidence=None):
    if evidence is None:
        path = canonical(path)
    else:
        path = evidence.primitive("cgroup-canonical", path,
            lambda: evidence.kernel.canonical(path), str)
    require(str(path).startswith("/sys/fs/cgroup/") and path.name == config["unit"], "unit-cgroup-path")
    info = path.stat() if evidence is None else evidence.primitive("cgroup-stat", path,
        lambda: evidence.kernel.stat(path), _retirement_stat)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "unit-cgroup-owner")
    def number(name):
        if evidence is None:
            raw = (path / name).read_bytes()
            event = None
        else:
            raw, event = evidence.kernel_bytes("cgroup-number", path / name)
        text = raw.decode("utf-8").strip()
        require(re.fullmatch(r"[0-9]+", text), "unit-limit-unbounded")
        value = int(text)
        return value if evidence is None else evidence.parsed(event, value)
    if evidence is None:
        cpu = (path / "cpu.max").read_text().split()
    else:
        raw, event = evidence.kernel_bytes("cgroup-cpu", path / "cpu.max")
        cpu = evidence.parsed(event, raw.decode("utf-8").split())
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


def prove_no_stop_commands(config, budget, *, cleanup=False, deadline=None, evidence=None):
    remaining = command_remaining(budget, cleanup, deadline)
    microseconds = int(min(5.0, remaining) * 1000000)
    require(microseconds > 0, "unit-property-deadline")
    timeout = "5s" if microseconds == 5000000 else str(microseconds) + "us"
    argv = [config['tools']['busctl']['path'], '--user', '--no-pager', '--timeout=' + timeout, '--json=short', 'get-property', 'org.freedesktop.systemd1', unit_object_path(config), 'org.freedesktop.systemd1.Service', *STOP_FIELDS]
    if evidence is None:
        status, raw = run(argv, budget, config["directory"], cleanup=cleanup, manager=True, deadline=deadline)
        event = None
    else:
        status, raw, event = evidence.manager("typed-stop", argv, budget, config["directory"], cleanup=cleanup, deadline=deadline)
    parsed = _stop_properties(raw, status)
    if evidence is not None:
        evidence.parsed(event, parsed)


def duration_seconds(value):
    units = {"us": 0.000001, "ms": 0.001, "s": 1, "min": 60, "h": 3600, "d": 86400}
    if value == "0":
        return 0
    parts = re.findall(r"([0-9]+(?:\.[0-9]+)?)(us|ms|min|s|h|d)", value)
    require(parts and " ".join(number + unit for number, unit in parts) == value, "unit-timer-unbounded")
    return sum(float(number) * units[unit] for number, unit in parts)


def simple_unit_show(config, budget, *, cleanup=False, deadline=None, evidence=None, site="unit-before"):
    argv = [config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "show", config["unit"],
            "--property=" + ",".join(SIMPLE_FIELDS)]
    if evidence is None:
        status, raw = run(argv, budget, config["directory"], cleanup=cleanup, manager=True, deadline=deadline)
        return _simple_unit(raw, status, config)
    status, raw, event = evidence.manager(site, argv, budget, config["directory"], cleanup=cleanup, deadline=deadline)
    return evidence.parsed(event, _simple_unit(raw, status, config))


def unit_show(config, budget, *, cleanup=False, deadline=None, evidence=None):
    result = simple_unit_show(config, budget, cleanup=cleanup, deadline=deadline, evidence=evidence)
    if result["LoadState"] == "not-found":
        require(result["ActiveState"] == "inactive" and result["MainPID"] == "0"
                and result["Job"] in ("", "0") and not result["InvocationID"] and not result["ControlGroup"],
                "unit-not-found-state-inconsistent")
        # No loaded service definition: report only the simple not-found
        # observation. It does NOT establish support or empty values for the
        # two complex service properties, and they are intentionally absent.
        return result
    prove_no_stop_commands(config, budget, cleanup=cleanup, deadline=deadline, evidence=evidence)
    after = simple_unit_show(config, budget, cleanup=cleanup, deadline=deadline, evidence=evidence, site="unit-after")
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
    argv = [config["tools"]["qemu"]["path"], "-no-user-config", "-nodefaults", "-display", "none",
            "-monitor", "none", "-serial", "stdio", "-machine", "q35,accel=kvm", "-cpu", "host",
            "-smp", str(config["cpus"]), "-m", str(config["guest_memory_mib"]), "-no-reboot",
            "-name", config["owner"], "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-drive", "file=" + str(directory / "overlay.qcow2") + ",if=virtio,format=qcow2,cache=none",
            "-fw_cfg", "name=opt/com.coreos/config,file=" + str(directory / "ignition.json"),
            "-nic", "user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:" + str(config["port"]) + "-:22"]
    if config.get("phase") == "run-rootful-kind":
        argv.remove("-no-reboot")
    return argv


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


def verify_source(config, budget, *, host_view=None, helper=None, helper_ref=None):
    check_source_bindings(config, budget)
    if host_view is None:
        require(admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-tools-drift")
    else:
        worker_pre_child(config, budget, host_view, helper=helper, helper_ref=helper_ref)
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


    if config.get("phase") == "run-rootful-kind":
        verify_rootful_stage_source(config, budget)


def verify_rootful_stage_source(config, budget):
    budget.remaining()
    stage = authenticated_module("owned_guest_stage", config, budget)
    base_path = ROOT / "scripts/fixtures/owned_guest_receiver.sh"
    base = read(base_path)
    require(digest(base) == config["source"].get(str(base_path)), "rootful-stage-base-binding")
    generated = stage.rootful_receiver(base)
    require(config.get("rootful_stage_receiver") == stage.rootful_receiver_binding(base, generated),
            "rootful-stage-generated-binding")
    directory = Path(config["directory"])
    document = strict_json(read(directory / "ignition.json"))
    files = document.get("storage", {}).get("files")
    require(type(files) is list, "rootful-stage-ignition-files")
    expected = stage.guest_files(read(directory / "stage-plan.json"), base, rootful=True)
    for path, (raw, mode) in expected.items():
        budget.remaining()
        matches = [row for row in files if type(row) is dict and row.get("path") == path]
        require(len(matches) == 1 and matches[0] == {"path": path, "mode": mode,
                "contents": {"source": "data:;base64," + base64.b64encode(raw).decode("ascii")}},
                "rootful-stage-ignition-source")


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
    require(name in ("owned_guest_stage", "owned_guest_rootful", "kind_runtime"), "owned-helper-catalogue")
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
        if name in ("owned_guest_stage", "owned_guest_rootful"):
            require(module.vm is sys.modules[__name__], "stage-owner-module-identity")
        return module
    except BaseException:
        del sys.modules[name]
        raise


def worker_pre_child(config, budget, frame, *, helper=None, helper_ref=None):
    check_source_bindings(config, budget)
    require(digest(read(config["manifest"])) == config["manifest_sha256"], "host-tools-manifest-drift")
    host_view = helper
    if host_view is None:
        host_view = host_view_module(config, budget)
        if helper_ref is not None:
            require(type(helper_ref) is list and len(helper_ref) == 1 and helper_ref[0] is None,
                    "host-view-helper-reference")
            helper_ref[0] = host_view
    host_view.validate_local(frame, config, budget)
    if config.get("phase") in ("stage-inputs", "run-rootful-kind"):
        for name, expected in config["input_files"].items():
            budget.remaining()
            target = canonical(Path(config["directory"]) / name)
            if name == "image.qcow2":
                require(file_id(target.stat()) == expected["identity"], "expanded-input-identity")
            else:
                require(digest(read(target)) == expected["sha256"], "private-input-drift")
    return host_view


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


def settle_guest_check(qemu, selector, budget):
    """One fixed rootful scheduling interval; never evidence of guest readiness."""
    budget.remaining()
    settle_end = time.monotonic() + 30
    require(settle_end < budget.work_end, "guest-settle-original-deadline")
    while True:
        budget.remaining()
        require(qemu.poll() is None, "qemu-exited-before-guest-check")
        remaining = settle_end - time.monotonic()
        if remaining <= 0:
            return
        for key, _ in selector.select(min(0.1, remaining, budget.remaining())):
            block = os.read(key.fd, 65536)
            require(bool(block), "qemu-console-closed")
            budget.charge(len(block))


def worker(path, expected):
    """Internal unit endpoint. No API accepts arbitrary guest or host commands."""
    raw = read(path)
    require(digest(raw) == expected, "worker-config-integrity")
    config = strict_json(raw)
    diagnostic_profile = diagnostic_credit_profile(config)
    budget = Budget(config["end"], config["cleanup_seconds"])
    require(time.monotonic() >= config["start"] and config["work_end"] == budget.work_end, "worker-original-deadline")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    qemu = None
    selector = None
    outcome, failure, qemu_record, ssh_record = None, None, None, None
    host_view_mismatch = None
    producers, producer_records, stage_result = [], [], None
    is_rootful = config.get("phase") == "run-rootful-kind"
    is_stage = config.get("phase") in ("stage-inputs", "run-rootful-kind")
    rootful_result = None
    guest_info_command = None
    guest_info_capture = command_outcome() if is_rootful else None
    diagnostic_helper = None
    diagnostic_helper_ref = [None] if diagnostic_profile is not None else None
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
        verify_source(config, budget, host_view=gate["host_view"], helper_ref=diagnostic_helper_ref)
        if diagnostic_helper_ref is not None:
            diagnostic_helper = diagnostic_helper_ref[0]
        directory = Path(config["directory"])
        if is_rootful:
            rootful = authenticated_module("owned_guest_rootful", config, budget)
            require(rootful.reserve(budget) == config["rootful_reservation"], "rootful-reservation-drift")
        status, raw_info = run([config["tools"]["qemu_img"]["path"], "info", "--output=json", "-f", "qcow2",
                                str(directory / "image.qcow2")], budget, directory)
        require(status == 0, "qemu-image-inspection-failed")
        image = strict_json(raw_info)
        require(image.get("format") == "qcow2" and type(image.get("virtual-size")) is int
                and 0 < image["virtual-size"] <= 32 * 1024**3
                and not any(key in image for key in ("backing-filename", "full-backing-filename", "encrypted")),
                "qemu-image-profile")
        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)
        status, _ = run([config["tools"]["qemu_img"]["path"], "create", "-f", "qcow2", "-F", "qcow2", "-b",
                         str(directory / "image.qcow2"), str(directory / "overlay.qcow2")], budget, directory,
                        file_bytes=config["overlay_max"])
        require(status == 0, "overlay-create-failed")
        budget.remaining()
        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)
        if is_rootful:
            budget.commands_left -= 1
            require(budget.commands_left >= 0, "command-budget")
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
        if is_rootful:
            settle_guest_check(qemu, selector, budget)
        def producer_started(process, phase):
            nonlocal guest_info_command
            # Retain the actual child before any identity, placement or channel
            # failure; worker finally reaps it even when registration fails.
            producers.append(process)
            record = process_identity(process.pid)
            producer_records.append({"phase": phase, "process": record})
            if is_rootful and phase == "guest-info":
                guest_info_command = {"phase": phase, "process": record, "outcome": guest_info_capture}
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
        if is_rootful:
            rootful.consume_record_purpose(budget, "guest-info")
        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)
        status, raw_info = run(rootful.ssh_arguments(config) if is_rootful else ssh_arguments(config), budget, directory, extra_streams=(qemu.stdout, qemu.stderr), on_start=ssh_started,
            **({"outcome_capture": guest_info_capture} if is_rootful else {}))
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
                if is_rootful:
                    rootful.consume_record_purpose(budget, phase)
                results.append(stage.transfer(session, phase, config,
                    extra_streams=(qemu.stdout, qemu.stderr),
                    on_start=lambda process, selected=phase: producer_started(process, selected),
                    pre_child=lambda: worker_pre_child(config, budget, gate["host_view"],
                                                       helper=diagnostic_helper)))
            require(session.next_phase == 3 and not session.failed
                    and session.input_sent == config["stage_input_limit"], "stage-cumulative-proof")
            stage_result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256,
                            "input_bytes": session.input_sent, "replies": results}
        if is_rootful:
            rootful.consume_record_purpose(budget, "rootful-kind")
            packet = rootful.request(config["owner"], config["stage_plan_sha256"], budget, config["rootful_spec"])
            require(len(packet) <= config["rootful_input_reserved"] == 4096, "rootful-input-reservation")
            worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)
            rootful_input = {"limit": config["rootful_input_reserved"], "written": 0}
            status, raw_result = run(rootful.ssh_arguments(config, execute=True), budget, directory,
                extra_streams=(qemu.stdout, qemu.stderr), input_bytes=packet, input_account=rootful_input,
                maximum=rootful.EVIDENCE_MAX, file_bytes=rootful.EVIDENCE_MAX,
                on_start=lambda process: producer_started(process, "rootful-kind"))
            require(rootful.record_schedule(budget)["consumed_purposes"] == list(rootful.PHASES),
                    "rootful-record-purpose-completion")
            rootful_result = rootful.wire_record(raw_result, config, allow_failure=True)
            write(directory / "rootful-wire.json", raw_result, maximum=rootful.EVIDENCE_MAX)
            rootful_wire_record = {"bytes": len(raw_result), "sha256": digest(raw_result),
                                   "identity": file_id((directory / "rootful-wire.json").stat())}
            require(status == 0, "rootful-kind-phase-failed")
            rootful.wire_record(raw_result, config)
        require(qemu.poll() is None and process_identity(qemu.pid) == qemu_record, "qemu-identity-before-retirement")
    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        failure = str(error) if isinstance(error, Refusal) else "worker-prerequisite-unavailable"
        if isinstance(error, Refusal) and failure == "host-view-object-not-equivalent":
            try:
                host_view_mismatch = validated_host_view_mismatch(getattr(error, "host_view_mismatch", None))
                require(host_view_mismatch["site"] == "worker-local", "worker-host-view-mismatch-site")
            except (Refusal, TypeError, ValueError, RecursionError):
                host_view_mismatch = None
    finally:
        if diagnostic_helper is None and diagnostic_helper_ref is not None:
            diagnostic_helper = diagnostic_helper_ref[0]
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
            if is_rootful:
                barrier["guest_info_command"] = guest_info_command
                barrier["rootful"] = rootful_result
                barrier["rootful_wire"] = rootful_wire_record if "rootful_wire_record" in locals() else None
                barrier["rootful_input_bytes"] = rootful_input["written"] if "rootful_input" in locals() else 0
                barrier["rootful_record_guards"] = (rootful.record_schedule(budget)
                    if hasattr(budget, "_rootful_record_purposes") else None)
            send(channel, barrier, budget, cleanup=True)
            if diagnostic_helper is not None:
                diagnostic_helper.send_optional_diagnostic(channel, host_view_mismatch, diagnostic_profile)
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


def attest_barrier_and_bind(row, hello, peer, config, config_sha, *, reservation=None, budget=None, channel=None):
    invocation, snapshot = attest_barrier(row, hello, peer, config, config_sha)
    if reservation is not None:
        reservation.bind_authenticated(budget, channel, peer, config_sha)
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


def process_retired(record, *, evidence=None):
    if record is None:
        return True
    try:
        current = process_identity(record["pid"]) if evidence is None else process_identity(record["pid"], evidence=evidence)
    except FileNotFoundError:
        if evidence is not None:
            evidence.process_result(record, True)
        return True
    require(current == record, "retirement-pid-reused")
    if evidence is not None:
        evidence.process_result(record, False)
    return False


def empty_cgroup(snapshot, config, *, evidence=None):
    path = Path(snapshot["path"])
    try:
        observed = cgroup_snapshot(path, config) if evidence is None else cgroup_snapshot(path, config, evidence=evidence)
        require(observed == snapshot, "retirement-cgroup-drift")
        if evidence is None:
            events = _cgroup_events((path / "cgroup.events").read_bytes())
        else:
            raw, event = evidence.kernel_bytes("cgroup-events", path / "cgroup.events")
            events = evidence.parsed(event, _cgroup_events(raw))
        require(events.get("populated") == "0", "retirement-cgroup-populated")
        if evidence is None:
            procs = (path / "cgroup.procs").read_text().strip()
        else:
            raw, event = evidence.kernel_bytes("cgroup-procs", path / "cgroup.procs")
            procs = evidence.parsed(event, raw.decode("utf-8").strip())
        require(not procs, "retirement-cgroup-populated")
        # Kernel populated=0 covers all descendants; direct membership alone does not.
        return "held-empty"
    except FileNotFoundError:
        exists = path.exists() if evidence is None else evidence.primitive("cgroup-exists", path,
            lambda: evidence.kernel.exists(path))
        require(not exists, "retirement-partial-cgroup-disappearance")
        return "removed"


RETIREMENT_TRACE_MAX = 32768
RETIREMENT_TRACE_RESERVATION = 65536
RETIREMENT_INPUT_MAX = 4096
RETIREMENT_POLLS = 128
RETIREMENT_SPACING = 0.100
RETIREMENT_SCHEMA = "kubernetes-lens-owned-vm-retirement-evidence-v1"


def _retirement_metadata_reservation():
    """Pure complete catalogue: no runtime storage or allowance discovery."""
    catalogue = dict.fromkeys(("config.json", "ignition.json", "known_hosts", "client_key", "client_key.pub",
                               "host_key", "host_key.pub", "stage_key", "stage_key.pub", "stage-plan.json"), META_MAX)
    catalogue["rootful-wire.json"] = 256 * 1024
    # Existing durable rootful evidence, existing receipt plus its exclusive
    # pre-deletion staging name, and the trace/one atomic-update temporary.
    reserved = sum(catalogue.values()) + 256 * 1024 + 2 * META_MAX + RETIREMENT_TRACE_RESERVATION
    require(reserved <= 4 * 1024**2, "retirement-complete-metadata-budget")
    return {"limit": 4 * 1024**2, "reserved": reserved, "lease_files": catalogue,
            "existing_durable_evidence": 256 * 1024, "receipt_and_staging": 2 * META_MAX,
            "trace_and_one_temporary": RETIREMENT_TRACE_RESERVATION}


def retirement_metadata_catalogue(directory):
    """Admit only the complete existing catalogue before any unit effect."""
    reservation = _retirement_metadata_reservation()
    catalogue = reservation["lease_files"]
    for path in Path(directory).iterdir():
        info = path.stat(follow_symlinks=False)
        if path.name == "control.sock":
            require(stat.S_ISSOCK(info.st_mode), "retirement-metadata-socket")
        elif path.name == "image.qcow2":
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= EXPANDED_MAX, "retirement-image-budget")
        else:
            require(path.name in catalogue and stat.S_ISREG(info.st_mode)
                    and info.st_size <= catalogue[path.name], "retirement-metadata-catalogue")
    return reservation



RETIREMENT_DECODE_MAX = 256 * 1024
RETIREMENT_RETAINED_MAX = 128


def _retirement_pack(document):
    """Deduplicate equal retained DATA, never substitute a later observation."""
    require(len(encode(document)) <= RETIREMENT_DECODE_MAX, "retirement-logical-trace-budget")
    counts, values = {}, {}
    def collect(value, depth=0):
        require(depth <= 64, "retirement-trace-depth")
        raw = encode(value)
        if len(raw) >= 48:
            key = digest(raw)
            require(key not in values or encode(values[key]) == raw, "retirement-retained-collision")
            counts[key] = counts.get(key, 0) + 1
            values[key] = value
        if type(value) is dict:
            require("$retained" not in value and "_retained_values" not in value, "retirement-retained-key")
            for child in value.values():collect(child, depth + 1)
        elif type(value) is list:
            for child in value:collect(child, depth + 1)
    collect(document)
    retained = {}
    def pack(value, *, root=False):
        raw = encode(value)
        key = digest(raw)
        count = counts.get(key, 0)
        reference = {"$retained": key}
        if (not root and count > 1 and count * len(raw) >
                count * len(encode(reference)) + len(encode({key: value}))):
            retained[key] = value
            return reference
        if type(value) is dict:return {key:pack(child) for key,child in value.items()}
        if type(value) is list:return [pack(child) for child in value]
        return value
    result = pack(document, root=True)
    result["_retained_values"] = retained
    require(len(retained) <= RETIREMENT_RETAINED_MAX, "retirement-retained-table")
    return result


def retirement_evidence_document(raw):
    """Bounded private codec readback; no manager, process or kernel reads."""
    require(type(raw) is bytes and len(raw) <= RETIREMENT_TRACE_MAX, "retirement-trace-budget")
    return _retirement_unpack(strict_json(raw), encoded_bytes=len(raw))


def _retirement_json_equal(left, right):
    """JSON values without Python's bool/integer equality coercion."""
    return encode(left) == encode(right)


def _retirement_shape(document, resolve=lambda value: value):
    """Reference-aware exact shape/type pass; never clones retained subtrees."""
    def mapping(value, required, optional=()):
        value = resolve(value)
        require(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional),
                "retirement-evidence-schema-map")
        return value
    def sequence(value, maximum):
        value = resolve(value)
        require(type(value) is list and len(value) <= maximum, "retirement-evidence-schema-list")
        return value
    def text(value, nullable=False):
        value = resolve(value)
        require(value is None and nullable or type(value) is str, "retirement-evidence-schema-text")
        return value
    def integer(value, minimum=0):
        value = resolve(value)
        require(type(value) is int and value >= minimum, "retirement-evidence-schema-int")
        return value
    def number(value, nullable=False):
        value = resolve(value)
        require(value is None and nullable or (type(value) is int or type(value) is float and math.isfinite(value)),
                "retirement-evidence-schema-number")
        return value
    def boolean(value):
        value = resolve(value)
        require(type(value) is bool, "retirement-evidence-schema-bool")
        return value
    def sha(value):
        value = text(value)
        require(HEX.fullmatch(value), "retirement-evidence-schema-digest")
    def same(left, right):
        left, right = resolve(left), resolve(right)
        if type(left) is not type(right):return False
        if type(left) is dict:
            return set(left) == set(right) and all(same(left[key], right[key]) for key in left)
        if type(left) is list:return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
        return left == right
    def identity(value, nullable=False):
        if resolve(value) is None:
            require(nullable, "retirement-evidence-schema-identity")
            return
        value = mapping(value, {"pid", "group", "session", "start"})
        for item in value.values():integer(item, 1)
    def cgroup(value, nullable=False):
        if resolve(value) is None:
            require(nullable, "retirement-evidence-schema-cgroup")
            return
        value = mapping(value, {"path", "device", "inode", "cpu_max", "memory_max", "pids_max", "swap_max"})
        text(value["path"]);text(value["cpu_max"])
        for key in ("device", "inode", "memory_max", "pids_max", "swap_max"):integer(value[key])
    def producers(value):
        value = sequence(value, 5)
        for row in value:
            row = mapping(row, {"phase", "process"})
            text(row["phase"]);identity(row["process"])
    def observation(value):
        value = mapping(value, {"at", "cgroup"})
        number(value["at"])
        require(text(value["cgroup"]) in ("held-empty", "removed"), "retirement-evidence-schema-cgroup-state")
    def retirement(value, nullable=False):
        if resolve(value) is None:
            require(nullable, "retirement-evidence-schema-result")
            return
        value = mapping(value, {"state", "observations", "invocation", "worker", "qemu", "ssh", "cgroup", "boot"}, {"producers"})
        require(text(value["state"]) == "retired", "retirement-evidence-schema-result-state")
        observations = sequence(value["observations"], 2)
        require(not complete or len(observations) == 2, "retirement-evidence-schema-observations")
        for row in observations:observation(row)
        text(value["invocation"]);text(value["boot"]);cgroup(value["cgroup"])
        for key in ("worker", "qemu", "ssh"):identity(value[key], nullable=True)
        if "producers" in value:producers(value["producers"])
    def outcome(value):
        value = mapping(value, {"schema", "classification", "returncode", "stdout", "stderr"})
        require(text(value["schema"]) == "kubernetes-lens-command-outcome-v1"
                and text(value["classification"]) in ("incomplete", "exit", "signal"), "retirement-evidence-schema-outcome")
        code = resolve(value["returncode"])
        require(code is None or type(code) is int, "retirement-evidence-schema-returncode")
        for name in ("stdout", "stderr"):
            stream = mapping(value[name], {"charged_bytes", "charged_sha256", "eof"})
            integer(stream["charged_bytes"]);sha(stream["charged_sha256"]);boolean(stream["eof"])
    root_keys = {"schema", "owner", "unit", "source", "boot", "owner_uid", "original_end", "original_cleanup_seconds",
                 "collection_end", "metadata", "state", "capture_error", "initial", "frames", "invocation", "cgroup",
                 "actors", "producer_prefix", "retirement", "final_receipt", "budget_before", "budget_after"}
    root = mapping(document, root_keys, {"retire_started"})
    require(text(root["schema"]) == RETIREMENT_SCHEMA, "retirement-evidence-schema")
    state = text(root["state"])
    require(state in ("incomplete", "unknown", "complete"), "retirement-evidence-schema-state")
    complete = state == "complete"
    require((text(root["capture_error"], nullable=True) is None) == (state != "unknown"), "retirement-evidence-schema-fault")
    for key in ("owner", "unit", "boot"):text(root[key])
    for key in ("invocation",):text(root[key], nullable=not complete)
    integer(root["owner_uid"])
    for key in ("original_end", "original_cleanup_seconds"):number(root[key])
    number(root["collection_end"], nullable=not complete)
    if "retire_started" in root:number(root["retire_started"])
    require(not complete or "retire_started" in root, "retirement-evidence-schema-start")
    sources = resolve(root["source"])
    require(type(sources) is dict and all(type(key) is str for key in sources), "retirement-evidence-schema-source")
    for value in sources.values():sha(value)
    require(same(root["metadata"], _retirement_metadata_reservation()), "retirement-evidence-metadata-budget")
    cgroup(root["cgroup"], nullable=not complete)
    for actor in sequence(root["actors"], 8):identity(actor)
    producers(root["producer_prefix"])
    retirement(root["retirement"], nullable=not complete)
    for key in ("budget_before", "budget_after"):
        if resolve(root[key]) is None:
            require(not complete, "retirement-evidence-schema-fuel")
        else:
            value = mapping(root[key], {"commands", "output"})
            # Partial predebit failure can truthfully retain negative remaining fuel.
            for item in value.values():
                require(type(resolve(item)) is int, "retirement-evidence-schema-int")
    receipt = resolve(root["final_receipt"])
    if receipt is not None:
        receipt = mapping(receipt, {"state", "native_error", "cleanup_error", "projection_sha256", "projection"})
        text(receipt["state"]);text(receipt["native_error"], nullable=True);text(receipt["cleanup_error"], nullable=True)
        sha(receipt["projection_sha256"])
        require(text(receipt["projection"]) == "private-receipt-without-retirement-evidence", "retirement-evidence-schema-projection")
    stat_keys = {"st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime_ns", "st_mtime_ns", "st_ctime_ns"}
    def parsed_kernel(kind, value, nullable):
        if resolve(value) is None:
            require(nullable, "retirement-evidence-schema-parsed")
            return
        if kind == "process":identity(value)
        elif kind == "cgroup-number":integer(value)
        elif kind == "cgroup-stat":
            value = mapping(value, stat_keys)
            for item in value.values():integer(item)
        elif kind == "cgroup-exists":boolean(value)
        elif kind == "cgroup-cpu":
            for item in sequence(value, RETIREMENT_INPUT_MAX):text(item)
        elif kind == "cgroup-events":
            value = resolve(value)
            require(type(value) is dict and all(type(key) is str for key in value), "retirement-evidence-schema-events")
            for item in value.values():text(item)
        else:text(value)
    def event(value):
        value = resolve(value)
        require(type(value) is dict and "kind" in value, "retirement-evidence-schema-event")
        kind = text(value["kind"])
        if kind == "manager":
            value = mapping(value, {"kind", "site", "argv", "parsed", "started", "deadline", "finished", "stdout_b64",
                                    "observed_bytes", "observed_sha256", "raw_complete", "outcome"})
            site = text(value["site"])
            require(site in ("unit-before", "unit-after", "typed-stop", "stop", "cancel"), "retirement-evidence-schema-site")
            for item in sequence(value["argv"], 16):text(item)
            for key in ("started", "deadline"):number(value[key])
            number(value["finished"], nullable=not complete)
            text(value["stdout_b64"]);integer(value["observed_bytes"]);sha(value["observed_sha256"])
            boolean(value["raw_complete"]);outcome(value["outcome"])
            parsed = resolve(value["parsed"])
            if site in ("stop", "cancel"):
                require(parsed is None, "retirement-evidence-schema-parsed")
            elif parsed is None:
                require(not complete, "retirement-evidence-schema-parsed")
            elif site == "typed-stop":
                parsed = mapping(parsed, set(STOP_FIELDS))
                for item in parsed.values():
                    row = mapping(item, {"type", "data"})
                    text(row["type"]);sequence(row["data"], 0)
            else:
                parsed = mapping(parsed, set(SIMPLE_FIELDS))
                for item in parsed.values():text(item)
            return
        require(kind in ("boot", "process", "process-cgroup", "cgroup-canonical", "cgroup-stat", "cgroup-exists",
                         "cgroup-cpu", "cgroup-number", "cgroup-events", "cgroup-procs"), "retirement-evidence-read-kind")
        base = {"kind", "path", "status", "parsed", "started", "finished"}
        if kind in ("process", "process-cgroup"):base.add("pid");integer(value.get("pid"), 1)
        status = text(value.get("status"))
        require(status in ("read", "missing", "error") and (not complete or status != "error"), "retirement-evidence-schema-status")
        text(value.get("path"));number(value.get("started"));number(value.get("finished"))
        if status != "read":
            mapping(value, base | {"errno"})
            code = resolve(value["errno"])
            require((code is None and status == "error") or type(code) is int, "retirement-evidence-schema-errno")
            require(resolve(value["parsed"]) is None, "retirement-evidence-schema-parsed")
        elif kind in ("cgroup-canonical", "cgroup-stat", "cgroup-exists"):
            mapping(value, base | {"raw_value"})
            parsed_kernel(kind, value["raw_value"], False);parsed_kernel(kind, value["parsed"], False)
            require(same(value["raw_value"], value["parsed"]), "retirement-evidence-schema-primitive")
        else:
            mapping(value, base | {"raw_b64", "observed_bytes", "observed_sha256", "raw_complete"})
            text(value["raw_b64"]);integer(value["observed_bytes"]);sha(value["observed_sha256"]);boolean(value["raw_complete"])
            parsed_kernel(kind, value["parsed"], not complete)
    initial = mapping(root["initial"], {"reads", "started", "finished"}, () if complete else {"error"})
    number(initial["started"]);number(initial["finished"], nullable=not complete)
    if "error" in initial:text(initial["error"])
    for item in sequence(initial["reads"], 64):event(item)
    frames = sequence(root["frames"], 2)
    require(not complete or len(frames) == 2, "retirement-evidence-schema-frames")
    for frame in frames:
        frame = mapping(frame, {"poll", "started", "reads", "processes", "unit", "cgroup", "at", "accepted"}, () if complete else {"error"})
        require(integer(frame["poll"], 1) <= RETIREMENT_POLLS, "retirement-evidence-schema-poll")
        number(frame["started"]);number(frame["at"], nullable=not complete);boolean(frame["accepted"])
        if "error" in frame:text(frame["error"])
        unit = resolve(frame["unit"])
        if unit is None:require(not complete, "retirement-evidence-schema-unit")
        else:
            unit = mapping(unit, set(SIMPLE_FIELDS), set(STOP_FIELDS))
            for value in unit.values():text(value)
        group = text(frame["cgroup"], nullable=not complete)
        require(group in (None, "held-empty", "removed"), "retirement-evidence-schema-cgroup-state")
        for process in sequence(frame["processes"], 8):
            process = mapping(process, {"record", "retired", "read"})
            identity(process["record"]);boolean(process["retired"]);integer(process["read"])
        for item in sequence(frame["reads"], 32):event(item)


def _retirement_unpack(document, *, encoded_bytes=None):
    require(type(document) is dict, "retirement-evidence-document")
    def no_refs(value, depth=0):
        require(depth <= 64, "retirement-trace-depth")
        if type(value) is dict:
            require("$retained" not in value and "_retained_values" not in value, "retirement-retained-value")
            return max([depth, *(no_refs(child, depth + 1) for child in value.values())])
        if type(value) is list:
            return max([depth, *(no_refs(child, depth + 1) for child in value)])
        return depth
    if "_retained_values" not in document:
        no_refs(document)
        _retirement_shape(document)
        return document
    # The canonical producer emits the immutable table before every reference.
    # Entries contain values, never chains: forward/cyclic entry refs cannot occur.
    require(next(iter(document)) == "_retained_values", "retirement-retained-forward")
    retained = document["_retained_values"]
    require(type(retained) is dict and len(retained) <= RETIREMENT_RETAINED_MAX, "retirement-retained-table")
    raw_values, depths = {}, {}
    for key, value in retained.items():
        require(type(key) is str and HEX.fullmatch(key), "retirement-retained-identity")
        depths[key] = no_refs(value)
        raw_values[key] = encode(value)
        require(digest(raw_values[key]) == key, "retirement-retained-integrity")
    left = RETIREMENT_DECODE_MAX - (len(encode(document)) if encoded_bytes is None else encoded_bytes)
    used = set()
    def preflight(value, depth=0):
        nonlocal left
        require(depth <= 64, "retirement-trace-depth")
        if type(value) is dict and "$retained" in value:
            require(set(value) == {"$retained"} and type(value["$retained"]) is str
                    and HEX.fullmatch(value["$retained"]) and value["$retained"] in raw_values,
                    "retirement-retained-reference")
            key = value["$retained"]
            require(depth + depths[key] <= 64, "retirement-trace-depth")
            left -= len(raw_values[key])
            require(left >= 0, "retirement-logical-trace-budget")
            used.add(key)
        elif type(value) is dict:
            for child in value.values():preflight(child, depth + 1)
        elif type(value) is list:
            for child in value:preflight(child, depth + 1)
    source = {key: value for key, value in document.items() if key != "_retained_values"}
    # Resolve no value until all references, total expansion, combined depth,
    # table cardinality and reachable entries have passed this complete preflight.
    preflight(source)
    require(used == set(retained), "retirement-retained-unused")
    def resolve(value):
        if type(value) is dict and "$retained" in value:
            return retained[value["$retained"]]
        return value
    _retirement_shape(source, resolve)
    def materialize(value):
        if type(value) is dict and "$retained" in value:
            return strict_json(raw_values[value["$retained"]])
        if type(value) is dict:return {key: materialize(child) for key, child in value.items()}
        if type(value) is list:return [materialize(child) for child in value]
        return value
    return materialize(source)



def _retirement_serialized(document, *, fault=False):
    raw = encode(_retirement_pack(document))
    require(len(raw) <= RETIREMENT_TRACE_MAX - (0 if fault else 512), "retirement-trace-budget")
    # Preflight the exact bounded reader before any new version replaces a
    # previously valid partial. In-memory values never accumulate old frames.
    _retirement_unpack(strict_json(raw), encoded_bytes=len(raw))
    return raw


class _RetirementKernel:
    """The existing read sites' injectable I/O; no observer or sampling loop."""
    def read(self, path):
        with Path(path).open("rb") as source:
            return source.read(RETIREMENT_INPUT_MAX + 1)

    def canonical(self, path):
        return canonical(path)

    def stat(self, path):
        return Path(path).stat()

    def exists(self, path):
        try:
            Path(path).stat()
        except FileNotFoundError:
            return False
        return True


def _retirement_stat(info):
    return {name: getattr(info, name) for name in ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid",
                                                  "st_size", "st_atime_ns", "st_mtime_ns", "st_ctime_ns")}


def _retirement_io(budget, operation, *args, **kwargs):
    """Fence existing metadata I/O; never renew fuel or interrupt a syscall."""
    budget.remaining(cleanup=True)
    value = operation(*args, **kwargs)
    budget.remaining(cleanup=True)
    return value


def _retirement_read(path, budget, maximum=META_MAX):
    # Same canonical/identity/byte checks as read(), with fences between its
    # individual metadata operations. Closing an acquired FD is mandatory.
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(path), "absolute-canonical-path-required")
    for part in (path, *path.parents):
        require(not _retirement_io(budget, part.is_symlink), "symlink-path-refused")
    budget.remaining(cleanup=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        budget.remaining(cleanup=True)
        before = _retirement_io(budget, os.fstat, fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "regular-file-budget")
        raw = bytearray()
        while len(raw) <= maximum:
            block = _retirement_io(budget, os.read, fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = _retirement_io(budget, os.fstat, fd)
        require(file_id(before) == file_id(after) and len(raw) == before.st_size, "file-identity-drift")
    finally:
        os.close(fd)
    budget.remaining(cleanup=True)
    return bytes(raw)


def _retirement_write(path, data, budget, *, maximum=META_MAX):
    require(type(maximum) is int and 0 < maximum <= 256 * 1024 and len(data) <= maximum, "metadata-budget")
    budget.remaining(cleanup=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        budget.remaining(cleanup=True)
        offset = 0
        while offset < len(data):
            written = _retirement_io(budget, os.write, fd, data[offset:])
            require(0 < written <= len(data) - offset, "retirement-metadata-write")
            offset += written
        _retirement_io(budget, os.fsync, fd)
    finally:
        os.close(fd)
    budget.remaining(cleanup=True)


class RetirementEvidence:
    """Durable capture within the same parent's existing retirement observer."""
    def __init__(self, parent, config, budget, *, kernel=None):
        self.config, self.budget = strict_json(encode(config)), budget
        config = self.config
        self.kernel = _RetirementKernel() if kernel is None else kernel
        self.error = None
        self.complete = False
        self.receipt_complete = False
        self.current_frame = False
        self.collection_end = budget.end
        self.identity = None
        self.last_raw = None
        self.path = Path(parent) / ("kubernetes-lens-vm-" + config["owner"] + ".retirement.json")
        self.temporary = self.path.with_name(self.path.name + ".tmp")
        require(re.fullmatch(r"[0-9a-f]{32}", config["owner"])
                and config["unit"] == "kubernetes-lens-vm-" + config["owner"] + ".service"
                and Path(config["directory"]).parent == Path(parent)
                and Path(config["directory"]).name == "kubernetes-lens-vm-" + config["owner"], "retirement-evidence-owner")
        parent_info = Path(parent).stat(follow_symlinks=False)
        require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid()
                and stat.S_IMODE(parent_info.st_mode) == 0o700, "retirement-evidence-private-parent")
        for reserved_path in (self.temporary,
                Path(parent) / ("kubernetes-lens-vm-" + config["owner"] + ".receipt.json"),
                Path(parent) / ("kubernetes-lens-vm-" + config["owner"] + ".receipt.json.pending"),
                Path(parent) / ("kubernetes-lens-vm-" + config["owner"] + ".evidence.json")):
            try:
                reserved_path.stat(follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refusal("retirement-metadata-already-exists")
        require(config["cleanup_seconds"] == budget.cleanup_seconds and config["end"] == budget.end
                and config["work_end"] == budget.work_end, "retirement-evidence-original-budget")
        self.document = {"schema": RETIREMENT_SCHEMA, "owner": config["owner"], "unit": config["unit"],
                         "source": strict_json(encode(config["source"])), "boot": config["boot"],
                         "owner_uid": os.getuid(), "original_end": budget.end,
                         "original_cleanup_seconds": config["cleanup_seconds"], "collection_end": None,
                         "metadata": retirement_metadata_catalogue(config["directory"]),
                         "state": "incomplete", "capture_error": None, "initial": {"reads": [], "started": time.monotonic(), "finished": None}, "frames": [],
                         "invocation": None, "cgroup": None, "actors": [], "producer_prefix": [],
                         "retirement": None, "final_receipt": None, "budget_before": None, "budget_after": None}
        try:
            raw = self.encoded()
            budget.remaining(cleanup=True)
            _retirement_write(self.path, raw, budget, maximum=RETIREMENT_TRACE_MAX)
            sync_retirement_parent(self.path.parent, budget=budget)
            self.identity = file_id(_retirement_io(budget, self.path.stat, follow_symlinks=False))
            self.last_raw = raw
            budget.remaining(cleanup=True)
        except Exception:
            self.fail("retirement-evidence-create")

    def encoded(self):
        # Leave fixed room for a sticky fault without losing the last partial.
        return _retirement_serialized(self.document)

    def group(self):
        return self.document["frames"][-1] if self.current_frame else self.document["initial"]

    def fail(self, code):
        self.error = self.error or code
        self.complete = False
        self.receipt_complete = False
        if self.last_raw is not None:
            try:
                self.document = retirement_evidence_document(self.last_raw)
            except Exception:
                pass
        self.document["capture_error"] = self.error
        self.document["state"] = "unknown"
        # Best effort only: failure must retain the previous exclusive partial,
        # never prevent the exact-unit stop or acquire fresh cleanup fuel.
        try:
            self._persist(_retirement_serialized(self.document, fault=True))
        except Exception:
            pass

    def _persist(self, raw):
        require(len(raw) <= RETIREMENT_TRACE_MAX, "retirement-trace-budget")
        info = _retirement_io(self.budget, self.path.stat, follow_symlinks=False)
        require(self.identity is not None and file_id(info) == self.identity
                and stat.S_IMODE(info.st_mode) == 0o600, "retirement-evidence-file-drift")
        created, fd = False, None
        try:
            self.budget.remaining(cleanup=True)
            fd = os.open(self.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created = True
            self.budget.remaining(cleanup=True)
            offset = 0
            while offset < len(raw):
                written = _retirement_io(self.budget, os.write, fd, raw[offset:])
                require(0 < written <= len(raw) - offset, "retirement-metadata-write")
                offset += written
            _retirement_io(self.budget, os.fsync, fd)
            _retirement_io(self.budget, os.replace, self.temporary, self.path)
            created = False
            self.identity = file_id(_retirement_io(self.budget, self.path.stat, follow_symlinks=False))
            sync_retirement_parent(self.path.parent, budget=self.budget)
            self.last_raw = raw
        finally:
            try:
                if created:
                    try:
                        self.budget.remaining(cleanup=True)
                    except Refusal:
                        pass  # No discovery/unlink after expiry; keep the temporary.
                    else:
                        # Our still-open exclusive FD proves this exact name's
                        # ownership before removing a funded failed update.
                        held = _retirement_io(self.budget, os.fstat, fd)
                        current = _retirement_io(self.budget, self.temporary.stat, follow_symlinks=False)
                        require(file_id(current) == file_id(held) and stat.S_ISREG(current.st_mode)
                                and stat.S_IMODE(current.st_mode) == 0o600 and current.st_uid == os.getuid()
                                and current.st_nlink == held.st_nlink == 1, "retirement-temporary-file-drift")
                        _retirement_io(self.budget, self.temporary.unlink)
            finally:
                if fd is not None:
                    os.close(fd)
        self.budget.remaining(cleanup=True)

    def sync(self):
        if self.error is None:
            try:
                self._persist(self.encoded())
            except Exception:
                self.fail("retirement-evidence-persistence")

    def add(self, event):
        if self.error is None:
            try:
                self.group()["reads"].append(event)
                self.sync()
            except Exception:
                self.fail("retirement-read-capture")
        return event

    def parsed(self, event, value):
        if self.error is None:
            try:
                event["parsed"] = strict_json(encode(value))
                self.sync()
            except Exception:
                self.fail("retirement-parsed-capture")
        return value

    def observation_error(self, code):
        if self.error is None:
            self.group()["error"] = code
            self.sync()

    def bind(self, invocation, snapshot, actors, producers, started, collection_end):
        try:
            self.collection_end = collection_end
            self.document.update(invocation=invocation, cgroup=strict_json(encode(snapshot)), actors=strict_json(encode(actors)), producer_prefix=strict_json(encode(producers)),
                                 retire_started=started, collection_end=collection_end,
                                 budget_before={"commands": self.budget.commands_left, "output": self.budget.output_left})
            self.sync()
        except Exception:
            self.fail("retirement-binding-capture")

    def begin_frame(self, poll):
        try:
            if not self.current_frame:
                self.document["initial"]["finished"] = time.monotonic()
            self.current_frame = True
            self.document["frames"] = [*self.document["frames"],
                {"poll": poll, "started": time.monotonic(), "reads": [], "processes": [],
                 "unit": None, "cgroup": None, "at": None, "accepted": False}][-2:]
            self.sync()
        except Exception:
            self.fail("retirement-frame-capture")

    def finish_frame(self, row, cgroup, accepted, at):
        try:
            if self.error is None:
                self.group().update(unit=strict_json(encode(row)), cgroup=cgroup, accepted=accepted, at=at)
                self.sync()
        except Exception:
            self.fail("retirement-frame-capture")

    def kernel_bytes(self, kind, path, **extra):
        self.budget.remaining(cleanup=True)
        event = {"kind": kind, "path": str(path), **extra, "status": "pending", "parsed": None,
                 "started": time.monotonic(), "finished": None}
        try:
            raw = self.kernel.read(path)
        except OSError as caught:
            event.update(status="missing" if caught.errno == errno.ENOENT else "error", errno=caught.errno, finished=time.monotonic())
            self.add(event)
            raise
        event["finished"] = time.monotonic()
        try:
            event.update(status="read", raw_b64=base64.b64encode(raw[:RETIREMENT_INPUT_MAX]).decode("ascii"),
                         observed_bytes=len(raw), observed_sha256=digest(raw), raw_complete=len(raw) <= RETIREMENT_INPUT_MAX)
        except Exception:
            if self.error is None:
                try:
                    self.budget.charge(len(raw))
                except Exception:
                    pass
            self.fail("retirement-kernel-capture")
            require(len(raw) <= RETIREMENT_INPUT_MAX, "retirement-kernel-input-budget")
            return raw, event
        if self.error is None:
            try:
                self.budget.charge(len(raw))
            except Exception:
                self.add(event)
                self.fail("retirement-kernel-output-budget")
            else:
                self.add(event)
        require(len(raw) <= RETIREMENT_INPUT_MAX, "retirement-kernel-input-budget")
        self.budget.remaining(cleanup=True)
        return raw, event

    def primitive(self, kind, path, operation, convert=lambda value: value):
        self.budget.remaining(cleanup=True)
        event = {"kind": kind, "path": str(path), "status": "pending", "parsed": None,
                 "started": time.monotonic(), "finished": None}
        try:
            result = operation()
        except OSError as caught:
            event.update(status="missing" if caught.errno == errno.ENOENT else "error", errno=caught.errno, finished=time.monotonic())
            self.add(event)
            raise
        event["finished"] = time.monotonic()
        try:
            value = convert(result)
            encoded_value = encode(value)
            require(len(encoded_value) <= RETIREMENT_INPUT_MAX, "retirement-kernel-primitive-budget")
            event.update(status="read", raw_value=strict_json(encoded_value), parsed=strict_json(encoded_value))
        except Exception:
            self.fail("retirement-primitive-capture")
            return result
        if self.error is None:
            try:
                self.budget.charge(len(encoded_value))
            except Exception:
                self.add(event)
                self.fail("retirement-kernel-output-budget")
            else:
                self.add(event)
        self.budget.remaining(cleanup=True)
        return result

    def manager(self, site, argv, budget, directory, *, cleanup=False, deadline=None):
        outcome = command_outcome()
        started = time.monotonic()
        limit = min(self.collection_end, started + 5.0, budget.end if deadline is None else deadline)
        event = self.add({"kind": "manager", "site": site, "argv": list(argv), "parsed": None,
                          "started": started, "deadline": limit, "finished": None,
                          "stdout_b64": "", "observed_bytes": 0, "observed_sha256": digest(b""),
                          "raw_complete": False, "outcome": outcome})
        accumulated = bytearray()
        hasher = hashlib.sha256()
        count = 0
        def stdout(raw):
            nonlocal count
            if self.error is not None:
                return
            try:
                count += len(raw)
                hasher.update(raw)
                accumulated.extend(raw[:max(0, RETIREMENT_INPUT_MAX - len(accumulated))])
                event.update(stdout_b64=base64.b64encode(accumulated).decode("ascii"), observed_bytes=count,
                             observed_sha256=hasher.hexdigest())
                self.sync()
            except Exception:
                self.fail("retirement-command-capture")
        try:
            status, raw = run(argv, budget, directory, cleanup=cleanup, manager=True, deadline=limit,
                              maximum=RETIREMENT_INPUT_MAX, outcome_capture=outcome, stdout_capture=stdout)
            if self.error is None:
                if bytes(accumulated) != raw or count != len(raw):
                    self.fail("retirement-command-same-read")
                else:
                    event["raw_complete"] = True
            require(time.monotonic() < limit, "retirement-manager-deadline")
            return status, raw, event
        finally:
            if self.error is None:
                try:
                    event["finished"] = time.monotonic()
                    event["outcome"] = strict_json(encode(outcome))
                    self.sync()
                except Exception:
                    self.fail("retirement-outcome-capture")

    def process_result(self, record, retired):
        try:
            if self.error is None:
                self.group()["processes"].append({"record": strict_json(encode(record)), "retired": retired,
                    "read": len(self.group()["reads"]) - 1})
                self.sync()
        except Exception:
            self.fail("retirement-process-capture")

    def finish(self, retirement):
        if self.error is None:
            self.budget.remaining(cleanup=True)
            self.document.update(state="complete", retirement=strict_json(encode(retirement)),
                budget_after={"commands": self.budget.commands_left, "output": self.budget.output_left})
            try:
                validated_retirement_evidence(self.document, self.config)
            except Exception:
                self.fail("retirement-evidence-readback")
                return
            self.sync()
            if self.error is None:
                try:
                    self.budget.remaining(cleanup=True)
                    raw = _retirement_read(self.path, self.budget, RETIREMENT_TRACE_MAX)
                    require(raw == self.last_raw, "retirement-evidence-file-integrity")
                    validated_retirement_evidence(strict_json(raw), self.config)
                    self.budget.remaining(cleanup=True)
                    self.complete = True
                except Exception:
                    self.fail("retirement-evidence-readback")

    def seal_receipt(self, private):
        try:
            if self.error is None:
                self.budget.remaining(cleanup=True)
                self.document["final_receipt"] = {"state": private["state"], "native_error": private["error"],
                    "cleanup_error": private["retirement_error"], "projection_sha256": digest(encode(private)),
                    "projection": "private-receipt-without-retirement-evidence"}
                self.sync()
                if self.error is None:
                    try:
                        self.budget.remaining(cleanup=True)
                        raw = _retirement_read(self.path, self.budget, RETIREMENT_TRACE_MAX)
                        require(raw == self.last_raw and retirement_evidence_document(raw)["final_receipt"] == self.document["final_receipt"],
                                "retirement-final-receipt-readback")
                        self.budget.remaining(cleanup=True)
                        self.receipt_complete = True
                    except Exception:
                        self.fail("retirement-final-receipt-readback")
        except Exception:
            self.fail("retirement-final-receipt-capture")

    def descriptor(self):
        if self.last_raw is None:
            return None
        return {"file": self.path.name, "bytes": len(self.last_raw), "sha256": digest(self.last_raw),
                "complete": self.complete and self.error is None}


def _process_stat(pid, raw):
    text = raw.decode("utf-8")
    tail = text[text.rfind(")") + 2:].split()
    require(len(tail) >= 20, "process-stat")
    return {"pid": pid, "group": int(tail[2]), "session": int(tail[3]), "start": int(tail[19])}


def _boot_identity(raw):
    value = raw.decode("utf-8").strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "host-boot-identity")
    return value


def _process_cgroup(raw):
    rows = [line[3:] for line in raw.decode("utf-8").splitlines() if line.startswith("0::")]
    require(len(rows) == 1 and rows[0].startswith("/"), "process-cgroup")
    return "/sys/fs/cgroup" + rows[0]


def _simple_unit(raw, status, config):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key in SIMPLE_FIELDS and key not in result, "unit-state-schema")
        result[key] = value
    require(set(result) == set(SIMPLE_FIELDS), "unit-state-incomplete")
    require(status == 0 or status in (1, 4) and result["LoadState"] == "not-found", "unit-state-unavailable")
    require(result["Id"] == config["unit"], "unit-state-name")
    return result


def _stop_properties(raw, status):
    require(status == 0, "unit-stop-properties-unavailable")
    lines = raw.splitlines()
    require(len(lines) == len(STOP_FIELDS), "unit-stop-properties-count")
    values = {}
    for name, line in zip(STOP_FIELDS, lines):
        value = strict_json(line)
        require(type(value) is dict and set(value) == {"type", "data"}
                and value["type"] == STOP_COMMAND_TYPE and type(value["data"]) is list,
                "unit-stop-properties-schema")
        require(not value["data"], "unit-stop-command-present")
        values[name] = value
    return values


def _cgroup_events(raw):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        pair = line.split()
        require(len(pair) == 2 and pair[0] not in result, "retirement-cgroup-events")
        result[pair[0]] = pair[1]
    return result


def validated_retirement_evidence(document, config):
    """Replay retained same-read DATA; never query a manager or the kernel."""
    document = _retirement_unpack(document)
    require(set(document) == {"schema", "owner", "unit", "source", "boot", "owner_uid", "original_end",
            "original_cleanup_seconds", "collection_end", "metadata", "state", "capture_error", "initial", "frames",
            "invocation", "cgroup", "actors", "producer_prefix", "retirement", "final_receipt", "retire_started",
            "budget_before", "budget_after"}, "retirement-evidence-fields")
    require(type(document) is dict and document["schema"] == RETIREMENT_SCHEMA
            and document["owner"] == config["owner"] and document["unit"] == config["unit"]
            and document["source"] == config["source"] and document["boot"] == config["boot"]
            and document["original_end"] == config["end"] and document["capture_error"] is None
            and document["state"] == "complete", "retirement-evidence-binding")
    require(document["original_cleanup_seconds"] == config["cleanup_seconds"]
            and 0 < document["original_cleanup_seconds"] <= 120
            and document["collection_end"] == min(document["original_end"],
                document["retire_started"] + document["original_cleanup_seconds"]), "retirement-evidence-end")
    require(document["metadata"] == _retirement_metadata_reservation(), "retirement-evidence-metadata-budget")
    scope = document["cgroup"]
    require(type(scope) is dict and set(scope) == {"path", "device", "inode", "cpu_max", "memory_max", "pids_max", "swap_max"}
            and type(scope["path"]) is str and scope["path"].startswith("/sys/fs/cgroup/")
            and Path(scope["path"]).name == config["unit"],
            "retirement-evidence-cgroup-scope")
    frames = document["frames"]
    require(len(frames) == 2 and all(frame["accepted"] is True for frame in frames)
            and 1 <= frames[0]["poll"] < frames[1]["poll"] <= RETIREMENT_POLLS
            and frames[1]["poll"] == frames[0]["poll"] + 1
            and frames[1]["at"] - frames[0]["at"] >= RETIREMENT_SPACING
            and all(document["retire_started"] <= frame["started"] <= frame["at"] < document["collection_end"]
                    for frame in frames), "retirement-evidence-samples")
    before, after = document["budget_before"], document["budget_after"]
    require(set(before) == set(after) == {"commands", "output"}
            and all(type(value) is int for value in (*before.values(), *after.values()))
            and 0 <= after["commands"] <= before["commands"] <= 128
            and before["commands"] - after["commands"] >= 4 + frames[-1]["poll"]
                + sum(sum(event["kind"] == "manager" for event in frame["reads"]) - 1 for frame in frames)
            and 0 <= after["output"] <= before["output"] <= OUTPUT_MAX, "retirement-evidence-original-fuel")
    require(set(document["initial"]) == {"reads", "started", "finished"}, "retirement-evidence-initial-fields")
    require(all(set(frame) == {"poll", "started", "reads", "processes", "unit", "cgroup", "at", "accepted"}
                for frame in frames), "retirement-evidence-frame-fields")
    groups = [document["initial"], *frames]
    initial_group = document["initial"]
    require(initial_group["started"] <= document["retire_started"] <= initial_group["finished"]
            <= frames[0]["started"], "retirement-evidence-initial-window")
    previous_end = initial_group["started"]
    for group in groups:
        lower, upper = group["started"], group.get("finished", group.get("at"))
        require(previous_end <= lower <= upper < document["collection_end"], "retirement-evidence-read-window")
        previous_read = lower
        for event in group["reads"]:
            require(previous_read <= event["started"] <= event["finished"] <= upper,
                    "retirement-evidence-read-order")
            previous_read = event["finished"]
        previous_end = upper
        for event in group["reads"]:
            require(event["kind"] in {"manager", "boot", "process", "process-cgroup", "cgroup-canonical",
                    "cgroup-stat", "cgroup-exists", "cgroup-cpu", "cgroup-number", "cgroup-events", "cgroup-procs"},
                    "retirement-evidence-read-kind")
            if event["kind"] != "manager" and event["status"] == "missing":
                require(event["errno"] == errno.ENOENT, "retirement-evidence-missing")
                continue
            if event["kind"] == "manager":
                require(event["site"] in {"unit-before", "unit-after", "typed-stop", "stop", "cancel"}
                        and event["started"] <= event["finished"] < event["deadline"]
                        <= min(document["collection_end"], event["started"] + 5.0),
                        "retirement-evidence-manager-end")
                if event["site"] == "typed-stop":
                    argv = event["argv"]
                    require(len(argv) == 11 and argv[3].startswith("--timeout="), "retirement-evidence-manager-argv")
                    timeout = argv[3].split("=", 1)[1]
                    require(0 < duration_seconds(timeout) <= 5.0, "retirement-evidence-manager-argv")
                    expected = [config["tools"]["busctl"]["path"], "--user", "--no-pager", argv[3], "--json=short",
                                "get-property", "org.freedesktop.systemd1", unit_object_path(config),
                                "org.freedesktop.systemd1.Service", *STOP_FIELDS]
                elif event["site"] == "stop":
                    expected = [config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password",
                                "stop", "--no-block", config["unit"]]
                elif event["site"] == "cancel":
                    expected = [config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "kill",
                                "--kill-whom=main", "--signal=SIGTERM", config["unit"]]
                else:
                    expected = [config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "show",
                                config["unit"], "--property=" + ",".join(SIMPLE_FIELDS)]
                require(event["argv"] == expected, "retirement-evidence-manager-argv")
                raw = base64.b64decode(event["stdout_b64"], validate=True)
                require(event["raw_complete"] is True and len(raw) == event["observed_bytes"] <= RETIREMENT_INPUT_MAX
                        and digest(raw) == event["observed_sha256"], "retirement-evidence-command-raw")
                outcome = validated_command_outcome(event["outcome"])
                require(outcome["classification"] == "exit" and outcome["stdout"]["eof"] is True
                        and outcome["stderr"]["eof"] is True and outcome["stdout"]["charged_bytes"] == len(raw)
                        and outcome["stdout"]["charged_sha256"] == digest(raw), "retirement-evidence-command-outcome")
                if event["site"] == "typed-stop":
                    parsed = _stop_properties(raw, outcome["returncode"])
                elif event["site"] in ("stop", "cancel"):
                    require(outcome["returncode"] == 0, "unit-stop-failed")
                    parsed = None
                else:
                    parsed = _simple_unit(raw, outcome["returncode"], config)
                require(_retirement_json_equal(parsed, event["parsed"]), "retirement-evidence-command-parsed")
            elif "raw_b64" in event:
                raw = base64.b64decode(event["raw_b64"], validate=True)
                require(event["raw_complete"] is True and len(raw) == event["observed_bytes"] <= RETIREMENT_INPUT_MAX
                        and digest(raw) == event["observed_sha256"], "retirement-evidence-kernel-raw")
                parsers = {"boot": _boot_identity, "process": lambda value: _process_stat(event["pid"], value),
                           "process-cgroup": _process_cgroup, "cgroup-events": _cgroup_events, "cgroup-procs": lambda value: value.decode("utf-8").strip(),
                           "cgroup-cpu": lambda value: value.decode("utf-8").split(),
                           "cgroup-number": lambda value: int(value.decode("utf-8").strip())}
                require(_retirement_json_equal(parsers[event["kind"]](raw), event["parsed"]), "retirement-evidence-kernel-parsed")
            else:
                require(event["status"] == "read" and _retirement_json_equal(event["raw_value"], event["parsed"]),
                        "retirement-evidence-kernel-primitive")
    result = document["retirement"]
    result_producers = result.get("producers", [])
    expected_actors = [result[key] for key in ("worker", "qemu", "ssh") if result[key] is not None]
    expected_actors += [item["process"] for item in result_producers]
    require(_retirement_json_equal(document["actors"], expected_actors)
            and _retirement_json_equal(document["producer_prefix"], result_producers)
            and _retirement_json_equal(result["observations"],
                [{"at": frame["at"], "cgroup": frame["cgroup"]} for frame in frames])
            and result["boot"] == document["boot"], "retirement-evidence-result-scope")
    require(("producers" in result) == (config.get("phase") in ("stage-inputs", "run-rootful-kind")),
            "retirement-evidence-result-phase")
    prefix = document["producer_prefix"]
    order = ("guest-info", "stage-kind", "stage-kubectl", "stage-node-oci", "rootful-kind")
    require(type(prefix) is list and len(prefix) <= 5
            and [item["phase"] for item in prefix] == list(order[:len(prefix)]), "retirement-evidence-producer-prefix")
    for record in document["actors"]:
        require(type(record) is dict and set(record) == {"pid", "group", "session", "start"}
                and all(type(value) is int and value > 0 for value in record.values()), "retirement-evidence-actor")
    initial = document["initial"]["reads"]
    require(any(event["kind"] == "manager" and event["site"] == "stop" for event in initial),
            "retirement-evidence-stop")
    initial_managers = [event for event in initial if event["kind"] == "manager"]
    require([event["site"] for event in initial_managers[-4:]] ==
            ["unit-before", "typed-stop", "unit-after", "stop"], "retirement-evidence-initial-policy")
    initial_units = initial_managers[-4:-1:2]
    fixed = ("Id", "Description", "LoadState", "Transient", "InvocationID", "Restart", "KillMode",
             "RemainAfterExit", "NRestarts", "Triggers", "TriggeredBy", "UpheldBy", "OnFailure", "OnSuccess",
             "FailureAction", "SuccessAction", "StartLimitAction")
    require(all(initial_units[0]["parsed"][name] == initial_units[1]["parsed"][name] for name in fixed),
            "retirement-evidence-initial-policy")
    initial_row = dict(initial_units[-1]["parsed"])
    initial_row.update(dict.fromkeys(STOP_FIELDS, ""))
    validate_unit(initial_row, config, live=False, invocation=document["invocation"])
    for frame in frames:
        reads = frame["reads"]
        boot = [event for event in reads if event["kind"] == "boot"]
        require(len(boot) == 1 and boot[0]["parsed"] == config["boot"]
                and boot[0]["path"] == "/proc/sys/kernel/random/boot_id", "retirement-evidence-boot")
        expected_path = document["cgroup"]["path"]
        require(all(event["status"] != "read" or event["parsed"] == expected_path
                    for event in reads if event["kind"] == "cgroup-canonical"), "retirement-evidence-cgroup-path")
        for event in reads:
            if event["kind"] in ("cgroup-canonical", "cgroup-stat", "cgroup-exists"):
                require(event["path"] == expected_path, "retirement-evidence-cgroup-path")
            elif event["kind"] in ("cgroup-events", "cgroup-procs", "cgroup-cpu", "cgroup-number"):
                require(str(Path(event["path"]).parent) == expected_path, "retirement-evidence-cgroup-path")
        managers = [event for event in reads if event["kind"] == "manager"]
        require(len(managers) in (1, 3) and managers[0]["site"] == "unit-before", "retirement-evidence-unit")
        row = dict(managers[-1]["parsed"])
        if len(managers) == 3:
            require(managers[1]["site"] == "typed-stop" and managers[2]["site"] == "unit-after"
                    and managers[0]["parsed"]["LoadState"] == "loaded", "retirement-evidence-typed-stop")
            row.update(dict.fromkeys(STOP_FIELDS, ""))
        else:
            require(row["LoadState"] == "not-found", "retirement-evidence-unloaded")
        if row["LoadState"] == "loaded":
            before = managers[0]["parsed"]
            fixed = ("Id", "Description", "LoadState", "Transient", "InvocationID", "Restart", "KillMode",
                     "RemainAfterExit", "NRestarts", "Triggers", "TriggeredBy", "UpheldBy", "OnFailure",
                     "OnSuccess", "FailureAction", "SuccessAction", "StartLimitAction")
            require(all(before[name] == row[name] for name in fixed)
                    and row["InvocationID"] in ("", document["invocation"])
                    and row["Restart"] == "no" and row["NRestarts"] == "0"
                    and not any(row[name] for name in ("Triggers", "TriggeredBy", "UpheldBy")), "retirement-evidence-unit-policy")
        else:
            require(row["LoadState"] == "not-found" and not row["InvocationID"] and not row["ControlGroup"],
                    "retirement-evidence-unit-unloaded")
        require(row == frame["unit"] and row["ActiveState"] in ("inactive", "failed")
                and row["MainPID"] == "0" and row["Job"] in ("", "0"), "retirement-evidence-inactive")
        require([item["record"] for item in frame["processes"]] == document["actors"]
                and all(item["retired"] is True and type(item["read"]) is int and 0 <= item["read"] < len(reads)
                        and reads[item["read"]]["kind"] == "process"
                        and reads[item["read"]]["status"] == "missing"
                        and type(reads[item["read"]]["pid"]) is int
                        and reads[item["read"]]["pid"] == item["record"]["pid"]
                        and reads[item["read"]]["path"] == f"/proc/{item['record']['pid']}/stat"
                        for item in frame["processes"]),
                "retirement-evidence-process-absence")
        prefix_kinds = ["boot", *("manager" for _ in managers), *("process" for _ in document["actors"])]
        kinds = [event["kind"] for event in reads]
        require(kinds[:len(prefix_kinds)] == prefix_kinds
                and [item["read"] for item in frame["processes"]] == list(range(1 + len(managers), len(prefix_kinds))),
                "retirement-evidence-read-association")
        cgroup_kinds = ["cgroup-canonical", "cgroup-stat", "cgroup-cpu", "cgroup-number", "cgroup-number",
                        "cgroup-number", "cgroup-events", "cgroup-procs"]
        if frame["cgroup"] == "removed":
            suffix = reads[len(prefix_kinds):]
            require(len(suffix) >= 2 and [event["kind"] for event in suffix[:-1]] == cgroup_kinds[:len(suffix)-1]
                    and suffix[-2]["status"] == "missing"
                    and suffix[-1]["kind"] == "cgroup-exists", "retirement-evidence-removed-association")
            require(any(event["kind"] in ("cgroup-canonical", "cgroup-stat", "cgroup-number", "cgroup-cpu", "cgroup-events", "cgroup-procs")
                        and event["status"] == "missing" for event in reads)
                    and any(event["kind"] == "cgroup-exists" and event["parsed"] is False for event in reads),
                    "retirement-evidence-cgroup-removed")
        else:
            require(kinds == prefix_kinds + cgroup_kinds, "retirement-evidence-read-association")
            require(frame["cgroup"] == "held-empty", "retirement-evidence-cgroup-state")
            events = [event for event in reads if event["kind"] == "cgroup-events"]
            procs = [event for event in reads if event["kind"] == "cgroup-procs"]
            require(len(events) == len(procs) == 1 and events[0]["parsed"].get("populated") == "0"
                    and procs[0]["parsed"] == "", "retirement-evidence-cgroup-empty")
            snapshot = document["cgroup"]
            path = Path(snapshot["path"])
            require(str(path).startswith("/sys/fs/cgroup/") and path.name == config["unit"], "retirement-evidence-cgroup-path")
            stats = [event for event in reads if event["kind"] == "cgroup-stat"]
            cpus = [event for event in reads if event["kind"] == "cgroup-cpu"]
            number_events = [event for event in reads if event["kind"] == "cgroup-number"]
            numbers = {Path(event["path"]).name: event["parsed"] for event in number_events}
            require(len(stats) == len(cpus) == 1 and len(number_events) == 3
                    and cpus[0]["path"] == str(path / "cpu.max"), "retirement-evidence-cgroup-snapshot")
            info, cpu = stats[0]["parsed"], cpus[0]["parsed"]
            require(stat.S_ISDIR(info["st_mode"]) and info["st_uid"] == document["owner_uid"]
                    and (info["st_dev"], info["st_ino"]) == (snapshot["device"], snapshot["inode"])
                    and len(cpu) == 2 and all(re.fullmatch(r"[0-9]+", value) for value in cpu)
                    and int(cpu[0]) > 0 and int(cpu[1]) > 0 and int(cpu[0]) <= config["cpus"] * int(cpu[1])
                    and " ".join(cpu) == snapshot["cpu_max"]
                    and numbers == {"memory.max": config["memory_bytes"], "pids.max": config["pids"], "memory.swap.max": 0}
                    and snapshot["memory_max"] == config["memory_bytes"] and snapshot["pids_max"] == config["pids"]
                    and snapshot["swap_max"] == 0
                    and all(event["path"] == str(path / "cgroup.events") for event in events)
                    and all(event["path"] == str(path / "cgroup.procs") for event in procs), "retirement-evidence-cgroup-scope")
    require(document["retirement"]["state"] == "retired"
            and document["retirement"]["invocation"] == document["invocation"]
            and document["retirement"]["cgroup"] == document["cgroup"], "retirement-evidence-receipt")
    return document


def retire(config, budget, invocation, snapshot, worker_record, qemu_record, barrier, ssh_record=None, producers=None, *, evidence=None):
    """Same outside observer; no worker booleans or partial trace prove success."""
    producers = [] if producers is None else producers
    require(evidence is None or evidence.budget is budget, "retirement-original-budget")
    if evidence is not None:
        require(all(config[key] == evidence.config[key] for key in
                    ("owner", "unit", "directory", "source", "end", "work_end", "cleanup_seconds", "boot", "cpus", "pids", "memory_bytes")),
                "retirement-original-scope")
    started = time.monotonic()
    cleanup_seconds = budget.cleanup_seconds
    require(type(cleanup_seconds) in (int, float) and 0 < cleanup_seconds <= 120, "retirement-cleanup-duration")
    collection_end = min(budget.end, started + cleanup_seconds)
    budget.retirement_end = collection_end
    actors = [record for record in (worker_record, qemu_record, ssh_record) if record is not None]
    actors += [item["process"] for item in producers]
    if evidence is not None:
        evidence.bind(invocation, snapshot, actors, producers, started, collection_end)
    try:
        row = unit_show(config, budget, cleanup=True) if evidence is None else unit_show(
            config, budget, cleanup=True, deadline=collection_end, evidence=evidence)
        validate_unit(row, config, live=False, invocation=invocation)
        argv = [config["tools"]["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "stop", "--no-block", config["unit"]]
        if evidence is None:
            status, _ = run(argv, budget, config["directory"], cleanup=True, manager=True, deadline=collection_end)
        else:
            status, _, _event = evidence.manager("stop", argv, budget, config["directory"], cleanup=True, deadline=collection_end)
        require(status == 0, "unit-stop-failed")
        empty = []
        previous = None
        for poll in range(1, RETIREMENT_POLLS + 1):
            budget.remaining(cleanup=True)
            if previous is not None:
                next_at = previous + RETIREMENT_SPACING
                while True:
                    now = time.monotonic()
                    if now >= next_at:
                        break
                    require(next_at < collection_end, "retirement-collection-end")
                    time.sleep(min(next_at - now, budget.remaining(cleanup=True)))
            require(time.monotonic() < collection_end, "retirement-collection-end")
            if evidence is not None:
                evidence.begin_frame(poll)
            observed_boot = boot_id() if evidence is None else boot_id(evidence=evidence)
            require(observed_boot == config["boot"], "retirement-host-boot-drift")
            row = unit_show(config, budget, cleanup=True) if evidence is None else unit_show(
                config, budget, cleanup=True, deadline=collection_end, evidence=evidence)
            if row["LoadState"] == "not-found":
                require(row["ActiveState"] == "inactive" and row["MainPID"] == "0", "unit-unloaded-active")
            else:
                if row["InvocationID"]:
                    require(row["InvocationID"] == invocation, "retirement-new-invocation")
                require(row["Restart"] == "no" and row["NRestarts"] == "0"
                        and not any(row[key] for key in ("Triggers", "TriggeredBy", "UpheldBy")), "retirement-respawn-policy")
            inactive = row["ActiveState"] in ("inactive", "failed") and row["MainPID"] == "0" and row["Job"] in ("", "0")
            gone = inactive and all(process_retired(record) if evidence is None else process_retired(record, evidence=evidence)
                                    for record in actors)
            group = (empty_cgroup(snapshot, config) if evidence is None else empty_cgroup(snapshot, config, evidence=evidence)) if gone else None
            at = time.monotonic()
            require(at < collection_end, "retirement-collection-end")
            accepted = gone and group in ("held-empty", "removed")
            if evidence is not None:
                evidence.finish_frame(row, group, accepted, at)
            if accepted:
                empty.append({"at": at, "cgroup": group})
            else:
                empty.clear()
            previous = at
            if len(empty) == 2:
                break
        require(len(empty) == 2 and empty[1]["at"] - empty[0]["at"] >= RETIREMENT_SPACING,
                "retirement-poll-budget")
        fields = {"stage", "error", "guest", "qemu", "ssh", "qemu_reaped", "ssh_reaped", "original_end"}
        if config.get("phase") in ("stage-inputs", "run-rootful-kind"):
            fields |= {"producers", "producers_reaped", "staging"}
            require(type(barrier) is dict and barrier.get("producers") == producers
                    and len(barrier.get("producers_reaped", [])) == len(producers)
                    and all(value is True for value in barrier["producers_reaped"]), "stage-producer-barrier-unproved")
        if config.get("phase") == "run-rootful-kind":
            fields |= {"rootful", "rootful_input_bytes", "rootful_wire", "rootful_record_guards"}
            require(type(barrier) is dict, "rootful-record-reservation-unproved")
            validated_rootful_record_guards(barrier.get("rootful_record_guards"), producers)
            if type(barrier) is dict and "guest_info_command" in barrier:
                fields.add("guest_info_command")
            require(type(barrier) is dict and type(barrier.get("rootful_input_bytes")) is int
                    and 0 <= barrier["rootful_input_bytes"] <= config["rootful_input_reserved"] == 4096, "rootful-retirement-input-budget")
        require(type(barrier) is dict and set(barrier) == fields
                and barrier["stage"] == "producer-stopped" and barrier["original_end"] == config["end"]
                and barrier["qemu"] == qemu_record and barrier["ssh"] == ssh_record and barrier["qemu_reaped"] is True
                and barrier["ssh_reaped"] is True, "producer-barrier-unproved")
        result = {"state": "retired", "observations": empty, "invocation": invocation,
                "worker": worker_record, "qemu": qemu_record, "ssh": ssh_record, "cgroup": snapshot, "boot": config["boot"],
                **({"producers": producers} if config.get("phase") in ("stage-inputs", "run-rootful-kind") else {})}
        if evidence is not None:
            evidence.finish(result)
        return result
    except Exception as caught:
        if evidence is not None:
            code = str(caught) if isinstance(caught, Refusal) else "retirement-observation-unavailable"
            evidence.observation_error(code)
        raise


def validated_rootful_record_guards(value, producers):
    if value is None:
        require(not producers, "rootful-record-reservation-unproved")
        return None
    phases = ("guest-info", "stage-kind", "stage-kubectl", "stage-node-oci", "rootful-kind")
    require(type(value) is dict and set(value) == {"prepaid", "consumed_purposes", "comparisons_attempted"}
            and type(value["prepaid"]) is int and value["prepaid"] == 24
            and type(value["consumed_purposes"]) is list
            and value["consumed_purposes"] == list(phases[:len(value["consumed_purposes"])])
            and len(producers) <= len(value["consumed_purposes"]) <= min(5, len(producers) + 1)
            and value["comparisons_attempted"] is None, "rootful-record-reservation-schema")
    return {"prepaid": 24, "consumed_purposes": list(value["consumed_purposes"]),
            "comparisons_attempted": None}


def admit_producer_event(event, records, qemu, snapshot, *, allow_retired=False, rootful=False, evidence=None):
    phases = ("guest-info", "stage-kind", "stage-kubectl", "stage-node-oci")
    if rootful:
        phases += ("rootful-kind",)
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
        observed = process_identity(record["pid"]) if evidence is None else process_identity(record["pid"], evidence=evidence)
        require(observed == record and (process_cgroup(record["pid"]) if evidence is None else
                process_cgroup(record["pid"], evidence=evidence)) == snapshot["path"],
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


def sync_retirement_parent(parent, *, budget=None):
    if budget is not None:
        budget.remaining(cleanup=True)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if budget is None:
            os.fsync(fd)
        else:
            _retirement_io(budget, os.fsync, fd)
    finally:
        os.close(fd)  # Always unwind an acquired descriptor, even after expiry.
    if budget is not None:
        budget.remaining(cleanup=True)


def stage_retirement_receipt(path, private, budget):
    raw = encode(private)
    require(len(raw) <= META_MAX, "metadata-budget")
    _retirement_write(path, raw, budget)
    sync_retirement_parent(path.parent, budget=budget)
    identity = file_id(_retirement_io(budget, path.stat, follow_symlinks=False))
    require(_retirement_read(path, budget) == raw
            and file_id(_retirement_io(budget, path.stat, follow_symlinks=False)) == identity,
            "private-receipt-staging-integrity")
    budget.remaining(cleanup=True)
    return identity, raw


def rewrite_staged_retirement_receipt(pending, replacement, identity, old_raw, private, budget):
    """Use only the two reserved receipt slots; never unlink the sole copy."""
    require(file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == identity,
            "private-receipt-staging-drift")
    new_identity, raw = stage_retirement_receipt(replacement, private, budget)
    def exact(path, expected, expected_raw):
        info = _retirement_io(budget, path.stat, follow_symlinks=False)
        require(file_id(info) == expected and stat.S_ISREG(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
                and info.st_nlink == 1 and _retirement_read(path, budget) == expected_raw
                and file_id(_retirement_io(budget, path.stat, follow_symlinks=False)) == expected,
                "private-receipt-rewrite-drift")
        return info
    newer = exact(replacement, new_identity, raw)
    exact(pending, identity, old_raw)
    # Refresh both exact identities after the full byte proofs, before mutation.
    require(file_id(_retirement_io(budget, replacement.stat, follow_symlinks=False)) == new_identity
            and file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == identity,
            "private-receipt-rewrite-drift")
    # Both exact full versions exist until this one atomic namespace operation.
    # A slow operation may finish late; its next I/O and publication are fenced.
    _retirement_io(budget, os.replace, replacement, pending)
    current = _retirement_io(budget, pending.stat, follow_symlinks=False)
    require(file_id(current)[:4] == new_identity[:4] and current.st_mode == newer.st_mode
            and current.st_uid == newer.st_uid and current.st_gid == newer.st_gid and current.st_nlink == 1
            and _retirement_read(pending, budget) == raw
            and file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == file_id(current),
            "private-receipt-rewrite-drift")
    # Only this proven own rename permits refreshing the new inode's ctime.
    identity = file_id(current)
    sync_retirement_parent(pending.parent, budget=budget)
    require(file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == identity,
            "private-receipt-rewrite-drift")
    return identity, raw


def publish_staged_retirement_receipt(pending, path, identity, budget, *, successful=False):
    budget.remaining(cleanup=True)
    before = _retirement_io(budget, pending.stat, follow_symlinks=False)
    require(file_id(before) == identity and stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_uid == os.getuid()
            and before.st_nlink == 1, "private-receipt-staging-drift")
    raw = _retirement_read(pending, budget)
    require(file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == identity, "private-receipt-staging-drift")
    def owned(candidate, links):
        info = _retirement_io(budget, candidate.stat, follow_symlinks=False)
        require(file_id(info)[:4] == identity[:4] and info.st_mode == before.st_mode
                and info.st_uid == before.st_uid and info.st_gid == before.st_gid
                and info.st_nlink == links and _retirement_read(candidate, budget) == raw
                and file_id(_retirement_io(budget, candidate.stat, follow_symlinks=False)) == file_id(info),
                "private-receipt-publication-drift")
        return info
    require(not successful or not CANCELLED, "cancelled")
    linked = False
    try:
        # Exclusive name creation never overwrites a preexisting receipt.
        budget.remaining(cleanup=True)
        os.link(pending, path, follow_symlinks=False)
        linked = True
        budget.remaining(cleanup=True)
        own = owned(path, 2)
        require(file_id(owned(pending, 2)) == file_id(own), "private-receipt-publication-drift")
        sync_retirement_parent(path.parent, budget=budget)
        budget.remaining(cleanup=True)
        require(not successful or not CANCELLED, "cancelled")
        budget.remaining(cleanup=True)
        _retirement_io(budget, pending.unlink)
        owned(path, 1)
        sync_retirement_parent(path.parent, budget=budget)
        budget.remaining(cleanup=True)
        require(not successful or not CANCELLED, "cancelled")
    except Exception as caught:
        if linked:
            try:
                budget.remaining(cleanup=True)
                # Only our proven same inode/content may be rolled back. An
                # unexpected replacement is retained, never removed by name.
                links = 2 if _retirement_io(budget, pending.exists) else 1
                owned(path, links)
                if links == 2:
                    owned(pending, 2)
                    _retirement_io(budget, path.unlink)
                    # Exactly our link/unlink changes ctime. Refresh only after
                    # immutable fields, mode/uid/gid, links and bytes all agree.
                    identity[:] = file_id(owned(pending, 1))
                    sync_retirement_parent(path.parent, budget=budget)
                # With no pending link the final prepared file is the sole
                # full private receipt. Keep that exact non-authorizing copy;
                # failed acknowledgement never justifies destroying custody.
            except Exception as rollback_error:
                try:
                    budget.remaining(cleanup=True)
                except Refusal:
                    raise Refusal("private-receipt-publication-rollback-unavailable") from rollback_error
                raise Refusal("private-receipt-publication-rollback-unproved") from rollback_error
            if links == 1:
                raise Refusal("private-receipt-publication-prepared-only") from caught
        raise caught


def finish_qualify_receipt(private, config, budget, parent, directory, retirement, retirement_evidence, attempted):
    try:
        return _finish_qualify_receipt(private, config, budget, parent, directory, retirement, retirement_evidence, attempted)
    except (Refusal, OSError, ValueError, TypeError, KeyError):
        if retirement_evidence is not None:
            retirement_evidence.fail("retirement-finalization-unproved")
        return {"state": "failed-quarantined", "owner": config["owner"],
            "error": private["error"] or ("cancelled" if CANCELLED else None),
            "retirement_error": private["retirement_error"] or "retirement-finalization-unproved",
            "receipt_sha256": None,
            "retirement_evidence": None if retirement_evidence is None else retirement_evidence.descriptor(),
            "runtime_conformance": "not-performed"}, 1


def _retirement_remove_lease(directory, config, budget):
    """Flat fd-relative cleanup of the source-defined lease catalogue only."""
    directory = Path(directory)
    require(str(directory) == config["directory"] and directory.is_absolute()
            and directory.name == "kubernetes-lens-vm-" + config["owner"], "private-artifact-lease-scope")
    overlay_max = config["overlay_max"]
    require(type(overlay_max) is int and overlay_max > 0, "private-artifact-overlay-budget")
    catalogue = {name: ("regular", maximum) for name, maximum in
                 _retirement_metadata_reservation()["lease_files"].items()}
    catalogue.update({"image.qcow2": ("regular", EXPANDED_MAX),
                      "image.qcow2.xz": ("regular", ARCHIVE_MAX),
                      "overlay.qcow2": ("regular", overlay_max), "control.sock": ("socket", 0)})
    def directory_matches(info, expected):
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
                == (expected.st_dev, expected.st_ino, expected.st_mode, expected.st_uid, expected.st_gid))
    def leaf_matches(info, expected):
        return (file_id(info) == file_id(expected) and info.st_mode == expected.st_mode
                and info.st_uid == expected.st_uid and info.st_gid == expected.st_gid
                and info.st_nlink == expected.st_nlink == 1)
    parent_info = _retirement_io(budget, directory.parent.stat, follow_symlinks=False)
    require(directory_matches(parent_info, parent_info), "private-artifact-parent-owner")
    parent_fd, lease_fd = None, None
    try:
        budget.remaining(cleanup=True)
        parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        budget.remaining(cleanup=True)
        parent_held = _retirement_io(budget, os.fstat, parent_fd)
        require(file_id(parent_held) == file_id(parent_info) and directory_matches(parent_held, parent_info),
                "private-artifact-parent-drift")
        original = _retirement_io(budget, os.stat, directory.name, dir_fd=parent_fd, follow_symlinks=False)
        require(directory_matches(original, original), "private-artifact-lease-owner")
        budget.remaining(cleanup=True)
        lease_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        budget.remaining(cleanup=True)
        held = _retirement_io(budget, os.fstat, lease_fd)
        require(file_id(held) == file_id(original) and directory_matches(held, original), "private-artifact-lease-drift")
        def bound():
            require(directory_matches(_retirement_io(budget, os.fstat, parent_fd), parent_held)
                    and directory_matches(_retirement_io(budget, os.fstat, lease_fd), held)
                    and directory_matches(_retirement_io(budget, os.stat, directory.name,
                        dir_fd=parent_fd, follow_symlinks=False), held), "private-artifact-lease-drift")
        bound()
        records = {}
        budget.remaining(cleanup=True)
        entries = os.scandir(lease_fd)
        try:
            budget.remaining(cleanup=True)
            while True:
                try:
                    entry = _retirement_io(budget, next, entries)
                except StopIteration:
                    budget.remaining(cleanup=True)
                    break
                name = entry.name
                require(name in catalogue and name not in records and len(records) < len(catalogue),
                        "private-artifact-unknown-entry")
                info = _retirement_io(budget, os.stat, name, dir_fd=lease_fd, follow_symlinks=False)
                kind, maximum = catalogue[name]
                require(info.st_uid == os.getuid() and info.st_nlink == 1
                        and not info.st_mode & 0o7000 and 0 <= info.st_size <= maximum
                        and (stat.S_ISREG(info.st_mode) if kind == "regular" else stat.S_ISSOCK(info.st_mode)),
                        "private-artifact-leaf-owner-type-budget")
                records[name] = info
        finally:
            entries.close()  # Mandatory iterator/FD unwind, including a late acquisition.
        for name, expected in sorted(records.items()):
            bound()
            current = _retirement_io(budget, os.stat, name, dir_fd=lease_fd, follow_symlinks=False)
            require(leaf_matches(current, expected), "private-artifact-leaf-drift")
            _retirement_io(budget, os.unlink, name, dir_fd=lease_fd)
        bound()
        # No recursive traversal. New/unknown leftovers make this fail closed.
        _retirement_io(budget, os.rmdir, directory.name, dir_fd=parent_fd)
    finally:
        try:
            if lease_fd is not None:
                os.close(lease_fd)
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
    budget.remaining(cleanup=True)


def _finish_qualify_receipt(private, config, budget, parent, directory, retirement, retirement_evidence, attempted):
    """One caller path: durable raw/receipt first, deletion guard, then publication."""
    owner = config["owner"]
    error, cleanup_error = private["error"], private["retirement_error"]
    if CANCELLED:
        error = error or "cancelled"
    if retirement_evidence is not None:
        cleanup_error = cleanup_error or retirement_evidence.error
    if attempted and (retirement is None or retirement_evidence is None or not retirement_evidence.complete):
        cleanup_error = cleanup_error or "retirement-evidence-incomplete"
    if (attempted and retirement_evidence is not None and retirement_evidence.complete
            and not _retirement_json_equal(retirement_evidence.document["retirement"], retirement)):
        cleanup_error = cleanup_error or "retirement-evidence-receipt-binding"
    success = error is None and cleanup_error is None and retirement is not None
    positive = ("rootful-kind-smoke-retired" if config.get("phase") == "run-rootful-kind" else
                "stage-inputs-retired" if config.get("phase") == "stage-inputs" else "vm-qualified-retired")
    private["publication"] = {"schema": "kubernetes-lens-retirement-publication-v1",
        "state": "prepared", "requires": ["matching-public-commit-acknowledgement", "cli-exit-zero"]}
    private.update(error=error, retirement_error=cleanup_error,
                   state=positive if success else "failed-quarantined" if cleanup_error else "failed-retired")
    # Persist both source-bound raw evidence and these final receipt bytes before
    # deleting the lease. The exclusive staging name is not a published receipt.
    if retirement_evidence is not None:
        retirement_evidence.seal_receipt(private)
        if retirement_evidence.error is not None:
            cleanup_error = cleanup_error or retirement_evidence.error
            success = False
            private.update(state="failed-quarantined", retirement_error=cleanup_error)
        private["retirement_evidence"] = retirement_evidence.descriptor()
    receipt_path = parent / ("kubernetes-lens-vm-" + owner + ".receipt.json")
    pending = receipt_path.with_name(receipt_path.name + ".pending")
    try:
        pending_identity, receipt_raw = stage_retirement_receipt(pending, private, budget)
    except (Refusal, OSError, ValueError, TypeError):
        cleanup_error = cleanup_error or "private-receipt-persistence-unproved"
        if retirement_evidence is not None:
            retirement_evidence.fail("retirement-final-receipt-persistence")
        return {"state": "failed-quarantined", "owner": owner, "error": error,
                "retirement_error": cleanup_error, "receipt_sha256": None,
                "retirement_evidence": None if retirement_evidence is None else retirement_evidence.descriptor(),
                "runtime_conformance": "not-performed"}, 1
    deletion_allowed = cleanup_error is None and (not attempted or
        retirement is not None and retirement_evidence is not None and retirement_evidence.complete
        and retirement_evidence.receipt_complete)
    if deletion_allowed:
        try:
            budget.remaining(cleanup=True)
            _retirement_remove_lease(directory, config, budget)
            require(not _retirement_io(budget, Path(directory).exists), "private-artifact-retirement-unproved")
            budget.remaining(cleanup=True)
        except (OSError, Refusal):
            cleanup_error = cleanup_error or "private-artifact-retirement-unproved"
            success = False
            private.update(state="failed-quarantined", retirement_error=cleanup_error)
            budget.remaining(cleanup=True)
            require(file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == pending_identity, "private-receipt-staging-drift")
            if retirement_evidence is not None:
                private.pop("retirement_evidence", None)
                retirement_evidence.seal_receipt(private)
                private["retirement_evidence"] = retirement_evidence.descriptor()
            pending_identity, receipt_raw = rewrite_staged_retirement_receipt(
                pending, receipt_path, pending_identity, receipt_raw, private, budget)
    try:
        publish_staged_retirement_receipt(pending, receipt_path, pending_identity, budget, successful=success)
    except (Refusal, OSError, ValueError, TypeError) as caught:
        if CANCELLED:
            error = error or "cancelled"
        if not isinstance(caught, Refusal) or str(caught) != "cancelled":
            cleanup_error = cleanup_error or (str(caught) if isinstance(caught, Refusal) else "private-receipt-publication-unproved")
            if retirement_evidence is not None:
                retirement_evidence.fail("retirement-final-publication")
            return {"state": "failed-quarantined", "owner": owner, "error": error,
                "retirement_error": cleanup_error, "receipt_sha256": None,
                "retirement_evidence": None if retirement_evidence is None else retirement_evidence.descriptor(),
                "runtime_conformance": "not-performed"}, 1
        error = error or "cancelled"
        success = False
        private.update(error=error, state="failed-quarantined" if cleanup_error else "failed-retired")
        budget.remaining(cleanup=True)
        require(file_id(_retirement_io(budget, pending.stat, follow_symlinks=False)) == pending_identity, "private-receipt-staging-drift")
        if retirement_evidence is not None:
            private.pop("retirement_evidence", None)
            retirement_evidence.seal_receipt(private)
            private["retirement_evidence"] = retirement_evidence.descriptor()
        pending_identity, receipt_raw = rewrite_staged_retirement_receipt(
            pending, receipt_path, pending_identity, receipt_raw, private, budget)
        try:
            publish_staged_retirement_receipt(pending, receipt_path, pending_identity, budget)
        except (Refusal, OSError, ValueError, TypeError):
            return {"state": "failed-quarantined", "owner": owner, "error": error,
                "retirement_error": cleanup_error or "private-receipt-publication-unproved",
                "receipt_sha256": None, "retirement_evidence": private.get("retirement_evidence"),
                "runtime_conformance": "not-performed"}, 1
    budget.remaining(cleanup=True)
    acknowledgement = ({"schema": "kubernetes-lens-retirement-publication-v1", "state": "committed",
        "owner": owner, "receipt_sha256": digest(receipt_raw),
        "retirement_evidence_sha256": private["retirement_evidence"]["sha256"]} if success else None)
    return {"state": private["state"], "owner": owner, "error": error, "retirement_error": cleanup_error,
            "receipt_sha256": digest(receipt_raw), "retirement_evidence": private.get("retirement_evidence"),
            "publication_commit": acknowledgement,
            "runtime_conformance": "not-performed"}, 0 if success else 1


def qualify(args, *, start=None):
    start = time.monotonic() if start is None else start
    diagnostic_profile = getattr(args, "host_view_diagnostic_profile", None)
    require(diagnostic_profile in (None, DIAGNOSTIC_CREDIT_PROFILE), "host-view-diagnostic-profile")
    parent = validate_config_args(args)
    budget = Budget(start + args.deadline_seconds, args.cleanup_seconds)
    args._retirement_budget = budget
    tools = admit_tools(args.host_tools, args.host_tools_sha256)
    pin, pin_sha = pin_document()
    owner = uuid.uuid4().hex
    directory = parent / ("kubernetes-lens-vm-" + owner)
    directory.mkdir(mode=0o700)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel, invocation, snapshot, worker_record, qemu_record, ssh_record, barrier = None, None, None, None, None, None, None
    error, cleanup_error, retirement = None, None, None
    retirement_evidence = None
    attempted = False
    view, view_frame = None, None
    view_impl, reservation = None, None
    host_view_mismatch = None
    host_view_failure_site = None
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
    if diagnostic_profile is not None:
        config.update(host_view_diagnostic_profile=diagnostic_profile,
                      host_view_diagnostic_credit_bytes=DIAGNOSTIC_CREDIT_BYTES)
    image_evidence, stage_evidence, guest_summary = None, None, None
    producer_records = []
    rootful_durable = None
    guest_info_command = None
    is_rootful = getattr(args, "phase", "qualify-vm") == "run-rootful-kind"
    is_stage = getattr(args, "phase", "qualify-vm") in ("stage-inputs", "run-rootful-kind")
    try:
        if is_stage:
            config["phase"] = "run-rootful-kind" if is_rootful else "stage-inputs"
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
            if is_rootful:
                for name in ("owned_guest_rootful.py", "owned_guest_rootful.sh",
                         "owned-live-resource-envelope-source-facts-v1.json",
                         "owned-live-resource-envelope-source-facts-v1.schema.json"):
                    path = ROOT / "scripts/fixtures" / name
                    config["source"][str(path)] = digest(read(path, 4 * 1024**2))
                scenarios = ROOT / "schemas/capabilities/kubernetes-native-scenarios.json"
                config["source"][str(scenarios)] = digest(read(scenarios, 4 * 1024**2))
                rootful = authenticated_module("owned_guest_rootful", config, budget)
                rootful.admit_resources(args)
                rootful.admit_live_resource_profile(config)
                receiver_path = ROOT / "scripts/fixtures/owned_guest_rootful.sh"
                receiver = read(receiver_path, 4 * 1024**2)
                require(digest(receiver) == config["source"][str(receiver_path)], "rootful-receiver-source-drift")
                rootful_files, spec = rootful.guest_files(plan, stage_evidence, receiver)
                require(spec["scenarios_sha256"] == config["source"][str(scenarios)], "rootful-scenarios-source-drift")
                require(config["stage_input_limit"] + 4096 <= stage.MAX_INPUT, "rootful-original-input-fit")
                config["rootful_input_reserved"] = 4096
                config["rootful_spec"] = spec
                config["rootful_reservation"] = rootful.reservation()
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
                             "stage_files": stage.guest_files(plan_raw, receiver, rootful=is_rootful)}
            if is_rootful:
                generated = stage_options["stage_files"]["/var/lib/kubernetes-lens-stage/receiver"][0]
                config["rootful_stage_receiver"] = stage.rootful_receiver_binding(receiver, generated)
                stage_options["rootful_files"] = rootful_files
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
        view_impl = host_view_module(config, budget)
        view = view_impl.ParentView(config, budget)
        parent_pre_child(config, budget)
        if diagnostic_profile is not None:
            reservation = view_impl.PendingDiagnosticReservation(budget, config_sha)
        retirement_evidence = RetirementEvidence(parent, config, budget)
        require(retirement_evidence.error is None, "retirement-evidence-prestart-unavailable")
        attempted = True
        status, _ = run(unit_arguments(config, config_path, config_sha, manager_keys), budget, directory, manager=True)
        require(status == 0, "owned-unit-start-failed")
        channel = await_worker_connection(server, config, budget)
        worker_record = peer_identity(channel)
        hello = receive(channel, budget)
        row = unit_show(config, budget)
        invocation, snapshot = attest_barrier_and_bind(row, hello, worker_record, config, config_sha,
            reservation=reservation, budget=budget, channel=channel)
        verify_source(config, budget)
        host_view_failure_site = "parent-attest"
        view_frame = view.attest(worker_record, invocation, snapshot, config_sha)
        host_view_failure_site = "parent-recheck"
        view.recheck()
        host_view_failure_site = None
        send(channel, {"stage": "go", "config_sha256": config_sha, "invocation": invocation, "cgroup": snapshot,
                       "host_view": view_frame if view_frame is not None else view.partial if view is not None else None, "host_view_sha256": digest(encode(view_frame))}, budget)
        if reservation is not None:
            reservation.activate(budget, channel, config_sha)
        while True:
            event = receive(channel, budget)
            if event.get("stage") == "qemu-started":
                require(qemu_record is None and set(event) == {"stage", "qemu"}, "qemu-start-event-schema")
                qemu_record = event["qemu"]
                require(process_identity(qemu_record["pid"]) == qemu_record
                        and process_cgroup(qemu_record["pid"]) == snapshot["path"], "qemu-external-identity")
            elif is_stage and event.get("stage") == "stage-producer-started":
                admit_producer_event(event, producer_records, qemu_record, snapshot, rootful=is_rootful)
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
        if is_rootful:
            try:
                guest_info_command = validated_guest_info_command(event.get("guest_info_command"), producer_records)
            except Refusal:
                # Retain the worker's earlier failure; neither diagnostic refusal
                # nor the outer error path may bypass independent retirement.
                if event.get("error"):
                    raise Refusal(event["error"]) from None
                raise
        if event.get("error"):
            raise Refusal(event["error"])
        guest_summary = validated_guest_summary(event.get("guest"))
        if is_stage:
            validate_stage_result(event.get("staging"), plan, stage, config)
            require(len(producer_records) == (5 if is_rootful else 4), "stage-producer-count")
        if is_rootful:
            record = event.get("rootful_wire")
            require(type(record) is dict and set(record) == {"bytes", "sha256", "identity"}, "rootful-wire-descriptor")
            require(type(event.get("rootful_input_bytes")) is int and 0 < event["rootful_input_bytes"] <= 4096, "rootful-input-completion")
    except (Refusal, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, subprocess.SubprocessError) as caught:
        observed_error = str(caught) if isinstance(caught, Refusal) else "vm-prerequisite-unavailable"
        if not attempted and observed_error.startswith("retirement-"):
            cleanup_error = cleanup_error or observed_error
        else:
            error = error or observed_error
        if diagnostic_profile is not None and isinstance(caught, Refusal) and error == "host-view-object-not-equivalent":
            detail = getattr(caught, "host_view_mismatch", None)
            if detail is not None:
                try:
                    host_view_mismatch = validated_host_view_mismatch(detail)
                    require(host_view_mismatch["site"] == host_view_failure_site,
                            "parent-host-view-mismatch-site")
                except (Refusal, TypeError, ValueError, RecursionError):
                    host_view_mismatch = None
    finally:
        if reservation is not None and reservation.state in ("pending", "bound"):
            reservation.finalize()
        server.close()
        if view is not None:
            view.close()
        if attempted:
            try:
                # Even failure before GO may leave a waiting worker. Adopt only
                # this uniquely described transient invocation, never a caller unit.
                if invocation is None:
                    row = unit_show(config, budget, cleanup=True, evidence=retirement_evidence)
                    invocation = validate_unit(row, config)
                    worker_record = process_identity(int(row["MainPID"]), evidence=retirement_evidence)
                    snapshot = cgroup_snapshot("/sys/fs/cgroup" + row["ControlGroup"], config, evidence=retirement_evidence)
                if channel is not None and barrier is None:
                    row = unit_show(config, budget, cleanup=True, evidence=retirement_evidence)
                    validate_unit(row, config, live=False, invocation=invocation)
                    cancel_argv = [tools["systemctl"]["path"], "--user", "--no-pager", "--no-ask-password", "kill", "--kill-whom=main", "--signal=SIGTERM", config["unit"]]
                    status, _, _event = retirement_evidence.manager("cancel", cancel_argv, budget, directory, cleanup=True)
                    require(status == 0, "worker-cancellation-unavailable")
                    for _ in range(7 if is_rootful else 6 if is_stage else 3):
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
                            admit_producer_event(event, producer_records, qemu_record, snapshot, allow_retired=True, rootful=is_rootful, evidence=retirement_evidence)
                        else:
                            raise Refusal("cancellation-event-order")
                if is_rootful and type(barrier) is dict:
                    try:
                        guest_info_command = validated_guest_info_command(barrier.get("guest_info_command"), producer_records)
                    except Refusal as diagnostic_error:
                        # Malformed diagnostics cannot prevent independent retirement.
                        error = error or str(diagnostic_error)
                retirement = retire(config, budget, invocation, snapshot, worker_record, qemu_record, barrier, ssh_record, producer_records, evidence=retirement_evidence)
                if is_rootful and type(barrier) is dict and barrier.get("rootful_wire") is not None:
                    record = barrier["rootful_wire"]
                    require(type(record) is dict and set(record) == {"bytes", "sha256", "identity"}
                            and type(record["bytes"]) is int and 0 < record["bytes"] <= rootful.EVIDENCE_MAX,
                            "rootful-wire-descriptor")
                    wire_path = directory / "rootful-wire.json"
                    require(file_id(wire_path.stat(follow_symlinks=False)) == record["identity"], "rootful-wire-file-identity")
                    wire_raw = read(wire_path, rootful.EVIDENCE_MAX)
                    require(len(wire_raw) == record["bytes"] and digest(wire_raw) == record["sha256"], "rootful-wire-file-integrity")
                    require(rootful.wire_record(wire_raw, config, allow_failure=True) == barrier.get("rootful"), "rootful-wire-summary")
                    rootful_durable = rootful.durable_wire(wire_raw, config, parent, budget)
                elif is_rootful and error is None:
                    raise Refusal("rootful-durable-evidence-missing")
            except (Refusal, OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError, subprocess.SubprocessError) as caught:
                cleanup_error = str(caught) if isinstance(caught, Refusal) else "outside-retirement-unavailable"
        if channel:
            if reservation is not None:
                if (retirement is not None and cleanup_error is None and error == "host-view-object-not-equivalent"
                        and host_view_mismatch is None and reservation.state == "active"):
                    try:
                        host_view_mismatch = reservation.drain_once(budget, channel)
                    except (Refusal, OSError, TypeError, ValueError, RecursionError):
                        host_view_mismatch = None
                if reservation.state in ("pending", "bound", "active"):
                    reservation.finalize()
            channel.close()
        elif reservation is not None and reservation.state in ("pending", "bound", "active"):
            reservation.finalize()
    if CANCELLED:
        error = error or "cancelled"
    if is_rootful and error is None:
        # Direct retirement controls may omit diagnostics; actual controller
        # success must have both real command EOFs and an observed zero exit.
        if (guest_info_command is None or guest_info_command["outcome"]["classification"] != "exit"
                or guest_info_command["outcome"]["returncode"] != 0):
            error = "guest-info-command-success-unproved"
    if retirement_evidence is not None:
        cleanup_error = cleanup_error or retirement_evidence.error
    if attempted and (retirement_evidence is None or not retirement_evidence.complete):
        cleanup_error = cleanup_error or "retirement-evidence-incomplete"
    success = error is None and cleanup_error is None and retirement is not None
    private = {"schema": "kubernetes-lens-owned-vm-receipt-v1", "owner": owner,
               "state": ("rootful-kind-smoke-retired" if is_rootful else "stage-inputs-retired" if is_stage else "vm-qualified-retired") if success else "failed-quarantined" if cleanup_error else "failed-retired",
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
    if is_rootful:
        private["guest_info_command"] = guest_info_command
        private["guest_info_stderr_pattern"] = guest_info_stderr_pattern(guest_info_command,
            config["source"].get(str(ROOT / "scripts/fixtures/owned_guest_rootful.sh")))
        private["rootful_result"] = barrier.get("rootful") if type(barrier) is dict else None
        private["rootful_durable_evidence"] = rootful_durable
        private["rootful_record_guards"] = None
        if type(barrier) is dict:
            try:
                private["rootful_record_guards"] = validated_rootful_record_guards(
                    barrier.get("rootful_record_guards"), producer_records)
            except Refusal:
                pass  # Preserve retirement/error evidence without inventing an accounting receipt.
        private["rootful_input_reserved"] = 4096
        private["rootful_input_bytes"] = barrier.get("rootful_input_bytes") if type(barrier) is dict else None
        private["runtime_conformance"] = "source-deployment-positive-only" if success else "not-established"
        private["kubernetes_readiness"] = "owned-node-observed" if success else "not-established"
    if diagnostic_profile is not None and error == "host-view-object-not-equivalent":
        private = with_optional_host_view_mismatch(private, host_view_mismatch)
    return finish_qualify_receipt(private, config, budget, parent, directory, retirement,
                                  retirement_evidence, attempted)






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
        return time.monotonic() < end
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
        import test_owned_guest_rootful
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module)
                                   for module in (test_owned_qemu, test_owned_host_view, test_owned_guest_stage, test_owned_guest_receiver, test_owned_guest_rootful))
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
    parser.add_argument("--phase", choices=["qualify-vm", "stage-inputs", "run-rootful-kind"], required=True)
    parser.add_argument("--host-view-diagnostic-profile", choices=[DIAGNOSTIC_CREDIT_PROFILE])
    for name in ("image", "host-tools", "host-tools-sha256", "output-parent"):
        parser.add_argument("--" + name, required=True)
    for name in ("cpus", "memory-mib", "guest-memory-mib", "pids", "disk-gib", "deadline-seconds", "cleanup-seconds", "ssh-port"):
        parser.add_argument("--" + name, required=True, type=int)
    for name in ("profile", "kind", "kubectl", "canonical-owner", "node-parent", "node-manifest", "node-config", "node-archive"):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    selected = (args.profile, args.kind, args.kubectl, args.node_parent, args.node_manifest, args.node_config, args.node_archive)
    if args.phase in ("stage-inputs", "run-rootful-kind") and not all(selected):
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
        control_budget = getattr(args, "_retirement_budget", None)
        end = min(end, getattr(control_budget, "retirement_end", end))
        published = publish_receipt(receipt, end)
        published = published and time.monotonic() < end
        return 128 + CANCELLED if CANCELLED else status if published else 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.exit(main())
