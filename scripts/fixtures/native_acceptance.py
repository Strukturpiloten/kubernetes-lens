#!/usr/bin/env python3
"""Authenticated official-source native acceptance; no renderer/API/runtime operations."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import signal
import stat
import tempfile
import subprocess
import time
import unittest

MAX_METADATA = 4 * 1024 * 1024
MAX_ASSET = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_REQUEST = 12 * 1024 * 1024
MAX_OUTPUT = 256 * 1024
MAX_ERROR = 4096
MAX_BINARY = 128 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FINDING_CODES = frozenset("malformed-document duplicate-key limit-exceeded invalid-alias invalid-mapping-key unsupported-merge-key unsupported-scalar invalid-identity duplicate-identity claim-identity-collision ambiguous-reference unresolved-reference selector-no-matches external-prerequisite operator-owned scope-unknown scope-mismatch unadmitted-kind unknown-kind native-field-invalid native-context-required native-naming-unverified unavailable-api unavailable-field unadmitted-field feature-gate-required invalid-target-profile unsupported-semantic-conversion protected-output-denied opaque-output-denied merge-conflict observed-field-removed collection-field-removed codec-identity-mismatch invalid-registration acquisition-failed unsupported-input-extension reference-cycle".split())

ACTIONABLE_FINDINGS = {
    "native-naming-unverified": "Select reviewed naming evidence for the exact GVK and target, or retain explicit unverified handling. For a historical generated prefix, replace or remove that prefix.",
    "unadmitted-field": "Review the bound original field evidence; selected preservation retains source but does not admit field semantics.",
    "unadmitted-kind": "Supply a delivered native codec or retain explicit source preservation; do not claim typed support.",
    "unknown-kind": "Supply a reviewed extension schema contract; preservation does not establish controller behavior.",
    "unavailable-api": "Select an available target or separately reviewed semantic migration; do not relabel apiVersion.",
    "unavailable-field": "Select a target that admits the field or review an explicit configuration change.",
    "protected-output-denied": "Authorize protected output explicitly only if original private payload generation is intended.",
    "opaque-output-denied": "Select preservation explicitly if retaining opaque source is intended; preserve the findings.",
    "limit-exceeded": "Reduce the explicit source set; do not treat exhausted checking as completed acceptance.",
    "unresolved-reference": "Supply the missing object in this case or retain the unresolved supplied-only dependency.",
    "scope-unknown": "Supply explicit namespace/scope evidence; do not infer a live cluster namespace.",
}


class AcceptanceError(Exception):
    """Fixed safe code; never source bytes, paths, identities or diagnostics."""


def require(condition, code):
    if not condition:
        raise AcceptanceError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative(path):
    require(isinstance(path, str) and path and "\\" not in path and ":" not in path, "invalid-path")
    value = PurePosixPath(path)
    require(not value.is_absolute() and str(value) == path and all(part not in {".", ".."} for part in value.parts), "invalid-path")
    return value.parts


def open_regular(root, path, maximum):
    """Resolve through no-follow directory descriptors and retain the authenticated inode."""
    parts = relative(path)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(leaf)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "unsafe-file-or-budget")
        except BaseException:
            os.close(leaf)
            raise
        return leaf
    finally:
        os.close(descriptor)


def read_record(root, record):
    require(type(record.get("bytes")) is int and 0 <= record["bytes"] <= MAX_ASSET, "asset-budget")
    require(isinstance(record.get("sha256"), str) and DIGEST.fullmatch(record["sha256"]), "invalid-digest")
    with os.fdopen(open_regular(root, record["path"], MAX_ASSET), "rb") as source:
        data = source.read(MAX_ASSET + 1)
    require(len(data) == record["bytes"] and digest(data) == record["sha256"], "asset-integrity")
    return data


def load_inventory(root, expected):
    require(isinstance(expected, str) and DIGEST.fullmatch(expected), "invalid-digest")
    with os.fdopen(open_regular(root, "inventory.json", MAX_METADATA), "rb") as source:
        data = source.read(MAX_METADATA + 1)
    require(len(data) <= MAX_METADATA and digest(data) == expected, "inventory-integrity")
    inventory = json.loads(data)
    assets = inventory.get("assets")
    require(isinstance(assets, list) and 1 <= len(assets) <= 2048, "inventory-budget")
    return inventory


def field(index, pointer, value, typed=None):
    item = {"resource_index": index, "pointer": pointer, "equals": value}
    if typed is not None:
        item["selected_builtin_codec"] = typed
    return item


def edge(index, path, target, subject="object", resolution="resolved-subjects", count=1):
    return {"resource_index": index, "path": path, "resolution": resolution, "count": count, "target_indices": [target], "subject_kind": subject}


# Expectations reviewed from the pinned sources, not harvested from generated output.
# Fixed source ordering is intentional; resource/name/field checks detect shifted indices.
CASES = [
    {"id": "grafana-standalone", "project": "grafana", "assets": ["grafana:derived/standalone-doc-block-0.yaml"], "resources": 3,
     "assertions": [field(0, "/metadata/name", "grafana-pvc", True), field(0, "/spec/accessModes", ["ReadWriteOnce"]),
                    field(0, "/spec/resources/requests/storage", "1Gi"), field(1, "/metadata/name", "grafana", True),
                    field(1, "/spec/selector/matchLabels/app", "grafana"), field(1, "/spec/template/metadata/labels/app", "grafana"),
                    field(1, "/spec/template/spec/securityContext/fsGroup", 472),
                    field(1, "/spec/template/spec/volumes/0/persistentVolumeClaim/claimName", "grafana-pvc"),
                    field(1, "/spec/template/spec/containers/0/volumeMounts/0/mountPath", "/var/lib/grafana"),
                    field(2, "/spec/type", "LoadBalancer", True), field(2, "/spec/ports/0/port", 3000),
                    field(2, "/spec/ports/0/targetPort", "http-grafana"), field(2, "/spec/selector/app", "grafana")],
     "graph_assertions": [edge(1, "/spec/template/spec/volumes/0/persistentVolumeClaim/claimName", 0), edge(2, "/spec/selector", 1, "template"), edge(2, "/spec/ports/0/targetPort", 1, "template")], "custom_semantics": "not-applicable"},
    {"id": "immich-library-pvc", "project": "immich", "assets": ["immich:source/local/pvc.yaml"], "resources": 1,
     "assertions": [field(0, "/metadata/name", "immich-library-pvc", True), field(0, "/spec/accessModes", ["ReadWriteOnce"]), field(0, "/spec/resources/requests/storage", "10Gi")],
     "graph_assertions": [], "custom_semantics": "not-applicable"},
    {"id": "immich-cnpg-inputs", "project": "immich", "assets": ["immich:source/local/cloudnative-pg.yaml", "immich:source/local/cloudnative-pg-database.yaml"], "resources": 2,
     "assertions": [field(0, "/kind", "Cluster"), field(0, "/metadata/name", "immich-database"), field(0, "/spec/instances", 1),
                    field(0, "/spec/storage/size", "1Gi"), field(0, "/spec/postgresql/shared_preload_libraries", ["vchord.so"]),
                    field(1, "/kind", "Database"), field(1, "/spec/cluster/name", "immich-database")],
     "graph_assertions": [], "custom_semantics": "pending-extension-schema-and-explicit-reference-evidence"},
    {"id": "cnpg-cluster-secret", "project": "cloudnativepg", "assets": ["cloudnativepg:source/docs/src/samples/cluster-example-secret.yaml"], "resources": 3,
     "assertions": [field(0, "/kind", "Cluster"), field(0, "/metadata/name", "cluster-example-secret"), field(0, "/spec/instances", 3),
                    field(0, "/spec/bootstrap/initdb/secret/name", "cluster-example-app-user"), field(0, "/spec/superuserSecret/name", "cluster-example-superuser"),
                    field(1, "/type", "kubernetes.io/basic-auth", True), field(1, "/data/username", "YXBw"), field(1, "/data/password", "cGFzc3dvcmQ="),
                    field(2, "/type", "kubernetes.io/basic-auth", True), field(2, "/data/username", "cG9zdGdyZXM="), field(2, "/data/password", "cGFzc3dvcmQ=")],
     "graph_assertions": [], "custom_semantics": "pending-extension-schema-and-explicit-reference-evidence"},
    {"id": "grafana-operator-credentials", "project": "grafana-operator", "assets": ["grafana-operator:source/examples/grafana/credential_secret/resources.yaml"], "resources": 2,
     "assertions": [field(0, "/metadata/namespace", "grafana", True), field(0, "/stringData/GF_SECURITY_ADMIN_PASSWORD", "secret"), field(0, "/stringData/GF_SECURITY_ADMIN_USER", "root"),
                    field(1, "/kind", "Grafana"), field(1, "/spec/disableDefaultAdminSecret", True),
                    field(1, "/spec/deployment/spec/template/spec/containers/0/env/0/valueFrom/secretKeyRef/name", "credentials"),
                    field(1, "/spec/deployment/spec/template/spec/containers/0/env/1/valueFrom/secretKeyRef/key", "GF_SECURITY_ADMIN_PASSWORD")],
     "graph_assertions": [], "custom_semantics": "pending-extension-schema-and-explicit-reference-evidence", "namespace": "grafana"},
    {"id": "cnpg-operator-release", "project": "cloudnativepg", "assets": ["cloudnativepg:manifests/cnpg-1.30.1.yaml"], "resources": 26,
     "assertions": [field(0, "/metadata/name", "cnpg-system", True), field(12, "/metadata/name", "cnpg-manager", True),
                    field(20, "/roleRef/name", "cnpg-manager", True), field(20, "/subjects/0/name", "cnpg-manager"),
                    field(23, "/spec/template/spec/serviceAccountName", "cnpg-manager", True), field(22, "/metadata/name", "cnpg-webhook-service", True),
                    field(3, "/spec/names/kind", "Cluster"), field(3, "/spec/group", "postgresql.cnpg.io")],
     "graph_assertions": [edge(20, "/roleRef", 15), edge(20, "/subjects/0", 12), edge(23, "/spec/template/spec/serviceAccountName", 12)],
     "custom_semantics": "pending-extension-crd-and-webhook-evidence", "namespace": "cnpg-system"},
    {"id": "grafana-operator-release", "project": "grafana-operator", "assets": ["grafana-operator:manifests/kustomize-cluster_scoped.yaml"], "resources": 21,
     "assertions": [field(0, "/metadata/name", "grafana", True), field(14, "/metadata/name", "grafana-operator-controller-manager", True),
                    field(18, "/roleRef/name", "grafana-operator-permissions", True), field(18, "/subjects/0/name", "grafana-operator-controller-manager"),
                    field(20, "/spec/template/spec/serviceAccountName", "grafana-operator-controller-manager", True), field(12, "/spec/names/kind", "Grafana")],
     "graph_assertions": [edge(18, "/roleRef", 16), edge(18, "/subjects/0", 14), edge(20, "/spec/template/spec/serviceAccountName", 14)],
     "custom_semantics": "pending-extension-crd-evidence", "namespace": "grafana"},
]
PENDING = [
    {"project": "forgejo", "form": "official-chart", "state": "pending-official-renderer-execution", "raw": "no-official-raw-form-in-selected-inventory"},
    {"project": "nextcloud-aio", "form": "official-chart", "state": "pending-official-renderer-execution", "raw": "no-official-raw-form-in-selected-inventory"},
    {"project": "immich", "form": "official-chart", "state": "pending-official-renderer-execution"},
    {"project": "cloudnativepg", "form": "official-chart-and-kustomize", "state": "pending-official-renderer-execution"},
    {"project": "grafana-operator", "form": "official-chart-and-kustomize", "state": "pending-official-renderer-execution"},
    {"project": "cloudnativepg", "form": "seven-kind-custom-corpus", "state": "pending-extension-schema-and-explicit-reference-evidence"},
    {"project": "grafana-operator", "form": "seven-kind-custom-corpus", "state": "pending-extension-schema-and-explicit-reference-evidence"},
]


def child_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def run_probe(descriptor, request, timeout):
    """Execute only the held, hash-authenticated original probe; cap every pipe and lifetime."""
    payload = canonical(request)
    require(len(payload) <= MAX_REQUEST and 0 < timeout <= 90, "request-budget")
    executable = f"/proc/self/fd/{descriptor}"
    process = subprocess.Popen([executable], executable=executable, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, pass_fds=(descriptor,), env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
                               cwd="/", start_new_session=True, preexec_fn=child_limits)
    output, error, written = bytearray(), bytearray(), 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, event, tag in [(process.stdin, selectors.EVENT_WRITE, "input"), (process.stdout, selectors.EVENT_READ, "output"), (process.stderr, selectors.EVENT_READ, "error")]:
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, event, tag)
            while selector.get_map():
                require(time.monotonic() < deadline, "probe-timeout")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    pipe, tag = key.fileobj, key.data
                    if tag == "input":
                        try:
                            written += os.write(pipe.fileno(), payload[written:written + 65536])
                        except BrokenPipeError:
                            selector.unregister(pipe)
                            pipe.close()
                            continue
                        if written == len(payload):
                            selector.unregister(pipe)
                            pipe.close()
                    else:
                        data = os.read(pipe.fileno(), 65536)
                        if not data:
                            selector.unregister(pipe)
                            pipe.close()
                            continue
                        target, maximum = (output, MAX_OUTPUT) if tag == "output" else (error, MAX_ERROR)
                        require(len(target) + len(data) <= maximum, "probe-output-budget")
                        target.extend(data)
        returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(returncode == 0 and not error and written == len(payload), "probe-failed")
        return json.loads(output)
    finally:
        # A child inheriting a pipe must not outlive a timed-out or completed owned invocation.
        if process.returncode is None:
            # The unreaped leader reserves its PID; never signal a potentially reused ID.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        for pipe in (process.stdin, process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()


def validate_response(response, request):
    require(isinstance(response, dict) and type(response.get("schema_version")) is int and response.get("schema_version") == 1, "invalid-probe-receipt")
    require(response.get("binding") == request["binding"] and type(response.get("target_minor")) is int and response.get("target_minor") == request["target_minor"], "probe-binding-mismatch")
    states = {"parse-refused", "decode-refused", "processing-refused", "generation-refused", "static-assertions-passed", "static-assertions-failed"}
    require(response.get("state") in states and response.get("api") == "pending" and response.get("runtime") == "pending" and response.get("controller") == "not-proven", "invalid-probe-state")
    require(all(type(response.get(key)) is int for key in ("field_assertions", "graph_assertions", "wrapper_assertions")) and response.get("field_assertions") == len(request["assertions"]) and response.get("graph_assertions") == len(request["graph_assertions"]) and response.get("wrapper_assertions") == len(request["wrapper_assertions"]), "probe-assertion-mismatch")
    # No native output/log/free-form values may cross into a public receipt.
    keys = {"schema_version", "binding", "target_minor", "state", "api", "runtime", "controller", "field_assertions", "graph_assertions", "wrapper_assertions", "wrapper_failures", "resources", "selected_builtin_codecs", "decode_findings", "validation_findings", "graph_findings", "graph_edges", "graph_failures", "default_generation", "opaque_preservation", "generation_findings", "findings", "field_failures", "reprojection_failures"}
    require(set(response) <= keys, "unsafe-probe-receipt")
    for key, value in response.items():
        if key.endswith("findings") or key == "findings":
            require(isinstance(value, dict) and len(value) <= 64 and all(code in FINDING_CODES and type(count) is int and 0 <= count <= 100000 for code, count in value.items()), "unsafe-probe-receipt")
        elif key == "opaque_preservation":
            require(value in {"selected-unadmitted-source", "not-required-by-default-check"}, "unsafe-probe-receipt")
        elif key == "default_generation":
            require(isinstance(value, dict) and set(value) <= {"state", "findings"} and value.get("state") in {"generated", "refused"}, "unsafe-probe-receipt")
            if "findings" in value:
                nested = dict(response)
                nested.pop(key)
                nested["findings"] = value["findings"]
                validate_response(nested, request)
        elif key in {"resources", "selected_builtin_codecs", "graph_edges", "graph_failures", "wrapper_failures", "field_failures", "reprojection_failures"}:
            require(type(value) is int and 0 <= value <= 100000, "unsafe-probe-receipt")
    if response["state"] in {"static-assertions-passed", "static-assertions-failed"}:
        require(response.get("opaque_preservation") in {"selected-unadmitted-source", "not-required-by-default-check"}, "incomplete-preservation-receipt")
    if response["state"] == "static-assertions-passed":
        require(all(response.get(key) == 0 for key in ("field_failures", "graph_failures", "wrapper_failures", "reprojection_failures")), "incomplete-success-receipt")
    return response


def with_actions(response):
    codes = set()
    for key, findings in response.items():
        if key.endswith("findings") or key == "findings":
            codes.update(findings)
    codes.update(response.get("default_generation", {}).get("findings", {}))
    result = dict(response)
    if response.get("opaque_preservation") == "selected-unadmitted-source":
        result["preservation_action"] = "Review the bound opaque source before conversion; selected generation preserved it without establishing native field admission."
    result["finding_actions"] = {code: ACTIONABLE_FINDINGS.get(code, "Review the bound original private evidence and correct the named structural condition.") for code in sorted(codes)}
    return result


def snapshot_probe(binary, expected):
    """Return sealed executable bytes; authenticate before granting execution permission."""
    binary = Path(binary)
    require(binary.is_absolute(), "explicit-probe-required")
    original = open_regular(binary.parent, binary.name, MAX_BINARY)
    with os.fdopen(original, "rb") as stream:
        require(os.fstat(stream.fileno()).st_mode & stat.S_IXUSR, "probe-not-executable")
        binary_bytes = stream.read(MAX_BINARY + 1)
    require(len(binary_bytes) <= MAX_BINARY and digest(binary_bytes) == expected, "probe-integrity")
    # Exec exactly the authenticated bytes, even if an external writer later replaces the file.
    descriptor = os.memfd_create("kubernetes-lens-native-probe", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        written = 0
        while written < len(binary_bytes):
            count = os.write(descriptor, binary_bytes[written:written + 65536])
            require(count > 0, "probe-snapshot-failed")
            written += count
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def execute(args):
    require(20 <= args.target_minor <= 37, "invalid-target")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z0-9]", args.namespace), "invalid-namespace")
    for value in (args.binary_sha256, args.candidate_sha256, args.inventory_sha256):
        require(DIGEST.fullmatch(value), "invalid-digest")
    candidate = Path(args.candidate_manifest)
    require(candidate.is_absolute(), "explicit-candidate-required")
    with os.fdopen(open_regular(candidate.parent, candidate.name, MAX_METADATA), "rb") as source:
        require(digest(source.read(MAX_METADATA + 1)) == args.candidate_sha256, "candidate-integrity")
    inventory = load_inventory(args.definitions, args.inventory_sha256)
    by_id, total, payloads = {}, 0, {}
    # Authenticate all retained upstream assets and license companions, not just chosen YAML.
    for asset in inventory["assets"]:
        require(isinstance(asset.get("id"), str) and asset["id"] not in by_id, "duplicate-asset")
        data = read_record(args.corpus, asset)
        total += len(data)
        require(total <= MAX_TOTAL, "corpus-budget")
        by_id[asset["id"]] = asset
        payloads[asset["id"]] = data
    descriptor = snapshot_probe(args.probe, args.binary_sha256)
    try:
        results = []
        for case in CASES:
            require(all(asset in by_id for asset in case["assets"]), "missing-official-case")
            request = {"schema_version": 1, "invocation_nonce": os.urandom(16).hex(), "target_minor": args.target_minor, "documented_gate_defaults": True,
                       "namespace": case.get("namespace", args.namespace), "preserve_unknown": args.preserve_unknown == "yes",
                       "include_protected": args.protected_output == "include", "max_input_bytes": MAX_ASSET,
                       "sources": [{"format": "yaml", "content": payloads[asset].decode("utf-8")} for asset in case["assets"]],
                       "assertions": case["assertions"], "graph_assertions": case["graph_assertions"], "wrapper_assertions": []}
            binding = {"request_sha256": digest(canonical(request)), "invocation_nonce": request["invocation_nonce"], "namespace_sha256": digest(request["namespace"].encode()), "candidate_sha256": args.candidate_sha256,
                       "binary_sha256": args.binary_sha256, "inventory_sha256": args.inventory_sha256,
                       "case_sha256": digest(canonical(case)), "assets": [{"id": asset, "sha256": by_id[asset]["sha256"]} for asset in case["assets"]]}
            request["binding"] = digest(canonical(binding))
            response = with_actions(validate_response(run_probe(descriptor, request, args.timeout), request))
            if response["state"] == "static-assertions-passed":
                require(response.get("resources") == case["resources"], "source-resource-count-mismatch")
            results.append({"id": case["id"], "project": case["project"], "binding": binding, "native": response, "custom_semantics": case["custom_semantics"]})
        return {"schema_version": 1, "state": "static-driver-executed-programme-incomplete", "candidate_sha256": args.candidate_sha256,
                "binary_sha256": args.binary_sha256, "inventory_sha256": args.inventory_sha256, "target_minor": args.target_minor,
                "expectation_sha256": digest(canonical({"cases": CASES, "pending": PENDING})), "cases": results, "pending": PENDING,
                "policies": {"preserve_unknown": args.preserve_unknown, "protected_output": args.protected_output, "gate_resolution": "documented-defaults-selected"},
                "api": "pending", "runtime": "pending", "controller": "not-proven", "publication": "not-authorized"}
    finally:
        os.close(descriptor)


class ContractTests(unittest.TestCase):
    """Pure tests of authentication, negative contracts and honest pending cells."""
    def test_binary_snapshot_is_hash_bound_and_sealed_against_later_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "probe"
            original = b"original-native-probe-byte-fixture"
            binary.write_bytes(original)
            binary.chmod(0o700)
            descriptor = snapshot_probe(binary, digest(original))
            try:
                self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS), fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                binary.write_bytes(b"changed-after-authentication")
                self.assertEqual(os.pread(descriptor, len(original), 0), original)
                with self.assertRaises(OSError):
                    os.write(descriptor, b"mutated")
            finally:
                os.close(descriptor)
            with self.assertRaises(AcceptanceError):
                snapshot_probe(binary, digest(original))

    def test_request_and_wall_budget_fail_before_any_execution(self):
        for timeout in (0, -1, 91):
            with self.assertRaises(AcceptanceError):
                run_probe(-1, {}, timeout)
        with self.assertRaises(AcceptanceError):
            run_probe(-1, {"oversized": "x" * MAX_REQUEST}, 1)

    def test_asset_hash_size_missing_and_symlink_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"official-source-private-marker"
            (root / "source.yaml").write_bytes(data)
            record = {"path": "source.yaml", "bytes": len(data), "sha256": digest(data)}
            self.assertEqual(read_record(root, record), data)
            for patch in ({"sha256": "0" * 64}, {"bytes": len(data) + 1}, {"bytes": MAX_ASSET + 1}):
                with self.assertRaises(AcceptanceError):
                    read_record(root, dict(record, **patch))
            with self.assertRaises(OSError):
                read_record(root, dict(record, path="missing.yaml"))
            (root / "link.yaml").symlink_to(root / "source.yaml")
            with self.assertRaises(OSError):
                read_record(root, dict(record, path="link.yaml"))
            (root / "linked-directory").symlink_to(root)
            with self.assertRaises(OSError):
                read_record(root, dict(record, path="linked-directory/source.yaml"))

    def test_inventory_authentication_and_metadata_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = canonical({"assets": [{"id": "official:source"}]})
            (root / "inventory.json").write_bytes(data)
            self.assertEqual(load_inventory(root, digest(data))["assets"][0]["id"], "official:source")
            with self.assertRaises(AcceptanceError):
                load_inventory(root, "0" * 64)
            with self.assertRaises(AcceptanceError):
                load_inventory(root, "not-a-digest")
            oversized = b" " * (MAX_METADATA + 1)
            (root / "inventory.json").write_bytes(oversized)
            with self.assertRaises(AcceptanceError):
                load_inventory(root, digest(oversized))

    def test_unknown_diagnostic_code_and_negative_counts_are_private(self):
        request = {"binding": "a" * 64, "target_minor": 20, "assertions": [1], "graph_assertions": [], "wrapper_assertions": []}
        response = {"schema_version": 1, "binding": "a" * 64, "target_minor": 20, "state": "generation-refused", "api": "pending", "runtime": "pending", "controller": "not-proven", "field_assertions": 1, "graph_assertions": 0, "wrapper_assertions": 0}
        validate_response(dict(response, findings={"protected-output-denied": 1}), request)
        for findings in ({"private-secret-marker": 1}, {"limit-exceeded": -1}, {"limit-exceeded": True}):
            with self.assertRaises(AcceptanceError):
                validate_response(dict(response, findings=findings), request)

    def test_naming_warning_receipt_is_fixed_private_and_still_pending(self):
        request = {"binding": "a" * 64, "target_minor": 20, "assertions": [], "graph_assertions": [], "wrapper_assertions": []}
        response = {"schema_version": 1, "binding": "a" * 64, "target_minor": 20,
                    "state": "generation-refused", "api": "pending", "runtime": "pending",
                    "controller": "not-proven", "field_assertions": 0, "graph_assertions": 0,
                    "wrapper_assertions": 0, "findings": {"native-naming-unverified": 1}}
        receipt = with_actions(validate_response(response, request))
        self.assertEqual(receipt["api"], "pending")
        self.assertIn("replace or remove", receipt["finding_actions"]["native-naming-unverified"])
        for patch in ({"findings": {"native-naming-unverified-private-marker": 1}},
                      {"raw_name": "Private Synthetic Ω"},
                      {"findings": {"native-naming-unverified": "Private Synthetic Ω"}}):
            with self.assertRaises(AcceptanceError) as caught:
                validate_response(dict(response, **patch), request)
            self.assertEqual(str(caught.exception), "unsafe-probe-receipt")

    def test_target_replay_and_incomplete_success(self):
        request = {"binding": "a" * 64, "target_minor": 20, "assertions": [1], "graph_assertions": [], "wrapper_assertions": []}
        response = {"schema_version": 1, "binding": "a" * 64, "target_minor": 20, "state": "static-assertions-passed", "api": "pending", "runtime": "pending", "controller": "not-proven", "field_assertions": 1, "graph_assertions": 0, "wrapper_assertions": 0, "wrapper_failures": 0, "field_failures": 0, "graph_failures": 0, "reprojection_failures": 0, "opaque_preservation": "not-required-by-default-check"}
        validate_response(response, request)
        for patch in ({"target_minor": 37}, {"binding": "b" * 64}, {"field_failures": 1}, {"raw": "protected-value"}, {"runtime": "passed"}):
            with self.assertRaises(AcceptanceError):
                validate_response(dict(response, **patch), request)
        incomplete = dict(response)
        del incomplete["reprojection_failures"]
        with self.assertRaises(AcceptanceError):
            validate_response(incomplete, request)

    def test_preservation_and_refusal_findings_have_fixed_actionable_guidance(self):
        preserved = with_actions({"generation_findings": {"unadmitted-field": 2}, "default_generation": {"state": "refused", "findings": {"protected-output-denied": 1}}})
        self.assertIn("does not admit", preserved["finding_actions"]["unadmitted-field"])
        self.assertIn("explicitly", preserved["finding_actions"]["protected-output-denied"])
        self.assertNotIn("private-token-marker", canonical(preserved).decode())

    def test_path_aliases(self):
        for path in ("../manifest.yaml", "/manifest.yaml", "a//b", "a/./b", "a\\b", "https://source", ""):
            with self.assertRaises(AcceptanceError):
                relative(path)

    def test_source_and_candidate_bindings_are_deterministic(self):
        source = {"request_sha256": "a" * 64, "candidate_sha256": "b" * 64, "target_minor": 20}
        self.assertEqual(digest(canonical(source)), digest(canonical(dict(reversed(list(source.items()))))))
        for key in source:
            self.assertNotEqual(digest(canonical(source)), digest(canonical(dict(source, **{key: "changed"}))))

    def test_official_forms_and_independent_semantics(self):
        self.assertEqual({case["project"] for case in CASES} | {case["project"] for case in PENDING}, {"immich", "forgejo", "cloudnativepg", "grafana", "grafana-operator", "nextcloud-aio"})
        self.assertFalse(any(case["project"] in {"forgejo", "nextcloud-aio"} for case in CASES))
        self.assertTrue(all(case["assertions"] for case in CASES))
        self.assertEqual(CASES[0]["graph_assertions"][2]["path"], "/spec/ports/0/targetPort")
        self.assertEqual(CASES[1]["assertions"][2]["equals"], "10Gi")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--definitions", type=Path)
    parser.add_argument("--inventory-sha256")
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument("--target-minor", type=int)
    parser.add_argument("--namespace")
    parser.add_argument("--preserve-unknown", choices=("yes", "no"))
    parser.add_argument("--protected-output", choices=("include", "deny"))
    parser.add_argument("--documented-gate-defaults", action="store_true")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)).wasSuccessful() else 1
    required = (args.definitions, args.inventory_sha256, args.corpus, args.probe, args.binary_sha256, args.candidate_sha256,
                args.candidate_manifest, args.target_minor, args.namespace, args.preserve_unknown, args.protected_output, args.documented_gate_defaults)
    try:
        require(all(value is not None and value is not False for value in required), "explicit-options-required")
        receipt = execute(args)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if all(case["native"]["state"] == "static-assertions-passed" for case in receipt["cases"]) else 1
    except (AcceptanceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as failure:
        code = str(failure) if isinstance(failure, AcceptanceError) else "acceptance-refused"
        print(json.dumps({"schema_version": 1, "state": "refused", "code": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
