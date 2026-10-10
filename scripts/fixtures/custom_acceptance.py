#!/usr/bin/env python3
"""Bounded official custom-document acceptance, never controller/API/runtime validation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import unittest

# Reuse the reviewed original private authentication/process machinery, not an oracle.
_SPEC = importlib.util.spec_from_file_location("original_native_acceptance", Path(__file__).with_name("native_acceptance.py"))
native = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(native)

STATES = frozenset("TargetProfileRequired MissingCrd AmbiguousCrd InvalidBinding VersionNotListed VersionNotServed ScopeMismatch MissingSchema InvalidSchema UnsupportedSchema SchemaViolations Bound Incomplete LimitExceeded missing-custom-result".split())
CATEGORIES = frozenset("Combinator Dependencies Definitions PatternProperties Pattern Format MultipleOf Cardinality TupleItems UnknownType IntOrString EmbeddedResource ListTopology MapTopology PreserveUnknownTransform SchemaReference Defaulting CelValidation UnknownSchemaField".split())
CNPG = "postgresql.cnpg.io"
GRAFANA = "grafana.integreatly.org"
GRAFANA_CRDS = "grafana-operator:source/deploy/kustomize/base/crds.yaml"


def field(index, pointer, value):
    return {"resource_index": index, "pointer": pointer, "equals": value}


def custom(index, source, document, group, kind, crd, crd_document, categories):
    return {"resource_index": index, "source_id": source, "source_document": document, "source_pointer": "",
            "identity": {"group": group, "kind": kind, "version": "v1" if group == CNPG else "v1beta1"},
            "check": "UnsupportedSchema", "positive_dependency": False, "supported_subset_satisfied": True, "issue_count": 0,
            "unsupported_categories": categories,
            "binding": {"crd_index": crd, "source_id": crd if group == CNPG else 0, "source_document": crd_document,
                        "crd_api_version": "apiextensions.k8s.io/v1", "crd_pointer": "",
                        "version_pointer": "/spec/versions/0", "schema_pointer": "/spec/versions/0/schema/openAPIV3Schema",
                        "namespaced": True, "served": True, "storage": True, "schema_family": "v1"}}


CASES = [
    {"id": "cnpg-cluster", "project": "cloudnativepg", "resources": 2,
     "assets": ["cloudnativepg:source/config/crd/bases/postgresql.cnpg.io_clusters.yaml", "cloudnativepg:source/docs/src/samples/cluster-example.yaml"],
     "assertions": [field(0, "/spec/names/kind", "Cluster"), field(1, "/kind", "Cluster"), field(1, "/spec/instances", 3), field(1, "/spec/storage/size", "1Gi")],
     "custom_assertions": [custom(1, 1, 0, CNPG, "Cluster", 0, 0, ["Defaulting", "CelValidation", "Format", "Pattern", "ListTopology", "MapTopology"])]},
    {"id": "cnpg-pooler", "project": "cloudnativepg", "resources": 4,
     "assets": ["cloudnativepg:source/config/crd/bases/postgresql.cnpg.io_clusters.yaml", "cloudnativepg:source/config/crd/bases/postgresql.cnpg.io_poolers.yaml", "cloudnativepg:source/docs/src/samples/pooler-example-explicit-image.yaml"],
     "assertions": [field(2, "/spec/instances", 1), field(2, "/spec/imageName", "ghcr.io/cloudnative-pg/postgresql:18.6-system-trixie"), field(3, "/kind", "Pooler"), field(3, "/spec/cluster/name", "cluster-example"), field(3, "/spec/instances", 1), field(3, "/spec/type", "rw"), field(3, "/spec/pgbouncer/poolMode", "session"), field(3, "/spec/pgbouncer/image", "ghcr.io/cloudnative-pg/pgbouncer:1.25.1")],
     "custom_assertions": [custom(2, 2, 0, CNPG, "Cluster", 0, 0, ["Defaulting", "CelValidation"]), custom(3, 2, 1, CNPG, "Pooler", 1, 0, ["Defaulting", "CelValidation", "Format", "Pattern", "ListTopology"])]},
    {"id": "cnpg-backup", "project": "cloudnativepg", "resources": 2,
     "assets": ["cloudnativepg:source/config/crd/bases/postgresql.cnpg.io_backups.yaml", "cloudnativepg:source/docs/src/samples/backup-example.yaml"],
     "assertions": [field(0, "/spec/names/kind", "Backup"), field(1, "/kind", "Backup"), field(1, "/spec/cluster/name", "pg-backup")],
     "custom_assertions": [custom(1, 1, 0, CNPG, "Backup", 0, 0, ["Defaulting", "CelValidation", "Format"])]},
    {"id": "cnpg-scheduled-backup", "project": "cloudnativepg", "resources": 2,
     "assets": ["cloudnativepg:source/config/crd/bases/postgresql.cnpg.io_scheduledbackups.yaml", "cloudnativepg:source/docs/src/samples/scheduled-backup-example.yaml"],
     "assertions": [field(1, "/kind", "ScheduledBackup"), field(1, "/spec/schedule", "0 0 0 * * *"), field(1, "/spec/backupOwnerReference", "self"), field(1, "/spec/cluster/name", "pg-backup")],
     "custom_assertions": [custom(1, 1, 0, CNPG, "ScheduledBackup", 0, 0, ["Defaulting", "CelValidation", "Format"])]},
    {"id": "grafana-credentials", "project": "grafana-operator", "resources": 15,
     "namespace": "grafana", "assets": [GRAFANA_CRDS, "grafana-operator:source/examples/grafana/credential_secret/resources.yaml"],
     "assertions": [field(11, "/spec/names/kind", "Grafana"), field(13, "/kind", "Secret"), field(13, "/stringData/GF_SECURITY_ADMIN_PASSWORD", "secret"), field(13, "/stringData/GF_SECURITY_ADMIN_USER", "root"), field(14, "/spec/disableDefaultAdminSecret", True), field(14, "/spec/config/log/mode", "console"), field(14, "/spec/deployment/spec/template/spec/containers/0/env/1/valueFrom/secretKeyRef/name", "credentials"), field(14, "/spec/deployment/spec/template/spec/containers/0/env/1/valueFrom/secretKeyRef/key", "GF_SECURITY_ADMIN_PASSWORD")],
     "custom_assertions": [custom(14, 1, 1, GRAFANA, "Grafana", 11, 11, ["Defaulting", "CelValidation", "Format", "Pattern", "ListTopology", "PreserveUnknownTransform"])]},
    {"id": "grafana-dashboard", "project": "grafana-operator", "resources": 16,
     "assets": [GRAFANA_CRDS, "grafana-operator:source/examples/dashboard/configmap/resources.yaml"],
     "assertions": [field(2, "/spec/names/kind", "GrafanaDashboard"), field(13, "/spec/config/security/admin_password", "secret"), field(13, "/metadata/labels/dashboards", "grafana"), field(14, "/kind", "ConfigMap"), field(15, "/kind", "GrafanaDashboard"), field(15, "/spec/instanceSelector/matchLabels/dashboards", "grafana"), field(15, "/spec/configMapRef/name", "dashboard-definition"), field(15, "/spec/configMapRef/key", "json")],
     "custom_assertions": [custom(13, 1, 0, GRAFANA, "Grafana", 11, 11, ["Defaulting", "CelValidation"]), custom(15, 1, 2, GRAFANA, "GrafanaDashboard", 2, 2, ["Defaulting", "CelValidation", "Format", "Pattern", "MapTopology"])]},
    {"id": "grafana-datasource", "project": "grafana-operator", "resources": 14,
     "assets": [GRAFANA_CRDS, "grafana-operator:source/examples/datasource/datasource_types/prometheus.yaml"],
     "assertions": [field(3, "/spec/names/kind", "GrafanaDatasource"), field(13, "/kind", "GrafanaDatasource"), field(13, "/spec/instanceSelector/matchLabels/dashboards", "grafana"), field(13, "/spec/datasource/name", "prom1"), field(13, "/spec/datasource/type", "prometheus"), field(13, "/spec/datasource/access", "proxy"), field(13, "/spec/datasource/url", "http://prometheus-service:9090"), field(13, "/spec/datasource/isDefault", True), field(13, "/spec/datasource/jsonData/tlsSkipVerify", True), field(13, "/spec/datasource/jsonData/timeInterval", "5s")],
     "custom_assertions": [custom(13, 1, 0, GRAFANA, "GrafanaDatasource", 3, 3, ["Defaulting", "CelValidation", "Format", "Pattern", "PreserveUnknownTransform"])]},
]

# These declaration facts are from the authenticated CRDs, independently of generated output.
CRD_NAMES = {"Cluster": "clusters.postgresql.cnpg.io", "Pooler": "poolers.postgresql.cnpg.io", "Backup": "backups.postgresql.cnpg.io", "ScheduledBackup": "scheduledbackups.postgresql.cnpg.io", "Grafana": "grafanas.grafana.integreatly.org", "GrafanaDashboard": "grafanadashboards.grafana.integreatly.org", "GrafanaDatasource": "grafanadatasources.grafana.integreatly.org"}
for _case in CASES:
    _seen = set()
    for _custom in _case["custom_assertions"]:
        _crd = _custom["binding"]["crd_index"]
        if _crd in _seen:
            continue
        _seen.add(_crd)
        _identity = _custom["identity"]
        for _path, _value in (("/apiVersion", "apiextensions.k8s.io/v1"), ("/kind", "CustomResourceDefinition"), ("/metadata/name", CRD_NAMES[_identity["kind"]]), ("/spec/group", _identity["group"]), ("/spec/names/kind", _identity["kind"]), ("/spec/scope", "Namespaced"), ("/spec/versions/0/name", _identity["version"]), ("/spec/versions/0/served", True), ("/spec/versions/0/storage", True)):
            _assertion = field(_crd, _path, _value)
            if _assertion not in _case["assertions"]:
                _case["assertions"].append(_assertion)


def safe_count(value):
    return type(value) is int and 0 <= value <= 100000


def validate_response(response, request):
    native_response = dict(response)
    for key in ("custom", "custom_assertions", "custom_reprojection", "custom_reprojection_failures"):
        native_response.pop(key, None)
    native.validate_response(native_response, request)
    expected_count = len(request["custom_assertions"])
    native.require(type(response.get("custom_assertions")) is int and response["custom_assertions"] == expected_count, "custom-count-mismatch")
    native.require(response.get("custom_reprojection") in {"checked", "not-executed-native-refusal"}, "unsafe-custom-receipt")
    custom_response = response.get("custom")
    if custom_response is None:
        native.require(response["state"] in {"parse-refused", "decode-refused", "processing-refused"}, "missing-custom-receipt")
        return response
    native.require(isinstance(custom_response, dict) and set(custom_response) <= {"state", "records", "failures", "custom_documents", "graph_findings", "findings"}, "unsafe-custom-receipt")
    native.require(custom_response.get("state") in {"checked", "processing-refused"} and safe_count(custom_response.get("failures")), "unsafe-custom-receipt")
    records = custom_response.get("records")
    native.require(isinstance(records, list) and len(records) <= expected_count, "unsafe-custom-receipt")
    for key in ("graph_findings", "findings"):
        if key in custom_response:
            native.require(isinstance(custom_response[key], dict) and all(k in native.FINDING_CODES and safe_count(v) for k, v in custom_response[key].items()), "unsafe-custom-receipt")
    if "custom_documents" in custom_response:
        native.require(safe_count(custom_response["custom_documents"]), "unsafe-custom-receipt")
    keys = {"assertion_index", "state", "passed", "source_evidence_checked", "identity_match", "binding_match", "graph_match", "unsupported_categories", "issue_count", "supported_subset_satisfied", "numeric_semantics_uncertain", "operator_prerequisites", "positive_dependencies"}
    for index, record in enumerate(records):
        native.require(isinstance(record, dict) and set(record) <= keys and type(record.get("assertion_index")) is int and record["assertion_index"] == index and record.get("state") in STATES, "unsafe-custom-receipt")
        for key in ("passed", "source_evidence_checked", "identity_match", "binding_match", "graph_match"):
            if key in record:
                native.require(type(record[key]) is bool, "unsafe-custom-receipt")
        if "unsupported_categories" in record:
            native.require(isinstance(record["unsupported_categories"], dict) and all(k in CATEGORIES and safe_count(v) for k, v in record["unsupported_categories"].items()), "unsafe-custom-receipt")
        if "issue_count" in record:
            native.require(record["issue_count"] is None or safe_count(record["issue_count"]), "unsafe-custom-receipt")
        for key in ("supported_subset_satisfied", "numeric_semantics_uncertain"):
            if key in record:
                native.require(record[key] is None or type(record[key]) is bool, "unsafe-custom-receipt")
        for key in ("operator_prerequisites", "positive_dependencies"):
            if key in record:
                native.require(safe_count(record[key]), "unsafe-custom-receipt")
    if "custom_reprojection_failures" in response:
        native.require(safe_count(response["custom_reprojection_failures"]), "unsafe-custom-receipt")
    if response["state"] == "static-assertions-passed":
        native.require(custom_response.get("state") == "checked" and custom_response.get("custom_documents") == expected_count and len(records) == expected_count and custom_response["failures"] == 0 and response["custom_reprojection"] == "checked" and response.get("custom_reprojection_failures") == 0, "incomplete-custom-success")
        for record, assertion in zip(records, request["custom_assertions"]):
            native.require(set(record) == keys and all(record[k] is True for k in ("passed", "source_evidence_checked", "identity_match", "binding_match", "graph_match")) and record["state"] == assertion["check"] and record["operator_prerequisites"] == 1 and record["positive_dependencies"] == int(assertion["positive_dependency"]), "incomplete-custom-success")
            native.require(all(record["unsupported_categories"].get(category, 0) > 0 for category in assertion.get("unsupported_categories", [])), "incomplete-custom-success")
            for key in ("issue_count", "supported_subset_satisfied"):
                if key in assertion:
                    native.require(record[key] == assertion[key] and type(record[key]) is type(assertion[key]), "incomplete-custom-success")
    return response


def schema_evidence_state(response):
    """Describe completed checks, independently of the case's expected schema outcome."""
    custom = response.get("custom") or {}
    if custom.get("state") == "checked":
        return "supported-subset-with-explicit-unsupported" if response["state"] == "static-assertions-passed" else "checked-assertions-failed"
    if custom.get("state") == "processing-refused":
        return "incomplete-processing"
    return "not-executed-native-refusal"


def execute(args):
    native.require(20 <= args.target_minor <= 37, "invalid-target")
    native.require(native.re.fullmatch(r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z0-9]", args.namespace), "invalid-namespace")
    for value in (args.binary_sha256, args.candidate_sha256, args.inventory_sha256):
        native.require(native.DIGEST.fullmatch(value), "invalid-digest")
    native.require(args.candidate_manifest.is_absolute(), "explicit-candidate-required")
    with os.fdopen(native.open_regular(args.candidate_manifest.parent, args.candidate_manifest.name, native.MAX_METADATA), "rb") as source:
        native.require(native.digest(source.read(native.MAX_METADATA + 1)) == args.candidate_sha256, "candidate-integrity")
    inventory = native.load_inventory(args.definitions, args.inventory_sha256)
    assets, payloads, total = {}, {}, 0
    for asset in inventory["assets"]:
        native.require(isinstance(asset.get("id"), str) and asset["id"] not in assets, "duplicate-asset")
        data = native.read_record(args.corpus, asset)
        total += len(data)
        native.require(total <= native.MAX_TOTAL, "corpus-budget")
        assets[asset["id"]], payloads[asset["id"]] = asset, data
    descriptor = native.snapshot_probe(args.probe, args.binary_sha256)
    try:
        results = []
        for case in CASES:
            native.require(all(a in assets for a in case["assets"]), "missing-official-custom-case")
            request = {"schema_version": 1, "invocation_nonce": os.urandom(16).hex(), "target_minor": args.target_minor, "documented_gate_defaults": True,
                       "namespace": case.get("namespace", args.namespace), "preserve_unknown": args.preserve_unknown == "yes", "include_protected": args.protected_output == "include", "max_input_bytes": native.MAX_ASSET,
                       "sources": [{"format": "yaml", "content": payloads[a].decode("utf-8")} for a in case["assets"]],
                       "assertions": case["assertions"], "graph_assertions": [], "wrapper_assertions": [], "custom_assertions": case["custom_assertions"]}
            binding = {"request_sha256": native.digest(native.canonical(request)), "invocation_nonce": request["invocation_nonce"], "namespace_sha256": native.digest(request["namespace"].encode()),
                       "candidate_sha256": args.candidate_sha256, "binary_sha256": args.binary_sha256, "inventory_sha256": args.inventory_sha256,
                       "case_sha256": native.digest(native.canonical(case)), "assets": [{"id": a, "sha256": assets[a]["sha256"]} for a in case["assets"]]}
            request["binding"] = native.digest(native.canonical(binding))
            response = native.with_actions(validate_response(native.run_probe(descriptor, request, args.timeout), request))
            if response["state"] == "static-assertions-passed":
                native.require(response.get("resources") == case["resources"], "source-resource-count-mismatch")
            results.append({"id": case["id"], "project": case["project"], "binding": binding, "native": response,
                            "schema": schema_evidence_state(response), "controller_behavior": "not-proven"})
        return {"schema_version": 1, "state": "official-custom-document-contract-executed-programme-incomplete", "candidate_sha256": args.candidate_sha256, "binary_sha256": args.binary_sha256, "inventory_sha256": args.inventory_sha256,
                "expectation_sha256": native.digest(native.canonical(CASES)), "target_minor": args.target_minor, "cases": results,
                "policies": {"preserve_unknown": args.preserve_unknown, "protected_output": args.protected_output, "gate_resolution": "documented-defaults-selected"},
                "api": "pending", "runtime": "pending", "controller": "not-proven", "publication": "not-authorized"}
    finally:
        os.close(descriptor)


class ContractTests(unittest.TestCase):
    def test_official_seven_kind_inventory_and_exact_source_indices(self):
        self.assertEqual({a["identity"]["kind"] for c in CASES for a in c["custom_assertions"]}, {"Cluster", "Pooler", "Backup", "ScheduledBackup", "Grafana", "GrafanaDashboard", "GrafanaDatasource"})
        self.assertEqual(sum(len(c["custom_assertions"]) for c in CASES), 9)
        self.assertEqual(CASES[4]["custom_assertions"][0]["binding"]["source_document"], 11)
        self.assertEqual(CASES[5]["custom_assertions"][1]["source_document"], 2)
        self.assertTrue(all(a["check"] == "UnsupportedSchema" and not a["positive_dependency"] for c in CASES for a in c["custom_assertions"]))

    def test_refused_or_incomplete_cases_cannot_claim_completed_schema_evidence(self):
        for state in ("parse-refused", "decode-refused", "processing-refused"):
            for custom in (None, {}, {"state": "not-executed-native-refusal"}):
                self.assertEqual(schema_evidence_state({"state": state, "custom": custom}), "not-executed-native-refusal")
        self.assertEqual(schema_evidence_state({"state": "processing-refused", "custom": {"state": "processing-refused"}}), "incomplete-processing")
        self.assertEqual(schema_evidence_state({"state": "static-assertions-failed", "custom": {"state": "checked"}}), "checked-assertions-failed")
        self.assertEqual(schema_evidence_state({"state": "static-assertions-passed", "custom": {"state": "checked"}}), "supported-subset-with-explicit-unsupported")

    def test_response_privacy_and_wrong_or_incomplete_success(self):
        request = {"binding": "a" * 64, "target_minor": 37, "assertions": [1], "graph_assertions": [], "wrapper_assertions": [], "custom_assertions": [{"check": "UnsupportedSchema", "positive_dependency": False, "unsupported_categories": ["Defaulting"], "issue_count": 0, "supported_subset_satisfied": True}]}
        record = {"assertion_index": 0, "state": "UnsupportedSchema", "passed": True, "source_evidence_checked": True, "identity_match": True, "binding_match": True, "graph_match": True, "unsupported_categories": {"Defaulting": 1}, "issue_count": 0, "supported_subset_satisfied": True, "numeric_semantics_uncertain": False, "operator_prerequisites": 1, "positive_dependencies": 0}
        response = {"schema_version": 1, "binding": "a" * 64, "target_minor": 37, "state": "static-assertions-passed", "api": "pending", "runtime": "pending", "controller": "not-proven", "field_assertions": 1, "graph_assertions": 0, "wrapper_assertions": 0, "field_failures": 0, "graph_failures": 0, "wrapper_failures": 0, "reprojection_failures": 0, "opaque_preservation": "selected-unadmitted-source", "custom_assertions": 1, "custom_reprojection": "checked", "custom_reprojection_failures": 0, "custom": {"state": "checked", "records": [record], "failures": 0, "custom_documents": 1}}
        validate_response(response, request)
        for key, value in (("raw", "private-source-marker"), ("state", "Bound"), ("positive_dependencies", 1), ("operator_prerequisites", 0), ("binding_match", False), ("unsupported_categories", {"private-schema-marker": 1}), ("unsupported_categories", {}), ("issue_count", True), ("issue_count", 1), ("supported_subset_satisfied", False), ("numeric_semantics_uncertain", "private-marker")):
            bad = dict(response, custom=dict(response["custom"], records=[dict(record, **{key: value})]))
            with self.assertRaises(native.AcceptanceError):
                validate_response(bad, request)
        for patch in ({"target_minor": 20}, {"binding": "b" * 64}, {"custom_reprojection": "not-executed-native-refusal"}, {"custom_reprojection_failures": 1}, {"custom": dict(response["custom"], records=[])}):
            with self.assertRaises(native.AcceptanceError):
                validate_response(dict(response, **patch), request)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    for name in ("definitions", "corpus", "probe", "candidate-manifest"):
        parser.add_argument("--" + name, type=Path)
    for name in ("inventory-sha256", "binary-sha256", "candidate-sha256", "namespace"):
        parser.add_argument("--" + name)
    parser.add_argument("--target-minor", type=int)
    parser.add_argument("--preserve-unknown", choices=("yes", "no"))
    parser.add_argument("--protected-output", choices=("include", "deny"))
    parser.add_argument("--documented-gate-defaults", action="store_true")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)).wasSuccessful() else 1
    try:
        native.require(all(v is not None and v is not False for k, v in vars(args).items() if k not in {"self_test", "timeout"}), "explicit-options-required")
        receipt = execute(args)
        print(json.dumps(receipt, sort_keys=True))
        return 0 if all(c["native"]["state"] == "static-assertions-passed" for c in receipt["cases"]) else 1
    except (native.AcceptanceError, OSError, ValueError, KeyError, TypeError, native.subprocess.SubprocessError) as failure:
        print(json.dumps({"schema_version": 1, "state": "refused", "code": str(failure) if isinstance(failure, native.AcceptanceError) else "acceptance-refused"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
