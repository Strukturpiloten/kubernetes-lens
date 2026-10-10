#!/usr/bin/env python3
"""Independent preparation/failure tests; deliberately no native-conformance claims."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("official_materializer", Path(__file__).with_name("materialize.py"))
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)
PUBLIC_PROTECTED_MARKER = b"PUBLIC-FIXTURE-PROTECTED-MARKER"


def archive_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "../../outside"
            if kind == tarfile.REGTYPE:
                member.size = len(content)
            archive.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def record(path, data):
    return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def synthetic_inventory(cache):
    """Small originally authored public source graph with independently known output bytes."""
    payloads = {
        "cloudnativepg/source/LICENSE": b"Public synthetic test license evidence.\n",
        "cloudnativepg/source/config/default/kustomization.yaml": b"---\nresources: [../base]\n",
        "cloudnativepg/source/config/base/kustomization.yaml": b"---\nresources: [service.yaml]\n",
        "cloudnativepg/source/config/base/service.yaml": b"---\nkind: Service\nmetadata: {name: independent-test}\n",
    }
    chart = "cloudnativepg/archives/test-1.tgz"
    member_payloads = {
        "test/Chart.yaml": b"---\nname: test\nversion: 1.0.0\ndependencies: [{name: common, version: 2.0.0}]\n",
        "test/charts/common/Chart.yaml": b"---\nname: common\nversion: 2.0.0\n",
        "test/templates/secret.yaml": b"---\nkind: Secret\nstringData: {password: " + PUBLIC_PROTECTED_MARKER + b"}\n",
    }
    payloads[chart] = archive_bytes([(name, data, tarfile.REGTYPE) for name, data in member_payloads.items()])
    assets = []
    for path, data in payloads.items():
        target = cache / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        asset = {**record(path, data), "id": "cloudnativepg:" + path.split("/", 1)[1], "project": "cloudnativepg",
                 "source_url": "https://example.invalid/synthetic-public-source", "original_path": path,
                 "source_revision": "a" * 40}
        if path.endswith("service.yaml"):
            asset["plain_resource_inventory"] = [{"apiVersion": "v1", "kind": "Service", "name": "independent-test"}]
        assets.append(asset)
    archive = assets[-1]
    extraction_root = "cloudnativepg/extracted/test-1"
    archive["extraction_root"] = extraction_root
    archive["renderer_input"] = extraction_root + "/test"
    dependency = {"name": "common", "version": "2.0.0", "repository": "https://example.invalid/not-contacted"}
    archive["packaged_chart_metadata"] = {"name": "test", "version": "1.0.0", "dependencies": [dependency]}
    archive["extracted_files"] = [
        {**record(extraction_root + "/" + name, data), "archive_id": archive["id"], "original_path": name}
        for name, data in member_payloads.items()
    ]
    inventory = {
        "schema_version": 1, "status": "source-prepared-native-pending", "errors": [],
        "projects": {"cloudnativepg": {"revision": "a" * 40, "license": "synthetic-test-only",
                     "license_asset_ids": [assets[0]["id"]], "redistribution_status": "evidence-only-review-pending"}},
        "assets": assets,
        "materialized_renderer_dependencies": [{"archive_id": archive["id"], "declared": dependency,
            "chart_paths": [extraction_root + "/test/charts/common/Chart.yaml"],
            "materialized_metadata": [{"name": "common", "version": "2.0.0"}], "materialized_versions": ["2.0.0"],
            "render_network_needed": False}],
        "kustomize_dependency_graph": [
            {"source_id": assets[1]["id"], "field": "resources", "reference": "../base",
             "target": "cloudnativepg/source/config/base", "external": False, "materialized": True},
            {"source_id": assets[2]["id"], "field": "resources", "reference": "service.yaml",
             "target": assets[3]["path"], "external": False, "materialized": True},
        ],
        "renderer_entrypoints": [{"input": "cloudnativepg/source/config/default", "project": "cloudnativepg", "tool": "Kustomize",
            "supplied_root": "cloudnativepg/source/config", "relative_entrypoint": "default", "load_restrictions": "default-root-only"},
                                 {"input": archive["renderer_input"], "project": "cloudnativepg", "tool": "Helm", "archive_id": archive["id"]}],
        "counts": {"assets": 5, "archive_members": 3, "plain_documents": 1, "renderer_entrypoints": 2,
                   "chart_dependencies": 1, "kustomize_edges": 2},
    }
    return inventory


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="official-fixture-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.destination = self.root / "prepared"
        self.inventory = synthetic_inventory(self.cache)

    def fails(self, code):
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "^" + code + "$"):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".official-fixtures-*")), [])

    def replace_archive(self, entries):
        asset = self.inventory["assets"][-1]
        data = archive_bytes(entries)
        asset.update(record(asset["path"], data))
        (self.cache / asset["path"]).write_bytes(data)

    def original_entries(self):
        asset = self.inventory["assets"][-1]
        with tarfile.open(fileobj=io.BytesIO((self.cache / asset["path"]).read_bytes())) as archive:
            return [(m.name, archive.extractfile(m).read(), tarfile.REGTYPE) for m in archive]

    def add_oci_manifest(self, matching=True):
        archive = self.inventory["assets"][-1]
        layer = {"digest": "sha256:" + (archive["sha256"] if matching else "0" * 64), "size": archive["bytes"]}
        data = json.dumps({"schemaVersion": 2, "layers": [layer]}).encode()
        path = "cloudnativepg/archives/oci-manifest.json"
        identity = "cloudnativepg:archives/oci-manifest.json"
        manifest = {**record(path, data), "id": identity, "project": "cloudnativepg",
                    "source_url": "https://example.invalid/synthetic-manifest", "original_path": path,
                    "registry_content_digest": None,
                    "oci_immutable_reference": "oci://example.invalid/chart@sha256:" + hashlib.sha256(data).hexdigest()}
        (self.cache / path).write_bytes(data)
        archive["manifest_id"] = identity
        self.inventory["assets"].append(manifest)
        self.inventory["counts"]["assets"] += 1

    def add_markdown_derivation(self):
        expected = b"---\nkind: Secret\nstringData:\n  password: PUBLIC-FIXTURE-PROTECTED-MARKER\n"
        original = (b"Public originally authored documentation.\n\n   ```yaml\n   ---\n   kind: Secret\n"
                    b"   stringData:\n     password: PUBLIC-FIXTURE-PROTECTED-MARKER\n   ```\nTrailing prose.\n")
        source_path = "cloudnativepg/source/docs/public-example.md"
        derived_path = "cloudnativepg/derived/public-example.yaml"
        source_id = "cloudnativepg:source/docs/public-example.md"
        for path, data in ((source_path, original), (derived_path, expected)):
            target = self.cache / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.inventory["assets"].append({**record(path, data), "id": "cloudnativepg:" + path.split("/", 1)[1],
                "project": "cloudnativepg", "original_path": path, "source_url": "https://example.invalid/synthetic-document"})
        derived = self.inventory["assets"][-1]
        derived.update({"derived_from_id": source_id, "source_start_line": 4, "source_end_line": 7,
                        "extraction": "Remove three common indentation spaces from a complete YAML fence payload.",
                        "extraction_contract": {"format": "markdown-yaml-fence", "line_numbers": "one-based-inclusive",
                                                "indentation_spaces": 3, "preserve_line_endings": True}})
        self.inventory["counts"]["assets"] += 2
        return original, derived, expected

    def add_document_slice(self):
        asset = self.inventory["assets"][3]
        data = (self.cache / asset["path"]).read_bytes()
        observed = asset["plain_resource_inventory"][0]
        observed["document"] = 1
        witness = {"byte_start": 0, "byte_end_exclusive": len(data), "bytes": len(data), "sha256": asset["sha256"],
                   "document": 1, "start_line": 1, "end_line_inclusive": 3,
                   "identity": {k: v for k, v in observed.items() if k != "document"}}
        asset["source_slices"] = [witness]
        asset["git_blob_sha1"] = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        asset["git_blob_verified"] = True
        self.inventory["source_slice_conventions"] = {"bytes": "zero-based-half-open", "lines": "one-based-inclusive",
                                                      "line_separator": "LF; preserve exact original bytes"}
        return asset, witness, data

    def test_complete_materialization_preserves_independent_known_bytes_and_private_modes(self):
        result = MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual(result["status"], "source-materialized-native-pending")
        self.assertEqual((self.destination / "cloudnativepg/source/config/base/service.yaml").read_bytes(),
                         b"---\nkind: Service\nmetadata: {name: independent-test}\n")
        self.assertEqual((self.destination / "cloudnativepg/extracted/test-1/test/templates/secret.yaml").read_bytes(),
                         b"---\nkind: Secret\nstringData: {password: PUBLIC-FIXTURE-PROTECTED-MARKER}\n")
        self.assertEqual(sum(path.is_file() for path in self.destination.rglob("*")), 8)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        for path in self.destination.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.assertTrue((self.cache / self.inventory["assets"][-1]["path"]).exists())

    def test_corrupt_same_size_source_fails_before_any_destination_is_visible(self):
        asset = self.inventory["assets"][-2]
        (self.cache / asset["path"]).write_bytes(b"X" * asset["bytes"])
        self.fails("asset-integrity")

    def test_invalid_digest_fails(self):
        self.inventory["assets"][0]["sha256"] = "not-a-digest"
        self.fails("invalid-digest")

    def test_duplicate_source_identity_fails(self):
        self.inventory["assets"].append(copy.deepcopy(self.inventory["assets"][0]))
        self.fails("duplicate-asset")

    def test_missing_cache_is_failure(self):
        (self.cache / self.inventory["assets"][0]["path"]).unlink()
        with self.assertRaises(OSError):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertFalse(self.destination.exists())

    def test_unsafe_receipt_paths(self):
        for path in ("../outside", "/outside", "cloudnativepg/../outside", "cloudnativepg\\outside", "cloudnativepg//source"):
            with self.subTest(path=path), self.assertRaises(MATERIALIZER.FixtureError):
                MATERIALIZER.relative(path)

    def test_cache_leaf_symlink_does_not_follow_source(self):
        asset = self.inventory["assets"][0]
        leaf = self.cache / asset["path"]
        outside = self.root / "outside"
        leaf.rename(outside)
        leaf.symlink_to(outside)
        with self.assertRaises(OSError):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertFalse(self.destination.exists())

    def test_cache_parent_symlink_does_not_follow_source(self):
        directory = self.cache / "cloudnativepg/source"
        outside = self.root / "outside"
        directory.rename(outside)
        directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertFalse(self.destination.exists())

    def test_cache_hardlink_is_rejected(self):
        asset = self.inventory["assets"][0]
        os.link(self.cache / asset["path"], self.root / "alias")
        self.fails("unsafe-cache-file")

    def test_existing_destination_and_its_unrelated_content_are_preserved(self):
        self.destination.mkdir()
        protected = self.destination / "unrelated"
        protected.write_bytes(b"preserve me")
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "destination-exists"):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual(protected.read_bytes(), b"preserve me")

    def test_destination_root_symlink_is_rejected(self):
        self.destination.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "unsafe-root"):
            MATERIALIZER.materialize(self.inventory, self.cache, self.destination)

    def test_overlapping_roots_are_rejected(self):
        self.destination = self.cache / "prepared"
        self.fails("overlapping-roots")

    def test_materialization_inside_repository_is_rejected(self):
        destination = MATERIALIZER.REPOSITORY / "fixtures" / "never-create-test-output"
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "destination-inside-repository"):
            MATERIALIZER.materialize(self.inventory, self.cache, destination)
        self.assertFalse(destination.exists())

    def test_missing_declared_chart_dependency_fails(self):
        self.inventory["materialized_renderer_dependencies"] = []
        self.fails("incomplete-chart-graph")

    def test_wrong_materialized_chart_version_fails(self):
        self.inventory["materialized_renderer_dependencies"][0]["materialized_versions"] = ["99.0.0"]
        self.fails("wrong-dependency-version")

    def test_unmaterialized_or_remote_chart_dependency_fails(self):
        dependency = self.inventory["materialized_renderer_dependencies"][0]
        dependency["chart_paths"] = ["cloudnativepg/extracted/test-1/test/charts/missing/Chart.yaml"]
        self.fails("incomplete-chart-graph")
        dependency["render_network_needed"] = True
        self.fails("incomplete-chart-graph")

    def test_kustomize_changed_relative_reference_fails(self):
        self.inventory["kustomize_dependency_graph"][0]["reference"] = "../elsewhere"
        self.fails("wrong-kustomize-target")

    def test_kustomize_missing_graph_edge_fails_frozen_receipt_count(self):
        self.inventory["kustomize_dependency_graph"].pop()
        self.fails("receipt-count-mismatch")

    def test_kustomize_remote_reference_is_not_admitted(self):
        self.inventory["kustomize_dependency_graph"][0]["reference"] = "https://example.invalid/base"
        self.fails("remote-or-invalid-kustomize-edge")

    def test_kustomize_missing_target_is_not_admitted(self):
        edge = self.inventory["kustomize_dependency_graph"][0]
        edge["reference"] = "../missing"
        edge["target"] = "cloudnativepg/source/config/missing"
        self.fails("incomplete-kustomize-graph")

    def test_renderer_entrypoint_must_be_materialized(self):
        self.inventory["renderer_entrypoints"][0]["input"] = "cloudnativepg/source/missing"
        self.fails("missing-entrypoint")

    def test_sibling_base_is_within_supplied_root_and_private_materialization(self):
        files = MATERIALIZER.validate_inventory(self.inventory)
        closure = MATERIALIZER.kustomize_closure(self.inventory, self.inventory["renderer_entrypoints"][0], files)
        self.assertEqual(closure, {
            "supplied_root": "cloudnativepg/source/config", "relative_entrypoint": "default", "edge_count": 2,
            "files": ["cloudnativepg/source/config/base/kustomization.yaml",
                      "cloudnativepg/source/config/base/service.yaml",
                      "cloudnativepg/source/config/default/kustomization.yaml"],
        })
        MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual((self.destination / "cloudnativepg/source/config/base/service.yaml").read_bytes(),
                         b"---\nkind: Service\nmetadata: {name: independent-test}\n")

    def test_malformed_supplied_root_and_entrypoint_are_rejected(self):
        original = copy.deepcopy(self.inventory)
        for field in ("supplied_root", "relative_entrypoint"):
            for value in (None, 4, "", ".", "..", "/absolute", "../escape", "default/../base", "default//base",
                          "https://example.invalid/root", "default\\base"):
                with self.subTest(field=field, value=value):
                    self.inventory = copy.deepcopy(original)
                    self.inventory["renderer_entrypoints"][0][field] = value
                    self.fails("invalid-path")

    def test_missing_supplied_root_and_relative_entrypoint_are_rejected(self):
        original = copy.deepcopy(self.inventory)
        for field in ("supplied_root", "relative_entrypoint"):
            self.inventory = copy.deepcopy(original)
            del self.inventory["renderer_entrypoints"][0][field]
            self.fails("invalid-path")

    def test_missing_cross_project_and_mismatched_supplied_roots_are_rejected(self):
        original = copy.deepcopy(self.inventory)
        for value, code in (("grafana-operator/source", "invalid-supplied-root"),
                            ("cloudnativepg/missing", "missing-supplied-root"),
                            ("cloudnativepg/source", "wrong-relative-entrypoint")):
            self.inventory = copy.deepcopy(original)
            self.inventory["renderer_entrypoints"][0]["supplied_root"] = value
            self.fails(code)

    def test_entrypoint_directory_is_not_the_supplied_project_root(self):
        entry = self.inventory["renderer_entrypoints"][0]
        entry.update(supplied_root="cloudnativepg/source/config/default", relative_entrypoint="default",
                     input="cloudnativepg/source/config/default/default")
        # Keeping the same input requires a root/entrypoint mismatch and must not
        # turn the entrypoint into an implicit boundary for sibling bases.
        entry["input"] = "cloudnativepg/source/config/default"
        self.fails("wrong-relative-entrypoint")

    def test_narrow_supplied_root_rejects_first_hop_outside_closure(self):
        entry = self.inventory["renderer_entrypoints"][0]
        entry.update(supplied_root="cloudnativepg/source/config/default", relative_entrypoint="nested",
                     input="cloudnativepg/source/config/default/nested")
        source = self.inventory["assets"][1]
        source["path"] = entry["input"] + "/kustomization.yaml"
        source["id"] = "cloudnativepg:" + source["path"].split("/", 1)[1]
        edge = self.inventory["kustomize_dependency_graph"][0]
        edge.update(source_id=source["id"], reference="../../base")
        self.fails("kustomize-outside-supplied-root")

    def test_second_hop_cannot_escape_supplied_root_even_within_project(self):
        asset = copy.deepcopy(self.inventory["assets"][3])
        asset.update(path="cloudnativepg/source/elsewhere/service.yaml", id="cloudnativepg:source/elsewhere/service.yaml")
        self.inventory["assets"].append(asset)
        self.inventory["counts"]["assets"] += 1
        self.inventory["counts"]["plain_documents"] += 1
        self.inventory["kustomize_dependency_graph"][1].update(
            reference="../../elsewhere/service.yaml", target=asset["path"])
        self.fails("kustomize-outside-supplied-root")

    def test_sibling_file_load_requires_its_own_loader_root(self):
        self.inventory["kustomize_dependency_graph"][1].update(
            reference="../default/kustomization.yaml", target=self.inventory["assets"][1]["path"])
        self.fails("kustomize-file-outside-loader-root")

    def test_local_base_cycle_is_rejected(self):
        self.inventory["kustomize_dependency_graph"][1].update(
            reference="../default", target="cloudnativepg/source/config/default")
        self.fails("cyclic-kustomize-graph")

    def test_loader_override_is_never_a_closure_repair(self):
        for value in (None, "LoadRestrictionsNone", "none", "--load-restrictor=LoadRestrictionsNone"):
            self.inventory["renderer_entrypoints"][0]["load_restrictions"] = value
            self.fails("unadmitted-load-restrictions")

    def test_license_and_revision_records_are_required(self):
        metadata = self.inventory["projects"]["cloudnativepg"]
        metadata["license_asset_ids"] = []
        self.fails("missing-license-evidence")
        metadata["license_asset_ids"] = [self.inventory["assets"][0]["id"]]
        metadata["revision"] = "main"
        self.fails("missing-provenance")

    def test_native_success_cannot_be_asserted_by_source_preparation(self):
        self.inventory["status"] = "native-conformance-passed"
        self.fails("invalid-evidence-state")

    def test_archive_traversal_absolute_and_link_members_are_rejected(self):
        original = self.original_entries()
        for name, kind, code in (("../outside", tarfile.REGTYPE, "invalid-path"),
                                 ("/outside", tarfile.REGTYPE, "invalid-path"),
                                 ("test/link", tarfile.SYMTYPE, "unsafe-archive-member"),
                                 ("test/link", tarfile.LNKTYPE, "unsafe-archive-member"),
                                 ("test/fifo", tarfile.FIFOTYPE, "unsafe-archive-member")):
            with self.subTest(kind=kind, name=name):
                self.replace_archive(original + [(name, b"public", kind)])
                self.fails(code)
        self.assertFalse((self.root / "outside").exists())

    def test_duplicate_archive_members_are_rejected(self):
        entries = self.original_entries()
        self.replace_archive(entries + [entries[0]])
        self.fails("duplicate-archive-member")

    def test_unrecorded_and_missing_archive_members_are_rejected(self):
        entries = self.original_entries()
        self.replace_archive(entries + [("test/unrecorded", b"public", tarfile.REGTYPE)])
        self.fails("unrecorded-archive-member")
        self.replace_archive(entries[:-1])
        self.fails("missing-archive-member")

    def test_member_payload_hash_is_verified_independently_of_archive_hash(self):
        entries = self.original_entries()
        name, content, kind = entries[-1]
        self.replace_archive(entries[:-1] + [(name, b"X" * len(content), kind)])
        self.fails("asset-integrity")

    def test_oci_chart_layer_is_verified_with_optional_registry_header_evidence(self):
        self.add_oci_manifest()
        result = MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual(result["assets"], 6)

    def test_oci_chart_layer_mismatch_fails_even_with_valid_manifest_byte_hash(self):
        self.add_oci_manifest(matching=False)
        self.fails("oci-layer-mismatch")

    def test_oci_immutable_reference_mismatch_fails(self):
        self.add_oci_manifest()
        self.inventory["assets"][-1]["oci_immutable_reference"] = "oci://example.invalid/chart@sha256:" + "0" * 64
        self.fails("oci-digest-mismatch")

    def test_source_slice_transformation_reconstructs_independent_expected_payload_and_hash(self):
        original, derived, expected = self.add_markdown_derivation()
        actual = MATERIALIZER.derive_markdown_bytes(original, derived)
        self.assertEqual(actual, expected)
        self.assertEqual(hashlib.sha256(actual).hexdigest(), hashlib.sha256(expected).hexdigest())
        self.assertNotIn(b"```", actual)
        MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual((self.destination / derived["path"]).read_bytes(), expected)

    def test_source_slice_including_closing_fence_fails_even_with_unchanged_derived_hash(self):
        _, derived, _ = self.add_markdown_derivation()
        derived["source_end_line"] = 8
        self.fails("invalid-derivation-fence")

    def test_wrong_source_slice_indentation_fails_derived_byte_hash(self):
        _, derived, _ = self.add_markdown_derivation()
        derived["extraction_contract"]["indentation_spaces"] = 2
        self.fails("asset-integrity")

    def test_changed_markdown_payload_cannot_match_independently_frozen_derived_bytes(self):
        original, derived, _ = self.add_markdown_derivation()
        source = self.inventory["assets"][-2]
        changed = original.replace(b"kind: Secret", b"kind: Pod")
        source.update(record(source["path"], changed))
        (self.cache / source["path"]).write_bytes(changed)
        self.fails("asset-integrity")

    def test_half_open_or_undeclared_derivation_convention_is_not_admitted(self):
        _, derived, _ = self.add_markdown_derivation()
        derived["extraction_contract"]["line_numbers"] = "half-open"
        self.fails("unsupported-derivation")

    def test_document_slice_and_git_blob_witnesses_verify_real_source_bytes(self):
        asset, witness, data = self.add_document_slice()
        MATERIALIZER.verify_source_slice(data, witness)
        MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertEqual((self.destination / asset["path"]).read_bytes(),
                         b"---\nkind: Service\nmetadata: {name: independent-test}\n")

    def test_git_blob_identity_is_independent_of_sha256_byte_verification(self):
        asset, _, _ = self.add_document_slice()
        asset["git_blob_sha1"] = "0" * 40
        self.fails("git-blob-mismatch")

    def test_wrong_slice_byte_hash_and_line_end_fail(self):
        _, witness, data = self.add_document_slice()
        witness["sha256"] = "0" * 64
        self.fails("asset-integrity")
        witness["sha256"] = hashlib.sha256(data).hexdigest()
        witness["end_line_inclusive"] = 4
        self.fails("source-slice-line-range")

    def test_document_slices_cannot_omit_source_bytes_or_change_identity(self):
        _, witness, _ = self.add_document_slice()
        witness["byte_start"] = 1
        witness["bytes"] -= 1
        self.fails("incomplete-document-slices")
        witness["byte_start"] = 0
        witness["bytes"] += 1
        witness["identity"]["name"] = "wrong-resource"
        self.fails("wrong-slice-identity")

    def test_midline_source_slice_is_rejected_before_any_native_interpretation(self):
        data = b"---\nkind: Service\n"
        witness = {"byte_start": 1, "byte_end_exclusive": len(data), "bytes": len(data) - 1,
                   "sha256": hashlib.sha256(data[1:]).hexdigest(), "start_line": 1, "end_line_inclusive": 2}
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "source-slice-line-boundary"):
            MATERIALIZER.verify_source_slice(data, witness)

    def test_unsupported_source_slice_convention_fails(self):
        self.add_document_slice()
        self.inventory["source_slice_conventions"]["bytes"] = "one-based-inclusive"
        self.fails("unsupported-source-slice-convention")

    def test_expanded_archive_member_count_and_file_budgets_are_enforced(self):
        with patch.object(MATERIALIZER, "MAX_TAR_BYTES", 100):
            self.fails("archive-budget")
        with patch.object(MATERIALIZER, "MAX_TAR_ENTRIES", 1):
            self.fails("archive-count-budget")
        with patch.object(MATERIALIZER, "MAX_FILE", 10):
            self.fails("file-budget")
        with patch.object(MATERIALIZER, "MAX_TOTAL", 10):
            self.fails("corpus-budget")

    def test_failed_write_leaves_no_partial_destination(self):
        with patch.object(Path, "open", side_effect=OSError("PUBLIC-FIXTURE-PROTECTED-MARKER")):
            with self.assertRaises(OSError):
                MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".official-fixtures-*")), [])

    def test_cli_redacts_os_paths_source_content_and_exceptions(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        missing = self.root / PUBLIC_PROTECTED_MARKER.decode()
        with patch.object(MATERIALIZER, "load_inventory", return_value=self.inventory), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MATERIALIZER.main(["--cache", str(missing), "--destination", str(self.destination)])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(json.loads(stderr.getvalue()), {"status": "failed", "code": "source-unavailable-or-invalid"})
        self.assertNotIn(PUBLIC_PROTECTED_MARKER.decode(), stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(str(self.root), stderr.getvalue())

    def test_cli_success_only_reports_preparation_counts(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(MATERIALIZER, "load_inventory", return_value=self.inventory), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = MATERIALIZER.main(["--cache", str(self.cache), "--destination", str(self.destination)])
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["status"], "source-materialized-native-pending")
        self.assertNotIn(PUBLIC_PROTECTED_MARKER.decode(), stdout.getvalue())

    def test_receipt_hash_protects_dependency_graph_and_provenance(self):
        official = self.root / "official"
        official.mkdir()
        data = json.dumps(self.inventory).encode()
        (official / "inventory.json").write_bytes(data)
        (official / "inventory.sha256").write_text(hashlib.sha256(data).hexdigest() + "\n")
        with patch.object(MATERIALIZER, "OFFICIAL", official):
            self.assertEqual(MATERIALIZER.load_inventory(), self.inventory)
            (official / "inventory.json").write_bytes(data.replace(b"2.0.0", b"9.0.0"))
            with self.assertRaisesRegex(MATERIALIZER.FixtureError, "receipt-integrity"):
                MATERIALIZER.load_inventory()


class LicenseCompanionTests(unittest.TestCase):
    """Independent originally authored sources: source attribution is not an upstream grant."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fixture-companion-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.destination = self.root / "prepared"
        self.inventory = synthetic_inventory(self.cache)

    def add_asset(self, project, suffix, data, **extra):
        path = project + "/" + suffix
        target = self.cache / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        asset = {**record(path, data), "id": project + ":" + suffix, "project": project,
                 "original_path": suffix, "source_url": "https://example.invalid/original-synthetic-source", **extra}
        self.inventory["assets"].append(asset)
        self.inventory["counts"]["assets"] += 1
        return asset

    def prepare_family(self, name):
        project = {"grafana-doc": "grafana", "forgejo-common": "forgejo", "aio-recipe": "nextcloud-aio"}[name]
        revision = "a" * 40
        root_license = self.add_asset(project, "source/LICENSE", b"Originally authored synthetic root license.\n")
        self.inventory["projects"][project] = {"revision": revision, "license": "synthetic-test-only",
            "license_asset_ids": [root_license["id"]], "redistribution_status": "evidence-only-review-pending"}
        covered, derivations = [], []
        if name == "grafana-doc":
            document = self.add_asset(project, "source/docs/sources/setup-grafana/installation/kubernetes/index.md",
                b"Synthetic source.\n\n   ```yaml\n   ---\n   kind: ConfigMap\n   ```\n", source_revision=revision)
            derived = self.add_asset(project, "derived/standalone-doc-block-0.yaml", b"---\nkind: ConfigMap\n",
                derived_from_id=document["id"], source_start_line=4, source_end_line=5,
                extraction="Only common Markdown indentation removed.",
                extraction_contract={"format":"markdown-yaml-fence", "line_numbers":"one-based-inclusive",
                                     "preserve_line_endings":True,"indentation_spaces":3})
            covered = [derived["path"], document["path"]]
            derivations = [{"source_id":document["id"],"source_sha256":document["sha256"],
                "derived_id":derived["id"],"derived_sha256":derived["sha256"],"source_start_line":4,"source_end_line":5,
                "extraction_contract":derived["extraction_contract"]}]
            specs = [("source/LICENSING.md", b"Synthetic default AGPL-3.0-only terms.\n", "repository-default",
                      "AGPL-3.0-only", "grafana/grafana", "LICENSING.md", revision)]
        elif name == "forgejo-common":
            specs = [("license-companions/common-LICENSE.md", b"Synthetic Broadcom Apache License\nEND OF TERMS AND CONDITIONS\n",
                "terms-only-not-implementation-source", "Apache-2.0", "bitnami/charts", "LICENSE.md",
                "f163ae82b57eaa2720237300a5911b9c9f496a01")]
            member_path = "forgejo/charts/common/README.md"
            content = b"Synthetic common source; Copyright 2025 Broadcom Inc.; SPDX-License-Identifier: APACHE-2.0\n"
        else:
            recipe_revision = "11f5018e269359d9f900ae3b5c2e94c306623053"
            repo = "ahmetb/kubernetes-network-policy-recipes"
            specs = [("license-companions/recipe-LICENSE", b"Synthetic Apache License; Copyright 2017 Google Inc.\nEND OF TERMS AND CONDITIONS\n",
                      "third-party-license", "Apache-2.0", repo, "LICENSE", recipe_revision),
                     ("license-companions/recipe-README.md", b"Ahmet Alp Balkan; Copyright 2017, Google Inc.; not an official Google product.\n",
                      "third-party-attribution", "Apache-2.0", repo, "README.md", recipe_revision),
                     ("license-companions/recipe-source.md", b"Synthetic independent current source witness, not historical derivation.\n",
                      "source-witness-not-historical-revision", "Apache-2.0", repo,
                      "04-deny-traffic-from-other-namespaces.md", recipe_revision)]
            member_path = "nextcloud-aio-helm-chart/templates/nextcloud-aio-networkpolicy.yaml"
            content = b"# Original synthetic upstream attribution retained.\n---\nkind: NetworkPolicy\n"
        if name != "grafana-doc":
            archive = self.add_asset(project,"archives/synthetic.tgz",archive_bytes([(member_path,content,tarfile.REGTYPE)]))
            extraction = project + "/extracted/synthetic"
            archive["extraction_root"] = extraction
            covered = [extraction + "/" + member_path]
            archive["extracted_files"] = [{**record(covered[0],content),"original_path":member_path,"archive_id":archive["id"]}]
            self.inventory["counts"]["archive_members"] += 1
        companions = []
        for suffix, data, role, expression, repository, source_path, source_revision in specs:
            companions.append(self.add_asset(project,suffix,data,source_revision=source_revision,
                source_url="https://raw.githubusercontent.com/"+repository+"/"+source_revision+"/"+source_path,
                license_companion={"role":role,"expression":expression,"repository":repository,
                                   "source_path":source_path,"revision":source_revision}))
        attribution = {"grafana-doc":"Grafana / Grafana Labs","forgejo-common":"Copyright 2025 Broadcom Inc.",
                       "aio-recipe":"Ahmet Alp Balkan; Copyright 2017 Google Inc.; not an official Google product"}[name]
        binding = {"id":name,"project":project,"covered_paths":sorted(covered),
            "companion_asset_ids":sorted(a["id"] for a in companions),"root_license_asset_ids":[root_license["id"]],
            "license_expression":"AGPL-3.0-only" if name=="grafana-doc" else "Apache-2.0",
            "upstream_attribution":attribution,"change_notice":"2026-10-10 synthetic fixture derivation; original source retained.",
            "notice_integration_date":"2026-10-10","redistribution_status":"evidence-only-review-pending"}
        if name == "grafana-doc":
            binding["derivations"] = derivations
            binding["original_extraction_date"] = None
            binding["original_extraction_date_status"] = "not-independently-established"
            binding["change_notice"] = (
                "2026-10-10 notice integration/correction only; original extraction date is not independently established. "
                "The previously derived YAML removes three common indentation spaces only; original source retained, "
                "with unchanged source/derived bytes and no YAML semantic edits."
            )
        elif name == "forgejo-common": binding["distribution_source_commit"] = None
        else: binding["historical_derivation_revision"] = None
        self.inventory["license_companion_requirements"] = [binding]
        return binding, companions

    def refusal(self, code):
        with self.assertRaisesRegex(MATERIALIZER.FixtureError,"^"+code+"$"):
            MATERIALIZER.materialize(self.inventory,self.cache,self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".official-fixtures-*")),[])

    def test_companions_and_dated_source_notices_accompany_each_valid_family(self):
        # Independent contributor/date assertions rather than only manifest roundtrips.
        for name, contributor in [("grafana-doc","Grafana Labs"),("forgejo-common","Broadcom"),("aio-recipe","Google Inc.")]:
            with self.subTest(name=name):
                self.inventory = synthetic_inventory(self.cache)
                binding, companions = self.prepare_family(name)
                MATERIALIZER.materialize(self.inventory,self.cache,self.destination)
                notices = json.loads((self.destination/"fixture-notices.json").read_bytes())
                self.assertEqual(notices["status"],"fetch-only-fixture-notices-redistribution-review-pending")
                self.assertEqual(notices["native_acceptance"],"pending")
                notice = notices["requirements"][0]
                self.assertIn(contributor,notice["upstream_attribution"])
                self.assertEqual(notice["notice_integration_date"],"2026-10-10")
                self.assertNotIn("modification_date", notice)
                self.assertIn("original source retained",notice["change_notice"])
                if name=="grafana-doc":
                    self.assertEqual(notice["license_expression"],"AGPL-3.0-only")
                    self.assertEqual(notice["derivations"][0]["source_start_line"],4)
                    self.assertIsNone(notice["original_extraction_date"])
                    self.assertEqual(notice["original_extraction_date_status"], "not-independently-established")
                    self.assertIn("notice integration/correction only", notice["change_notice"])
                evidence = {asset["id"]: asset for asset in notices["companion_asset_evidence"]}
                self.assertEqual(set(evidence), set(binding["companion_asset_ids"]))
                for asset in companions:
                    for field in ["id", "path", "bytes", "sha256", "source_url", "source_revision", "license_companion"]:
                        self.assertEqual(evidence[asset["id"]][field], asset[field])
                    self.assertEqual((self.destination/asset["path"]).read_bytes(),(self.cache/asset["path"]).read_bytes())
                import shutil
                shutil.rmtree(self.destination)

    def test_removing_all_requirements_cannot_bypass_root_license_and_transitive_obligations(self):
        for name in ["grafana-doc","forgejo-common","aio-recipe"]:
            self.inventory = synthetic_inventory(self.cache)
            self.prepare_family(name)
            self.inventory.pop("license_companion_requirements")
            self.refusal("missing-license-companion-requirement")

    def test_valid_root_license_cannot_replace_missing_or_inapplicable_companion(self):
        binding, companions = self.prepare_family("forgejo-common")
        original = copy.deepcopy(self.inventory)
        self.inventory["assets"].remove(companions[0])
        self.refusal("missing-license-companion")
        self.inventory = copy.deepcopy(original)
        binding = self.inventory["license_companion_requirements"][0]
        binding["companion_asset_ids"] = self.inventory["projects"]["cloudnativepg"]["license_asset_ids"]
        self.refusal("missing-license-companion")
        self.inventory = copy.deepcopy(original)
        self.inventory["license_companion_requirements"][0]["covered_paths"] = [self.inventory["assets"][0]["path"]]
        self.refusal("inapplicable-license-companion")

    def test_missing_and_mismatched_companion_bytes_leave_no_destination(self):
        _, companions = self.prepare_family("aio-recipe")
        path = self.cache/companions[0]["path"]
        data = path.read_bytes();path.unlink()
        with self.assertRaises(OSError):MATERIALIZER.materialize(self.inventory,self.cache,self.destination)
        self.assertFalse(self.destination.exists())
        path.write_bytes(b"x"*len(data))
        self.refusal("asset-integrity")

    def test_wrong_license_expression_and_unrelated_provenance_refuse_even_valid_bytes(self):
        self.prepare_family("aio-recipe")
        original = copy.deepcopy(self.inventory)
        for field, value, code in [("expression","MIT","inapplicable-license-companion"),
                                   ("repository","unrelated/project","inapplicable-license-companion"),
                                   ("role","repository-default","inapplicable-license-companion")]:
            self.inventory = copy.deepcopy(original)
            asset = next(a for a in self.inventory["assets"] if a["id"].endswith("recipe-LICENSE"))
            asset["license_companion"][field] = value
            self.refusal(code)
        self.inventory = copy.deepcopy(original)
        next(a for a in self.inventory["assets"] if a["id"].endswith("recipe-LICENSE"))["source_url"]="https://example.invalid/unrelated"
        self.refusal("unsupported-license-provenance")
        self.inventory = copy.deepcopy(original)
        self.inventory["license_companion_requirements"][0]["license_expression"]="MIT"
        self.refusal("wrong-license-expression")

    def test_notice_date_and_extraction_linkage_are_required(self):
        self.prepare_family("grafana-doc")
        original = copy.deepcopy(self.inventory)
        for field in ["notice_integration_date","change_notice","upstream_attribution"]:
            self.inventory = copy.deepcopy(original)
            self.inventory["license_companion_requirements"][0].pop(field)
            self.refusal("missing-license-notice")
        self.inventory = copy.deepcopy(original)
        self.inventory["license_companion_requirements"][0]["derivations"][0]["source_end_line"]=6
        self.refusal("missing-license-derivation-notice")

    def test_detached_notices_authenticate_aio_companions_without_inventory_or_cache(self):
        self.prepare_family("aio-recipe")
        MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        import shutil
        shutil.rmtree(self.cache)
        self.inventory = None
        notices = json.loads((self.destination / "fixture-notices.json").read_bytes())
        revision = "11f5018e269359d9f900ae3b5c2e94c306623053"
        source_paths = {"recipe-LICENSE": "LICENSE", "recipe-README.md": "README.md",
                        "recipe-source.md": "04-deny-traffic-from-other-namespaces.md"}
        self.assertEqual(len(notices["companion_asset_evidence"]), 3)
        for evidence in notices["companion_asset_evidence"]:
            source_path = source_paths[Path(evidence["path"]).name]
            self.assertEqual(evidence["source_url"], "https://raw.githubusercontent.com/"
                             "ahmetb/kubernetes-network-policy-recipes/" + revision + "/" + source_path)
            self.assertEqual(evidence["source_revision"], revision)
            self.assertEqual(evidence["license_companion"]["revision"], revision)
            self.assertEqual(evidence["license_companion"]["expression"], "Apache-2.0")
            payload = (self.destination / evidence["path"]).read_bytes()
            self.assertEqual(len(payload), evidence["bytes"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), evidence["sha256"])
        self.assertIsNone(notices["requirements"][0]["historical_derivation_revision"])

    def test_detached_notice_privacy_and_modes_do_not_expose_unselected_asset_metadata(self):
        _, companions = self.prepare_family("aio-recipe")
        for asset in companions:
            asset["private_cache_path"] = str(self.cache)
            asset["private_source_content"] = PUBLIC_PROTECTED_MARKER.decode()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(MATERIALIZER, "load_inventory", return_value=self.inventory), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(MATERIALIZER.main(["--cache", str(self.cache), "--destination", str(self.destination)]), 0)
        notice_path = self.destination / "fixture-notices.json"
        notice = notice_path.read_bytes()
        self.assertNotIn(PUBLIC_PROTECTED_MARKER, notice)
        self.assertNotIn(str(self.cache).encode(), notice)
        self.assertEqual(notice_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(str(self.cache), stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(PUBLIC_PROTECTED_MARKER.decode(), stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_notice_evidence_counts_toward_metadata_file_and_total_byte_budgets(self):
        self.prepare_family("aio-recipe")
        MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
        outputs = [p for p in self.destination.rglob("*") if p.is_file()]
        limits = {"MAX_METADATA": (self.destination / "fixture-notices.json").stat().st_size,
                  "MAX_FILES": len(outputs), "MAX_TOTAL": sum(p.stat().st_size for p in outputs)}
        import shutil
        shutil.rmtree(self.destination)
        for name, limit in limits.items():
            with self.subTest(budget=name):
                with patch.object(MATERIALIZER, name, limit - 1):
                    self.refusal("corpus-budget")
                with patch.object(MATERIALIZER, name, limit):
                    MATERIALIZER.materialize(self.inventory, self.cache, self.destination)
                shutil.rmtree(self.destination)

    def test_original_extraction_date_cannot_be_inferred_from_notice_integration(self):
        self.prepare_family("grafana-doc")
        original = copy.deepcopy(self.inventory)
        mutations = [("original_extraction_date", "2026-10-10", "unsupported-license-provenance"),
                     ("original_extraction_date_status", "independently-established", "unsupported-license-provenance"),
                     ("modification_date", "2026-10-10", "ambiguous-license-notice-date"),
                     ("change_notice", "2026-10-10 original extraction occurred", "ambiguous-license-notice-date"),
                     ("notice_integration_date", "2026-10-09", "ambiguous-license-notice-date"),
                     ("notice_integration_date", "2026-13-40", "missing-license-notice")]
        for field, value, code in mutations:
            with self.subTest(field=field):
                self.inventory = copy.deepcopy(original)
                self.inventory["license_companion_requirements"][0][field] = value
                self.refusal(code)
        for field in ["original_extraction_date", "original_extraction_date_status"]:
            self.inventory = copy.deepcopy(original)
            self.inventory["license_companion_requirements"][0].pop(field)
            self.refusal("unsupported-license-provenance")

    def test_wrong_or_missing_companion_revision_cannot_enter_detached_notice(self):
        self.prepare_family("aio-recipe")
        original = copy.deepcopy(self.inventory)
        for value in [None, "b" * 40]:
            self.inventory = copy.deepcopy(original)
            asset = next(a for a in self.inventory["assets"] if a["id"].endswith("recipe-LICENSE"))
            if value is None:
                asset.pop("source_revision")
            else:
                asset["source_revision"] = value
            self.refusal("unsupported-license-provenance")

    def test_new_receipt_cannot_strip_authenticated_contributor_notice(self):
        _, companions = self.prepare_family("aio-recipe")
        asset = next(a for a in companions if a["id"].endswith("recipe-README.md"))
        data = (self.cache/asset["path"]).read_bytes().replace(b"Copyright 2017, Google Inc.",b"Copyright omitted")
        (self.cache/asset["path"]).write_bytes(data);asset.update(record(asset["path"],data))
        self.refusal("missing-upstream-license-notice")

    def test_license_witness_must_not_invent_historical_source_revision(self):
        for name, field in [("forgejo-common","distribution_source_commit"),("aio-recipe","historical_derivation_revision")]:
            self.inventory = synthetic_inventory(self.cache)
            binding,_ = self.prepare_family(name)
            binding[field]="a"*40
            self.refusal("unsupported-license-provenance")


class OfficialReceiptTests(unittest.TestCase):
    def test_fixture_sources_companions_and_preparation_scripts_are_excluded_from_cargo_package(self):
        import fnmatch
        import tomllib
        manifest = tomllib.loads((MATERIALIZER.REPOSITORY / "Cargo.toml").read_text())
        package = manifest["package"]
        self.assertEqual(package["license"], "MPL-2.0")
        self.assertFalse(package["publish"])
        self.assertTrue(package["include"])
        protected = ["fixtures/official/inventory.json", "fixtures/official/license/fixture-license.txt",
                     "fixtures/official/upstream/chart.tgz", "fixtures/official/derived/source.yaml",
                     "scripts/fixtures/materialize.py", "docs/fixtures/official-corpus.md"]
        for path in protected:
            self.assertFalse(any(fnmatch.fnmatchcase(path, pattern.lstrip("/")) for pattern in package["include"]), path)
        self.assertTrue(any(fnmatch.fnmatchcase("src/lib.rs", pattern.lstrip("/")) for pattern in package["include"]))

    def test_official_source_receipt_is_portable_complete_and_has_no_native_success(self):
        inventory = MATERIALIZER.load_inventory()
        files = MATERIALIZER.validate_inventory(inventory)
        self.assertNotIn("/tmp/", json.dumps(inventory))
        self.assertEqual(len(files), inventory["counts"]["assets"] + inventory["counts"]["archive_members"])
        self.assertEqual(set(inventory["projects"]), MATERIALIZER.PROJECTS)
        self.assertTrue(inventory["pending_acceptance"])
        self.assertEqual(inventory["source_observation_count"], inventory["counts"]["assets"] + len(inventory["duplicate_source_observations"]))
        for asset in inventory["assets"]:
            for resource in asset.get("plain_resource_inventory", []):
                self.assertTrue(set(resource) <= {"apiVersion", "document", "kind", "name", "namespace"})

    def test_official_grafana_notice_dates_only_the_correction_not_original_extraction(self):
        inventory = MATERIALIZER.load_inventory()
        self.assertTrue(inventory["prepared_at_utc"].startswith("2026-10-09"))
        grafana = next(r for r in inventory["license_companion_requirements"] if r["id"] == "grafana-doc")
        self.assertEqual(grafana["notice_integration_date"], "2026-10-10")
        self.assertNotIn("modification_date", grafana)
        self.assertIsNone(grafana["original_extraction_date"])
        self.assertEqual(grafana["original_extraction_date_status"], "not-independently-established")
        self.assertIn("notice integration/correction only", grafana["change_notice"])
        self.assertIn("original extraction date is not independently established", grafana["change_notice"])

    def test_expected_values_are_independent_and_resolved_source_gaps_retain_pending_acceptance(self):
        expected = json.loads((MATERIALIZER.OFFICIAL / "expected.json").read_text())
        self.assertEqual(expected["status"], "independent-expectation-plan-native-pending")
        self.assertEqual(expected["default_namespaces"]["grafana-operator:source/examples/grafana/credential_secret/resources.yaml"], "grafana")
        grafana = expected["projects"]["grafana"]["invariants"]
        service = next(i for i in grafana if i["kind"] == "Service")
        self.assertEqual(service["fields"]["spec.ports[0].targetPort"], "http-grafana")
        self.assertEqual(expected["missing_selected_cr_samples"], [])
        self.assertIn("postgresql.cnpg.io/v1 Pooler", expected["resolved_source_gaps"][0]["kinds"])
        self.assertIn("grafana.integreatly.org/v1beta1 GrafanaDatasource", expected["resolved_source_gaps"][0]["kinds"])
        self.assertEqual(expected["source_presence_status"], "all-seven-selected-CR-kinds-have-pinned-official-samples-native-pending")

    def test_all_selected_cr_kinds_have_exact_official_source_observations(self):
        inventory = MATERIALIZER.load_inventory()
        selected = inventory["selected_custom_resource_sources"]
        self.assertEqual(set(selected["kinds"]), MATERIALIZER.SELECTED_CR_KINDS)
        self.assertEqual(selected["status"], "official-source-presence-native-pending")
        assets = {a["id"]: a for a in inventory["assets"]}
        for gvk, identities in selected["kinds"].items():
            version, kind = gvk.split(" ", 1)
            self.assertTrue(identities)
            for identity in identities:
                self.assertIn(assets[identity]["project"], {"cloudnativepg", "grafana-operator"})
                self.assertTrue(any(r["apiVersion"] == version and r["kind"] == kind
                                    for r in assets[identity]["plain_resource_inventory"]))

    def test_selected_cr_source_omission_or_native_success_claim_is_rejected(self):
        inventory = MATERIALIZER.load_inventory()
        selected = inventory["selected_custom_resource_sources"]
        selected["kinds"]["postgresql.cnpg.io/v1 Pooler"] = []
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "incomplete-selected-cr-sources"):
            MATERIALIZER.validate_inventory(inventory)
        inventory = MATERIALIZER.load_inventory()
        inventory["selected_custom_resource_sources"]["status"] = "native-accepted"
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "invalid-cr-evidence-state"):
            MATERIALIZER.validate_inventory(inventory)

    def test_crd_witness_identity_and_manifest_hash_are_bound_to_recorded_sources(self):
        for field, value, code in (("source_manifest_sha256", "0" * 64, "wrong-crd-manifest"),
                                    ("crd_name", "missing.example.invalid", "wrong-crd-identity"),
                                    ("source_manifest_url", "https://example.invalid/wrong", "wrong-crd-provenance"),
                                    ("evidence_level", "native-schema-passed", "invalid-cr-evidence-state")):
            with self.subTest(field=field):
                inventory = MATERIALIZER.load_inventory()
                inventory["custom_resource_crd_linkages"][0][field] = value
                with self.assertRaisesRegex(MATERIALIZER.FixtureError, code):
                    MATERIALIZER.validate_inventory(inventory)

    def test_every_added_selected_cr_document_has_one_crd_witness(self):
        inventory = MATERIALIZER.load_inventory()
        inventory["custom_resource_crd_linkages"].pop()
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "incomplete-crd-witness-graph"):
            MATERIALIZER.validate_inventory(inventory)
        inventory = MATERIALIZER.load_inventory()
        inventory["custom_resource_crd_linkages"].append(copy.deepcopy(inventory["custom_resource_crd_linkages"][0]))
        with self.assertRaisesRegex(MATERIALIZER.FixtureError, "incomplete-crd-witness-graph"):
            MATERIALIZER.validate_inventory(inventory)

    def test_selected_cr_expectations_keep_missing_dependencies_and_cases_separate(self):
        expected = json.loads((MATERIALIZER.OFFICIAL / "expected.json").read_text())
        groups = expected["selected_custom_resource_fixture_groups"]
        for group in groups.values():
            self.assertEqual(group["acceptance_status"], "source-reviewed-expectations-native-pending")
        complete = groups["cnpg-pooler-complete-example"]
        auth = groups["cnpg-pooler-auth-negative"]
        self.assertNotEqual(complete["assets"], auth["assets"])
        pooler = next(r for r in complete["expected_resources"] if r["kind"] == "Pooler")
        self.assertEqual(pooler["name"], auth["expected_resources"][0]["name"])
        self.assertEqual(pooler["fields"]["/spec/pgbouncer/poolMode"], "session")
        self.assertEqual({r["target"] for r in auth["expected_references"]},
                         {"Cluster/cluster-example", "Secret/cluster-example-superuser"})
        self.assertEqual(groups["cnpg-backup-missing-cluster"]["expected_references"][0]["target"], "Cluster/pg-backup")
        postgresql = groups["grafana-datasource-postgresql-protected"]
        self.assertEqual(postgresql["expected_resources"][0]["namespace"], "grafana")
        self.assertEqual(postgresql["protected_source_paths"], ["/spec/datasource/secureJsonData/password"])
        self.assertNotIn("/spec/datasource/secureJsonData/password", postgresql["expected_resources"][0]["fields"])

    def test_public_value_plans_remain_pending_and_align_explicit_sample_namespaces(self):
        plans = json.loads((MATERIALIZER.OFFICIAL / "public-values.json").read_text())
        self.assertEqual(plans["status"], "public-value-plan-renderer-admission-pending")
        self.assertEqual(plans["projects"]["grafana-operator"]["default_input_namespace"], "grafana")
        forgejo = plans["projects"]["forgejo"]["values"]["gitea"]
        self.assertEqual(forgejo["config"]["database"]["DB_TYPE"], "sqlite3")
        self.assertTrue(forgejo["admin"]["password"].startswith("PUBLIC-FIXTURE-"))
        nextcloud = plans["projects"]["nextcloud-aio"]
        self.assertEqual(nextcloud["namespace"], nextcloud["values"]["NAMESPACE"])
        for key, value in nextcloud["values"].items():
            if key.endswith(("PASSWORD", "SECRET", "KEY")):
                self.assertTrue(value.startswith("PUBLIC-FIXTURE-"))
                self.assertNotIn("@", value)
                self.assertNotIn(":", value)


if __name__ == "__main__":
    unittest.main()
