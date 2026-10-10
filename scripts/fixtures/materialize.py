#!/usr/bin/env python3
"""Verify a public source cache and prepare official fixtures without network or execution.

This is source preparation, never native conformance. No upstream script is executed.
Failures expose fixed codes only: paths, source bytes and credentials stay private.
"""

import argparse
from datetime import date
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import tempfile

REPOSITORY = Path(__file__).resolve().parents[2]
OFFICIAL = REPOSITORY / "fixtures" / "official"
PROJECTS = {"immich", "forgejo", "cloudnativepg", "grafana", "grafana-operator", "nextcloud-aio"}
SELECTED_CR_KINDS = {"postgresql.cnpg.io/v1 " + kind for kind in ("Cluster", "Pooler", "Backup", "ScheduledBackup")} | {
    "grafana.integreatly.org/v1beta1 " + kind for kind in ("Grafana", "GrafanaDashboard", "GrafanaDatasource")}
MAX_METADATA = 4 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 2048
MAX_TAR_BYTES = 16 * 1024 * 1024
MAX_TAR_ENTRIES = 2048
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")


class FixtureError(Exception):
    """Fixed public diagnostic code; never contains input data."""


def require(condition, code):
    if not condition:
        raise FixtureError(code)


def relative(value):
    """Reject filesystem/URL aliases rather than silently normalizing source paths."""
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value, "invalid-path")
    require(all(ord(c) >= 32 and ord(c) != 127 for c in value), "invalid-path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value, "invalid-path")
    require(path.parts and all(part not in {".", ".."} for part in path.parts), "invalid-path")
    return value


def checked_record(record):
    relative(record["path"])
    require(type(record["bytes"]) is int and 0 <= record["bytes"] <= MAX_FILE, "file-budget")
    require(isinstance(record["sha256"], str) and DIGEST.fullmatch(record["sha256"]), "invalid-digest")


def checked_slice(witness, size):
    start, end = witness["byte_start"], witness["byte_end_exclusive"]
    require(type(start) is int and type(end) is int and 0 <= start < end <= size, "invalid-source-slice")
    require(type(witness["bytes"]) is int and witness["bytes"] == end - start
            and DIGEST.fullmatch(witness["sha256"]), "invalid-source-slice")
    require(type(witness["start_line"]) is int and type(witness["end_line_inclusive"]) is int
            and 0 < witness["start_line"] <= witness["end_line_inclusive"], "invalid-source-slice")



KUSTOMIZATION_NAMES = ("kustomization.yaml", "kustomization.yml", "Kustomization")


def kustomize_closure(inventory, entry, files):
    """Check source-receipt closure inside a supplied root, not renderer acceptance.

    Sibling directory bases may leave the entrypoint directory but not the supplied
    project root. Direct file loads must also remain below their own loader root.
    """
    root = relative(entry.get("supplied_root"))
    subpath = relative(entry.get("relative_entrypoint"))
    require(root.startswith(entry["project"] + "/"), "invalid-supplied-root")
    require(any(path.startswith(root + "/") for path in files), "missing-supplied-root")
    require(entry["input"] == root + "/" + subpath, "wrong-relative-entrypoint")
    require(entry.get("load_restrictions") == "default-root-only", "unadmitted-load-restrictions")
    by_id = {asset["id"]: asset for asset in inventory["assets"]}
    edges = {}
    for edge in inventory["kustomize_dependency_graph"]:
        source = by_id[edge["source_id"]]["path"]
        edges.setdefault(source, []).append(edge)
    observed_files, observed_edges, active, finished = set(), set(), set(), set()

    pending = [(entry["input"], False)]
    while pending:
        directory, leaving = pending.pop()
        candidates = [directory + "/" + name for name in KUSTOMIZATION_NAMES if directory + "/" + name in files]
        require(len(candidates) == 1, "ambiguous-or-missing-kustomization")
        source = candidates[0]
        if leaving:
            active.remove(source)
            finished.add(source)
            continue
        require(source not in active, "cyclic-kustomize-graph")
        if source in finished:
            continue
        active.add(source)
        observed_files.add(source)
        pending.append((directory, True))
        for edge in edges.get(source, []):
            target = edge["target"]
            require(target == root or target.startswith(root + "/"), "kustomize-outside-supplied-root")
            observed_edges.add((source, edge["field"], edge["reference"]))
            if target in files:
                require(target.startswith(directory + "/"), "kustomize-file-outside-loader-root")
                observed_files.add(target)
            else:
                pending.append((target, False))
    return {"supplied_root": root, "relative_entrypoint": subpath,
            "files": sorted(observed_files), "edge_count": len(observed_edges)}


# Mandatory for these selected source families even if a receipt loses its requirement list.
# These are immutable fixture-license witnesses, never operational dependencies or source replacements.
COMPANION_TERMS = {
    "grafana:source/LICENSING.md": ("repository-default", "AGPL-3.0-only", "grafana/grafana", "LICENSING.md", None),
    "forgejo:license-companions/common-LICENSE.md": ("terms-only-not-implementation-source", "Apache-2.0", "bitnami/charts", "LICENSE.md", "f163ae82b57eaa2720237300a5911b9c9f496a01"),
    "nextcloud-aio:license-companions/recipe-LICENSE": ("third-party-license", "Apache-2.0", "ahmetb/kubernetes-network-policy-recipes", "LICENSE", "11f5018e269359d9f900ae3b5c2e94c306623053"),
    "nextcloud-aio:license-companions/recipe-README.md": ("third-party-attribution", "Apache-2.0", "ahmetb/kubernetes-network-policy-recipes", "README.md", "11f5018e269359d9f900ae3b5c2e94c306623053"),
    "nextcloud-aio:license-companions/recipe-source.md": ("source-witness-not-historical-revision", "Apache-2.0", "ahmetb/kubernetes-network-policy-recipes", "04-deny-traffic-from-other-namespaces.md", "11f5018e269359d9f900ae3b5c2e94c306623053"),
}
GRAFANA_DOCUMENT = "grafana:source/docs/sources/setup-grafana/installation/kubernetes/index.md"
NOTICE_PATH = "fixture-notices.json"
GRAFANA_CHANGE_NOTICE = (
    "notice integration/correction only; original extraction date is not independently established. "
    "The previously derived YAML removes three common indentation spaces only; original source retained, "
    "with unchanged source/derived bytes and no YAML semantic edits."
)


def license_coverage(by_id, files):
    grafana = [a["path"] for a in by_id.values()
               if a["id"] == GRAFANA_DOCUMENT or a.get("derived_from_id") == GRAFANA_DOCUMENT]
    forgejo = [p for p, r in files.items() if p.startswith("forgejo/")
               and r.get("original_path", "").startswith("forgejo/charts/common/")]
    aio = [p for p, r in files.items() if p.startswith("nextcloud-aio/")
           and r.get("original_path", "").endswith("/templates/nextcloud-aio-networkpolicy.yaml")]
    return {name: sorted(paths) for name, paths in
            [("grafana-doc", grafana), ("forgejo-common", forgejo), ("aio-recipe", aio)] if paths}


def validate_license_companions(inventory, by_id, files):
    coverage = license_coverage(by_id, files)
    requirements = inventory.get("license_companion_requirements", [])
    require(isinstance(requirements, list), "missing-license-companion-requirement")
    bindings = {r["id"]: r for r in requirements}
    require(len(bindings) == len(requirements) and set(bindings) == set(coverage), "missing-license-companion-requirement")
    for name, covered in coverage.items():
        binding = bindings[name]
        project = {"grafana-doc": "grafana", "forgejo-common": "forgejo", "aio-recipe": "nextcloud-aio"}[name]
        identities = sorted(identity for identity in COMPANION_TERMS if identity.startswith(project + ":"))
        require(binding.get("project") == project and binding.get("covered_paths") == covered,
                "inapplicable-license-companion")
        require(binding.get("companion_asset_ids") == identities, "missing-license-companion")
        require(binding.get("root_license_asset_ids") == inventory["projects"][project]["license_asset_ids"],
                "inapplicable-license-companion")
        require(binding.get("redistribution_status") == "evidence-only-review-pending", "invalid-license-state")
        expected_attribution = {"grafana-doc": "Grafana / Grafana Labs", "forgejo-common": "Copyright 2025 Broadcom Inc.",
                                "aio-recipe": "Ahmet Alp Balkan; Copyright 2017 Google Inc.; not an official Google product"}[name]
        require(binding.get("upstream_attribution") == expected_attribution, "missing-license-notice")
        notice = binding.get("change_notice")
        require(isinstance(notice, str) and 0 < len(notice) <= 4096, "missing-license-notice")
        require("modification_date" not in binding, "ambiguous-license-notice-date")
        try:
            recorded_date = date.fromisoformat(binding.get("notice_integration_date", ""))
        except (ValueError, TypeError):
            raise FixtureError("missing-license-notice") from None
        require(recorded_date.isoformat() == binding["notice_integration_date"], "missing-license-notice")
        if name == "forgejo-common":
            require("distribution_source_commit" in binding and binding["distribution_source_commit"] is None,
                    "unsupported-license-provenance")
        if name == "aio-recipe":
            require("historical_derivation_revision" in binding and binding["historical_derivation_revision"] is None,
                    "unsupported-license-provenance")
        if name == "grafana-doc":
            require("original_extraction_date" in binding and binding["original_extraction_date"] is None
                    and binding.get("original_extraction_date_status") == "not-independently-established",
                    "unsupported-license-provenance")
            require(notice == recorded_date.isoformat() + " " + GRAFANA_CHANGE_NOTICE,
                    "ambiguous-license-notice-date")
            require(binding.get("license_expression") == "AGPL-3.0-only", "wrong-license-expression")
            require(GRAFANA_DOCUMENT in by_id, "missing-license-companion-source")
            derived = [a for a in by_id.values() if a.get("derived_from_id") == GRAFANA_DOCUMENT]
            expected = [{"source_id": GRAFANA_DOCUMENT, "source_sha256": by_id[GRAFANA_DOCUMENT]["sha256"],
                         "derived_id": a["id"], "derived_sha256": a["sha256"],
                         "source_start_line": a["source_start_line"], "source_end_line": a["source_end_line"],
                         "extraction_contract": a["extraction_contract"]} for a in derived]
            require(binding.get("derivations") == expected, "missing-license-derivation-notice")
        else:
            require(binding.get("license_expression") == "Apache-2.0", "wrong-license-expression")
        for identity in identities:
            require(identity in by_id, "missing-license-companion")
            asset = by_id[identity]
            role, expression, repository, source_path, revision = COMPANION_TERMS[identity]
            revision = revision or inventory["projects"][project]["revision"]
            expected = {"role": role, "expression": expression, "repository": repository,
                        "source_path": source_path, "revision": revision}
            require(asset.get("license_companion") == expected and asset["project"] == project,
                    "inapplicable-license-companion")
            require(asset.get("source_revision") == revision and asset.get("source_url") ==
                    "https://raw.githubusercontent.com/" + repository + "/" + revision + "/" + source_path,
                    "unsupported-license-provenance")
    return requirements


def retained_license_notices(inventory, by_id, payloads):
    # Integrity alone cannot justify removing supplied contributor notices from a new receipt.
    required = {
        "grafana:source/LICENSING.md": [b"AGPL-3.0-only"],
        "forgejo:license-companions/common-LICENSE.md": [b"Broadcom", b"Apache License", b"END OF TERMS AND CONDITIONS"],
        "nextcloud-aio:license-companions/recipe-LICENSE": [b"Copyright 2017 Google Inc.", b"Apache License", b"END OF TERMS AND CONDITIONS"],
        "nextcloud-aio:license-companions/recipe-README.md": [b"Ahmet Alp Balkan", b"Copyright 2017, Google Inc.", b"not an official Google product"],
    }
    for binding in inventory.get("license_companion_requirements", []):
        for identity in binding["companion_asset_ids"]:
            data = payloads[by_id[identity]["path"]]
            require(all(notice in data for notice in required.get(identity, [])), "missing-upstream-license-notice")
    if inventory.get("license_companion_requirements"):
        # Detached notices retain immutable correspondence without serializing arbitrary
        # inventory/cache metadata or embedding companion source bytes.
        companion_ids = sorted({identity for binding in inventory["license_companion_requirements"]
                                for identity in binding["companion_asset_ids"]})
        fields = ("id", "project", "path", "bytes", "sha256", "source_url", "source_revision", "license_companion")
        companions = [{field: by_id[identity][field] for field in fields} for identity in companion_ids]
        notices = {"status": "fetch-only-fixture-notices-redistribution-review-pending",
                   "native_acceptance": "pending", "requirements": inventory["license_companion_requirements"],
                   "companion_asset_evidence": companions}
        data = (json.dumps(notices, sort_keys=True, indent=2) + "\n").encode()
        require(NOTICE_PATH not in payloads and len(data) <= MAX_METADATA and len(payloads) + 1 <= MAX_FILES
                and sum(len(value) for value in payloads.values()) + len(data) <= MAX_TOTAL, "corpus-budget")
        payloads[NOTICE_PATH] = data


def validate_inventory(inventory):
    """Check immutable receipt closure; this does not parse or validate Kubernetes YAML."""
    require(inventory["schema_version"] == 1, "unsupported-receipt-version")
    require(inventory["status"] == "source-prepared-native-pending", "invalid-evidence-state")
    require(not inventory["errors"], "source-preparation-incomplete")
    assets = inventory["assets"]
    require(isinstance(assets, list) and 0 < len(assets) <= MAX_FILES, "file-count-budget")
    by_id, files = {}, {}
    total = 0
    for asset in assets:
        checked_record(asset)
        project = asset["project"]
        require(project in PROJECTS and project in inventory["projects"], "unofficial-project")
        require(asset["id"] == project + ":" + asset["path"].split("/", 1)[1], "invalid-asset-identity")
        require(asset["path"].startswith(project + "/"), "cross-project-path")
        require(asset["id"] not in by_id, "duplicate-asset")
        by_id[asset["id"]] = asset
        require(asset["path"] not in files, "path-collision")
        files[asset["path"]] = asset
        total += asset["bytes"]
        require(asset.get("source_url", "").startswith("https://"), "missing-provenance")
        if "source_revision" in asset:
            require(REVISION.fullmatch(asset["source_revision"]), "missing-provenance")
        if "git_blob_sha1" in asset:
            require(REVISION.fullmatch(asset["git_blob_sha1"]) and asset["git_blob_verified"] is True, "invalid-git-blob-evidence")
        slices = asset.get("source_slices", [])
        if slices:
            cursor = 0
            observations = {r["document"]: r for r in asset["plain_resource_inventory"]}
            require(len(slices) == len(observations) == len(asset["plain_resource_inventory"]), "incomplete-document-slices")
            for witness in slices:
                checked_slice(witness, asset["bytes"])
                require(witness["byte_start"] == cursor, "incomplete-document-slices")
                observed = observations.get(witness["document"])
                require(observed is not None and witness["identity"] == {k: v for k, v in observed.items() if k != "document"},
                        "wrong-slice-identity")
                cursor = witness["byte_end_exclusive"]
            require(cursor == asset["bytes"], "incomplete-document-slices")
        if asset.get("registry_content_digest") is not None:
            require(asset["registry_content_digest"] == "sha256:" + asset["sha256"], "oci-digest-mismatch")
        if "oci_immutable_reference" in asset:
            require(asset["oci_immutable_reference"].endswith("@sha256:" + asset["sha256"]), "oci-digest-mismatch")
        members = asset.get("extracted_files", [])
        if members:
            extraction_root = relative(asset["extraction_root"])
            require(extraction_root.startswith(project + "/extracted/"), "invalid-extraction-root")
        for member in members:
            checked_record(member)
            relative(member["original_path"])
            require(member["archive_id"] == asset["id"], "wrong-member-parent")
            require(member["path"] == extraction_root + "/" + member["original_path"], "wrong-member-path")
            require(member["path"] not in files, "path-collision")
            files[member["path"]] = member
            total += member["bytes"]
    require(len(files) <= MAX_FILES and total <= MAX_TOTAL, "corpus-budget")
    for path in files:
        require(not any(str(p) in files for p in PurePosixPath(path).parents), "path-collision")
    for project, metadata in inventory["projects"].items():
        require(project in PROJECTS and REVISION.fullmatch(metadata["revision"]), "missing-provenance")
        require(metadata["license"] and metadata["license_asset_ids"], "missing-license-evidence")
        require(metadata["redistribution_status"] == "evidence-only-review-pending", "invalid-license-state")
        for identity in metadata["license_asset_ids"]:
            require(identity in by_id and by_id[identity]["project"] == project, "missing-license-evidence")
    validate_license_companions(inventory, by_id, files)
    for asset in assets:
        if "derived_from_id" in asset:
            require(asset["derived_from_id"] in by_id and asset.get("extraction"), "missing-derivation")
            require(type(asset["source_start_line"]) is int and type(asset["source_end_line"]) is int
                    and 0 < asset["source_start_line"] <= asset["source_end_line"], "missing-derivation")
            contract = asset["extraction_contract"]
            require(contract["format"] == "markdown-yaml-fence"
                    and contract["line_numbers"] == "one-based-inclusive"
                    and contract["preserve_line_endings"] is True
                    and type(contract["indentation_spaces"]) is int
                    and 0 <= contract["indentation_spaces"] <= 32, "unsupported-derivation")
        if "manifest_id" in asset:
            require(asset["manifest_id"] in by_id, "missing-oci-manifest")
    if "selected_custom_resource_sources" in inventory:
        selected = inventory["selected_custom_resource_sources"]
        require(selected["status"] == "official-source-presence-native-pending", "invalid-cr-evidence-state")
        require(set(selected["kinds"]) == SELECTED_CR_KINDS, "incomplete-selected-cr-sources")
        for gvk, identities in selected["kinds"].items():
            require(identities and len(set(identities)) == len(identities), "incomplete-selected-cr-sources")
            version, kind = gvk.split(" ", 1)
            for identity in identities:
                require(identity in by_id and any(r["apiVersion"] == version and r["kind"] == kind
                        for r in by_id[identity].get("plain_resource_inventory", [])), "wrong-selected-cr-source")
    links = inventory.get("custom_resource_crd_linkages", [])
    if links or any(a.get("source_slices") for a in assets):
        require(inventory["source_slice_conventions"] == {"bytes": "zero-based-half-open", "lines": "one-based-inclusive",
                "line_separator": "LF; preserve exact original bytes"}, "unsupported-source-slice-convention")
    required_links = {(asset["id"], witness["document"]) for asset in assets for witness in asset.get("source_slices", [])
                      if witness["identity"]["apiVersion"] + " " + witness["identity"]["kind"] in SELECTED_CR_KINDS}
    observed_links = {(link["asset_id"], link["document"]) for link in links}
    require(required_links == observed_links and len(observed_links) == len(links), "incomplete-crd-witness-graph")
    for link in links:
        require(link["asset_id"] in by_id and link["source_manifest_asset_id"] in by_id, "missing-crd-source")
        resource = by_id[link["asset_id"]]
        manifest = by_id[link["source_manifest_asset_id"]]
        require(any(r["document"] == link["document"] and r["apiVersion"] == link["apiVersion"]
                    and r["kind"] == link["kind"] for r in resource.get("plain_resource_inventory", [])), "wrong-cr-linkage")
        require(link["source_manifest_path"] == manifest["path"] and link["source_manifest_sha256"] == manifest["sha256"],
                "wrong-crd-manifest")
        require(link["source_manifest_url"] == manifest["source_url"], "wrong-crd-provenance")
        require(link["evidence_level"] == "supplied CRD identity/scope/served-version/schema linkage only; no schema/API/runtime validation",
                "invalid-cr-evidence-state")
        require(link["scope"] in {"Namespaced", "Cluster"}
                and type(link["served"]) is bool and type(link["storage"]) is bool
                and type(link["schema_present"]) is bool, "invalid-crd-observation")
        require(any(r["kind"] == "CustomResourceDefinition" and r["name"] == link["crd_name"]
                    for r in manifest.get("plain_resource_inventory", [])), "wrong-crd-identity")
        checked_slice(link["source_slice"], manifest["bytes"])
    dependencies = inventory["materialized_renderer_dependencies"]
    declarations = [(a["id"], d) for a in assets
                    for d in a.get("packaged_chart_metadata", {}).get("dependencies") or []]
    require(len(declarations) == len(dependencies), "incomplete-chart-graph")
    unmatched = list(declarations)
    for dependency in dependencies:
        pair = (dependency["archive_id"], dependency["declared"])
        require(pair in unmatched and dependency["render_network_needed"] is False, "incomplete-chart-graph")
        unmatched.remove(pair)
        parent = by_id[dependency["archive_id"]]
        member_paths = {m["path"] for m in parent.get("extracted_files", [])}
        paths = dependency["chart_paths"]
        metadata = dependency["materialized_metadata"]
        require(paths and len(paths) == len(metadata) == len(dependency["materialized_versions"]), "incomplete-chart-graph")
        for path, chart, version in zip(paths, metadata, dependency["materialized_versions"]):
            require(relative(path) in member_paths and path.endswith("/Chart.yaml"), "incomplete-chart-graph")
            require(chart["version"] == version and chart["name"] == dependency["declared"]["name"], "wrong-dependency-version")
    directories = {str(parent) for path in files for parent in PurePosixPath(path).parents}
    seen_edges = set()
    for edge in inventory["kustomize_dependency_graph"]:
        require(edge["source_id"] in by_id and edge["materialized"] is True and edge["external"] is False,
                "incomplete-kustomize-graph")
        source = by_id[edge["source_id"]]["path"]
        target = relative(edge["target"])
        ref = edge["reference"]
        require(isinstance(ref, str) and ref and not ref.startswith("/") and ":" not in ref and "\\" not in ref,
                "remote-or-invalid-kustomize-edge")
        require(posixpath.normpath(posixpath.join(posixpath.dirname(source), ref)) == target,
                "wrong-kustomize-target")
        require(target.split("/", 1)[0] == source.split("/", 1)[0], "cross-project-edge")
        require(target in files or target in directories, "incomplete-kustomize-graph")
        if target in directories:
            require(any(target + "/" + name in files for name in ("kustomization.yaml", "kustomization.yml", "Kustomization")),
                    "missing-kustomization")
        key = (source, edge["field"], ref)
        require(key not in seen_edges, "duplicate-kustomize-edge")
        seen_edges.add(key)
    for entry in inventory["renderer_entrypoints"]:
        path = relative(entry["input"])
        require(entry["project"] in PROJECTS and path.startswith(entry["project"] + "/"), "invalid-entrypoint")
        require(entry["tool"] in {"Helm", "Kustomize"}, "unadmitted-renderer")
        names = ("Chart.yaml",) if entry["tool"] == "Helm" else KUSTOMIZATION_NAMES
        require(any(path + "/" + name in files for name in names), "missing-entrypoint")
        if entry["tool"] == "Helm":
            require(entry["archive_id"] in by_id and by_id[entry["archive_id"]].get("renderer_input") == path,
                    "wrong-chart-entrypoint")
        else:
            kustomize_closure(inventory, entry, files)
    counts = {"assets": len(assets), "archive_members": len(files) - len(assets),
              "plain_documents": sum(len(a.get("plain_resource_inventory", [])) for a in assets),
              "renderer_entrypoints": len(inventory["renderer_entrypoints"]),
              "chart_dependencies": len(dependencies), "kustomize_edges": len(seen_edges)}
    require(inventory["counts"] == counts, "receipt-count-mismatch")
    return files


def verify_bytes(data, record):
    require(len(data) == record["bytes"] and hashlib.sha256(data).hexdigest() == record["sha256"], "asset-integrity")


def verify_source_slice(data, witness):
    """Check exact byte/line/hash witness without interpreting YAML or CRD schema semantics."""
    checked_slice(witness, len(data))
    start, end = witness["byte_start"], witness["byte_end_exclusive"]
    require(start == 0 or data[start - 1:start] == b"\n", "source-slice-line-boundary")
    require(end == len(data) or data[end - 1:end] == b"\n", "source-slice-line-boundary")
    require(witness["start_line"] == data[:start].count(b"\n") + 1, "source-slice-line-range")
    last = data[:end]
    require(witness["end_line_inclusive"] == last.count(b"\n") + (0 if last.endswith(b"\n") else 1),
            "source-slice-line-range")
    verify_bytes(data[start:end], witness)


def derive_markdown_bytes(source, record):
    """Reconstruct the inclusive YAML payload, preserving every byte except declared indentation."""
    lines = source.splitlines(keepends=True)
    start, end = record["source_start_line"], record["source_end_line"]
    require(1 < start <= end < len(lines), "invalid-derivation-range")
    require(lines[start - 2].strip() == b"```yaml" and lines[end].strip() == b"```", "invalid-derivation-fence")
    prefix = b" " * record["extraction_contract"]["indentation_spaces"]
    output = []
    for line in lines[start - 1:end]:
        require(not line.lstrip().startswith(b"```"), "invalid-derivation-fence")
        require(line.startswith(prefix) or not line.strip(), "invalid-derivation-indentation")
        output.append(line[len(prefix):] if line.startswith(prefix) else line)
    data = b"".join(output)
    verify_bytes(data, record)
    return data


def cache_bytes(root, record):
    """Open each component without following links, including during concurrent replacement."""
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = relative(record["path"]).split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(leaf, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe-cache-file")
            require(info.st_size == record["bytes"], "asset-integrity")
            data = source.read(record["bytes"] + 1)
            verify_bytes(data, record)
            return data
    finally:
        os.close(descriptor)


def archive_members(data, asset):
    """Decode with independent compressed/expanded/member bounds; never use extractall."""
    require(len(data) <= MAX_FILE, "archive-budget")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_TAR_BYTES + 1)
    require(len(expanded) <= MAX_TAR_BYTES, "archive-budget")
    expected = {m["original_path"]: m for m in asset["extracted_files"]}
    seen, output = set(), {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for index, member in enumerate(archive):
            require(index < MAX_TAR_ENTRIES, "archive-count-budget")
            # Some upstream archives mark directory names with a trailing slash.
            name = relative(member.name.rstrip("/") if member.isdir() else member.name)
            require(name not in seen, "duplicate-archive-member")
            seen.add(name)
            require(member.isdir() or member.isreg(), "unsafe-archive-member")
            if member.isdir():
                require(any(path.startswith(name + "/") for path in expected), "unrecorded-archive-member")
                continue
            require(name in expected, "unrecorded-archive-member")
            require(member.size == expected[name]["bytes"] and member.size <= MAX_FILE, "archive-budget")
            source = archive.extractfile(member)
            require(source is not None, "invalid-archive-member")
            with source:
                payload = source.read(member.size + 1)
            verify_bytes(payload, expected[name])
            output[expected[name]["path"]] = payload
    require(len(output) == len(expected), "missing-archive-member")
    return output


def reject_symlink_components(path):
    for component in (path, *path.parents):
        require(not component.is_symlink(), "unsafe-root")


def materialize(inventory, cache, destination):
    """Publish a complete private local tree only after every source and graph check passes."""
    files = validate_inventory(inventory)
    cache = Path(cache).absolute()
    destination = Path(destination).absolute()
    reject_symlink_components(cache)
    reject_symlink_components(destination)
    cache = cache.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    require(not destination.exists(), "destination-exists")
    require(not destination.is_relative_to(REPOSITORY), "destination-inside-repository")
    require(not destination.is_relative_to(cache) and not cache.is_relative_to(destination), "overlapping-roots")
    payloads = {}
    for asset in inventory["assets"]:
        data = cache_bytes(cache, asset)
        if "git_blob_sha1" in asset:
            blob = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
            require(hashlib.sha1(blob).hexdigest() == asset["git_blob_sha1"], "git-blob-mismatch")
        for witness in asset.get("source_slices", []):
            verify_source_slice(data, witness)
        payloads[asset["path"]] = data
        if asset.get("extracted_files"):
            payloads.update(archive_members(data, asset))
    by_id = {asset["id"]: asset for asset in inventory["assets"]}
    for asset in inventory["assets"]:
        if "derived_from_id" in asset:
            source = payloads[by_id[asset["derived_from_id"]]["path"]]
            require(derive_markdown_bytes(source, asset) == payloads[asset["path"]], "derived-payload-mismatch")
        if "manifest_id" in asset:
            manifest = json.loads(payloads[by_id[asset["manifest_id"]]["path"]])
            require(any(layer.get("digest") == "sha256:" + asset["sha256"]
                        and layer.get("size") == asset["bytes"] for layer in manifest["layers"]),
                    "oci-layer-mismatch")
    for link in inventory.get("custom_resource_crd_linkages", []):
        verify_source_slice(payloads[by_id[link["source_manifest_asset_id"]]["path"]], link["source_slice"])
    require(set(payloads) == set(files), "incomplete-materialization")
    retained_license_notices(inventory, by_id, payloads)
    temporary = Path(tempfile.mkdtemp(prefix=".official-fixtures-", dir=parent))
    try:
        for path, data in sorted(payloads.items()):
            target = temporary / path
            directory = temporary
            for component in PurePosixPath(path).parts[:-1]:
                directory = directory / component
                directory.mkdir(exist_ok=True, mode=0o700)
            with target.open("xb") as output:
                os.chmod(target, 0o600)
                output.write(data)
        # A caller-selected destination must remain absent; do not overwrite concurrent work.
        require(not destination.exists() and not destination.is_symlink(), "destination-exists")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return {"status": "source-materialized-native-pending", **inventory["counts"]}


def load_inventory():
    """Pin the entire reviewed graph and provenance receipt, not just upstream payloads."""
    digest = (OFFICIAL / "inventory.sha256").read_text(encoding="ascii").strip()
    require(DIGEST.fullmatch(digest), "invalid-receipt-digest")
    with (OFFICIAL / "inventory.json").open("rb") as source:
        data = source.read(MAX_METADATA + 1)
    require(len(data) <= MAX_METADATA and hashlib.sha256(data).hexdigest() == digest, "receipt-integrity")
    return json.loads(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, type=Path, help="explicit previously acquired anonymous-public source cache")
    parser.add_argument("--destination", required=True, type=Path, help="absent destination outside the repository; parent must exist")
    args = parser.parse_args(argv)
    try:
        result = materialize(load_inventory(), args.cache, args.destination)
    except FixtureError as failure:
        print(json.dumps({"status": "failed", "code": str(failure)}), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError, EOFError):
        # OS and parser errors may contain protected paths or source fragments.
        print(json.dumps({"status": "failed", "code": "source-unavailable-or-invalid"}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
