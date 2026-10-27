#!/usr/bin/env python3
"""Pure authored Helm fixture integrity/admission DATA; never execute a renderer.

The fixed companion and member set are review roots, not caller credentials.
Supplied maps cannot repin bytes or promote source preparation into native success.
No CLI, broker, renderer, downloader, subprocess or fallback is provided.
"""

import hashlib
import json
from pathlib import Path
import stat

from materialize import FixtureError, MAX_FILE, MAX_FILES, MAX_TOTAL, REPOSITORY, relative, require

COMPANION = "docs/evidence/helm-command-fixture-source-v1.json"
SOURCE = "fixtures/conformance/helm-local-template-source"
LEDGER = "schemas/capabilities/kubernetes-1.20-1.37.json"
LEDGER_SHA256 = "9095ab78099577b056cfb677c3211f8c0deae2c73931ad5307a06fdff41fa5d8"
RECORD_SHA256 = "90b45a1c4f1c0dd82338d1a1af3802670b2d4c88f472434cd0ca8aea6847423d"
LEDGER_CANONICAL_SHA256 = "9069b2b7b09d110c94cf1544c77fa3818505af84f74e6635252d19aa7b7e5acf"
MEMBERS = frozenset((
    "expected.json", "public-values.json", "chart/Chart.yaml", "chart/values.yaml",
    "chart/values.schema.json", "chart/templates/deployment.yaml",
    "chart/templates/service.yaml", "chart/templates/lifecycle.yaml", "chart/crds/widgets.yaml",
))
DIRECTORIES = frozenset(("chart", "chart/templates", "chart/crds"))
PROFILES = ("helm-3.22.0", "helm-4.3.0")
MODES = ("install", "upgrade")
PATCHES = ("1.20.15", "1.37.0")
APIS = ["example.org/v1", "example.org/v1/Widget"]
PROTECTED = {"classification": "protected-by-default", "argv": "values-file-path-only",
             "reports": "fixed-codes-only", "stdout_stderr": "private-until-explicit-access",
             "artifact_access": "explicit-caller-selection-required"}
CAPABILITIES = {"kubernetes_patch": list(PATCHES), "api_versions": APIS,
                "include_crds": True, "hook_policy": "retain with lifecycle findings"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    except (ValueError, TypeError):
        raise FixtureError("helm-source-type") from None


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "helm-source-json")
            value[key] = item
        return value
    def invalid_constant(_value):
        raise ValueError
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, TypeError, UnicodeError):
        raise FixtureError("helm-source-json") from None


def _load_source():
    """Read only this fixed trusted repository DATA closure; no acquisition plan.

    Links/special files and extra members refuse. This is not a hostile concurrent
    filesystem custody claim or a replacement for future immutable broker staging.
    """
    base = REPOSITORY / SOURCE
    require(stat.S_ISDIR(base.lstat().st_mode), "helm-source-file-type")
    files = {}
    for path in base.rglob("*"):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), "helm-source-file-type")
        if stat.S_ISDIR(mode):
            require(path.relative_to(base).as_posix() in DIRECTORIES, "helm-source-members")
            continue
        require(stat.S_ISREG(mode), "helm-source-file-type")
        name = relative(path.relative_to(base).as_posix())
        require(name in MEMBERS and len(files) < MAX_FILES, "helm-source-members")
        require(path.stat().st_size <= MAX_FILE, "file-budget")
        files[name] = path.read_bytes()
    raw = (REPOSITORY / LEDGER).read_bytes()
    require(digest(raw) == LEDGER_SHA256, "helm-source-ledger")
    return decode((REPOSITORY / COMPANION).read_bytes()), files, decode(raw)


def load_source():
    """Retain fixed public errors even for missing/unreadable repository DATA."""
    try:
        return _load_source()
    except OSError:
        raise FixtureError("helm-source-read") from None


def validate_source(record, files, ledger, selection):
    """Validate finite source input/expectations, returning safe pending counts only."""
    require(type(record) is dict and type(files) is dict and type(selection) is dict,
            "helm-source-type")
    require(record.get("phase") == "source-preparation"
            and record.get("state") == "authored-unexecuted-native-pending", "helm-source-phase")
    require(record.get("execution") == {"helm": "not-executed", "native": "pending", "api": "pending",
                                      "runtime": "pending", "complete_gate": "pending", "publication": False},
            "helm-source-phase")
    require(record.get("protected_values") == PROTECTED, "helm-source-protected")
    require(type(record.get("capabilities")) is dict
            and record["capabilities"].get("include_crds") is True
            and canonical(record["capabilities"]) == canonical(CAPABILITIES), "helm-source-capabilities")
    require(type(record.get("members")) is dict, "helm-source-type")
    for name, member in record["members"].items():
        relative(name)
        require(type(member) is dict and set(member) == {"bytes", "sha256"}
                and type(member["bytes"]) is int and 0 <= member["bytes"] <= MAX_FILE
                and type(member["sha256"]) is str and len(member["sha256"]) == 64
                and all(char in "0123456789abcdef" for char in member["sha256"]), "helm-source-type")
    for name in files:
        relative(name)
    require(set(files) == set(record["members"]) == MEMBERS, "helm-source-members")
    require(digest(canonical(record)) == RECORD_SHA256, "helm-source-record")
    require(type(ledger) is dict and digest(canonical(ledger)) == LEDGER_CANONICAL_SHA256,
            "helm-source-ledger")
    total = 0
    for name in sorted(MEMBERS):
        raw = files[name]
        require(type(raw) is bytes, "helm-source-type")
        total += len(raw)
        require(len(raw) <= MAX_FILE and total <= MAX_TOTAL, "file-budget")
        require({"bytes": len(raw), "sha256": digest(raw)} == record["members"][name], "helm-source-digest")
    require(set(selection) == {"phase", "profile", "fixture_id", "mode", "target_patch",
                               "api_versions", "include_crds", "hook_policy", "protected_values"},
            "helm-source-selection")
    require(selection["phase"] == "source-preparation", "helm-source-phase")
    require(type(selection["profile"]) is str and selection["profile"] in PROFILES, "helm-source-profile")
    require(type(selection["mode"]) is str and selection["mode"] in MODES, "helm-source-mode")
    mode = selection["mode"]
    require(selection["fixture_id"] == "helm-local-template.source." + mode, "helm-source-mode")
    require(type(selection["target_patch"]) is str and selection["target_patch"] in PATCHES,
            "helm-source-capabilities")
    require(type(selection["api_versions"]) is list and selection["api_versions"] == APIS
            and selection["include_crds"] is True
            and selection["hook_policy"] == "retain with lifecycle findings", "helm-source-capabilities")
    require(selection["protected_values"] == "explicit-access-required", "helm-source-protected")
    cells = [row for row in ledger["command_evidence_cases"]
             if row["command_id"] == "helm-local-template" and row["artifact"] == "source"
             and row["category"] == "positive"]
    require([row["id"] for row in cells] == record["cell_ids"] and len(cells) == 4,
            "helm-source-ledger")
    require(all(row["state"] == "pending" and row["fixture_state"] ==
                "pending immutable revision/digest/license under issue14"
                and row["explicit_capabilities"] == CAPABILITIES for row in cells), "helm-source-ledger")
    cell = next(row for row in cells if row["tool_profile_id"] == selection["profile"] and row["mode"] == mode)
    expectations = decode(files["expected.json"])
    require(expectations["all_native_tool_api_runtime_states"] == "pending"
            and len(expectations["cases"]) == 8, "helm-source-expectations")
    rows = [row for row in expectations["cases"] if row["cell_id"] == cell["id"]
            and row["target_patch"] == selection["target_patch"]]
    require(len(rows) == 1 and rows[0]["state"] == "authored-unexecuted", "helm-source-expectations")
    # Do not return resource/value payloads or a renderer invocation/capability.
    return {"status": "authored-source-native-pending", "files": len(files),
            "cells": len(cells), "expectation_cases": 8, "selected_resources": len(rows[0]["resources"])}
