#!/usr/bin/env python3
"""Independent admission-plan regressions, never renderer/native success evidence."""

import copy
import json
import unittest

import admission
import materialize


class AdmissionExpectationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = materialize.load_inventory()
        cls.ledger = json.loads((materialize.REPOSITORY / "schemas/capabilities/kubernetes-1.20-1.37.json").read_text())
        cls.original = json.loads((materialize.OFFICIAL / "expected.json").read_text())

    def setUp(self):
        self.expected = copy.deepcopy(self.original)
        self.plan = self.expected["renderer_admission"]
        self.host = self.plan["grafana_operator_host_users"]

    def check(self):
        return admission.validate_admission_expectations(self.inventory, self.expected, self.ledger)

    def fails(self, code):
        with self.assertRaisesRegex(materialize.FixtureError, "^" + code + "$"):
            self.check()

    def case(self, minor, gate, value=True):
        return next(case for case in self.host["cases"] if case["kubernetes_minor"] == minor
                    and case["gate_setting"] == gate and case["value"] is value)

    def test_official_plan_remains_pending_with_independent_closure_counts(self):
        self.assertEqual(self.check(), {"status": "source-reviewed-renderer-admission-native-pending",
                                      "kustomize_closures": 3, "host_users_expectation_cases": 36})
        cnpg, cluster, namespace = self.plan["kustomize_closures"]
        self.assertEqual((len(cnpg["files"]), cnpg["edge_count"]), (30, 29))
        self.assertEqual((len(cluster["files"]), cluster["edge_count"]), (11, 10))
        self.assertEqual((len(namespace["files"]), namespace["edge_count"]), (11, 10))
        self.assertEqual(cnpg["supplied_root"], "cloudnativepg/source/config")
        self.assertEqual(cnpg["relative_entrypoint"], "default")
        self.assertIn("cloudnativepg/source/config/crd/bases/postgresql.cnpg.io_clusters.yaml", cnpg["files"])
        self.assertIn("cloudnativepg/source/config/webhook/manifests.yaml", cnpg["files"])
        self.assertIn("grafana-operator/source/deploy/kustomize/base/role.yaml", cluster["files"])

    def test_independent_version_boundary_does_not_admit_either_boolean(self):
        for value in (True, False):
            before = self.case("1.32", "documented-default", value)
            after = self.case("1.33", "documented-default", value)
            self.assertEqual(before["source_condition_expectation"], "omitted")
            self.assertIsNone(before["expected"]["diagnostic_code"])
            self.assertEqual(after["source_condition_expectation"], "emitted")
            self.assertFalse(after["expected"]["typed_admitted"])
            self.assertEqual(after["expected"]["diagnostic_code"], "unadmitted-field")
            self.assertEqual(after["expected"]["desired_output"], "denied")
            self.assertEqual(after["expected"]["source_preserving_output"],
                             "explicit-preserve-source-with-findings-required")
        self.assertFalse(self.host["gate_documented_defaults"]["1.32"])
        self.assertTrue(self.host["gate_documented_defaults"]["1.33"])

    def test_enabled_disabled_and_stable_default_stay_unadmitted(self):
        for minor in ("1.33", "1.35"):
            for setting in ("documented-default", "enabled", "disabled"):
                for value in (True, False):
                    expected = self.case(minor, setting, value)["expected"]
                    self.assertTrue(expected["profile_valid"])
                    self.assertEqual(expected["diagnostic_code"], "unadmitted-field")
                    self.assertFalse(expected["typed_admitted"])
                    self.assertEqual(expected["desired_output"], "denied")
        for minor in ("1.36", "1.37"):
            for setting in ("enabled", "disabled"):
                for value in (True, False):
                    expected = self.case(minor, setting, value)["expected"]
                    self.assertFalse(expected["profile_valid"])
                    self.assertEqual(expected["diagnostic_code"], "invalid-target-profile")
                    self.assertEqual(expected["source_preserving_output"], "denied")
            self.assertEqual(self.case(minor, "documented-default")["expected"]["diagnostic_code"], "unadmitted-field")

    def test_public_value_plan_selects_true_without_claiming_admission(self):
        public = json.loads((materialize.OFFICIAL / "public-values.json").read_text())
        plan = public["projects"]["grafana-operator"]["chart_render_plan"]
        self.assertIs(plan["values"]["hostUsers"], True)
        self.assertEqual(plan["target_patch"], "1.37.0")
        self.assertEqual(plan["status"], "public-value-plan-unrendered-unadmitted")

    def test_source_presence_never_asserts_executed_success(self):
        self.plan["status"] = "renderer-native-api-passed"
        self.fails("invalid-admission-evidence-state")

    def test_incomplete_or_changed_local_closure_is_rejected(self):
        self.plan["kustomize_closures"][0]["files"].pop()
        self.fails("wrong-admission-closure")

    def test_root_and_loader_contract_mutations_fail(self):
        self.plan["kustomize_closures"][0]["supplied_root"] = "cloudnativepg/source/config/default"
        self.fails("wrong-admission-root")
        self.setUp()
        self.plan["kustomize_closures"][0]["load_restrictions"] = "LoadRestrictionsNone"
        self.fails("unadmitted-load-restrictions")

    def test_version_condition_mutation_cannot_claim_field_absence(self):
        self.case("1.33", "documented-default")["source_condition_expectation"] = "omitted"
        self.fails("wrong-host-users-source-expectation")

    def test_enabled_gate_cannot_promote_the_frozen_field(self):
        self.case("1.33", "enabled")["expected"]["typed_admitted"] = True
        self.fails("implicit-host-users-admission")

    def test_default_or_stable_gate_cannot_promote_the_frozen_field(self):
        self.case("1.37", "documented-default")["expected"]["typed_admitted"] = True
        self.fails("implicit-host-users-admission")

    def test_stable_gate_toggle_cannot_be_a_valid_profile(self):
        self.case("1.36", "enabled")["expected"]["profile_valid"] = True
        self.fails("implicit-host-users-admission")

    def test_diagnostic_is_structured_and_required(self):
        for field in ("source_location", "field_pointer", "actionable_remediation", "target_profile",
                      "protected_evidence_reference"):
            self.setUp()
            del self.host["diagnostic"][field]
            self.fails("incomplete-host-users-diagnostic")

    def test_preservation_needs_explicit_selection_and_a_finding(self):
        self.host["preservation_policy"]["selection"] = "automatic"
        self.fails("implicit-host-users-preservation")
        self.setUp()
        self.case("1.33", "enabled")["expected"]["diagnostic_code"] = None
        self.fails("wrong-host-users-diagnostic")
        self.setUp()
        self.case("1.33", "enabled")["expected"]["source_preserving_output"] = "allowed-by-default"
        self.fails("implicit-host-users-preservation")

    def test_desired_output_is_denied_without_selected_preservation(self):
        self.case("1.33", "disabled", False)["expected"]["desired_output"] = "allowed"
        self.fails("implicit-host-users-desired-output")

    def test_documented_default_cannot_be_changed_to_match_chart_emission(self):
        self.host["gate_documented_defaults"]["1.32"] = True
        self.fails("wrong-gate-default-expectation")

    def test_missing_or_duplicate_boundary_cases_fail(self):
        self.host["cases"].pop()
        self.fails("incomplete-host-users-cases")
        self.setUp()
        self.host["cases"].append(copy.deepcopy(self.host["cases"][0]))
        self.fails("duplicate-host-users-case")

    def test_whitelist_change_requires_a_separate_reviewed_contract(self):
        original = self.ledger
        ledger = dict(original)
        ledger["typed_struct_inventory"] = dict(original["typed_struct_inventory"])
        pod = dict(original["typed_struct_inventory"]["io.k8s.api.core.v1.PodSpec"])
        pod["proposed_admitted_members"] = dict(pod["proposed_admitted_members"], hostUsers={})
        ledger["typed_struct_inventory"]["io.k8s.api.core.v1.PodSpec"] = pod
        self.ledger = ledger
        self.fails("changed-host-users-admission")

    def test_changed_chart_member_cannot_reuse_source_witness(self):
        self.host["source_member"]["sha256"] = "0" * 64
        self.fails("wrong-host-users-source-witness")


class AuthoredHelmSourceTests(unittest.TestCase):
    """Original command fixture DATA controls; no Helm/product/native invocation."""

    @classmethod
    def setUpClass(cls):
        import helm_source_fixture
        cls.owner = helm_source_fixture
        cls.record, cls.files, cls.ledger = cls.owner.load_source()

    def setUp(self):
        self.selection = {"phase": "source-preparation", "profile": "helm-3.22.0",
                          "fixture_id": "helm-local-template.source.install", "mode": "install",
                          "target_patch": "1.20.15", "api_versions": ["example.org/v1", "example.org/v1/Widget"],
                          "include_crds": True, "hook_policy": "retain with lifecycle findings",
                          "protected_values": "explicit-access-required"}

    def check(self, record=None, files=None, ledger=None):
        return self.owner.validate_source(self.record if record is None else record,
                                         self.files if files is None else files,
                                         self.ledger if ledger is None else ledger, self.selection)

    def rejected(self, code, **changes):
        with self.assertRaisesRegex(materialize.FixtureError, "^" + code + "$"):
            self.check(**changes)

    def test_all_four_frozen_cells_and_two_patches_are_only_pending_data(self):
        for profile in self.owner.PROFILES:
            for mode in self.owner.MODES:
                for patch in self.owner.PATCHES:
                    with self.subTest(profile=profile, mode=mode, patch=patch):
                        self.selection.update(profile=profile, mode=mode, target_patch=patch,
                                              fixture_id="helm-local-template.source." + mode)
                        self.assertEqual(self.check(), {"status": "authored-source-native-pending", "files": 9,
                                                       "cells": 4, "expectation_cases": 8, "selected_resources": 4})
        expected = json.loads(self.files["expected.json"])
        self.assertEqual(len(expected["cases"]), 8)
        install = expected["cases"][0]["resources"]
        upgrade = expected["cases"][2]["resources"]
        self.assertEqual(install["deployment"]["fields"]["/spec/replicas"], 2)
        self.assertEqual(upgrade["deployment"]["fields"]["/spec/replicas"], 3)
        self.assertEqual(install["hook"]["fields"]["/metadata/annotations/helm.sh~1hook"], "pre-install")
        self.assertEqual(upgrade["hook"]["fields"]["/metadata/annotations/helm.sh~1hook"], "pre-upgrade")
        self.assertIn("offline-lookup-incomplete", expected["cases"][0]["required_plan_findings"])

    def test_missing_extra_and_colliding_members_refuse(self):
        for name in self.files:
            files = dict(self.files)
            del files[name]
            self.rejected("helm-source-members", files=files)
        for name in ("unexpected.yaml", "chart", "chart/templates/plugin.yaml"):
            self.rejected("helm-source-members", files={**self.files, name: b"---\n"})

    def test_unsafe_paths_never_become_closure_members(self):
        for name in ("../escape", "/absolute", "chart/../escape", "chart//alias", "chart\\alias",
                     "https://invalid.example/a", "chart/line\nvalue", "chart/./alias"):
            with self.subTest(path_kind=name.split("/")[0]):
                self.rejected("invalid-path", files={**self.files, name: b"secret-sentinel"})

    def test_each_changed_digest_and_caller_repin_refuses(self):
        for name, raw in self.files.items():
            with self.subTest(member=name):
                changed = {**self.files, name: raw[:-1] + b"X"}
                self.rejected("helm-source-digest", files=changed)
                record = copy.deepcopy(self.record)
                record["members"][name]["sha256"] = self.owner.digest(changed[name])
                self.rejected("helm-source-record", record=record, files=changed)

    def test_types_and_protected_data_do_not_leak_or_alias_booleans(self):
        self.rejected("helm-source-type", files={**self.files, "public-values.json": "secret-sentinel"})
        record = copy.deepcopy(self.record)
        record["members"]["public-values.json"]["bytes"] = True
        self.rejected("helm-source-type", record=record)
        record = copy.deepcopy(self.record)
        record["protected_values"]["classification"] = "public-unprotected"
        self.rejected("helm-source-protected", record=record)
        self.selection["protected_values"] = "automatic"
        self.rejected("helm-source-protected")
        self.selection["protected_values"] = "explicit-access-required"
        try:
            self.check(files={**self.files, "public-values.json": b"secret-sentinel"})
        except materialize.FixtureError as error:
            self.assertEqual(str(error), "helm-source-digest")
            self.assertNotIn("secret-sentinel", str(error))
        else:
            self.fail("changed protected fixture accepted")

    def test_phase_profile_mode_and_fixture_cannot_promote_or_substitute(self):
        for key, value, code in (("phase", "native-executed", "helm-source-phase"),
                                 ("profile", "helm-4.0.0", "helm-source-profile"),
                                 ("profile", True, "helm-source-profile"),
                                 ("mode", "rollback", "helm-source-mode"),
                                 ("mode", True, "helm-source-mode"),
                                 ("fixture_id", "helm-local-template.source.upgrade", "helm-source-mode")):
            self.setUp()
            self.selection[key] = value
            self.rejected(code)
        self.setUp()
        record = copy.deepcopy(self.record)
        record["execution"]["helm"] = "passed"
        self.rejected("helm-source-phase", record=record)
        self.selection["extra"] = True
        self.rejected("helm-source-selection")

    def test_explicit_capability_mismatches_are_not_silently_defaulted(self):
        for key, value in (("target_patch", "1.20.0"), ("target_patch", 1.37),
                           ("api_versions", []), ("api_versions", "example.org/v1"),
                           ("api_versions", ["example.org/v1/Widget", "example.org/v1"]),
                           ("api_versions", ["example.org/v1", "example.org/v1"]),
                           ("include_crds", False), ("include_crds", 1),
                           ("hook_policy", "drop")):
            self.setUp()
            self.selection[key] = value
            self.rejected("helm-source-capabilities")

    def test_immutable_ledger_and_expected_outcomes_cannot_be_relabelled(self):
        ledger = copy.deepcopy(self.ledger)
        next(row for row in ledger["command_evidence_cases"] if row["id"] == self.record["cell_ids"][0])["state"] = "passed"
        self.rejected("helm-source-ledger", ledger=ledger)
        expected = json.loads(self.files["expected.json"])
        expected["cases"][0]["resources"]["deployment"]["fields"]["/spec/replicas"] = True
        changed = {**self.files, "expected.json": json.dumps(expected).encode()}
        self.rejected("helm-source-digest", files=changed)

    def test_fixed_native_contract_import_has_no_bytecode_or_global_flag_side_effect(self):
        import os
        from pathlib import Path
        import shutil
        import subprocess
        import sys
        import tempfile
        code = ("import json,runpy,sys; before=sys.dont_write_bytecode; "
                "loaded=runpy.run_path(sys.argv[1]); native=loaded['native']; "
                "native.require(True,'unreachable'); "
                "print(json.dumps({'before':before,'after':sys.dont_write_bytecode,"
                "'module':native.__name__,'function_module':native.require.__module__,"
                "'metadata_matches':native.__spec__.name==native.__name__ and "
                "native.__spec__.origin==native.__file__==native.require.__code__.co_filename}))")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("custom_acceptance.py", "native_acceptance.py"):
                shutil.copyfile(Path(__file__).with_name(name), root / name)
            # Bytecode is deliberately enabled in this task-private child. -I
            # ignores the gate's Python environment, exposing the old loader write.
            result = subprocess.run([sys.executable, "-I", "-c", code, str(root / "custom_acceptance.py")],
                                    cwd=root, env={"PATH": os.defpath, "LANG": "C.UTF-8"},
                                    capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"before": False, "after": False,
                             "module": "original_native_acceptance", "function_module": "original_native_acceptance",
                             "metadata_matches": True})
            self.assertEqual(list(root.rglob("*.pyc")), [])

    def test_loader_refuses_links_and_missing_fixed_source_with_safe_codes(self):
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(self.owner, "REPOSITORY", root):
                with self.assertRaisesRegex(materialize.FixtureError, "^helm-source-read$"):
                    self.owner.load_source()
                source = root / self.owner.SOURCE
                source.mkdir(parents=True)
                extra = source / "unexpected-empty-directory"
                extra.mkdir()
                with self.assertRaisesRegex(materialize.FixtureError, "^helm-source-members$"):
                    self.owner.load_source()
                extra.rmdir()
                (source / "linked").symlink_to(root)
                with self.assertRaisesRegex(materialize.FixtureError, "^helm-source-file-type$"):
                    self.owner.load_source()


if __name__ == "__main__":
    unittest.main()
