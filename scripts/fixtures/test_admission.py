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


if __name__ == "__main__":
    unittest.main()
