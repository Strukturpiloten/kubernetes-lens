#!/usr/bin/env python3
"""Regression tests for independent source facts and effective frozen admission."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('contract', ROOT / 'scripts/compatibility-ledger.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(contract.LEDGER.read_text())
        cls.witnesses = json.loads((contract.LEDGER.parent / 'kubernetes-schema-witnesses.json').read_text())
        cls.scenarios = json.loads((ROOT / cls.ledger['native_scenario_file']).read_text())

    def settings(self, **changes):
        return {**contract.default_settings(self.ledger), **changes}

    def evaluate(self, definition, name, target, value=None, context=None, **changes):
        return contract.evaluate_member(self.ledger, definition, name, target, self.settings(**changes), value, context)

    def root_evaluate(self, kind, api, pointer, target, value=None, **changes):
        return contract.evaluate_root(self.ledger, kind, api, pointer, target, self.settings(**changes), value)

    def test_current_frozen_contract_has_no_native_success(self):
        self.assertEqual(contract.validate(self.ledger, self.witnesses, self.scenarios), [])
        self.assertEqual(self.ledger['frozen_scope']['claimable_supported_minors'], [])

    def test_numeric_floor_ceiling_and_malformed_minor(self):
        self.assertLess(contract.minor('1.9'), contract.minor('1.20'))
        self.assertGreater(contract.minor('1.100'), contract.minor('1.37'))
        for value in ['v1.20', '1.20.0', '2.20', '1.x']:
            with self.assertRaises(ValueError):
                contract.minor(value)
        for value in ['1.19', '1.38', '1.100']:
            self.assertEqual(contract.target_profile(self.ledger, value, self.settings()), 'invalid-target-profile')

    def test_profile_requires_exact_explicit_feature_settings(self):
        self.assertEqual(contract.target_profile(self.ledger, '1.20', {}), 'invalid-target-profile')
        self.assertEqual(contract.target_profile(self.ledger, '1.20', self.settings(UnknownGate='enabled')), 'invalid-target-profile')
        self.assertEqual(contract.target_profile(self.ledger, '1.20', self.settings(SidecarContainers='enabled')), 'invalid-target-profile')
        self.assertEqual(contract.target_profile(self.ledger, '1.30', self.settings()), 'valid')

    def test_removed_apis_are_not_inferred_from_current_schema_or_relabeled(self):
        settings = self.settings()
        for kind, api, target in [('PodSecurityPolicy', 'policy/v1beta1', '1.25'), ('CronJob', 'batch/v1beta1', '1.25'), ('Ingress', 'networking.k8s.io/v1beta1', '1.22'), ('HorizontalPodAutoscaler', 'autoscaling/v2beta2', '1.26')]:
            self.assertEqual(contract.evaluate_root(self.ledger, kind, api, '/metadata/name', target, settings), 'unavailable-api')
        self.assertEqual(contract.evaluate_root(self.ledger, 'CronJob', 'batch/v1', '/metadata/name', '1.20', settings), 'unavailable-api')

    def test_unknown_descendant_does_not_gain_prefix_or_helper_admission(self):
        self.assertEqual(contract.evaluate_root(self.ledger, 'Pod', 'v1', '/spec/containers/0/futureField', '1.37', self.settings()), 'unadmitted-field')
        self.assertEqual(self.evaluate('io.k8s.api.core.v1.Container', 'futureField', '1.37'), 'unadmitted-field')
        self.assertEqual(contract.evaluate_root(self.ledger, 'FutureKind', 'v1', '/metadata/name', '1.37', self.settings()), 'unknown-kind')

    def test_sidecar_stage_default_explicit_setting_and_context(self):
        d = 'io.k8s.api.core.v1.Container'
        ctx = {'container_role': 'initContainers', 'workload': 'Deployment'}
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.27', 'Always', ctx), 'unavailable-field')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.28', 'Always', ctx), 'unadmitted-field')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.28', 'Always', ctx, SidecarContainers='enabled'), 'selected_expected_pending')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.29', 'Always', ctx), 'selected_expected_pending')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.29', 'Always', ctx, SidecarContainers='disabled'), 'unadmitted-field')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.29', 'Always', {'container_role': 'containers'}), 'native-field-invalid')
        self.assertEqual(self.evaluate(d, 'restartPolicy', '1.29', 'Never', ctx), 'unadmitted-field')

    def test_sidecar_pod_and_job_restrictions_propagate_to_all_templates(self):
        self.assertEqual(self.ledger['template_context_bindings']['PodSpec'], contract.POD_CONTEXTS)
        for workload in contract.POD_CONTEXTS:
            ctx = {'container_role': 'initContainers', 'workload': workload}
            self.assertEqual(self.evaluate('io.k8s.api.core.v1.Container', 'restartPolicy', '1.29', 'Always', ctx), 'selected_expected_pending')
        for workload in ['Job', 'CronJob']:
            self.assertEqual(self.evaluate('io.k8s.api.core.v1.PodSpec', 'restartPolicy', '1.37', 'Always', {'workload': workload}), 'native-field-invalid')

    def test_pvc_retention_has_explicit_beta_and_stable_rules(self):
        d = 'StatefulSet'
        self.assertEqual(self.root_evaluate(d, 'apps/v1', '/spec/persistentVolumeClaimRetentionPolicy', '1.23'), 'unadmitted-field')
        self.assertEqual(self.root_evaluate(d, 'apps/v1', '/spec/persistentVolumeClaimRetentionPolicy', '1.23', StatefulSetAutoDeletePVC='enabled'), 'selected_expected_pending')
        self.assertEqual(self.root_evaluate(d, 'apps/v1', '/spec/persistentVolumeClaimRetentionPolicy', '1.27'), 'selected_expected_pending')
        self.assertEqual(self.root_evaluate(d, 'apps/v1', '/spec/persistentVolumeClaimRetentionPolicy', '1.27', StatefulSetAutoDeletePVC='disabled'), 'unadmitted-field')
        self.assertEqual(self.root_evaluate(d, 'apps/v1', '/spec/persistentVolumeClaimRetentionPolicy', '1.32'), 'selected_expected_pending')

    def test_daemon_surge_preserves_pre_ga_and_admits_stable(self):
        d = 'io.k8s.api.apps.v1.RollingUpdateDaemonSet'
        self.assertEqual(self.evaluate(d, 'maxSurge', '1.21', DaemonSetUpdateSurge='enabled'), 'unadmitted-field')
        self.assertEqual(self.evaluate(d, 'maxSurge', '1.24'), 'unadmitted-field')
        self.assertEqual(self.evaluate(d, 'maxSurge', '1.25'), 'selected_expected_pending')
        self.assertEqual(self.evaluate(d, 'maxSurge', '1.37'), 'selected_expected_pending')
        self.assertEqual(self.evaluate(d, 'maxSurge', '1.37', DaemonSetUpdateSurge='disabled'), 'invalid-target-profile')

    def test_generic_ephemeral_and_proc_mount_differ_by_value_and_context(self):
        self.assertEqual(self.evaluate('io.k8s.api.core.v1.Volume', 'ephemeral', '1.20', GenericEphemeralVolume='enabled'), 'unadmitted-field')
        self.assertEqual(self.evaluate('io.k8s.api.core.v1.Volume', 'ephemeral', '1.23'), 'selected_expected_pending')
        for target in ['1.20', '1.31', '1.33', '1.36']:
            self.assertEqual(self.evaluate('io.k8s.api.core.v1.SecurityContext', 'procMount', target, 'Default'), 'selected_expected_pending')
            self.assertEqual(self.evaluate('io.k8s.api.core.v1.SecurityContext', 'procMount', target, 'Unmasked'), 'unadmitted-field')
        source = next(g for g in self.ledger['feature_gate_sources'] if g['gate'] == 'ProcMountType')
        self.assertFalse(contract.documented_gate(source, '1.31')['defaultValue'])
        self.assertTrue(contract.documented_gate(source, '1.33')['defaultValue'])

    def test_hpa_metric_and_zero_replica_value_branches(self):
        d = 'io.k8s.api.autoscaling.v2.MetricSpec'
        self.assertEqual(self.evaluate(d, 'type', '1.23', 'Resource'), 'selected_expected_pending')
        self.assertEqual(self.evaluate(d, 'type', '1.23', 'ContainerResource'), 'unadmitted-field')
        self.assertEqual(self.evaluate(d, 'type', '1.30', 'ContainerResource'), 'selected_expected_pending')
        hpa = 'HorizontalPodAutoscaler'
        self.assertEqual(self.root_evaluate(hpa, 'autoscaling/v2', '/spec/minReplicas', '1.37', 1), 'selected_expected_pending')
        self.assertEqual(self.root_evaluate(hpa, 'autoscaling/v2', '/spec/minReplicas', '1.37', 0), 'unadmitted-field')
        self.assertEqual(self.root_evaluate(hpa, 'autoscaling/v2', '/spec/minReplicas', '1.37', 0, HPAScaleToZero='enabled'), 'unadmitted-field')

    def test_native_positive_artifacts_reject_gvk_and_body_mismatches(self):
        hpa = next(scenario for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == 'HorizontalPodAutoscaler')
        wrong_hpa = copy.deepcopy(hpa['positive_document'])
        wrong_hpa['apiVersion'] = 'autoscaling/v1'
        self.assertTrue(any('/spec/metrics' in error for error in contract.scenario_shape_errors(self.ledger, 'HorizontalPodAutoscaler', 'autoscaling/v1', wrong_hpa)))
        ingress = next(scenario for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == 'Ingress')
        wrong_ingress = copy.deepcopy(ingress['positive_document'])
        wrong_ingress['apiVersion'] = 'extensions/v1beta1'
        self.assertTrue(any('/backend/service' in error for error in contract.scenario_shape_errors(self.ledger, 'Ingress', 'extensions/v1beta1', wrong_ingress)))
        for artifact in hpa['api_documents'] + ingress['api_documents']:
            self.assertEqual(contract.scenario_shape_errors(self.ledger, artifact['positive_document']['kind'], artifact['api_version'], artifact['positive_document']), [])

    def test_referenced_fixture_objects_require_shapes_and_required_members(self):
        pod = next(scenario['positive_document'] for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == 'Pod')
        for mutation in ['scalar_spec', 'missing_containers', 'missing_name']:
            changed = copy.deepcopy(pod)
            if mutation == 'scalar_spec':
                changed['spec'] = 42
            elif mutation == 'missing_containers':
                changed['spec'].pop('containers')
            else:
                changed['spec']['containers'][0].pop('name')
            self.assertTrue(contract.scenario_shape_errors(self.ledger, 'Pod', 'v1', changed))
        pvc = next(scenario['positive_document'] for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == 'PersistentVolumeClaim')
        changed = copy.deepcopy(pvc)
        changed['spec']['resources']['requests']['storage'] = False
        self.assertTrue(contract.scenario_shape_errors(self.ledger, 'PersistentVolumeClaim', 'v1', changed))

    def test_root_required_fields_and_empty_unknown_maps_are_rejected(self):
        for kind, required in [('RuntimeClass', 'handler'), ('PriorityClass', 'value'), ('RoleBinding', 'roleRef'), ('EndpointSlice', 'addressType'), ('EndpointSlice', 'endpoints')]:
            original = next(scenario['positive_document'] for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == kind)
            changed = copy.deepcopy(original)
            changed.pop(required)
            self.assertTrue(any('required root field' in error for error in contract.scenario_shape_errors(self.ledger, kind, changed['apiVersion'], changed)))
        pod = copy.deepcopy(next(scenario['positive_document'] for scenario in self.scenarios['kind_scenarios'] if scenario['kind'] == 'Pod'))
        pod['future'] = {}
        self.assertTrue(any('unknown root prefix' in error for error in contract.scenario_shape_errors(self.ledger, 'Pod', 'v1', pod)))

    def test_exact_command_flag_classification_tool_and_graph_mutations_fail(self):
        mutations = [('helm-local-template', '--enable-dns'), ('helm-local-template', '--dry-run=server'), ('helm-local-template', '--post-renderer=/tmp/x'), ('kustomize-build', '--enable-exec'), ('kustomize-build', '--enable-alpha-plugins'), ('kustomize-build', '--load-restrictor=LoadRestrictionsNone')]
        for cid, flag in mutations:
            changed = copy.deepcopy(self.ledger)
            command = next(c for c in changed['command_catalogue'] if c['id'] == cid)
            command['literal_argv'].append(flag)
            errors = contract.validate(changed, self.witnesses, self.scenarios)
            self.assertTrue(any('exact frozen argv' in error for error in errors))
            self.assertTrue(any('unsafe offline' in error or 'forbidden command flag' in error for error in errors))
        changed = copy.deepcopy(self.ledger)
        next(c for c in changed['command_catalogue'] if c['id'] == 'helm-local-template')['literal_argv'] = ['kubectl', 'apply', '-f', 'input.yaml']
        changed['graph_relationships'] = {}
        changed['tool_profiles'][0]['sha256'] = '0' * 64
        errors = contract.validate(changed, self.witnesses, self.scenarios)
        for required in ['product mutation forbidden', 'graph relationship', 'tool provenance/integrity']:
            self.assertTrue(any(required in error for error in errors))
        self.assertTrue(contract.flag_present(['helm', '--dry-run', 'server'], '--dry-run=server'))
        self.assertFalse(contract.flag_present(['helm', '--dry-run=client'], '--dry-run=server'))

    def test_served_gvk_and_shape_corruption_are_rejected(self):
        changed = copy.deepcopy(self.ledger)
        changed['resources'][0]['observed_gvk_inventory'][0]['schema_operation_ranges'][0]['through'] = '1.36'
        self.assertTrue(any('GVK defined/served' in error for error in contract.validate(changed, self.witnesses, self.scenarios)))
        changed = copy.deepcopy(self.ledger)
        changed['resources'][0]['proposed_admitted_api_profiles'][0]['typed_field_pointers'][0]['schema_forms'][0]['schema_shape'] = {'type': 'integer'}
        self.assertTrue(any('shape witness mismatch' in error for error in contract.validate(changed, self.witnesses, self.scenarios)))

    def test_requiredness_is_independent_of_property_shape(self):
        changed = copy.deepcopy(self.ledger)
        field = changed['resources'][0]['proposed_admitted_api_profiles'][0]['typed_field_pointers'][0]
        field['schema_required_profile_ids'] = list(field['schema_forms'][0]['source_schema_ids'])
        self.assertTrue(any('requiredness mismatch' in error for error in contract.validate(changed, self.witnesses, self.scenarios)))

    def test_per_field_profile_evidence_cannot_be_replaced_by_generic_kind_case(self):
        changed = copy.deepcopy(self.ledger)
        case = next(case for case in changed['evidence_cases'] if 'coverage_dimensions' in case)
        case['coverage_dimensions']['schema_profile_ids'].pop()
        self.assertTrue(any('exact field/profile coverage' in error for error in contract.validate(changed, self.witnesses, self.scenarios)))

    def test_command_matrix_cannot_skip_old_tool_generated_artifact_or_upgrade(self):
        for predicate in [lambda c: c['tool_profile_id'] == 'helm-3.22.0' and c['mode'] == 'upgrade', lambda c: c['command_id'] == 'kubectl-kustomize' and c['artifact'] == 'generated']:
            changed = copy.deepcopy(self.ledger)
            row = next(c for c in changed['command_evidence_cases'] if predicate(c))
            changed['command_evidence_cases'].remove(row)
            self.assertTrue(any('Cartesian coverage' in error for error in contract.validate(changed, self.witnesses, self.scenarios)))

    def test_gate_defaults_hash_and_native_success_claims_are_rejected(self):
        changed = copy.deepcopy(self.ledger)
        changed['feature_gate_sources'][0]['documented_stages'][0]['defaultValue'] = True
        changed['frozen_scope']['claimable_supported_minors'] = ['1.37']
        errors = contract.validate(changed, self.witnesses, self.scenarios)
        self.assertTrue(any('source stages/defaults' in error for error in errors))
        self.assertTrue(any('cannot claim native support' in error for error in errors))

    def test_exhaustive_gate_cases_cannot_skip_disabled_or_invalid_context(self):
        cases = json.loads((ROOT / self.ledger['gate_case_file']).read_text())
        self.assertEqual(contract.validate_gate_cases(self.ledger, cases), [])
        removed = copy.deepcopy(cases)
        removed['cases'].pop()
        self.assertTrue(any('coverage' in error for error in contract.validate_gate_cases(self.ledger, removed)))
        changed = copy.deepcopy(cases)
        changed['cases'][0]['expected_outcome'] = 'native-success'
        self.assertTrue(any('admission expectation' in error for error in contract.validate_gate_cases(self.ledger, changed)))

    def test_optional_cache_reports_missing_or_corrupt_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = {**self.ledger, 'schema_profiles': self.ledger['schema_profiles'][:1]}
            self.assertTrue(contract.verify_schema_cache(sample, self.witnesses, Path(directory)))
            (Path(directory) / sample['schema_profiles'][0]['cache_filename']).write_text('{}')
            self.assertTrue(any('integrity mismatch' in error for error in contract.verify_schema_cache(sample, self.witnesses, Path(directory))))


if __name__ == '__main__':
    unittest.main()
