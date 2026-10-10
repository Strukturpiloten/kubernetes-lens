#!/usr/bin/env python3
"""Regression tests for independent source facts and effective frozen admission."""
import copy
import hashlib
import re
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

    def test_load_balancer_class_requires_stable_admission_not_gate_presence(self):
        pointer = '/spec/loadBalancerClass'
        gate = 'ServiceLoadBalancerClass'
        for target in ('1.21', '1.22', '1.23'):
            for setting in ('documented-default', 'enabled', 'disabled'):
                self.assertEqual(self.root_evaluate('Service', 'v1', pointer, target,
                                                   'example.com/internal-vip', **{gate: setting}),
                                 'unadmitted-field')
        self.assertEqual(self.root_evaluate('Service', 'v1', pointer, '1.20'), 'unavailable-field')
        for number in range(24, 38):
            target = f'1.{number}'
            self.assertEqual(self.root_evaluate('Service', 'v1', pointer, target,
                                               'example.com/internal-vip'), 'selected_expected_pending')
            for setting in ('enabled', 'disabled'):
                self.assertEqual(self.root_evaluate('Service', 'v1', pointer, target,
                                                   'example.com/internal-vip', **{gate: setting}),
                                 'invalid-target-profile')
        source = next(s for s in self.ledger['feature_gate_sources'] if s['gate'] == gate)
        stage = contract.documented_gate(source, '1.26')
        self.assertEqual(stage['stage'], 'stable')
        self.assertEqual(stage['fromVersion'], '1.24')
        self.assertTrue(stage['configuration_removed'])

    def test_load_balancer_class_gate_evidence_detects_missing_constraint_or_binding(self):
        gate = 'ServiceLoadBalancerClass'
        cases = json.loads((ROOT / self.ledger['gate_case_file']).read_text())
        binding = next(b for b in self.ledger['feature_gate_bindings'] if b['gate'] == gate)
        self.assertEqual((binding['kind'], binding['api_version'], binding['pointer'], binding['selection']),
                         ('Service', 'v1', '/spec/loadBalancerClass', 'stable_only'))
        self.assertEqual(len([c for c in cases['cases'] if c['binding_id'] == binding['id']]), 54)
        changed = copy.deepcopy(self.ledger)
        changed['feature_gate_bindings'] = [b for b in changed['feature_gate_bindings'] if b['gate'] != gate]
        self.assertTrue(contract.validate_gate_cases(changed, cases))
        changed = copy.deepcopy(self.ledger)
        resource = next(r for r in changed['resources'] if r['kind'] == 'Service')
        api = next(a for a in resource['proposed_admitted_api_profiles'] if a['api_version'] == 'v1')
        field = next(f for f in api['typed_field_pointers'] if f['pointer'] == '/spec/loadBalancerClass')
        field['native_constraints'] = []
        self.assertTrue(contract.validate_gate_cases(changed, cases))

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



    @staticmethod
    def workload_current_code_errors(evidence):
        """Authenticate the current candidate without rewriting historical receipts."""
        errors = []
        expected_sources = {
            'schemas/capabilities/kubernetes-1.20-1.37.json',
            'src/capability.rs', 'src/generation.rs', 'src/graph.rs', 'src/model.rs',
            'src/processing.rs', 'src/registry.rs', 'src/resources/common.rs',
            'src/resources/common/native_helpers.rs', 'src/resources/common/native_time.rs',
            'src/resources/common/unknown_scopes_tests.rs', 'src/resources/common/workload_specs.rs',
            'src/resources/mod.rs', 'src/resources/workloads.rs', 'src/source.rs',
            'src/syntax.rs', 'src/value.rs', 'src/value/access_modes.rs',
            'src/value/exact_json_number.rs', 'src/value/protected_json.rs',
            'src/value/protected_json_tests.rs', 'tests/access_modes.rs',
            'tests/exact_json_number.rs', 'tests/foundation/core.rs', 'tests/foundation/graph.rs',
            'tests/foundation/root-status-role-evidence.json', 'tests/protected_json.rs',
            'tests/workloads.rs',
        } | {str(path.relative_to(ROOT)) for path in (ROOT / 'src/resources/workloads').glob('*.rs')}
        current = evidence.get('current_evaluation', {})
        bindings = current.get('source_sha256', {})
        if set(bindings) != expected_sources:
            errors.append('incomplete current workload source binding')
        for name, digest in bindings.items():
            if name not in expected_sources or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                errors.append('stale current workload source binding')
        if current.get('status') != 'source_bound_native_conformance_pending' or current.get('native_conformance') != 'pending':
            errors.append('unsupported current workload conformance claim')
        validation = evidence.get('current_evaluation_validation', {})
        if validation.get('status') != 'candidate_validation_receipts_required' or validation.get('native_conformance') != 'pending':
            errors.append('unsupported current workload validation claim')
        return errors

    def test_workload_current_evaluation_authenticates_current_source_separately_from_history(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/workload-code-evidence.json').read_text())
        self.assertEqual(self.workload_current_code_errors(evidence), [])

    def test_workload_current_evaluation_refuses_omitted_stale_or_fabricated_guards(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/workload-code-evidence.json').read_text())
        historical = {key: copy.deepcopy(evidence[key]) for key in ['source_sha256', 'local_run', 'prior_evaluations']}
        changed = copy.deepcopy(evidence)
        changed['current_evaluation']['source_sha256'].pop('src/graph.rs')
        self.assertIn('incomplete current workload source binding', self.workload_current_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['current_evaluation']['source_sha256']['src/graph.rs'] = '0' * 64
        self.assertIn('stale current workload source binding', self.workload_current_code_errors(changed))
        for section in ['current_evaluation', 'current_evaluation_validation']:
            changed = copy.deepcopy(evidence)
            changed[section]['native_conformance'] = 'passed'
            self.assertTrue(self.workload_current_code_errors(changed))
        self.assertEqual({key: evidence[key] for key in historical}, historical)

    def access_code_errors(self, evidence):
        errors = []
        if evidence.get('format') != 'local_access_code_evidence_v1' or evidence.get('issue') != 12:
            errors.append('access evidence identity')
        if evidence.get('status') != 'offline_code_obligations_only':
            errors.append('unsupported evidence status')
        expected_conformance = {
            'supported_kubernetes_versions': [], 'field_cases': 'pending',
            'native_kind_scenarios': 'pending', 'tool_commands': 'pending',
            'api_server': 'pending', 'runtime': 'pending',
        }
        if evidence.get('conformance') != expected_conformance:
            errors.append('fabricated native success')
        ledger_path = 'schemas/capabilities/kubernetes-1.20-1.37.json'
        if evidence.get('canonical_ledger') != {
            'path': ledger_path, 'sha256': hashlib.sha256((ROOT / ledger_path).read_bytes()).hexdigest(),
        }:
            errors.append('stale canonical ledger')
        expected_roots = []
        for i, resource in enumerate(self.ledger['resources']):
            if resource['cohort_issue'] != 12:
                continue
            for j, profile in enumerate(resource['proposed_admitted_api_profiles']):
                expected_roots.append({
                    'kind': resource['kind'], 'api_version': profile['api_version'],
                    'selected_field_catalogue_pointer': f'/resources/{i}/proposed_admitted_api_profiles/{j}',
                    'expected_availability_ranges': profile['target_availability_ranges'],
                    'code_registration': 'src/resources/access/roots.rs', 'native_case_status': 'pending',
                })
        if len(expected_roots) != 18 or evidence.get('roots') != expected_roots:
            errors.append('incomplete or unsupported access roots')
        expected_sources = {
            'src/capability.rs', 'src/generation.rs', 'src/graph.rs', 'src/model.rs', 'src/registry.rs',
            'src/resources/common.rs', 'src/resources/common/native_helpers.rs', 'src/resources/mod.rs',
            'src/resources/access.rs', 'src/value.rs', 'src/value/native_quantity.rs',
            'tests/access.rs', 'tests/access/native_rules.rs',
        } | {str(path.relative_to(ROOT)) for path in (ROOT / 'src/resources/access').glob('*.rs')}
        hashes = evidence.get('source_sha256', {})
        if set(hashes) != expected_sources:
            errors.append('incomplete source binding')
        for name, digest in hashes.items():
            if name not in expected_sources or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                errors.append('stale source binding')
        expected_tests = []
        for name, prefix in [('tests/access.rs', ''), ('tests/access/native_rules.rs', 'native_rules::')]:
            expected_tests.extend(prefix + case for case in re.findall(
                r'#\[test\]\s*fn (\w+)\(', (ROOT / name).read_text()))
        if len(expected_tests) != 46 or evidence.get('independent_access_tests') != expected_tests:
            errors.append('incomplete independent cases')
        checks = evidence.get('selected_native_checks', [])
        if len(checks) != 18 or len({check['id'] for check in checks}) != 18:
            errors.append('incomplete native check obligations')
        for check in checks:
            if check['test'] not in expected_tests or check['code'] not in expected_sources:
                errors.append('unbound native check')
        witness_path = 'docs/evidence/access-native-specification.json'
        if evidence.get('native_source_witnesses') != {
            'path': witness_path, 'sha256': hashlib.sha256((ROOT / witness_path).read_bytes()).hexdigest(),
        }:
            errors.append('stale native witness')
        witness = json.loads((ROOT / witness_path).read_text())
        if witness['evidence_kind'] != 'static-source-inspection-only' or witness['native_commands_run']:
            errors.append('unsupported witness claim')
        records = witness['records']
        if len(records) != 92 or len({record['id'] for record in records}) != 92:
            errors.append('incomplete native witnesses')
        for record in records:
            if not re.fullmatch(r'[0-9a-f]{64}', record['sha256']) or not record['license_url'].startswith('https://github.com/kubernetes/'):
                errors.append('invalid witness integrity or attribution')
        if not evidence.get('limitations'):
            errors.append('missing native limitations')
        return errors

    def test_access_code_evidence_binds_all_roots_cases_sources_and_pending_native_profiles(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/access-code-evidence.json').read_text())
        self.assertEqual(self.access_code_errors(evidence), [])

    def test_access_code_evidence_rejects_omissions_stale_sources_and_fabricated_success(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/access-code-evidence.json').read_text())
        for field in ['roots', 'independent_access_tests', 'selected_native_checks']:
            changed = copy.deepcopy(evidence)
            changed[field].pop()
            self.assertTrue(self.access_code_errors(changed), field)
        changed = copy.deepcopy(evidence)
        changed['source_sha256']['src/resources/access/quantity_rules.rs'] = '0' * 64
        self.assertIn('stale source binding', self.access_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['conformance']['api_server'] = 'passed'
        self.assertIn('fabricated native success', self.access_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['roots'][0]['native_case_status'] = 'passed'
        self.assertIn('incomplete or unsupported access roots', self.access_code_errors(changed))

    def networking_code_errors(self, evidence):
        errors = []
        expected_roots = []
        for i, resource in enumerate(self.ledger['resources']):
            if resource['cohort_issue'] != 10:
                continue
            for j, profile in enumerate(resource['proposed_admitted_api_profiles']):
                expected_roots.append({
                    'kind': resource['kind'], 'api_version': profile['api_version'],
                    'selected_field_catalogue_pointer': f'/resources/{i}/proposed_admitted_api_profiles/{j}',
                    'expected_availability_ranges': profile['target_availability_ranges'],
                    'code_registration': 'src/resources/networking.rs', 'native_case_status': 'pending',
                })
        if evidence.get('roots') != expected_roots or len({r['kind'] for r in expected_roots}) != 6:
            errors.append('incomplete or unsupported networking roots')
        expected_sources = {
            'src/capability.rs', 'src/generation.rs', 'src/graph.rs', 'src/model.rs',
            'src/registry.rs', 'src/resources/mod.rs', 'src/resources/common.rs',
            'src/resources/common/native_helpers.rs', 'src/value.rs',
            'src/resources/networking.rs', 'tests/networking.rs',
        } | {str(p.relative_to(ROOT)) for directory in ['src/resources/networking', 'tests/networking']
             for p in (ROOT / directory).rglob('*.rs')}
        sources = evidence.get('source_sha256', {})
        if set(sources) != expected_sources:
            errors.append('incomplete source binding')
        for name, digest in sources.items():
            if name not in expected_sources or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                errors.append('stale source binding')
        expected_cases = []
        for path in [ROOT / 'tests/networking.rs', *sorted((ROOT / 'tests/networking').rglob('*.rs'))]:
            prefix = '' if path.name == 'networking.rs' else path.stem + '::'
            expected_cases.extend(prefix + case for case in re.findall(r'#\[test\]\s*fn (\w+)\(', path.read_text()))
        if len(expected_cases) != 74 or evidence.get('independent_networking_tests') != expected_cases:
            errors.append('incomplete independent cases')
        canonical = evidence.get('canonical_ledger', {})
        if canonical.get('path') != str(contract.LEDGER.relative_to(ROOT)) or canonical.get('sha256') != hashlib.sha256(contract.LEDGER.read_bytes()).hexdigest():
            errors.append('stale canonical ledger')
        if evidence.get('status') != 'typed-native-static-code-present-native-profiles-pending':
            errors.append('invalid static status')
        if evidence.get('conformance') != {name: 'pending' for name in ['api_server', 'runtime', 'controller_cni', 'official_corpus', 'native_kind_profiles']}:
            errors.append('fabricated native success')
        if not evidence.get('limitations') or len(evidence.get('reviewed_correction_groups', [])) != 7:
            errors.append('missing reviewed scope or limitations')
        return errors

    def test_networking_code_evidence_binds_roots_sources_cases_and_pending_profiles(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/networking-code-evidence.json').read_text())
        self.assertEqual(self.networking_code_errors(evidence), [])

    def test_networking_code_evidence_rejects_missing_stale_and_fabricated_claims(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/networking-code-evidence.json').read_text())
        for field in ['roots', 'independent_networking_tests']:
            changed = copy.deepcopy(evidence)
            changed[field].pop()
            self.assertTrue(self.networking_code_errors(changed), field)
        changed = copy.deepcopy(evidence)
        changed['source_sha256']['src/resources/networking.rs'] = '0' * 64
        self.assertIn('stale source binding', self.networking_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['source_sha256'].pop('src/model.rs')
        self.assertIn('incomplete source binding', self.networking_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['conformance']['api_server'] = 'passed'
        self.assertIn('fabricated native success', self.networking_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['roots'][0]['native_case_status'] = 'passed'
        self.assertIn('incomplete or unsupported networking roots', self.networking_code_errors(changed))


    def storage_code_errors(self, evidence):
        errors = []
        expected_roots = []
        for i, resource in enumerate(self.ledger['resources']):
            if resource['cohort_issue'] != 11:
                continue
            for j, profile in enumerate(resource['proposed_admitted_api_profiles']):
                expected_roots.append({
                    'kind': resource['kind'], 'api_version': profile['api_version'],
                    'selected_field_catalogue_pointer': f'/resources/{i}/proposed_admitted_api_profiles/{j}',
                    'expected_availability_ranges': profile['target_availability_ranges'],
                    'code_registration': 'src/resources/configuration_storage.rs', 'native_case_status': 'pending',
                })
        if evidence.get('roots') != expected_roots or len({r['kind'] for r in expected_roots}) != 5:
            errors.append('incomplete or unsupported storage roots')
        expected_sources = {
            'src/capability.rs', 'src/generation.rs', 'src/graph.rs', 'src/model.rs',
            'src/registry.rs', 'src/resources/mod.rs', 'src/resources/common.rs',
            'src/resources/common/native_helpers.rs', 'src/value.rs',
            'src/resources/configuration_storage.rs', 'tests/configuration_storage.rs', 'tests/access_modes.rs',
        } | {str(p.relative_to(ROOT)) for directory in ['src/resources/configuration_storage', 'tests/configuration_storage']
             for p in (ROOT / directory).rglob('*.rs')}
        sources = evidence.get('source_sha256', {})
        if set(sources) != expected_sources:
            errors.append('incomplete source binding')
        for name, digest in sources.items():
            if name not in expected_sources or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
                errors.append('stale source binding')
        expected_cases = []
        for path in [ROOT / 'tests/configuration_storage.rs', *sorted((ROOT / 'tests/configuration_storage').rglob('*.rs'))]:
            prefix = '' if path.name == 'configuration_storage.rs' else path.stem + '::'
            expected_cases.extend(prefix + case for case in re.findall(r'#\[test\]\s*fn (\w+)\(', path.read_text()))
        if len(expected_cases) != 41 or evidence.get('independent_storage_tests') != expected_cases:
            errors.append('incomplete independent cases')
        canonical = evidence.get('canonical_ledger', {})
        if canonical.get('path') != str(contract.LEDGER.relative_to(ROOT)) or canonical.get('sha256') != hashlib.sha256(contract.LEDGER.read_bytes()).hexdigest():
            errors.append('stale canonical ledger')
        if evidence.get('status') != 'typed-native-static-code-present-native-profiles-pending':
            errors.append('invalid static status')
        if evidence.get('conformance') != {name: 'pending' for name in ['api_server', 'runtime', 'controller_driver', 'official_corpus', 'native_kind_profiles']}:
            errors.append('fabricated native success')
        witness_path = 'tests/configuration_storage/native-source-witnesses.json'
        witness = json.loads((ROOT / witness_path).read_text())
        if evidence.get('native_source_witnesses') != {'path': witness_path, 'sha256': hashlib.sha256((ROOT / witness_path).read_bytes()).hexdigest()}:
            errors.append('stale native witnesses')
        errors.extend(self.storage_witness_errors(witness))
        if not evidence.get('limitations') or len(evidence.get('reviewed_correction_groups', [])) != 5:
            errors.append('missing reviewed scope or limitations')
        return errors

    @staticmethod
    def storage_witness_errors(witness):
        errors = []
        if witness.get('evidence_kind') != 'static-source-inspection-only' or witness.get('native_commands_run') is not False:
            errors.append('unsupported witness claim')
        records = witness.get('records', [])
        if len(records) != 66 or witness.get('acquisition_record_count') != 66:
            errors.append('incomplete native witnesses')
        sources = {}
        for record in records:
            commit = record.get('commit', record.get('resolved_commit', ''))
            path = record.get('source_path', '')
            digest = record.get('sha256', '')
            size = record.get('byte_size')
            source_url = record.get('immutable_source_url', '')
            project = next((name for name in ['kubernetes', 'website'] if source_url ==
                            f'https://raw.githubusercontent.com/kubernetes/{name}/{commit}/{path}'), None)
            expected_license = 'CC-BY-4.0' if project == 'website' else 'Apache-2.0'
            valid = (re.fullmatch(r'[0-9a-f]{40}', commit) and
                     re.fullmatch(r'[0-9a-f]{64}', digest) and
                     isinstance(size, int) and not isinstance(size, bool) and size > 0 and
                     path and not path.startswith('/') and '..' not in path.split('/') and
                     project and record.get('license') == expected_license and
                     record.get('license_url') == f'https://github.com/kubernetes/{project}/blob/{commit}/LICENSE')
            receipt = record.get('acquisition_receipt_sha256')
            if receipt is not None and not re.fullmatch(r'[0-9a-f]{64}', receipt):
                valid = False
            if 'receipt_path' in record or not valid:
                errors.append('invalid witness integrity or attribution')
            key = (project, commit, path)
            integrity = (digest, size, record.get('license'), record.get('license_url'))
            if key in sources and sources[key] != integrity:
                errors.append('contradictory source acquisitions')
            sources[key] = integrity
        if len(sources) != 62 or witness.get('distinct_source_count') != 62:
            errors.append('incomplete distinct native sources')
        return errors

    def test_storage_code_evidence_binds_roots_sources_cases_and_pending_native_profiles(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/storage-code-evidence.json').read_text())
        self.assertEqual(self.storage_code_errors(evidence), [])

    def test_storage_code_evidence_rejects_missing_stale_and_fabricated_claims(self):
        evidence = json.loads((ROOT / 'schemas/capabilities/storage-code-evidence.json').read_text())
        for field in ['roots', 'independent_storage_tests']:
            changed = copy.deepcopy(evidence)
            changed[field].pop()
            self.assertTrue(self.storage_code_errors(changed), field)
        changed = copy.deepcopy(evidence)
        changed['source_sha256']['src/resources/configuration_storage.rs'] = '0' * 64
        self.assertIn('stale source binding', self.storage_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['source_sha256'].pop('src/model.rs')
        self.assertIn('incomplete source binding', self.storage_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['native_source_witnesses']['sha256'] = '0' * 64
        self.assertIn('stale native witnesses', self.storage_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['conformance']['api_server'] = 'passed'
        self.assertIn('fabricated native success', self.storage_code_errors(changed))
        changed = copy.deepcopy(evidence)
        changed['roots'][0]['native_case_status'] = 'passed'
        self.assertIn('incomplete or unsupported storage roots', self.storage_code_errors(changed))

    def test_storage_witnesses_authenticate_heterogeneous_and_repeated_acquisitions(self):
        witness = json.loads((ROOT / 'tests/configuration_storage/native-source-witnesses.json').read_text())
        self.assertEqual(self.storage_witness_errors(witness), [])
        self.assertTrue(any('id' not in record for record in witness['records']))
        changed = copy.deepcopy(witness)
        changed['records'].pop()
        self.assertIn('incomplete native witnesses', self.storage_witness_errors(changed))
        for field, value in [('sha256', 'invalid'), ('commit', 'main'),
                             ('license_url', 'https://github.com/kubernetes/kubernetes/blob/main/LICENSE'),
                             ('immutable_source_url', 'https://example.invalid/source'),
                             ('receipt_path', '/tmp/nonportable-research-receipt.json')]:
            changed = copy.deepcopy(witness)
            changed['records'][0][field] = value
            self.assertIn('invalid witness integrity or attribution', self.storage_witness_errors(changed), field)
        changed = copy.deepcopy(witness)
        first = changed['records'][0]
        repeated = next(record for record in changed['records'][1:]
                        if record.get('commit', record.get('resolved_commit')) == first['commit']
                        and record['source_path'] == first['source_path'])
        repeated['sha256'] = '0' * 64
        self.assertIn('contradictory source acquisitions', self.storage_witness_errors(changed))
        changed = copy.deepcopy(witness)
        changed['native_commands_run'] = True
        self.assertIn('unsupported witness claim', self.storage_witness_errors(changed))


if __name__ == '__main__':
    unittest.main()
