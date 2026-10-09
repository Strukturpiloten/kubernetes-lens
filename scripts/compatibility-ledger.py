#!/usr/bin/env python3
"""Offline checks and admission expectations for the frozen contract, not a native parser."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'schemas/capabilities/kubernetes-1.20-1.37.json'
KINDS = frozenset('Pod Deployment StatefulSet DaemonSet ReplicaSet ReplicationController Job CronJob Service Endpoints EndpointSlice Ingress IngressClass NetworkPolicy ConfigMap Secret PersistentVolumeClaim PersistentVolume StorageClass Namespace ServiceAccount Role RoleBinding ClusterRole ClusterRoleBinding HorizontalPodAutoscaler PodDisruptionBudget ResourceQuota LimitRange PriorityClass RuntimeClass PodSecurityPolicy CustomResourceDefinition MutatingWebhookConfiguration ValidatingWebhookConfiguration'.split())
CATEGORIES = {'positive', 'invalid', 'unavailable', 'version-boundary', 'deterministic-generation', 'privacy-reference'}
COMMAND_CATEGORIES = {'positive', 'invalid', 'unavailable', 'privacy', 'deterministic'}
POD_CONTEXTS = {'Pod': '/spec', 'Deployment': '/spec/template/spec', 'StatefulSet': '/spec/template/spec', 'DaemonSet': '/spec/template/spec', 'ReplicaSet': '/spec/template/spec', 'ReplicationController': '/spec/template/spec', 'Job': '/spec/template/spec', 'CronJob': '/spec/jobTemplate/spec/template/spec'}


def minor(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r'1\.[0-9]+', value):
        raise ValueError(f'invalid Kubernetes minor: {value!r}')
    return int(value.split('.')[1])


def clean_shape(value):
    if isinstance(value, dict):
        return {key: clean_shape(item) for key, item in value.items() if key != 'description'}
    if isinstance(value, list):
        return [clean_shape(item) for item in value]
    return value


def shape_digest(value) -> str:
    return hashlib.sha256(json.dumps(clean_shape(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def ranges_include(ranges, target):
    return any(minor(r['from']) <= minor(target) <= minor(r['through']) for r in ranges)


def parse_gate_stages(markdown):
    """Read the small upstream front-matter subset; never execute YAML/Hugo content."""
    stages = []
    current = None
    for line in markdown.splitlines():
        match = re.fullmatch(r'  - stage: (alpha|beta|stable)\s*', line)
        if match:
            current = {'stage': match.group(1)}
            stages.append(current)
        elif current:
            match = re.fullmatch(r'    (defaultValue|fromVersion|toVersion|locked):\s*(.*?)\s*', line)
            if match:
                key, value = match.groups()
                value = value.strip('"')
                current[key] = {'true': True, 'false': False}.get(value, value)
    return stages


def documented_gate(source, target):
    stages = source['documented_stages']
    for stage in stages:
        if minor(stage['fromVersion']) <= minor(target) and ('toVersion' not in stage or minor(target) <= minor(stage['toVersion'])):
            return stage
    stable = next((stage for stage in reversed(stages) if stage['stage'] == 'stable' and minor(stage['fromVersion']) <= minor(target)), None)
    if stable:
        return {**stable, 'configuration_removed': True}
    return None


def default_settings(ledger):
    return {gate: 'documented-default' for gate in ledger['target_profile_contract']['feature_gate_names']}


def target_profile(ledger, target, settings):
    if target not in ledger['target_profile_contract']['kubernetes_minors']:
        return 'invalid-target-profile'
    if set(settings) != set(ledger['target_profile_contract']['feature_gate_names']):
        return 'invalid-target-profile'
    for name, setting in settings.items():
        if setting not in ledger['target_profile_contract']['setting_values']:
            return 'invalid-target-profile'
        source = next(source for source in ledger['feature_gate_sources'] if source['gate'] == name)
        stage = documented_gate(source, target)
        if setting != 'documented-default' and (stage is None or stage['stage'] == 'stable'):
            return 'invalid-target-profile'
    return 'valid'


def evaluate_field(ledger, field, target, settings, value=None, context=None):
    """Return the contract's typed-selection expectation, without claiming implementation."""
    if target_profile(ledger, target, settings) != 'valid':
        return 'invalid-target-profile'
    if target not in field['admission_predicate']['target_minors']:
        return 'unavailable-field'
    if field['typed_admission'] == 'preserve_only':
        return 'unadmitted-field'
    context = context or {}
    rules = field.get('native_constraints', [])
    for rule in rules:
        if rule['rule'] == 'enum' and value is not None:
            values = value if isinstance(value, list) else [value]
            if any(item not in rule['values'] for item in values):
                return 'unadmitted-field'
        if rule['rule'] == 'init_container_only' and context.get('container_role') != 'initContainers':
            return 'native-field-invalid'
        if rule['rule'] == 'workload_restart_policy' and value is not None:
            if value not in rule.get(context.get('workload', 'Pod'), rule['Pod']):
                return 'native-field-invalid'
        if rule['rule'] == 'value_predicate' and rule.get('unmasked_from_1_30') and value == 'Unmasked' and minor(target) >= 30:
            return 'unadmitted-field'
        if rule['rule'] == 'integer_range' and value is not None:
            if not isinstance(value, int) or isinstance(value, bool) or not rule['minimum'] <= value <= rule['maximum']:
                return 'native-field-invalid'
    for rule in rules:
        if rule['rule'] not in ('feature_gate', 'value_predicate') or 'gate' not in rule:
            continue
        unconditional = rule.get('unconditional_values', [])
        if value in unconditional or ('unconditional_integer_minimum' in rule and isinstance(value, int) and value >= rule['unconditional_integer_minimum']):
            continue
        # Value predicates only gate their explicit branch, not ordinary values.
        if rule.get('gated_values') is not None and value is not None and value not in rule['gated_values']:
            continue
        source = next(source for source in ledger['feature_gate_sources'] if source['gate'] == rule['gate'])
        stage = documented_gate(source, target)
        if not stage:
            return 'unadmitted-field'
        setting = settings[rule['gate']]
        enabled = stage['defaultValue'] if setting == 'documented-default' else setting == 'enabled'
        if not enabled or (rule.get('selection', 'stable_only') == 'stable_only' and stage['stage'] != 'stable'):
            return 'unadmitted-field'
    return 'selected_expected_pending'


def member(ledger, definition, name):
    return ledger['typed_struct_inventory'].get(definition, {}).get('proposed_admitted_members', {}).get(name)


def evaluate_member(ledger, definition, name, target, settings, value=None, context=None):
    field = member(ledger, definition, name)
    if field is None:
        return 'unadmitted-field'
    return evaluate_field(ledger, field, target, settings, value, context)


def evaluate_root(ledger, kind, api_version, pointer, target, settings, value=None, context=None):
    if target_profile(ledger, target, settings) != 'valid':
        return 'invalid-target-profile'
    resource = next((r for r in ledger['resources'] if r['kind'] == kind), None)
    if not resource:
        return 'unknown-kind'
    api = next((a for a in resource['proposed_admitted_api_profiles'] if a['api_version'] == api_version), None)
    if api is None or not ranges_include(api['target_availability_ranges'], target):
        return 'unavailable-api'
    field = next((f for f in api['typed_field_pointers'] if f['pointer'] == pointer), None)
    if field is None:
        return 'unadmitted-field'
    return evaluate_field(ledger, field, target, settings, value, context)


def frozen_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def flag_present(argv, forbidden):
    name, separator, expected_value = forbidden.partition('=')
    for index, token in enumerate(argv):
        flag, equals, value = token.partition('=')
        if flag != name:
            continue
        if not separator:
            return True
        if not equals and index + 1 < len(argv):
            value = argv[index + 1]
        if value == expected_value:
            return True
    return False


def required_command_cells(command):
    cid = command['id']
    profiles = command['profile_ids'] or ['offline-documents']
    artifacts = ['generated'] if 'generated' in cid or 'server-acceptance' in cid else ['source', 'generated'] if 'kustomize' in cid or cid == 'documents' else ['source']
    modes = ['install', 'upgrade'] if 'template' in cid else ['default']
    return {(profile, artifact, mode, category) for profile in profiles for artifact in artifacts for mode in modes for category in COMMAND_CATEGORIES}


def scenario_shape_errors(ledger, kind, api, document):
    """Check synthetic artifacts against finite source/profile shapes, not native semantics."""
    errors = []
    resource = next(resource for resource in ledger['resources'] if resource['kind'] == kind)
    profile = next(profile for profile in resource['proposed_admitted_api_profiles'] if profile['api_version'] == api)
    target = profile['target_availability_ranges'][0]['from']
    sid = next(p['id'] for p in ledger['schema_profiles'] if p['minor'] == target)
    fields = {field['pointer']: field for field in profile['typed_field_pointers']}
    root_shape = next(form['schema_shape'] for form in profile['root_schema_forms'] if sid in form['source_schema_ids'])
    for required in root_shape.get('required', []):
        if required not in document:
            errors.append(f'scenario missing required root field {api} /{required}')
    def form(field):
        return next((item['schema_shape'] for item in field['schema_forms'] if sid in item['source_schema_ids']), None)
    def walk(value, shape, pointer):
        if shape is None:
            errors.append(f'scenario unavailable source shape {api} {pointer}'); return
        if '$ref' in shape:
            definition = shape['$ref'].split('/')[-1]
            definition_form = next((f['schema_shape'] for f in ledger['schema_definition_inventory'].get(definition, []) if sid in f['source_schema_ids']), None)
            if definition_form is None:
                errors.append(f'scenario unknown referenced definition {api} {pointer}'); return
            if definition_form.get('x-kubernetes-int-or-string') or definition_form.get('format') == 'int-or-string':
                if not isinstance(value, (str, int)) or isinstance(value, bool):
                    errors.append(f'scenario IntOrString shape {api} {pointer}')
                return
            if definition_form.get('type') != 'object':
                walk(value, definition_form, pointer); return
            if not isinstance(value, dict):
                errors.append(f'scenario referenced object shape {api} {pointer}'); return
            for required in definition_form.get('required', []):
                if required not in value:
                    errors.append(f'scenario missing required field {api} {pointer}/{required}')
            inventory = ledger['typed_struct_inventory'].get(definition)
            if inventory is None:
                errors.append(f'scenario unlisted helper definition {api} {pointer}'); return
            for name, child in value.items():
                field = inventory['proposed_admitted_members'].get(name)
                if field is None:
                    errors.append(f'scenario unknown helper member {api} {pointer}/{name}')
                else:
                    walk(child, form(field), pointer + '/' + name)
            return
        if shape.get('x-kubernetes-int-or-string'):
            if not isinstance(value, (str, int)) or isinstance(value, bool):
                errors.append(f'scenario IntOrString shape {api} {pointer}')
            return
        expected = shape.get('type')
        valid = {'string': isinstance(value, str), 'integer': isinstance(value, int) and not isinstance(value, bool), 'number': isinstance(value, (int, float)) and not isinstance(value, bool), 'boolean': isinstance(value, bool), 'array': isinstance(value, list), 'object': isinstance(value, dict)}
        if expected in valid and not valid[expected]:
            errors.append(f'scenario scalar/container shape {api} {pointer}'); return
        if isinstance(value, list) and 'items' in shape:
            for index, item in enumerate(value):
                walk(item, shape['items'], pointer + '/' + str(index))
        if isinstance(value, dict):
            for required in shape.get('required', []):
                if required not in value:
                    errors.append(f'scenario missing required field {api} {pointer}/{required}')
            for name, child in value.items():
                child_shape = shape.get('properties', {}).get(name, shape.get('additionalProperties'))
                if isinstance(child_shape, dict):
                    walk(child, child_shape, pointer + '/' + name)
                elif child_shape is not True:
                    errors.append(f'scenario unknown nested field {api} {pointer}/{name}')
    def root_walk(value, pointer):
        if pointer and pointer not in fields and not any(candidate.startswith(pointer + '/') for candidate in fields):
            errors.append(f'scenario unknown root prefix {api} {pointer}'); return
        if pointer in fields:
            walk(value, form(fields[pointer]), pointer); return
        if isinstance(value, dict):
            for name, child in value.items():
                if pointer == '' and name in ('apiVersion', 'kind'):
                    continue
                root_walk(child, pointer + '/' + name)
        else:
            errors.append(f'scenario unknown root field {api} {pointer}')
    root_walk(document, '')
    return errors


def validate(ledger, witnesses, scenarios):
    errors = []
    def need(condition, message):
        if not condition:
            errors.append(message)
    anchors = json.loads((LEDGER.parent / 'kubernetes-contract-anchors.json').read_text())
    need(frozen_digest(ledger['graph_relationships']) == anchors['graph_relationships'], 'frozen required graph relationship contract')
    need(frozen_digest(ledger['canonical_tool_owner']) == anchors['canonical_tool_owner'], 'one frozen immutable operational tool owner')
    for tool in ledger['tool_profiles']:
        need(frozen_digest(tool) == anchors['tools'].get(tool['id']), f'frozen tool provenance/integrity anchor {tool["id"]}')
    need({tool['id'] for tool in ledger['tool_profiles']} == set(anchors['tools']), 'exact frozen tool profile set')
    scope = ledger['frozen_scope']
    need(scope['minimum_minor'] == '1.20' and scope['maximum_minor'] == '1.37', 'frozen numerical ceiling/floor changed')
    need(scope['admitted_minors'] == [f'1.{n}' for n in range(20, 38)], 'minor enumeration mismatch')
    need(scope['claimable_supported_minors'] == [] and ledger['future_completion_gate']['current_native_passed_count'] == 0, 'frozen expectation cannot claim native support')
    kinds = [resource['kind'] for resource in ledger['resources']]
    need(len(kinds) == 35 and set(kinds) == KINDS, 'exactly 35 required unique kinds')
    need(ledger['template_context_bindings']['PodSpec'] == POD_CONTEXTS, 'PodSpec predicates must propagate through every workload template')
    need(ledger['template_context_bindings']['JobSpec'] == {'Job': '/spec', 'CronJob': '/spec/jobTemplate/spec'}, 'JobSpec predicates missing CronJob context')
    profiles = {profile['id']: profile for profile in ledger['schema_profiles']}
    observed = {profile['schema_id']: profile for profile in witnesses['profiles']}
    need(len(profiles) == len(observed) == 18 and set(profiles) == set(observed), 'exact schema profile coverage')
    for pid, profile in profiles.items():
        need(re.fullmatch('[a-f0-9]{40}', profile['resolved_commit']) is not None and profile['resolved_commit'] in profile['immutable_source_url'], f'immutable schema commit {pid}')
        need(profile['sha256'] == observed.get(pid, {}).get('source_sha256'), f'independent schema digest {pid}')
        need(profile['license'] == 'Apache-2.0' and profile['byte_size'] > 0, f'schema provenance/license {pid}')
    for definition, forms in ledger['schema_definition_inventory'].items():
        for form in forms:
            for pid in form['source_schema_ids']:
                need(observed[pid]['definition_shapes'].get(definition) == form['schema_shape'], f'independent definition shape/requiredness {pid} {definition}')
    cases = {case['id']: case for case in ledger['evidence_cases']}
    need(len(cases) == len(ledger['evidence_cases']) and all(case['state'] == 'pending' for case in cases.values()), 'native cases unique and pending')
    def field_check(field, pointers):
        ids = field['evidence_case_ids']
        need(len(ids) == 6 and {cid.rsplit('.', 1)[1] for cid in ids} == CATEGORIES, 'exact per-field evidence classes')
        need(field['typed_admission'] in ('selected_expected_pending', 'preserve_only'), 'unknown admission state')
        schema_ids = {pid for form in field['schema_forms'] for pid in form['source_schema_ids']}
        need(field['admission_predicate']['target_minors'] == sorted({profiles[pid]['minor'] for pid in schema_ids}, key=minor), 'field numeric presence/admission mismatch')
        required_profiles = {pid for pid in schema_ids if any(observed[pid]['required_properties'].get(pointer, False) for pointer in pointers)}
        need(set(field['schema_required_profile_ids']) == required_profiles, 'independent schema requiredness mismatch')
        for cid in ids:
            case = cases.get(cid)
            need(case is not None and bool(case.get('expected_outcome')), f'missing independent field case {cid}')
            if case:
                dimensions = case.get('coverage_dimensions', {})
                need(set(dimensions.get('schema_profile_ids', [])) == schema_ids and dimensions.get('field_selection') == field['typed_admission'], f'exact field/profile coverage {cid}')
        for form in field['schema_forms']:
            for pid in form['source_schema_ids']:
                hashes = observed[pid]['properties']
                need(any(hashes.get(pointer) == shape_digest(form['schema_shape']) for pointer in pointers), f'upstream shape witness mismatch {pid} {pointers[0]}')
        for constraint in field.get('native_constraints', []):
            need('rule' in constraint and constraint['rule'] != 'future-review', 'unresolved future predicate')
            if constraint['rule'] == 'feature_gate':
                need(constraint['gate'] in {source['gate'] for source in ledger['feature_gate_sources']}, 'missing immutable gate source')
                need(constraint['selection'] in ('stable_only', 'enabled_stage'), 'finite feature selection rule')
        if field['typed_admission'] == 'preserve_only':
            need(bool(field.get('preserve_only_reason')), 'excluded member needs actionable preserved finding')
    for resource in ledger['resources']:
        kind = resource['kind']
        for inventory in resource['observed_gvk_inventory']:
            gvk = inventory['api_version'] + '|' + kind
            for pid, profile in profiles.items():
                for key, witness_key in [('schema_definition_ranges', 'defined_gvks'), ('schema_operation_ranges', 'served_gvks')]:
                    need(ranges_include(inventory[key], profile['minor']) == (gvk in observed[pid][witness_key]), f'GVK defined/served mismatch {pid} {gvk} {key}')
        for api in resource['proposed_admitted_api_profiles']:
            inventory = next(x for x in resource['observed_gvk_inventory'] if x['api_version'] == api['api_version'])
            need(api['target_availability_ranges'] == inventory['schema_operation_ranges'], f'API serving boundaries {kind}')
            for form in api['root_schema_forms']:
                for pid in form['source_schema_ids']:
                    need(observed[pid]['definition_shapes'].get(form['definition']) == form['schema_shape'], 'source-backed resource root requiredness')
            pointers = [field['pointer'] for field in api['typed_field_pointers']]
            need(len(pointers) == len(set(pointers)) and all(pointer.startswith('/') and '*' not in pointer for pointer in pointers), f'finite unique root pointers {kind}')
            for field in api['typed_field_pointers']:
                field_check(field, [form['schema_pointer'] for form in field['schema_forms']])
    for definition, inventory in ledger['typed_struct_inventory'].items():
        for name, field in inventory['proposed_admitted_members'].items():
            field_check(field, [f'#/definitions/{definition}/properties/{name}'])
    gates = ledger['feature_gate_sources']
    need(len({g['gate'] for g in gates}) == len(gates), 'unique gate sources')
    need(set(ledger['target_profile_contract']['feature_gate_names']) == {g['gate'] for g in gates}, 'explicit finite TargetProfile settings')
    for gate in gates:
        data = gate['source_markdown'].encode()
        need(hashlib.sha256(data).hexdigest() == gate['sha256'] and len(data) == gate['byte_size'], f'gate source digest {gate["gate"]}')
        need(gate['documented_stages'] == parse_gate_stages(gate['source_markdown']), f'gate source stages/defaults {gate["gate"]}')
        need(gate['license'] == 'CC-BY-4.0' and gate['resolved_commit'] in gate['immutable_source_url'], f'gate source provenance {gate["gate"]}')
    for record in ledger['restriction_audit']:
        for observation in record['observations']:
            need(hashlib.sha256(observation['description'].encode()).hexdigest() == observation['description_sha256'], 'restriction source fingerprint')
    need(scenarios['native_success_count'] == 0, 'scenario is not native execution')
    native = scenarios['kind_scenarios']
    need(len(native) == 35 and {x['kind'] for x in native} == KINDS, 'independent native kind scenario coverage')
    for scenario in native:
        need(scenario['state'] == 'pending' and bool(scenario['invalid_expected']['reason']), 'concrete pending native scenario')
        need(scenario['invalid_expected']['diagnostic'] == 'native-field-invalid', 'invalid native scenario diagnostic')
        need(scenario['positive_document']['kind'] == scenario['kind'], 'independent scenario identity')
        errors.extend(scenario_shape_errors(ledger, scenario['kind'], scenario['positive_document']['apiVersion'], scenario['positive_document']))
        resource = next(resource for resource in ledger['resources'] if resource['kind'] == scenario['kind'])
        need({item['api_version'] for item in scenario['api_documents']} == {api['api_version'] for api in resource['proposed_admitted_api_profiles']}, 'exact native scenario API profile coverage')
        for artifact in scenario['api_documents']:
            need(artifact['positive_document']['apiVersion'] == artifact['api_version'], 'scenario API identity')
            errors.extend(scenario_shape_errors(ledger, scenario['kind'], artifact['api_version'], artifact['positive_document']))
        need(scenario['kind'] == 'Namespace' or not scenario['invalid_mutation']['pointer'].startswith('/metadata/'), 'kind behavior cannot be proved by generic metadata case')
    tools = {tool['id']: tool for tool in ledger['tool_profiles']}
    command_cases = {case['id']: case for case in ledger['command_evidence_cases']}
    need(len(command_cases) == len(ledger['command_evidence_cases']), 'unique command evidence cells')
    for command in ledger['command_catalogue']:
        cid = command['id']
        need(frozen_digest({key:command[key] for key in ('literal_argv', 'producer_execution_class', 'profile_ids', 'forbidden_flags')}) == anchors['commands'].get(cid), f'exact frozen argv/execution contract {cid}')
        need(set(command['profile_ids']) <= set(tools), f'command tool profile {cid}')
        rows = [case for case in command_cases.values() if case['command_id'] == cid]
        cells = {(case['tool_profile_id'], case['artifact'], case['mode'], case['category']) for case in rows}
        need(len(rows) == len(cells) and cells == required_command_cells(command), f'command/profile/artifact/mode Cartesian coverage {cid}')
        need(set(command['required_evidence_case_ids']) == {case['id'] for case in rows}, f'command exact case references {cid}')
        need(all(case['state'] == 'pending' and case['expected_outcome'] and case['fixture_id'] for case in rows), f'concrete pending command outcomes {cid}')
        bounds = command['execution_bounds']
        need(all(isinstance(bounds.get(key), int) and bounds[key] > 0 for key in ('timeout_seconds', 'stdout_limit_bytes', 'stderr_limit_bytes', 'memory_limit_bytes')), f'finite command bounds {cid}')
        argv = command['literal_argv'] or []
        for flag in command['forbidden_flags']:
            need(not flag_present(argv, flag), f'forbidden command flag {cid} {flag}')
        if command['producer_execution_class'] == 'explicit-offline-renderer':
            for flag in ['--validate', '--dependency-update', '--enable-helm', '--enable-alpha-plugins', '--enable-exec', '--enable-plugins', '--enable-dns', '--network', '--post-renderer', '--post-renderer-args', '--dry-run=server', '--load-restrictor=LoadRestrictionsNone']:
                need(not flag_present(argv, flag), f'unsafe offline flags {cid} {flag}')
            need(not (argv[:2] in [['kubectl', 'apply'], ['helm', 'install'], ['helm', 'upgrade']]), f'product mutation forbidden {cid}')
        if 'template' in cid:
            need('--dry-run=client' in argv and '--include-crds' in argv and '--kube-version' in argv, f'exact Helm client contract {cid}')
        if 'server-acceptance' in cid:
            need(command['producer_execution_class'] == 'external-owned-harness' and '--kubeconfig' in argv and '--context' in argv and '--dry-run=server' in argv, f'external-only explicit runtime {cid}')
            need(('--validate=true' if cid.startswith('legacy') else '--validate=strict') in argv, f'historical exact validation flags {cid}')
    return errors


def validate_gate_cases(ledger, specification):
    errors = []
    if specification['native_success_count'] != 0 or not specification['source_evidence_only']:
        errors.append('gate expectations cannot claim native success')
    cases = specification['cases']
    if len({case['id'] for case in cases}) != len(cases):
        errors.append('duplicate gate evidence ID')
    bindings = {binding['id']: binding for binding in ledger['feature_gate_bindings']}
    expected_cells = set()
    for binding in bindings.values():
        for target in ledger['target_profile_contract']['kubernetes_minors']:
            for setting in ledger['target_profile_contract']['setting_values']:
                for vi, value in enumerate(binding['variants']):
                    for ci, context in enumerate(binding['contexts']):
                        expected_cells.add(f"gate.{binding['id']}.{target}.{setting}.v{vi}.c{ci}")
    if {case['id'] for case in cases} != expected_cells:
        errors.append('exact gate/version/default/on/off/value/context coverage')
    for case in cases:
        binding = bindings.get(case['binding_id'])
        if binding is None:
            errors.append('unknown gate case binding'); continue
        source = next(source for source in ledger['feature_gate_sources'] if source['gate'] == binding['gate'])
        stage = documented_gate(source, case['target_minor'])
        if case['expected_stage'] != (stage['stage'] if stage else 'not-introduced') or case['expected_documented_default'] != (stage['defaultValue'] if stage else None):
            errors.append(f"independent gate stage/default expectation {case['id']}")
        settings = {**default_settings(ledger), binding['gate']: case['setting']}
        if 'definition' in binding:
            actual = evaluate_member(ledger, binding['definition'], binding['member'], case['target_minor'], settings, case['value'], case['context'])
        else:
            actual = evaluate_root(ledger, binding['kind'], binding['api_version'], binding['pointer'], case['target_minor'], settings, case['value'], case['context'])
        if case['expected_outcome'] != actual or case['state'] != 'pending':
            errors.append(f"effective gate admission expectation {case['id']}: {actual}")
    return errors


def verify_schema_cache(ledger, witnesses, directory):
    """Optional independent rederivation; the normal gate requires no network/cache."""
    errors = []
    for profile in ledger['schema_profiles']:
        source = directory / profile['cache_filename']
        try:
            data = source.read_bytes()
        except OSError as error:
            errors.append(str(error)); continue
        if len(data) != profile['byte_size'] or hashlib.sha256(data).hexdigest() != profile['sha256']:
            errors.append(f'full raw schema integrity mismatch: {source}'); continue
        raw = json.loads(data)
        witness = next(p for p in witnesses['profiles'] if p['schema_id'] == profile['id'])
        for definition, expected in witness['definition_shapes'].items():
            source_definition = raw.get('definitions', {}).get(definition, {})
            actual = {key: source_definition[key] for key in ('type', 'format', 'required', 'enum', 'x-kubernetes-int-or-string') if key in source_definition}
            if actual != expected:
                errors.append(f'raw definition shape mismatch {source} {definition}')
        for record in ledger['restriction_audit']:
            for observation in record['observations']:
                if observation['schema_id'] == profile['id']:
                    actual = raw.get('definitions', {}).get(record['definition'], {}).get('properties', {}).get(record['member'], {}).get('description')
                    if actual != observation['description']:
                        errors.append(f'raw description mismatch {source}')
        for pointer, expected in witness['properties'].items():
            _, _, definition, _, name = pointer.split('/')
            field = raw.get('definitions', {}).get(definition, {}).get('properties', {}).get(name)
            if (name in raw.get('definitions', {}).get(definition, {}).get('required', [])) != witness['required_properties'][pointer]:
                errors.append(f'raw requiredness mismatch {source} {pointer}')
            if field is None or shape_digest(field) != expected:
                errors.append(f'raw property mismatch {source} {pointer}')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-cache', type=Path)
    args = parser.parse_args()
    ledger = json.loads(LEDGER.read_text())
    witnesses = json.loads((LEDGER.parent / 'kubernetes-schema-witnesses.json').read_text())
    scenarios = json.loads((ROOT / ledger['native_scenario_file']).read_text())
    errors = validate(ledger, witnesses, scenarios)
    errors += validate_gate_cases(ledger, json.loads((ROOT / ledger['gate_case_file']).read_text()))
    if args.schema_cache:
        errors += verify_schema_cache(ledger, witnesses, args.schema_cache)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Frozen Kubernetes 1.20–1.37 contract checked: 35 kinds; native execution remains pending.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
