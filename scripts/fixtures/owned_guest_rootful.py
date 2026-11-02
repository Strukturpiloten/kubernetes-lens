"""Host-only contracts for one explicitly selected rootful kind smoke cohort.

Guest execution is Bash, never this module. No import starts a tool or VM.
"""
from dataclasses import dataclass
import math
import re
from pathlib import Path
import owned_qemu as vm

ROOT = '/var/lib/kubernetes-lens-rootful'
PREREQUISITE_INTENT = 'rootful-prerequisite-v1'
EXECUTION_INTENT = 'rootful-execution-v1'
# The fixed SSH dispatcher consumes caller text only as a case word. Neither
# branch interpolates it into executable text, argv or a diagnostic. Dispatch
# happens before env -i, which removes SSH_ORIGINAL_COMMAND and ambient state.
COMMAND = ("case ${SSH_ORIGINAL_COMMAND-} in "
           "rootful-prerequisite-v1) exec /usr/bin/sudo -n /usr/bin/env -i "
           "HOME=/root PATH=/usr/bin:/usr/sbin " + ROOT + "/receiver prerequisite-v1 ;; "
           "rootful-execution-v1) exec /usr/bin/sudo -n /usr/bin/env -i "
           "HOME=/root PATH=/usr/bin:/usr/sbin " + ROOT + "/receiver execution-v1 ;; "
           "*) exit 1 ;; esac")
GUARD_FUEL = (10, 3, 3, 3, 5)
GUARD_PREPAID = 24
UTILITY_WORK = 680
UTILITY_CLEANUP = 64
GUEST_NATIVE = 75
GUEST_OUTPUT = 1024 * 1024
HOST_ACTIONS = 8
PHASES = ('guest-info', 'stage-kind', 'stage-kubectl', 'stage-node-oci', 'rootful-kind')
RESOURCE_VALUES = {'cpus': 2, 'memory_mib': 8192, 'guest_memory_mib': 4096,
                   'pids': 256, 'disk_gib': 24, 'deadline_seconds': 1800,
                   'cleanup_seconds': 120}



# ADR0101: exact compatibility metadata, never an installer or runtime probe.
LIVE_RESOURCE_PROFILE = 'owned-vm-live-v1'
LIVE_FACTS_NAME = 'owned-live-resource-envelope-source-facts-v1.json'
LIVE_SCHEMA_NAME = 'owned-live-resource-envelope-source-facts-v1.schema.json'
LIVE_FACTS_SHA256 = '171aa78b13ac5e1a5b3863adab4f6b3dfd48a5877d2e06132bcb4a7a5c272106'
LIVE_SCHEMA_SHA256 = '927b21e524f846d598c258c105ac2b1f27f656c5b3b7d5be0533946cca1f3c91'


def admit_live_resource_profile(config):
    """Qualify only fixed source/VM/tool premises before any guest effects.

    The record documents relevant-source equivalence, not runtime/binary
    attestation or native qualification. Existing coherent OS/module/livepatch,
    allocator, managed-system-RAM and global preservation premises remain.
    """
    directory = Path(__file__).parent
    raw = vm.read(directory / LIVE_FACTS_NAME, 16384)
    schema_raw = vm.read(directory / LIVE_SCHEMA_NAME, 16384)
    vm.require(vm.digest(raw) == LIVE_FACTS_SHA256
               and vm.digest(schema_raw) == LIVE_SCHEMA_SHA256, 'rootful-live-facts-integrity')
    facts, schema = vm.strict_json(raw), vm.strict_json(schema_raw)
    vm.require(type(facts) is dict and type(schema) is dict and schema.get('const') == facts
               and set(facts) == set(schema.get('required', ()))
               and schema.get('additionalProperties') is False
               and facts.get('schema') == 'owned-live-resource-envelope-source-facts-v1'
               and facts.get('resource_profile') == LIVE_RESOURCE_PROFILE,
               'rootful-live-facts-schema')
    pin, _pin_sha = vm.pin_document()
    vm.require(facts['canonical_image'] == {'owner': 'scripts/kind-vm-image.json', **pin},
               'rootful-live-canonical-image')
    vm.require(type(config) is dict and type(config.get('tools')) is dict
               and type(config['tools'].get('qemu')) is dict, 'rootful-live-host-domain')
    domain = facts['domain']
    qemu = config['tools']['qemu']
    vm.require(type(config.get('guest_memory_mib')) is int
               and config['guest_memory_mib'] == domain['guest_memory_mib'] == 4096
               and domain['managed_system_ram_max_bytes'] == 2**32
               and domain['machine'] == 'q35,accel=kvm'
               and all(type(qemu.get(key)) is type(value) and qemu.get(key) == value for key, value in domain['qemu'].items()),
               'rootful-live-host-domain')
    proof = facts['theorem']
    vm.require(proof['minimum_unique_resident_managed_page_bytes'] == 4096
               and proof['fd_slots_per_owner_conservative'] == 2**28
               and proof['aggregate_upper'] == 2**48 < proof['original_strict_ceiling'] == 32767*9999999999
               and facts['qualification']['state'] == 'relevant-source-qualified',
               'rootful-live-proof-scope')
    return {'resource_profile': LIVE_RESOURCE_PROFILE, 'resource_facts_sha256': LIVE_FACTS_SHA256}

def admit_resources(args):
    vm.require(all(getattr(args, name) == value for name, value in RESOURCE_VALUES.items()),
               'rootful-fixed-resource-profile')


def reservation():
    return {'native': GUEST_NATIVE, 'output': GUEST_OUTPUT, 'utilities': 768,
            'utility_work': UTILITY_WORK, 'utility_cleanup': UTILITY_CLEANUP,
            'record_guards_prepaid': GUARD_PREPAID}


def consume_record_purpose(budget, purpose):
    """Consume the original serial purpose before pre-child checks or spawn."""
    vm.require(type(budget) is vm.Budget and hasattr(budget, '_rootful_record_purposes'),
               'rootful-record-guard-reservation')
    consumed = budget._rootful_record_purposes
    vm.require(type(consumed) is list and len(consumed) < len(PHASES)
               and purpose == PHASES[len(consumed)] and consumed == list(PHASES[:len(consumed)]),
               'rootful-record-purpose-replay')
    consumed.append(purpose)  # Never refunded, including pre-child or spawn failure.
    return GUARD_FUEL[len(consumed)-1]


def record_schedule(budget):
    consumed = getattr(budget, '_rootful_record_purposes', None)
    vm.require(type(consumed) is list and consumed == list(PHASES[:len(consumed)])
               and len(consumed) <= len(PHASES), 'rootful-record-schedule')
    return {'prepaid': GUARD_PREPAID, 'consumed_purposes': list(consumed),
            'comparisons_attempted': None}  # A failed guest may not report its count.


def reserve(budget):
    """Irrevocable delegation from the actual caller's original worker Budget."""
    vm.require(type(budget) is vm.Budget and not hasattr(budget, '_rootful_record_purposes')
               and budget.commands_left >= GUEST_NATIVE + HOST_ACTIONS
               and budget.output_left >= GUEST_OUTPUT, 'rootful-original-budget-fit')
    budget.remaining()
    budget.commands_left -= GUEST_NATIVE
    budget.charge(GUEST_OUTPUT)
    budget._rootful_record_purposes = []
    return reservation()


def request(owner, plan, budget, spec):
    # Floor at send, with one second transport allowance; host still owns the
    # authoritative original end and kills/reaps every producer and the VM.
    remaining = math.floor(budget.remaining()) - 1
    vm.require(0 < remaining <= 1680, 'rootful-request-original-work-end')
    vm.require(len(owner) == 32 and all(c in '0123456789abcdef' for c in owner)
               and vm.HEX.fullmatch(plan), 'rootful-request-binding')
    packet = f'rootful-kind-v1 {owner} {plan} {vm.digest(vm.encode(spec))} {remaining}\n'.encode('ascii')
    vm.require(len(packet) <= 4096, 'rootful-input-reservation')
    return packet


def ssh_arguments(config, *, execute=False):
    argv = vm.ssh_arguments(config)
    argv[-1] = EXECUTION_INTENT if execute else PREREQUISITE_INTENT
    if execute:
        argv.remove('-n')
    return argv


def guest_files(plan, evidence, receiver):
    """Source-owned read-only Ignition inputs; no network or executable input."""
    vm.require(plan.profile in ('legacy-1.20.15', 'modern-1.37.0'), 'rootful-profile')
    scenarios_path = vm.ROOT / 'schemas/capabilities/kubernetes-native-scenarios.json'
    raw = vm.read(scenarios_path, 4 * 1024**2)
    scenarios = vm.strict_json(raw)
    matches = [x for x in scenarios['kind_scenarios'] if x['kind'] == 'Deployment']
    vm.require(len(matches) == 1, 'rootful-source-fixture')
    fixture = vm.encode(matches[0]['positive_document']) + b'\n'
    vm.require(vm.strict_json(fixture)['metadata']['namespace'] == 'demo', 'rootful-source-namespace')
    for sha in (evidence['manifest_sha256'], evidence['config_sha256']):
        record = evidence['catalogue'].get('blobs/sha256/' + sha)
        vm.require(type(record) is dict and type(record.get('bytes')) is int
                   and 0 < record['bytes'] <= 16384, 'rootful-fixed-raw-metadata-budget')
    old = plan.profile == 'legacy-1.20.15'
    spec = {'schema': 'kubernetes-lens-owned-rootful-v13', 'owner': plan.owner,
            'resource_profile': LIVE_RESOURCE_PROFILE, 'resource_facts_sha256': LIVE_FACTS_SHA256,
            'plan_sha256': plan.sha256, 'profile': plan.profile,
            'kind_version': '0.14.0' if old else '0.33.0',
            'server_patch': '1.20.15' if old else '1.37.0',
            'kind_sha256': plan.files[0].sha256, 'kubectl_sha256': plan.files[1].sha256,
            'archive_sha256': plan.files[2].sha256,
            'manifest_sha256': evidence['manifest_sha256'], 'config_sha256': evidence['config_sha256'],
            'parent_sha256': evidence['parent_sha256'],
            'expanded_image_bytes': evidence['expanded_bytes_hashed'],
            'archive_bytes': evidence['archive_bytes'], 'stage_payload_bytes': sum(f.size for f in plan.files),
            'fixture_sha256': vm.digest(fixture), 'scenarios_sha256': vm.digest(raw),
            'native_work_max': 70, 'native_cleanup_max': 5,
            'utility_max': 768, 'utility_work_max': UTILITY_WORK,
            'utility_cleanup_max': UTILITY_CLEANUP, 'record_guards_prepaid': GUARD_PREPAID,
            'output_max': GUEST_OUTPUT}
    files = {ROOT + '/receiver': (receiver, 0o500), ROOT + '/spec.json': (vm.encode(spec), 0o400),
             ROOT + '/deployment.json': (fixture, 0o400)}
    # A source-owned wrapper name selects ONLY a closed provider argv grammar.
    files[ROOT + '/bin/podman'] = (("#!/usr/bin/bash\nexec " + ROOT + "/receiver provider \"$@\"\n").encode(), 0o500)
    checks = ''.join(vm.digest(data) + '  ' + path + '\n' for path, (data, _) in files.items())
    files[ROOT + '/checks.sha256'] = (checks.encode(), 0o400)
    return files, spec



LOG_ROLES = frozenset(('wrapper', 'child', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee'))
LOG_STATES = frozenset(('not-established', 'direct-wait-zero', 'retired-wait-and-signal-cause-unavailable'))
RESULT_V1 = 'kubernetes-lens-owned-rootful-result-v1'
RESULT_V2 = 'kubernetes-lens-owned-rootful-result-v2'
RESULT_V3 = 'kubernetes-lens-owned-rootful-result-v3'
RESULT_V4 = 'kubernetes-lens-owned-rootful-result-v4'
RESULT_V5 = 'kubernetes-lens-owned-rootful-result-v5'
RESULT_V6 = 'kubernetes-lens-owned-rootful-result-v6'
RESULT_V7 = 'kubernetes-lens-owned-rootful-result-v7'
RESULT_V8 = 'kubernetes-lens-owned-rootful-result-v8'
RESULT_V9 = 'kubernetes-lens-owned-rootful-result-v9'
RESULT_V10 = 'kubernetes-lens-owned-rootful-result-v10'
RESULT_V11 = 'kubernetes-lens-owned-rootful-result-v11'
RESULT_V12 = 'kubernetes-lens-owned-rootful-result-v12'
RESULT_V13 = 'kubernetes-lens-owned-rootful-result-v13'
V11_I_REASONS = frozenset('k3.i.' + str(r) + '.' + c for r in (1, 2) for c in 'pcnvr') | frozenset('k3.i.' + str(r) + '.x.' + str(n) for r in (1, 2) for n in range(1, 256) if n not in (64, 65, 66, 67))
I_ATOM_REASONS = frozenset('k2.i.' + str(r) + '.' + c for r in (1, 2) for c in 'pcnvr') | frozenset('k2.i.' + str(r) + '.e.' + str(n) for r in (1, 2) for n in range(1, 256) if n not in (64, 65, 66, 67))
K_SUBSTAGES = frozenset('k1.' + code for code in 'abcdefghijklmn')
K_NATIVE_SUBSTAGES = frozenset('k1.' + code for code in 'acehjm')
V12_K_SUBSTAGES = frozenset('k4.' + code for code in 'abcdefghijklmno')
V12_K_NATIVE_SUBSTAGES = frozenset('k4.' + code for code in 'acehjmo')
V12_I_REASONS = frozenset(reason.replace('k3.', 'k4.', 1) for reason in V11_I_REASONS)
POSTLOG_REASONS = frozenset(('block', 'filesystem', 'inv-drift', 'inv-empty', 'inv-fd-access', 'inv-fd-form', 'inv-fd-range', 'inv-nf-form', 'inv-nf-range', 'inv-pid-range', 'inv-proc-form', 'inv-proc-pid', 'inv-proc-read', 'inv-proc-task', 'inv-snap-size', 'inv-task-empty', 'inv-task-form', 'inv-task-read', 'inv-task-tid', 'inv-tid-count', 'mapper', 'memory', 'mount', 'mount-both', 'mount-proc', 'mount-root', 'namespace', 'nr-open-form', 'nr-open-range', 'pid-max', 'unlabelled'))
POSTLOG_FAILURES = frozenset('pl1.' + code for code in 'rifnje')
POSTNODE_FAILURES = frozenset(('pl2.a', 'pl2.b', 'pl2.c', 'pl2.d', 'pl2.g', 'pl2.h', 'pl2.k'))
LOG_ROLES_V4 = frozenset(('native', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee'))
POSTCREATE_GUARD_STATES = frozenset('pg1.' + code for code in 'abcdefghijklmnop')


@dataclass(frozen=True)
class LogPollFailure:
    """Cached guest-log DATA only; no liveness, signal or retirement authority."""
    reason: str
    role: str
    pid: int
    start: int
    last_observed_state: str | None
    iterations_completed: int
    last_sample_index: int | None
    deadline_fact: str


def _poll_parts(state, *, version):
    if type(state) is not str or not state.startswith('pg2.'):
        return None
    vm.require(version in (RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) and len(state) <= 46 and state.isascii(),
               'rootful-poll-code')
    roles = 'native|out|err|out-dd|out-tee|err-dd|err-tee' if version in (RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) else 'wrapper|child|out|err|out-dd|out-tee|err-dd|err-tee'
    matched = re.fullmatch(r'pg2\.([gp])\.('+roles+r')'
                          r'\.([RSDZTtXIu])\.(0|[1-9][0-9]{0,3})'
                          r'\.([1-9][0-9]{0,4})\.([1-9][0-9]{0,18})', state)
    vm.require(matched is not None, 'rootful-poll-code')
    cause, role, observed, count, pid, start = matched.groups()
    count, pid, start = int(count), int(pid), int(start)
    vm.require(0 < pid < 32768 and 0 < start < 2**63 - 1
               and (count == 4096 if cause == 'g' else count <= 4095)
               and (count != 0 or observed == 'u'), 'rootful-poll-range')
    return cause, role, observed, count, pid, start


def _postcreate_guard_state(state, *, version):
    poll = _poll_parts(state, version=version)
    return poll is not None or (type(state) is str and version in (RESULT_V2, RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13)
                                and state in POSTCREATE_GUARD_STATES
                                and (version not in (RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) or state != 'pg1.n'))


def _logs_unestablished(state, *, version):
    return type(state) is str and (state == 'not-established'
                                  or _postcreate_guard_state(state, version=version))


def _postcreate_guard_context(failure, logs, *, version):
    return (type(failure) is dict and type(logs) is dict
        and version in (RESULT_V2, RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) and failure.get('schema') == version
        and failure.get('state') == 'failed'
        and type(failure.get('kind_create_status')) is int and failure['kind_create_status'] == 0
        and failure.get('source_deployment') == 'not-reached' and failure.get('logs') == logs
        and logs.get('startup_marker') is False)


def logs_evidence(value, *, complete, version=RESULT_V1, failure=None):
    """Authenticate closed trusted-guest reporting, never invent an owned wait."""
    vm.require(type(version) is str and version in (RESULT_V1, RESULT_V2, RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13), 'rootful-result-version')
    vm.require(type(value) is dict and set(value) == {'state', 'identities', 'collectors',
               'startup_marker', 'wrapper_observed_child_wait_status', 'signal_cause'}, 'rootful-logs-schema')
    state, identities, collectors = value['state'], value['identities'], value['collectors']
    roles = LOG_ROLES_V4 if version in (RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) else LOG_ROLES
    vm.require(type(state) is str and (state in LOG_STATES
               or _postcreate_guard_state(state, version=version)) and type(identities) is dict
               and set(identities) == roles and type(collectors) is dict
               and set(collectors) == {'out', 'err'} and type(value['startup_marker']) is bool
               and value['signal_cause'] is None, 'rootful-logs-binding')
    incomplete = _logs_unestablished(state, version=version)
    if _postcreate_guard_state(state, version=version):
        vm.require(not complete and _postcreate_guard_context(failure, value, version=version), 'rootful-postcreate-guard-scope')
    observed = set()
    for role, identity in identities.items():
        if identity is None:
            vm.require(not complete and incomplete, 'rootful-logs-missing-identity')
            continue
        vm.require(type(identity) is dict and set(identity) == {'pid', 'start'}
                   and type(identity['pid']) is int and 0 < identity['pid'] < 32768
                   and type(identity['start']) is int and 0 < identity['start'] < 2**63 - 1,
                   'rootful-logs-identity')
        pair = identity['pid'], identity['start']
        vm.require(pair not in observed, 'rootful-logs-role-alias')
        observed.add(pair)
    poll = _poll_parts(state, version=version)
    if poll is not None:
        _cause, role, _observed, _count, pid, start = poll
        vm.require(identities[role] == {'pid': pid, 'start': start}, 'rootful-poll-identity')
    for role, record in collectors.items():
        if record is None:
            vm.require(not complete and incomplete, 'rootful-logs-missing-collector')
            continue
        maximum = 16384 if role == 'out' else 4096
        vm.require(type(record) is dict and set(record) == {'dd_status', 'tee_status', 'bytes', 'source_eof'}
                   and all(type(record[key]) is int and 0 <= record[key] <= 255
                           for key in ('dd_status', 'tee_status'))
                   and type(record['bytes']) is int and 0 <= record['bytes'] <= maximum + 1
                   and type(record['source_eof']) is bool, 'rootful-logs-collector')
        if not incomplete:
            vm.require(record['dd_status'] == record['tee_status'] == 0 and record['bytes'] <= maximum
                       and record['source_eof'] is True, 'rootful-logs-eof')
    status = value['wrapper_observed_child_wait_status']
    if version in (RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        vm.require(status is None and state != 'direct-wait-zero', 'rootful-logs-v4-wait-unavailable')
    vm.require(status is None or type(status) is int and 0 <= status <= 255,
               'rootful-logs-wait-status')
    if state == 'direct-wait-zero':
        vm.require(type(status) is int and status == 0 and value['startup_marker'] is True,
                   'rootful-logs-direct-wait')
    elif state == 'retired-wait-and-signal-cause-unavailable':
        vm.require(status is None and value['startup_marker'] is True, 'rootful-logs-unknown-wait')
    else:
        vm.require(value['startup_marker'] is False, 'rootful-logs-unestablished-marker')
    vm.require(not complete or not incomplete, 'rootful-logs-retirement-unproved')
    return dict(value)


def poll_failure(logs, *, version, failure):
    """Decode private cached facts only; never add a serialized summary field."""
    logs_evidence(logs, complete=False, version=version, failure=failure)
    poll = _poll_parts(logs['state'], version=version)
    if poll is None:
        return None
    cause, role, observed, count, pid, start = poll
    return LogPollFailure('iteration-limit' if cause == 'g' else 'work-deadline', role, pid, start,
        None if observed == 'u' else observed, count, count - 1 if count else None,
        'last-existing-comparison-passed-before-last-sample' if cause == 'g'
        else 'current-existing-work-comparison-failed-before-next-sample')


def postlog_failure(value, *, version):
    """Validate private first explicit-fail site; never infer a runtime cause."""
    if version not in (RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        return
    vm.require(type(value) is dict and value.get('schema') == version
               and 'postlog_failure' in value, 'rootful-postlog-version')
    code = value['postlog_failure']
    vm.require(code is None or type(code) is str
               and (code in POSTLOG_FAILURES or version in (RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) and code in POSTNODE_FAILURES),
               'rootful-postlog-code')
    if code is not None:
        vm.require(value.get('state') == 'failed'
                   and type(value.get('kind_create_status')) is int
                   and value['kind_create_status'] == 0
                   and value.get('source_deployment') == 'not-reached',
                   'rootful-postlog-scope')
        logs_evidence(value.get('logs'), complete=True, version=version, failure=value)
    if version in (RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        postlog_native(value)
    if version in (RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        postlog_reason(value)


def postlog_native(value):
    """Validate obtained native-wrapper statuses, never tool launch or cause."""
    vm.require('postlog_native' in value, 'rootful-postlog-native-member')
    record = value['postlog_native']
    if not (value['postlog_failure'] == 'pl1.n'
            or value.get('schema') in (RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) and value['postlog_failure'] == 'pl2.k'
            and type(value.get('postlog_reason')) is str
            and (value['postlog_reason'] in K_NATIVE_SUBSTAGES if value['schema'] not in (RESULT_V12, RESULT_V13)
                 else value['postlog_reason'] in V12_K_NATIVE_SUBSTAGES)):
        vm.require(record is None, 'rootful-postlog-native-scope')
        return
    keys = {'return_status', 'command_status', 'stdout_capture_status', 'stderr_capture_status'}
    vm.require(type(record) is dict and set(record) == keys, 'rootful-postlog-native-shape')
    returned = record['return_status']
    vm.require(returned is None or type(returned) is int and 1 <= returned <= 255,
               'rootful-postlog-native-return')
    statuses = [record[key] for key in ('command_status', 'stdout_capture_status', 'stderr_capture_status')]
    vm.require(all(status is None or type(status) is int and 0 <= status <= 255 for status in statuses),
               'rootful-postlog-native-status')
    vm.require(all(status is None for status in statuses) or all(status is not None for status in statuses),
               'rootful-postlog-native-availability')
    command, stdout, stderr = statuses
    if command is None:
        vm.require(returned is None, 'rootful-postlog-native-unavailable')
    elif returned is None:
        vm.require(stdout == stderr == 0, 'rootful-postlog-native-clock')
    elif stdout != 0 or stderr != 0:
        vm.require(returned == 125, 'rootful-postlog-native-capture')
    else:
        vm.require(returned == command, 'rootful-postlog-native-command')


def postlog_reason(value):
    """Validate closed resource/k action groups, never messages or cause."""
    vm.require('postlog_reason' in value, 'rootful-postlog-reason-member')
    reason = value['postlog_reason']
    if value['postlog_failure'] == 'pl1.r':
        allowed = POSTLOG_REASONS if value['schema'] != RESULT_V13 else POSTLOG_REASONS - {r for r in POSTLOG_REASONS if r.startswith('inv-')}
        vm.require(type(reason) is str and reason in allowed, 'rootful-postlog-reason')
    elif value.get('schema') in (RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13) and value['postlog_failure'] == 'pl2.k':
        if value['schema'] in (RESULT_V12, RESULT_V13):
            allowed = V12_K_SUBSTAGES | V12_I_REASONS
        else:
            allowed = K_SUBSTAGES
            if value['schema'] == RESULT_V10:
                allowed |= I_ATOM_REASONS
            elif value['schema'] == RESULT_V11:
                allowed |= V11_I_REASONS
        vm.require(type(reason) is str and reason in allowed, 'rootful-k-substage')
    else:
        vm.require(reason is None, 'rootful-postlog-reason-scope')


def result(raw, config, *, allow_failure=False):
    vm.require(len(raw) <= vm.META_MAX and raw.endswith(b'\n') and len(raw.splitlines()) == 1,
               'rootful-result-framing')
    value = vm.strict_json(raw)
    keys = {'schema', 'owner', 'plan_sha256', 'profile', 'state', 'native_actions',
            'utility_actions', 'utility_ledger_actions', 'record_guards', 'output_reserved', 'kind_create_status', 'kind_delete_status',
            'source_deployment', 'server_patch', 'network_retirement', 'remaining_cases', 'logs'}
    if type(value) is dict and value.get('schema') in (RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        keys = keys | {'postlog_failure'}
    if type(value) is dict and value.get('schema') in (RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        keys = keys | {'postlog_native'}
    if type(value) is dict and value.get('schema') in (RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        keys = keys | {'postlog_reason'}
    if type(value) is dict and value.get('schema') == RESULT_V13:
        keys = keys | {'resource_profile'}
    expected = config['rootful_spec']
    vm.require(type(value) is dict and set(value) == keys
               and type(value['schema']) is str and value['schema'] in (RESULT_V1, RESULT_V2, RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13)
               and value['owner'] == config['owner']
               and value['plan_sha256'] == config['stage_plan_sha256']
               and value['profile'] == expected['profile']
               and value['server_patch'] == expected['server_patch']
               and value['state'] in ('failed', 'source-deployment-positive')
               and type(value['kind_create_status']) is int and -1 <= value['kind_create_status'] <= 255
               and type(value['kind_delete_status']) is int and -1 <= value['kind_delete_status'] <= 255
               and value['source_deployment'] in ('not-reached', 'server-dry-run-observed')
               and value['network_retirement'] == 'whole-vm-required'
               and value['remaining_cases'] == 'pending-fresh-runs', 'rootful-result-binding')
    vm.require((value['schema'] == RESULT_V12)
               == (expected.get('schema') == 'kubernetes-lens-owned-rootful-v12'),
               'rootful-v12-spec')
    vm.require((value['schema'] == RESULT_V13)
               == (expected.get('schema') == 'kubernetes-lens-owned-rootful-v13'),
               'rootful-v13-spec')
    if value['schema'] == RESULT_V13:
        vm.require(value['resource_profile'] == expected.get('resource_profile') == LIVE_RESOURCE_PROFILE
                   and expected.get('resource_facts_sha256') == LIVE_FACTS_SHA256,
                   'rootful-v13-resource-profile')
    success = (value['state'] == 'source-deployment-positive'
               and value['kind_create_status'] == value['kind_delete_status'] == 0
               and value['source_deployment'] == 'server-dry-run-observed')
    vm.require(success or allow_failure and value['state'] == 'failed', 'rootful-success-unproved')
    logs_evidence(value['logs'], complete=success, version=value['schema'], failure=value)
    postlog_failure(value, version=value['schema'])
    vm.require(type(value['utility_ledger_actions']) is int
               and 0 <= value['utility_ledger_actions'] <= UTILITY_WORK + UTILITY_CLEANUP
               and type(value['record_guards']) is dict
               and set(value['record_guards']) == {'prepaid', 'attempted'}
               and all(type(value['record_guards'][name]) is int
                       and value['record_guards'][name] == GUARD_PREPAID for name in ('prepaid', 'attempted'))
               and type(value['utility_actions']) is int
               and value['utility_actions'] == value['utility_ledger_actions'] + GUARD_PREPAID,
               'rootful-record-guard-accounting')
    for key, maximum in (('native_actions', 75), ('utility_actions', 768), ('output_reserved', GUEST_OUTPUT)):
        vm.require(type(value[key]) is int and 0 < value[key] <= maximum, 'rootful-result-budget')
    return dict(value)


EVIDENCE_MAX = 256 * 1024
RAW_MAX = 128 * 1024
EVIDENCE_NAMES = frozenset(('podman-info', 'manifest', 'config', 'image-inspect', 'network-inspect', 'node-inspect'))

PRIVATE_FAILURE_ROLE = 'node-init-stdout-prefix'
KIND_STDERR_ROLE = 'kind-create-stderr-prefix'
KIND_ATTRIBUTION_ROLE = 'kind-create-attribution'
KIND_FAILURE_ROLES = frozenset((KIND_STDERR_ROLE, KIND_ATTRIBUTION_ROLE))


def kind_create_failure(decoded, failure, *, complete):
    """Check private capture attribution, never infer a runtime cause or readiness."""
    vm.require(not complete and type(failure) is dict and failure['state'] == 'failed'
               and failure['source_deployment'] == 'not-reached'
               and KIND_ATTRIBUTION_ROLE in decoded, 'rootful-kind-failure-scope')
    raw = decoded[KIND_ATTRIBUTION_ROLE]
    vm.require(0 < len(raw) <= 1024, 'rootful-kind-attribution-budget')
    value = vm.strict_json(raw)
    keys = {'schema', 'kind_child_wait_status', 'native_wrapper_status', 'stdout_capture_status',
            'stderr_capture_status', 'stderr_captured_bytes', 'stderr_prefix_bytes',
            'stderr_source_eof', 'stderr_overflow_sentinel', 'stderr_prefix_truncated',
            'provider_child_wait_status', 'provider_wrapper_status'}
    vm.require(type(value) is dict and set(value) == keys
               and value['schema'] == 'kind-create-failure-attribution-v1', 'rootful-kind-attribution')
    for name in ('kind_child_wait_status', 'stdout_capture_status', 'stderr_capture_status'):
        vm.require(type(value[name]) is int and -1 <= value[name] <= 255,
                   'rootful-kind-attribution-status')
    vm.require(value['kind_child_wait_status'] == failure['kind_create_status']
               and type(value['native_wrapper_status']) is int
               and 0 < value['native_wrapper_status'] <= 255
               and value['provider_child_wait_status'] is None
               and value['provider_wrapper_status'] is None, 'rootful-kind-attribution-status')
    vm.require(all(type(value[name]) is int for name in ('stderr_captured_bytes', 'stderr_prefix_bytes'))
               and 0 <= value['stderr_captured_bytes'] <= 32769
               and value['stderr_prefix_bytes'] == min(value['stderr_captured_bytes'], 4096),
               'rootful-kind-capture-budget')
    captured = value['stderr_captured_bytes']
    vm.require(type(value['stderr_overflow_sentinel']) is bool
               and value['stderr_overflow_sentinel'] == (captured == 32769)
               and type(value['stderr_prefix_truncated']) is bool
               and value['stderr_prefix_truncated'] == (captured > 4096)
               and (value['stderr_source_eof'] is True if value['stderr_capture_status'] == 0
                    else value['stderr_source_eof'] is None)
               and (value['stderr_capture_status'] != 0 or captured <= 32768),
               'rootful-kind-capture-completeness')
    vm.require((value['native_wrapper_status'] == value['kind_child_wait_status']
                if value['stdout_capture_status'] == value['stderr_capture_status'] == 0
                else value['native_wrapper_status'] == 125), 'rootful-kind-wrapper-attribution')
    prefix = decoded.get(KIND_STDERR_ROLE, b'')
    vm.require((KIND_STDERR_ROLE in decoded) == (captured > 0)
               and len(prefix) == value['stderr_prefix_bytes'], 'rootful-kind-prefix-capture')
    return [{'role': name, 'bytes': len(decoded[name]), 'sha256': vm.digest(decoded[name]),
             'protected': True, 'scope': 'kind-create-failure-only',
             'completeness': 'diagnostic-prefix-only' if name == KIND_STDERR_ROLE else 'attribution-only'}
            for name in sorted(KIND_FAILURE_ROLES & decoded.keys())]


def evidence(value, config, *, complete, failure=None, version=RESULT_V1):
    """Authenticate the closed durable raw-byte catalogue; never normalize it."""
    vm.require(type(version) is str and version in (RESULT_V1, RESULT_V2, RESULT_V3, RESULT_V4, RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13),
               'rootful-result-version')
    import base64
    import binascii
    vm.require(type(value) is dict and set(value) == {'schema', 'owner', 'plan_sha256', 'source_spec_sha256', 'files'}
               and value['schema'] == 'kubernetes-lens-owned-rootful-evidence-v1'
               and value['owner'] == config['owner'] and value['plan_sha256'] == config['stage_plan_sha256']
               and value['source_spec_sha256'] == vm.digest(vm.encode(config['rootful_spec']))
               and type(value['files']) is dict and set(value['files']) <= EVIDENCE_NAMES | {PRIVATE_FAILURE_ROLE} | KIND_FAILURE_ROLES
               and (not complete or set(value['files']) == EVIDENCE_NAMES), 'rootful-evidence-catalogue')
    if version in (RESULT_V5, RESULT_V6, RESULT_V7, RESULT_V8, RESULT_V9, RESULT_V10, RESULT_V11, RESULT_V12, RESULT_V13):
        postlog_failure(failure, version=version)
        code = failure['postlog_failure']
        if code in POSTNODE_FAILURES:
            vm.require('node-inspect' in value['files'], 'rootful-postnode-node-evidence')
        else:
            vm.require(code is None or 'node-inspect' not in value['files'],
                       'rootful-postlog-node-evidence')
    total, decoded = 0, {}
    for name, record in value['files'].items():
        vm.require(type(record) is dict and set(record) == {'bytes', 'sha256', 'base64'}
                   and type(record['bytes']) is int and 0 < record['bytes'] <= RAW_MAX
                   and isinstance(record['sha256'], str) and vm.HEX.fullmatch(record['sha256'])
                   and isinstance(record['base64'], str) and len(record['base64']) <= 4 * ((RAW_MAX+2)//3),
                   'rootful-evidence-file')
        try:
            raw = base64.b64decode(record['base64'], validate=True)
        except (ValueError, binascii.Error) as error:
            raise vm.Refusal('rootful-evidence-base64') from error
        vm.require(base64.b64encode(raw).decode('ascii') == record['base64']
                   and len(raw) == record['bytes'] and vm.digest(raw) == record['sha256'], 'rootful-evidence-raw-integrity')
        total += len(raw)
        vm.require(total <= RAW_MAX, 'rootful-evidence-aggregate')
        decoded[name] = raw
    protected = []
    if PRIVATE_FAILURE_ROLE in decoded:
        vm.require(not complete and type(failure) is dict and failure.get('state') == 'failed'
                   and failure.get('source_deployment') == 'not-reached'
                   and type(failure.get('kind_create_status')) is int
                   and 0 <= failure['kind_create_status'] <= 255
                   and type(failure.get('logs')) is dict
                   and _logs_unestablished(failure['logs'].get('state'), version=version)
                   and failure['logs'].get('startup_marker') is False,
                   'rootful-private-prefix-scope')
        if _postcreate_guard_state(failure['logs']['state'], version=version):
            logs_evidence(failure['logs'], complete=False, version=version, failure=failure)
        collector = failure['logs']['collectors']['out']
        raw = decoded[PRIVATE_FAILURE_ROLE]
        vm.require(type(collector) is dict and 0 < collector['bytes'] <= 16385
                   and len(raw) == min(collector['bytes'], 16384), 'rootful-private-prefix-capture')
        protected.append({'role': PRIVATE_FAILURE_ROLE, 'bytes': len(raw), 'sha256': vm.digest(raw),
                          'protected': True, 'scope': 'pre-readiness-node-init-only',
                          'completeness': 'diagnostic-prefix-only'})
    if KIND_FAILURE_ROLES & decoded.keys():
        protected.extend(kind_create_failure(decoded, failure, complete=complete))
    spec = config['rootful_spec']
    for name, key in (('manifest', 'manifest_sha256'), ('config', 'config_sha256')):
        if name in decoded:
            vm.require(vm.digest(decoded[name]) == spec[key], 'rootful-evidence-publisher-identity')
    if 'manifest' in decoded:
        manifest = vm.strict_json(decoded['manifest'])
        vm.require(manifest.get('config', {}).get('digest') == 'sha256:' + spec['config_sha256'], 'rootful-evidence-config-lineage')
    def one(name):
        rows = vm.strict_json(decoded[name])
        vm.require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'rootful-evidence-inspect-schema')
        return rows[0]
    if 'podman-info' in decoded:
        vm.guest_info(decoded['podman-info'])
        info = vm.strict_json(decoded['podman-info'])
        host, store = info['host'], info.get('store', {})
        vm.require(host.get('networkBackend') == 'netavark' and host.get('cgroupManager') == 'cgroupfs'
                   and store.get('graphDriverName') == 'overlay' and store.get('graphRoot') == ROOT+'/storage'
                   and store.get('runRoot') == '/run/kubernetes-lens-rootful/storage'
                   and store.get('graphStatus', {}).get('Backing Filesystem') == 'xfs', 'rootful-evidence-private-store')
    if 'image-inspect' in decoded:
        row = one('image-inspect')
        vm.require(row.get('Id') == spec['config_sha256']
                   and (row.get('RepoDigests') is None or type(row['RepoDigests']) is list
                        and all(isinstance(s, str) for s in row['RepoDigests'])), 'rootful-evidence-image-identity')
    network_id = None
    if 'network-inspect' in decoded:
        row = one('network-inspect')
        network_id = row.get('id')
        vm.require(isinstance(network_id, str) and vm.HEX.fullmatch(network_id)
                   and row.get('name') == 'kind' and row.get('driver') == 'bridge'
                   and row.get('network_interface') == 'klbr0' and row.get('ipv6_enabled') is False
                   and row.get('dns_enabled') is False
                   and row.get('subnets') == [{'subnet': '172.30.0.0/16', 'gateway': '172.30.0.1'}]
                   and row.get('labels', {}).get('io.kubernetes-lens.issue2.owner') == config['owner'],
                   'rootful-evidence-network-identity')
    if 'node-inspect' in decoded:
        row = one('node-inspect')
        identity, state = row.get('Id'), row.get('State', {})
        node = 'kl-' + config['owner'] + '-control-plane'
        networks = row.get('NetworkSettings', {}).get('Networks', {})
        command = row.get('Config', {}).get('CreateCommand')
        vm.require(isinstance(identity, str) and vm.HEX.fullmatch(identity)
                   and row.get('Image') == spec['config_sha256'] and row.get('Name') == node
                   and state.get('Running') is True and type(state.get('Pid')) is int and 0 < state['Pid'] < 32768
                   and state.get('CgroupPath') == '/libpod_parent/libpod-' + identity
                   and type(networks) is dict and set(networks) == {'kind'} and network_id is not None
                   and networks['kind'].get('NetworkID') == network_id
                   and isinstance(command, list) and command.count('--pull=never') == 1
                   and command[-1:] == [spec['config_sha256']], 'rootful-evidence-node-identity')
    return {'sha256': vm.digest(vm.encode(value)), 'bytes': len(vm.encode(value)), 'raw_bytes': total,
            'files': sorted(decoded), **({'protected_files': protected} if protected else {})}


def wire_record(raw, config, *, allow_failure=False):
    vm.require(type(raw) is bytes and 0 < len(raw) <= EVIDENCE_MAX, 'rootful-wire-budget')
    vm.require(raw.endswith(b'\n') and len(raw.splitlines()) == 1, 'rootful-wire-framing')
    envelope = vm.strict_json(raw)
    vm.require(type(envelope) is dict and 'evidence' in envelope, 'rootful-wire-evidence')
    summary = dict(envelope)
    raw_evidence = summary.pop('evidence')
    checked = result(vm.encode(summary)+b'\n', config, allow_failure=allow_failure)
    record = evidence(raw_evidence, config, complete=checked['state'] == 'source-deployment-positive',
                      failure=checked, version=checked['schema'])
    return {**checked, 'evidence': record}


def durable_wire(raw, config, parent, budget):
    """One bounded0600 exclusive/no-follow sidecar after actual VM retirement."""
    summary = wire_record(raw, config, allow_failure=True)
    budget.remaining(cleanup=True)
    name = 'kubernetes-lens-vm-' + config['owner'] + '.evidence.json'
    path = vm.canonical(Path(parent) / name)
    try:
        vm.write(path, raw, maximum=EVIDENCE_MAX)
    except OSError as error:
        raise vm.Refusal('rootful-durable-evidence-write-failed') from error
    budget.remaining(cleanup=True)
    return {'name': name, 'bytes': len(raw), 'sha256': vm.digest(raw), 'catalogue': summary['evidence']}
