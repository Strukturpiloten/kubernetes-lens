"""Independent pure controls. Never observe a host or start native tools/managers."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import hosted_native_prerequisites as h

SHA = '1' * 40
SECRET = 'PRIVATE-CREDENTIAL-HOST-USER-ADDRESS'


def environment():
    return {'HN_EVENT': 'workflow_dispatch', 'HN_REF': 'refs/heads/main',
            'HN_REPOSITORY': 'Strukturpiloten/kubernetes-lens', 'HN_SOURCE_SHA': SHA,
            'HN_WORKFLOW_SHA': SHA,
            'HN_WORKFLOW_REF': 'Strukturpiloten/kubernetes-lens/' + h.WORKFLOW + '@refs/heads/main',
            'HN_RUN_ID': '123', 'HN_RUN_ATTEMPT': '2', 'HN_RUNNER_OS': 'Linux',
            'HN_RUNNER_ARCH': 'X64', 'HN_RUNNER_ENVIRONMENT': 'github-hosted',
            'UNSELECTED_SECRET': SECRET}


def facts():
    cg = {'status': 'observed', 'required_controllers_present': True,
          'subtree_control_writable_indicator': True,
          'ancestor_effective_cpu_memory_pids_limits': 'unknown-not-observed',
          'leaf_limits_are_global_effective_limits': False}
    return {'host': {'architecture': 'x86_64', 'interpreter': {'executable_matches_python_role': True}},
            'tools': {r: {'status': 'observed'} for r in h.TOOLS}, 'kvm': {'status': 'observed'},
            'user_manager': {'status': 'observed', 'delegate_property': True, 'cgroup': deepcopy(cg)},
            'job_cgroup': cg}


def decode(payload):
    lines = payload.splitlines()
    assert lines[0] == b'HOSTED_NATIVE_PREREQUISITES_V1_BEGIN'
    assert lines[3] == b'HOSTED_NATIVE_PREREQUISITES_V1_END'
    assert lines[4].startswith(b'Hosted prerequisite observation: ')
    assert lines[2] == b'sha256:' + hashlib.sha256(lines[1]).hexdigest().encode()
    value = json.loads(lines[1])
    assert h.encode(value) == lines[1]
    return value


class HostedCandidateControls(unittest.TestCase):
    def session(self):
        session = Mock()
        session.run.side_effect = [(0, (SHA + '\n').encode(), b''), (0, b'', b'')]
        session.hashed_file.return_value = (None, 'a' * 64, b'')
        return session

    def test_exact_source_workflow_main_run_attempt_and_fixed_policy_hashes(self):
        session = self.session()
        value = h.candidate(session, SHA, environment())
        self.assertEqual((value['source_sha'], value['workflow_sha'], value['run_id'], value['run_attempt']),
                         (SHA, SHA, '123', '2'))
        self.assertEqual(set(value['source_file_sha256']), {h.WORKFLOW,
                         'scripts/fixtures/hosted_native_prerequisites.py',
                         'scripts/test-repository-policy.py', '.github/renovate.json'})
        self.assertEqual(session.run.call_count, 2)
        self.assertNotIn(SECRET, json.dumps(value))

    def test_invalid_candidate_ref_event_repository_workflow_runner_and_run_refuse_before_reads(self):
        for key in environment():
            if key == 'UNSELECTED_SECRET':
                continue
            session = self.session()
            env = environment()
            env[key] = SECRET
            with self.subTest(key=key), self.assertRaises(h.Refusal):
                h.candidate(session, SHA, env)
            session.run.assert_not_called()
            session.hashed_file.assert_not_called()
        for sha in ('main', 'A' * 40, '1' * 39, SHA + '\n', '${touch file}'):
            session = self.session()
            with self.assertRaises(h.Refusal):
                h.candidate(session, sha, environment())
            session.run.assert_not_called()

    def test_wrong_checked_out_head_and_dirty_source_never_observe(self):
        for responses in ([(0, b'2' * 40 + b'\n', b'')],
                          [(0, (SHA + '\n').encode(), b''), (0, SECRET.encode(), b'')]):
            session = self.session()
            session.run.side_effect = responses
            with self.assertRaisesRegex(h.Refusal, 'source-binding'):
                h.candidate(session, SHA, environment())
            session.hashed_file.assert_not_called()


class HostedObservationControls(unittest.TestCase):
    def test_kvm_missing_denied_unsupported_and_only_api_ioctl_with_close(self):
        session = Mock(fds=set())
        session.open.return_value = 42
        for error, expected in ((FileNotFoundError(), 'missing'), (PermissionError(), 'denied')):
            with patch.object(h.os, 'lstat', side_effect=error), patch.object(h.fcntl, 'ioctl') as ioctl:
                self.assertEqual(h.kvm(session)['status'], expected)
                ioctl.assert_not_called()
        info = Mock(st_mode=stat.S_IFCHR | 0o660)
        with patch.object(h.os, 'lstat', return_value=info), patch.object(h.os, 'open', return_value=42), \
             patch.object(h.os, 'fstat', return_value=info), patch.object(h.fcntl, 'ioctl', return_value=12) as ioctl:
            self.assertEqual(h.kvm(session), {'status': 'observed', 'api_version': 12})
            ioctl.assert_called_once_with(42, 0xAE00, 0)
            session.close.assert_called_once_with(42)
        with patch.object(h.os, 'lstat', return_value=Mock(st_mode=stat.S_IFREG)):
            self.assertEqual(h.kvm(session)['status'], 'unsupported')

    def test_manager_missing_does_not_start_bus_or_query_system_manager(self):
        session = Mock()
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError()):
            self.assertEqual(h.manager(session, '/usr/bin/busctl', 1001)['status'], 'missing')
        session.run.assert_not_called()

    def test_dbus_fixed_no_autostart_scalar_schema_and_private_error_rejection(self):
        session = Mock()
        session.run.return_value = (0, b'{"type":"s","data":"255"}', b'')
        self.assertEqual(h.property_value(session, '/usr/bin/busctl', 'unix:path=/run/user/1001/bus',
                                         '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
                                         'Version', 's'), '255')
        argv = session.run.call_args.args[0]
        self.assertIn('--auto-start=no', argv)
        self.assertIn('--address=unix:path=/run/user/1001/bus', argv)
        self.assertEqual(argv[7:], ['org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                                   'org.freedesktop.systemd1.Manager', 'Version'])
        for raw in (b'{"type":"s","data":true}', b'{"type":"s","data":["255"]}',
                    b'{"type":"s","data":"255","data":"256"}', SECRET.encode()):
            session.run.return_value = (0, raw, b'')
            with self.assertRaises(h.Refusal):
                h.property_value(session, '/usr/bin/busctl', 'unix:path=/run/user/1001/bus',
                                 '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'Version', 's')

    def test_manager_rejects_foreign_cgroup_and_retains_partial_unknown_property(self):
        endpoint = Mock(st_mode=stat.S_IFSOCK | 0o600, st_uid=1001)
        parent = Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=1001)
        for raw in ('/system.slice/foreign.service', '/user.slice/user-1001.slice/user@1001.service/init.scope'):
            session = Mock()
            with patch.object(Path, 'lstat', side_effect=[parent, endpoint]), \
                 patch.object(h, 'property_value', side_effect=['255 (255.4-1ubuntu8)', raw, h.Refusal(SECRET)]), \
                 patch.object(h, 'cgroup', return_value={'status': 'observed'}) as cg:
                result = h.manager(session, '/usr/bin/busctl', 1001)
            self.assertEqual(result['status'], 'unknown')
            self.assertEqual(result['version_major'], '255')
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertEqual(cg.call_count, 0 if raw.startswith('/system.') else 1)

    def test_leaf_cgroup_values_missing_controllers_and_unknown_ancestor_effective_limits(self):
        session = Mock()
        session.file.side_effect = [b'cpu memory\n', b'cpu\n', b'100000 100000\n', b'0\n', b'max\n', b'0-1\n']
        with patch.object(h, 'cgroup_path', return_value=Path('/fixed-own-leaf')), \
             patch.object(h.os, 'access', return_value=False):
            result = h.cgroup(session, '/owned')
        self.assertFalse(result['required_controllers_present'])
        self.assertFalse(result['leaf_limits_are_global_effective_limits'])
        self.assertEqual(result['ancestor_effective_cpu_memory_pids_limits'], 'unknown-not-observed')
        self.assertEqual(session.file.call_count, 6)
        self.assertNotIn('cgroup.procs', repr(session.file.call_args_list))
        with self.assertRaises(h.Refusal):
            h.cgroup_path('/owned/../foreign')

    def test_private_provider_or_kernel_metadata_is_rejected_before_tool_queries(self):
        for kernel, image in [('6.14.0-private-host', {}),
                              ('6.14.0-1017-azure', {'HN_ImageVersion': SECRET}),
                              ('6.14.0-1017-azure', {'HN_ImageOS': SECRET})]:
            with patch.object(h.os, 'geteuid', return_value=1001), \
                 patch.object(h.os, 'uname', return_value=SimpleNamespace(release=kernel, machine='x86_64')), \
                 patch.object(h, 'tools') as inventory, self.assertRaises(h.Refusal):
                h.observe(Mock(), image)
            inventory.assert_not_called()

    def test_version_queries_are_fixed_no_keygen_and_private_output_never_echoed(self):
        outputs = [b'QEMU emulator version 9.2.1 ' + SECRET.encode(), b'qemu-img version 9.2.1\n',
                   b'OpenSSH_9.9p1, ' + SECRET.encode(), b'1:9.9p1-3ubuntu1',
                   b'systemd 255\n', b'systemd 255\n', b'systemd 255\n', b'Python 3.12.1\n']
        session = Mock()
        session.run.side_effect = [(0, out, b'') for out in outputs]
        with patch.object(h, 'tool_identity', side_effect=lambda _session, path: {'path': path}):
            result = h.tools(session)
        self.assertEqual(set(result), {'qemu', 'qemu_img', 'ssh', 'ssh_keygen', 'systemctl', 'systemd_run', 'busctl', 'python'})
        self.assertTrue(all(row['status'] == 'observed' for row in result.values()))
        self.assertEqual(result['ssh_keygen']['version'], '9.9p1')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertFalse(any(call.args[0][0].endswith('ssh-keygen') for call in session.run.call_args_list))
        self.assertTrue(all(tuple(call.args[0][1:]) in set(h.VERSION_ARGS.values())
                            or call.args[0][1:] == ['--show', '--showformat=${Version}', 'openssh-client']
                            for call in session.run.call_args_list))

    def test_root_elf_authority_capabilities_ancestors_and_changed_identity_refuse(self):
        def info(**changes):
            values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0,
                          st_nlink=1, st_size=4, st_mtime_ns=1, st_ctime_ns=1)
            return SimpleNamespace(**(values | changes))
        original = info()
        for change in ('none', 'setid', 'writable', 'owner', 'not-elf', 'capabilities', 'ancestor', 'changed'):
            file_info = deepcopy(original)
            parent_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            prefix = b'\x7fELF'
            if change == 'setid': file_info.st_mode |= 0o4000
            if change == 'writable': file_info.st_mode |= 0o002
            if change == 'owner': file_info.st_uid = 1001
            if change == 'not-elf': prefix = b'#!xx'
            if change == 'ancestor': parent_info.st_mode |= 0o002
            path = MagicMock()
            path.__str__.return_value = '/usr/bin/fixed'
            path.parents = [Mock(lstat=Mock(return_value=parent_info))]
            path.lstat.return_value = info(st_ino=3) if change == 'changed' else file_info
            session = Mock()
            session.hashed_file.return_value = (file_info, 'a' * 64, prefix)
            caps = b'capability' if change == 'capabilities' else OSError(h.errno.ENODATA, 'absent')
            with patch.object(h, 'Path') as constructor, patch.object(h.os, 'getxattr', side_effect=caps if isinstance(caps, Exception) else None, return_value=caps):
                constructor.return_value.resolve.return_value = path
                if change == 'none':
                    self.assertEqual(h.tool_identity(session, '/fixed')['uid'], 0)
                else:
                    with self.assertRaises(h.Refusal): h.tool_identity(session, '/fixed')

    def test_identity_or_version_unknown_does_not_become_missing_or_admitted(self):
        session = Mock()
        session.run.return_value = (1, b'', SECRET.encode())
        def identify(_session, path):
            if path.endswith('qemu-img'):
                raise FileNotFoundError()
            if path.endswith('ssh'):
                raise h.Refusal(SECRET)
            return {'path': path, 'sha256': 'a' * 64}
        with patch.object(h, 'tool_identity', side_effect=identify):
            result = h.tools(session)
        self.assertEqual(result['qemu_img']['status'], 'missing')
        self.assertEqual(result['ssh']['status'], 'unknown')
        self.assertEqual(result['ssh_keygen']['status'], 'unknown')
        self.assertEqual(result['qemu']['sha256'], 'a' * 64)
        self.assertNotIn(SECRET, json.dumps(result))


class HostedLifecycleControls(unittest.TestCase):
    def fake_collect(self, data=None, *, failure=None, clean=True):
        session = Mock(absolute_end=10**12, cleanup_end=10**12, children_started=0)
        session.cleanup.return_value = {'complete': clean, 'children_reaped': clean,
                                        'owned_readers_closed': clean, 'fds_closed': clean, 'scratch_removed': clean}
        with patch.object(h, 'Session', return_value=session), \
             patch.object(h.signal, 'setitimer'), patch.object(h, 'candidate', return_value={'source_sha': SHA}), \
             patch.object(h, 'observe', return_value=data or facts(), side_effect=failure):
            code, payload = h.collect(SHA, environment(), emit=Mock())
        return session, code, decode(payload)

    def test_completed_compatible_indicators_still_have_unknown_required_native_prerequisites(self):
        session, code, report = self.fake_collect()
        self.assertEqual(code, 0)
        self.assertEqual(report['observation_outcome'], 'complete-compatible-indicators')
        self.assertEqual(report['prerequisite_decision'], 'unknown')
        self.assertEqual(report['required_native_prerequisites'], 'unknown')
        self.assertFalse(report['native_admission'])
        self.assertIn('ancestor-effective-limits-unobserved', report['remaining_gaps'])
        session.cleanup.assert_called_once()

    def test_missing_and_unknown_indicators_have_independent_decisions(self):
        for status, outcome, decision in [('missing', 'complete-missing-unsupported', 'missing'),
                                          ('denied', 'complete-missing-unsupported', 'missing'),
                                          ('unknown', 'incomplete-invalid', 'unknown')]:
            data = facts()
            data['kvm'] = {'status': status}
            _session, code, report = self.fake_collect(data)
            self.assertEqual((code, report['observation_outcome'], report['prerequisite_decision']),
                             (1 if status == 'unknown' else 0, outcome, decision))
            self.assertFalse(report['native_admission'])

    def test_timeout_cancellation_private_error_and_cleanup_failure_are_incomplete(self):
        for failure in (h.Refusal('child-timeout'), h.Refusal('cancelled-or-deadline'), h.Refusal(SECRET)):
            _session, code, report = self.fake_collect(failure=failure)
            self.assertEqual((code, report['observation_outcome']), (1, 'incomplete-invalid'))
            self.assertNotIn(SECRET, json.dumps(report))
        _session, code, report = self.fake_collect(clean=False)
        self.assertEqual((code, report['cleanup']['complete']), (1, False))

    def test_report_overflow_is_body_free_and_framed_digest_is_canonical(self):
        data = facts()
        data['unexpected'] = SECRET * h.REPORT_BYTES
        _session, code, report = self.fake_collect(data)
        self.assertEqual((code, report['failure'], report['facts']), (1, 'report-output-limit', {}))
        self.assertNotIn(SECRET, json.dumps(report))
        with patch.object(h, 'PUBLIC_BYTES', 1), self.assertRaises(h.Refusal):
            h.frame({'native_admission': False})

    def test_independent_literal_canonical_frame_and_fd_registration_interrupt(self):
        payload = h.frame({'schema': 'fixed', 'native_admission': False,
                           'observation_outcome': 'complete-missing-unsupported'})
        expected = b'{"native_admission":false,"observation_outcome":"complete-missing-unsupported","schema":"fixed"}'
        self.assertEqual(payload.splitlines()[1], expected)
        self.assertEqual(payload.splitlines()[2], b'sha256:' + hashlib.sha256(expected).hexdigest().encode())
        session = h.Session()
        with patch.object(h.os, 'open', return_value=42), \
             patch.object(h.signal, 'pthread_sigmask', side_effect=[set(), h.Refusal('cancelled-or-deadline')]), \
             self.assertRaises(h.Refusal):
            session.open('/fixed', h.os.O_RDONLY)
        self.assertEqual(session.fds, {42})
        with patch.object(h.os, 'close') as close:
            self.assertTrue(session.cleanup()['complete'])
        close.assert_called_once_with(42)

    def test_scratch_fd_close_and_failed_removal_are_actual_cleanup_facts(self):
        with tempfile.TemporaryDirectory() as parent:
            session = h.Session()
            session.scratch = Path(parent) / 'private'
            session.scratch.mkdir(mode=0o700)
            (session.scratch / 'unexpected').write_bytes(SECRET.encode())
            receipt = session.cleanup()
            self.assertFalse(receipt['complete'])
            self.assertFalse(receipt['scratch_removed'])
            (session.scratch / 'unexpected').unlink()
            session.scratch.rmdir()
        session = h.Session()
        session.fds.add(123)
        with patch.object(h.os, 'close', side_effect=OSError()):
            session.close(123)
            result = session.cleanup()
        self.assertFalse(result['complete'])
        self.assertFalse(result['fds_closed'])

    def test_hash_stream_budget_identity_change_and_close_use_fixed_chunks(self):
        info = Mock(st_mode=stat.S_IFREG | 0o755, st_size=4)
        session = h.Session()
        with patch.object(h.os, 'open', return_value=42), patch.object(h.os, 'fstat', return_value=info), \
             patch.object(h.os, 'lstat', return_value=info), patch.object(h.os, 'read', side_effect=[b'\x7fELF', b'']) as read, \
             patch.object(h.os, 'close') as close:
            _info, value, prefix = session.hashed_file('/fixed', 4)
        self.assertEqual((value, prefix), (hashlib.sha256(b'\x7fELF').hexdigest(), b'\x7fELF'))
        self.assertEqual(read.call_args_list[0].args, (42, 4))
        close.assert_called_once_with(42)
        self.assertFalse(session.fds)
        session.hashed = h.HASH_BYTES
        with patch.object(h.os, 'open', return_value=42), patch.object(h.os, 'fstat', return_value=info), \
             patch.object(h.os, 'read', return_value=b'x'), patch.object(h.os, 'close'), \
             self.assertRaisesRegex(h.Refusal, 'hash-budget'):
            session.hashed_file('/fixed', 4)

    def test_expired_deadline_starts_no_child_and_count_cap_does_not_spawn(self):
        session = h.Session()
        session.end = 0
        with patch.object(h.subprocess, 'Popen') as spawn, self.assertRaisesRegex(h.Refusal, 'observation-timeout'):
            session.run(['/fixed-version-only'])
        spawn.assert_not_called()
        session.end = 10**12
        session.children_started = h.CHILD_MAX
        with patch.object(h.subprocess, 'Popen') as spawn, self.assertRaisesRegex(h.Refusal, 'child-count-limit'):
            session.run(['/fixed-version-only'])
        spawn.assert_not_called()

    def test_owned_child_timeout_output_limit_clean_environment_and_reap(self):
        class Selector:
            def __enter__(self): self.entries = {}; return self
            def __exit__(self, *_args): pass
            def register(self, stream, _event, index): self.entries[stream] = index
            def unregister(self, stream): self.entries.pop(stream)
            def get_map(self): return self.entries
            def select(self, _remaining):
                return [(Mock(fileobj=next(iter(self.entries)), data=0), None)]
        for oversized in (True, False):
            session = h.Session()
            process = Mock(pid=4321, returncode=None)
            process.stdout.fileno.return_value = 50
            process.stderr.fileno.return_value = 51
            process.wait.side_effect = lambda **_kwargs: setattr(process, 'returncode', -15) or -15
            times = [0, 0, 0, 0, 3, 3, 3, 3, 3] if not oversized else [0] * 20
            with patch.object(h.subprocess, 'Popen', return_value=process) as spawn, \
                 patch.object(h.selectors, 'DefaultSelector', Selector), \
                 patch.object(h.os, 'set_blocking'), patch.object(h.os, 'read', return_value=b'x' * (h.CHILD_BYTES + 1) if oversized else b'x'), \
                 patch.object(h.os, 'killpg') as kill, patch.object(h.time, 'monotonic', side_effect=times), \
                 self.assertRaisesRegex(h.Refusal, 'child-output-limit' if oversized else 'child-timeout'):
                session.run(['/fixed-version-only'])
            self.assertEqual(spawn.call_args.kwargs['env'], h.CLEAN_ENV)
            self.assertNotIn('UNSELECTED_SECRET', spawn.call_args.kwargs['env'])
            self.assertTrue(spawn.call_args.kwargs['close_fds'])
            self.assertTrue(spawn.call_args.kwargs['start_new_session'])
            kill.assert_called_once_with(4321, signal.SIGTERM)
            process.stdout.close.assert_called_once()
            process.stderr.close.assert_called_once()
            self.assertEqual(process.returncode, -15)


class HostedFinalOutputDeadlineControls(unittest.TestCase):
    def exercise(self, *, frame_effect=None, emit_effect=None, cleanup_time=164):
        clock, armed = [100], [None]
        events = []
        session = Mock(start=100, end=160, absolute_end=170, cleanup_end=170, children_started=0)
        def observe(*_args):
            clock[0] = 159
            return facts()
        def cleanup():
            clock[0] = cleanup_time
            events.append(('cleanup', clock[0]))
            return {'complete': True, 'children_reaped': True, 'owned_readers_closed': True,
                    'fds_closed': True, 'scratch_removed': True}
        session.cleanup.side_effect = cleanup
        def timer(which, remaining):
            self.assertEqual(which, signal.ITIMER_REAL)
            armed[0] = clock[0] + remaining if remaining else None
            events.append(('timer', remaining, armed[0]))
        original_frame = h.frame
        def framed(report):
            self.assertEqual(armed[0], 170, 'framing retains the ORIGINAL absolute end')
            events.append(('frame', clock[0]))
            if frame_effect:
                return frame_effect(report, clock, armed)
            return original_frame(report)
        def emit(payload, deadline):
            self.assertEqual((deadline, armed[0]), (170, 170))
            self.assertGreater(deadline, clock[0])
            events.append(('emit', clock[0]))
            if emit_effect:
                return emit_effect(payload, deadline, clock, armed)
            clock[0] = 169
        with patch.object(h, 'CANCELLED', False), patch.object(h.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(h, 'Session', return_value=session), patch.object(h, 'candidate', return_value={'source_sha': SHA}), \
             patch.object(h, 'observe', side_effect=observe), patch.object(h.signal, 'setitimer', side_effect=timer), \
             patch.object(h, 'frame', side_effect=framed) as renderer:
            # Emit is injected; no real timer, write, observation or waiting occurs.
            result = h.collect(SHA, environment(), emit=emit)
        return result, events, renderer.call_count, session

    def test_remaining_original_deadline_stays_armed_until_after_output(self):
        with patch.object(h.time, 'monotonic', return_value=100):
            session = h.Session()
        self.assertEqual((session.start, session.end, session.absolute_end), (100, 160, 170))
        result, events, renders, _session = self.exercise()
        self.assertEqual((result[0], renders), (0, 1))
        self.assertFalse(decode(result[1])['native_admission'])
        self.assertEqual(events[0], ('timer', 10, 169))
        self.assertIn(('timer', 6, 170), events)
        self.assertEqual(events[-1], ('timer', 0, None))
        self.assertEqual(sum(event[:2] == ('timer', 0) for event in events), 1)
        self.assertLess(events.index(('emit', 164)), len(events) - 1)

    def test_preexpired_original_end_never_starts_frame_or_output(self):
        result, events, renders, session = self.exercise(cleanup_time=170)
        self.assertEqual((result, renders), ((1, b''), 0))
        session.cleanup.assert_called_once()
        self.assertFalse(any(event[0] == 'emit' for event in events))
        self.assertFalse(any(event[0] == 'timer' and event[1] > 0 and event[2] > 170 for event in events))

    def test_expiry_and_cancellation_inside_frame_never_create_replacement_frame(self):
        for sig in (signal.SIGALRM, signal.SIGTERM):
            def expire(_report, clock, _armed):
                if sig == signal.SIGALRM:
                    clock[0] = 170
                h.cancelled(sig, None)
            result, events, renders, _session = self.exercise(frame_effect=expire)
            self.assertEqual((result, renders), ((1, b''), 1))
            self.assertFalse(any(event[0] == 'emit' for event in events))

    def test_delayed_alarm_after_frame_and_limit_fallback_cannot_extend_end(self):
        for limit in (False, True):
            def expire(_report, clock, _armed):
                clock[0] = 170
                if limit:
                    raise h.Refusal('report-output-limit')
                return b'not-emitted'
            result, events, renders, _session = self.exercise(frame_effect=expire)
            self.assertEqual((result, renders), ((1, b''), 1))
            self.assertFalse(any(event[0] == 'emit' for event in events))

    def test_stalled_direct_writer_is_interrupted_under_original_end_without_flush(self):
        calls = []
        def emit(payload, deadline, clock, armed):
            def stalled(fd, raw):
                self.assertEqual((fd, armed[0]), (1, 170))
                calls.append(bytes(raw))
                clock[0] = 170
                h.cancelled(signal.SIGALRM, None)
            with patch.object(h.os, 'write', side_effect=stalled):
                h.write_stdout(payload, deadline)
        buffer = Mock()
        buffer.write.side_effect = AssertionError('buffered write must never be used')
        buffer.flush.side_effect = AssertionError('unbounded flush must never be used')
        with patch.object(h.sys, 'stdout', Mock(buffer=buffer)):
            result, _events, renders, _session = self.exercise(emit_effect=emit)
        self.assertEqual((result, renders, len(calls)), ((1, b''), 1, 1))
        buffer.write.assert_not_called()
        buffer.flush.assert_not_called()

    def test_partial_output_then_expiry_or_failed_transport_never_returns_success(self):
        for mode in ('partial', 'zero', 'broken-pipe', 'late-completion'):
            calls = []
            def emit(payload, deadline, clock, _armed):
                def write(fd, raw):
                    self.assertEqual(fd, 1)
                    calls.append(bytes(raw))
                    if mode == 'broken-pipe':
                        raise BrokenPipeError()
                    if mode == 'zero':
                        return 0
                    clock[0] = 170
                    return 1 if mode == 'partial' else len(raw)
                with patch.object(h.os, 'write', side_effect=write):
                    h.write_stdout(payload, deadline)
            result, _events, renders, _session = self.exercise(emit_effect=emit)
            self.assertEqual((result, renders, len(calls)), ((1, b''), 1, 1))

    def test_direct_writer_chunks_are_bounded_and_inherited_stdout_is_not_closed(self):
        written = []
        payload = b'x' * 8193
        with patch.object(h, 'CANCELLED', False), patch.object(h.time, 'monotonic', return_value=169), \
             patch.object(h.os, 'write', side_effect=lambda fd, raw: written.append((fd, bytes(raw))) or len(raw)), \
             patch.object(h.os, 'close') as close:
            h.write_stdout(payload, 170)
        self.assertEqual([len(raw) for _fd, raw in written], [4096, 4096, 1])
        self.assertEqual(b''.join(raw for _fd, raw in written), payload)
        self.assertTrue(all(fd == 1 for fd, _raw in written))
        close.assert_not_called()

    def test_main_wires_direct_writer_and_never_uses_buffered_stdout(self):
        writer, buffer = Mock(), Mock()
        with patch.object(h.sys, 'argv', ['collector', '--expected-source-sha', SHA]), \
             patch.object(h.sys, 'stdout', Mock(buffer=buffer)), patch.object(h.signal, 'signal'), \
             patch.object(h.signal, 'setitimer'), patch.object(h, 'write_stdout', writer), \
             patch.object(h, 'collect', return_value=(0, b'already-emitted')) as collect:
            self.assertEqual(h.main(), 0)
        collect.assert_called_once_with(SHA, h.os.environ, emit=writer)
        buffer.write.assert_not_called()
        buffer.flush.assert_not_called()


class HostedWorkflowControls(unittest.TestCase):
    def source(self):
        return (Path(__file__).resolve().parents[2] / h.WORKFLOW).read_text()

    def validate(self, text):
        self.assertTrue(text.startswith('---\n'))
        event = text.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', event, re.M), ['workflow_dispatch'])
        self.assertEqual(re.findall(r'^      ([a-z_]+):', event, re.M), ['expected_source_sha'])
        self.assertEqual(text.split('\npermissions:\n', 1)[1].split('\njobs:', 1)[0].strip(), 'contents: read')
        self.assertIn('    timeout-minutes: 5\n', text)
        actions = re.findall(r'uses: (\S+)', text)
        ci = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text()
        self.assertEqual(re.findall(r'^    runs-on: (.+)', text, re.M),
                         [re.search(r'^    runs-on: (.+)', ci, re.M).group(1)])
        checkout = re.search(r'uses: (actions/checkout@[a-f0-9]{40})( # v[0-9.]+)', ci)
        self.assertEqual(actions, [checkout.group(1)])
        self.assertIn(checkout.group(0), text)
        self.assertIn('          persist-credentials: false\n', text)
        self.assertIn('          ref: ${{ github.sha }}', text)
        self.assertIn('exec env -i PATH=/usr/bin:/bin', text)
        self.assertIn('/usr/bin/python3 -B scripts/fixtures/hosted_native_prerequisites.py', text)
        self.assertNotRegex(text, r'(?i)secrets[.]|sudo|apt-get|docker|podman|upload-artifact|actions/cache|container:')

    def test_manual_only_pinned_read_only_workflow_and_mutations(self):
        original = self.source()
        self.validate(original)
        for before, after in [('workflow_dispatch:', 'push:'), ('contents: read', 'contents: write'),
                              ('persist-credentials: false', 'persist-credentials: true'),
                              ('ubuntu-24.04', 'ubuntu-latest'), ('timeout-minutes: 5', 'timeout-minutes: 30')]:
            with self.assertRaises(AssertionError):
                self.validate(original.replace(before, after, 1))

    def test_executed_pre_checkout_guard_rejects_mismatches_and_shell_text_is_data(self):
        body = textwrap.dedent(self.source().split('        run: |\n', 1)[1].split('      - name:', 1)[0])
        env = {'EXPECTED_SOURCE_SHA': SHA, 'SOURCE_SHA': SHA, 'WORKFLOW_SHA': SHA,
               'WORKFLOW_REF': 'Strukturpiloten/kubernetes-lens/' + h.WORKFLOW + '@refs/heads/main',
               'REPOSITORY': 'Strukturpiloten/kubernetes-lens', 'EVENT': 'workflow_dispatch', 'REF': 'refs/heads/main'}
        self.assertEqual(subprocess.run(['/bin/bash', '-c', body], env=env, capture_output=True, timeout=1).returncode, 0)
        for key in env:
            bad = {**env, key: '$(printf PRIVATE)'}
            result = subprocess.run(['/bin/bash', '-c', body], env=bad, capture_output=True, timeout=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'PRIVATE', result.stdout)


if __name__ == '__main__':
    unittest.main()
