#!/usr/bin/env python3
"""Manual hosted indicators only. No native admission, provisioning or fallback."""
import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

CANCELLED = False
ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = '.github/workflows/hosted-native-prerequisites.yml'
REPOSITORY = 'Strukturpiloten/kubernetes-lens'
TOOLS = {'qemu': '/usr/bin/qemu-system-x86_64', 'qemu_img': '/usr/bin/qemu-img',
         'ssh': '/usr/bin/ssh', 'ssh_keygen': '/usr/bin/ssh-keygen',
         'systemctl': '/usr/bin/systemctl', 'systemd_run': '/usr/bin/systemd-run',
         'busctl': '/usr/bin/busctl', 'python': '/usr/bin/python3'}
VERSION_ARGS = {'qemu': ('--version',), 'qemu_img': ('--version',), 'ssh': ('-V',),
                'systemctl': ('--version',), 'systemd_run': ('--version',),
                'busctl': ('--version',), 'python': ('--version',)}
VERSION_PATTERNS = {'qemu': rb'QEMU emulator version ([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)(?: |$)',
                    'qemu_img': rb'qemu-img version ([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)(?: |$)',
                    'ssh': rb'OpenSSH_([0-9]{1,6}\.[0-9]{1,6}p[0-9]{1,6})(?:[ ,]|$)',
                    'python': rb'Python ([0-9]+\.[0-9]+\.[0-9]+)',
                    **{k: rb'systemd ([0-9]{1,6})' for k in ('systemctl', 'systemd_run', 'busctl')}}
COLLECTION_SECONDS = 60
CLEANUP_SECONDS = 10
CHILD_SECONDS = 2
CHILD_BYTES = 4096
CHILD_MAX = 16
TOOL_BYTES = 128 * 1024**2
HASH_BYTES = 512 * 1024**2
REPORT_BYTES = 65536
PUBLIC_BYTES = 81920
FILE_BYTES = 4096
CLEAN_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
             'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
             'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
             'GIT_OPTIONAL_LOCKS': '0'}
GAPS = ['provider-image-digest-unattested', 'publisher-loader-libraries-unattested',
        'native-tool-manifest-unreviewed', 'ancestor-effective-limits-unobserved',
        'transient-unit-and-guest-execution-unproved', 'later-host-instance-unbound']


@contextmanager
def registered_acquisition():
    """Defer cancellation only until an owned resource has its cleanup handle."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGTERM, signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class Refusal(Exception):
    """Only fixed source-selected codes reach public output."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class Session:
    def __init__(self):
        self.start = time.monotonic()
        self.end = self.start + COLLECTION_SECONDS
        self.absolute_end = self.end + CLEANUP_SECONDS
        self.cleanup_end = self.absolute_end
        self.hashed = 0
        self.children = []
        self.children_started = 0
        self.uncertain = False
        self.scratch = None
        self.fds = set()

    def begin(self):
        with registered_acquisition():
            self.scratch = Path(tempfile.mkdtemp(prefix='kubernetes-lens-hosted-'))

    def check(self):
        require(time.monotonic() < self.end, 'observation-timeout')
        require(not self.uncertain, 'cleanup-uncertain')
        require(not CANCELLED, 'cancelled-or-deadline')

    def retire(self, process):
        if process.returncode is not None:
            return
        # Every child has its own session. The unreaped leader retains its PID;
        # signal only that collector-created group, never a manager or other job.
        retire_end = min(self.cleanup_end, time.monotonic() + CLEANUP_SECONDS)
        for sig, grace in ((signal.SIGTERM, 0.2), (signal.SIGKILL, CLEANUP_SECONDS)):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            except OSError:
                self.uncertain = True
            try:
                process.wait(timeout=max(0, min(grace, retire_end - time.monotonic())))
                return
            except subprocess.TimeoutExpired:
                pass
        self.uncertain = True

    def run(self, argv):
        self.check()
        require(self.children_started < CHILD_MAX, 'child-count-limit')
        self.children_started += 1
        process = None
        output = [bytearray(), bytearray()]
        try:
            end = min(self.end, time.monotonic() + CHILD_SECONDS)
            with registered_acquisition():
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, cwd=self.scratch, env=CLEAN_ENV,
                                           close_fds=True, start_new_session=True)
                self.children.append(process)
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    remaining = end - time.monotonic()
                    require(remaining > 0, 'child-timeout')
                    for key, _events in selector.select(remaining):
                        data = os.read(key.fileobj.fileno(), CHILD_BYTES + 1)
                        if not data:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.data].extend(data)
                            require(sum(map(len, output)) <= CHILD_BYTES, 'child-output-limit')
                try:
                    code = process.wait(timeout=max(0, end - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise Refusal('child-timeout') from error
            return code, bytes(output[0]), bytes(output[1])
        except Refusal:
            if process is not None:
                self.uncertain = True
            raise
        except OSError as error:
            if process is not None:
                self.uncertain = True
            raise Refusal('child-unavailable') from error
        finally:
            if process is not None:
                # Close readers even on cancellation/oversize before owned reap.
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            self.uncertain = True
                self.retire(process)

    def cleanup(self):
        for child in self.children:
            self.retire(child)
        for fd in tuple(self.fds):
            self.close(fd)
        removed = self.scratch is None
        if self.scratch is not None:
            try:
                # Fixed queries create no files. Unexpected contents are not
                # recursively followed or disclosed; cleanup remains incomplete.
                self.scratch.rmdir()
                removed = True
            except OSError:
                self.uncertain = True
        return {'children_started': self.children_started,
                'children_reaped': all(c.returncode is not None for c in self.children),
                'owned_readers_closed': all(c.stdout.closed and c.stderr.closed for c in self.children),
                'fds_closed': not self.fds, 'scratch_removed': removed, 'complete': not self.uncertain and not self.fds and removed
                and all(c.returncode is not None and c.stdout.closed and c.stderr.closed for c in self.children)}

    def close(self, fd):
        try:
            with registered_acquisition():
                os.close(fd)
                self.fds.discard(fd)
        except OSError:
            self.uncertain = True

    def open(self, path, flags):
        with registered_acquisition():
            fd = os.open(path, flags)
            self.fds.add(fd)
        return fd

    def file(self, path, cap=FILE_BYTES):
        self.check()
        fd = self.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            self.check()
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode), 'file-type')
            raw = os.read(fd, cap + 1)
            require(len(raw) <= cap, 'file-size')
            require(identity(before) == identity(os.fstat(fd)) == identity(os.lstat(path)), 'file-changed')
            return raw
        finally:
            self.close(fd)

    def hashed_file(self, path, cap):
        self.check()
        fd = self.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'hash-file-type-or-size')
            require(before.st_size <= HASH_BYTES - self.hashed, 'hash-budget')
            h = hashlib.sha256()
            size = 0
            prefix = b''
            while size < before.st_size:
                self.check()
                raw = os.read(fd, min(65536, before.st_size - size))
                require(bool(raw), 'hash-file-changed')
                prefix = (prefix + raw)[:4]
                size += len(raw)
                self.hashed += len(raw)
                h.update(raw)
            require(size == before.st_size and identity(before) == identity(os.fstat(fd))
                    == identity(os.lstat(path)), 'hash-file-changed')
            return before, h.hexdigest(), prefix
        finally:
            self.close(fd)


def candidate(session, expected, env):
    require(re.fullmatch('[0-9a-f]{40}', expected) is not None, 'candidate-binding')
    fixed = {'HN_EVENT': 'workflow_dispatch', 'HN_REF': 'refs/heads/main',
             'HN_REPOSITORY': REPOSITORY, 'HN_SOURCE_SHA': expected, 'HN_WORKFLOW_SHA': expected,
             'HN_WORKFLOW_REF': REPOSITORY + '/' + WORKFLOW + '@refs/heads/main',
             'HN_RUNNER_OS': 'Linux', 'HN_RUNNER_ARCH': 'X64', 'HN_RUNNER_ENVIRONMENT': 'github-hosted'}
    require(all(env.get(k) == v for k, v in fixed.items()), 'candidate-binding')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', env.get(k, '')) for k in ('HN_RUN_ID', 'HN_RUN_ATTEMPT')),
            'candidate-binding')
    git = ['/usr/bin/git', '--no-optional-locks', '-C', str(ROOT), '-c', 'core.fsmonitor=false']
    code, out, _err = session.run([*git, 'rev-parse', '--verify', 'HEAD'])
    require(code == 0 and out == (expected + '\n').encode(), 'source-binding')
    code, out, _err = session.run([*git, 'status', '--porcelain=v1', '--untracked-files=all'])
    require(code == 0 and not out, 'source-binding')
    hashes = {}
    for path in (WORKFLOW, 'scripts/fixtures/hosted_native_prerequisites.py',
                 'scripts/test-repository-policy.py', '.github/renovate.json'):
        _info, value, _prefix = session.hashed_file(ROOT / path, 1024**2)
        hashes[path] = value
    return {'source_sha': expected, 'workflow_sha': expected, 'workflow_ref': fixed['HN_WORKFLOW_REF'],
            'event': fixed['HN_EVENT'], 'ref': fixed['HN_REF'], 'repository': REPOSITORY,
            'run_id': env['HN_RUN_ID'], 'run_attempt': env['HN_RUN_ATTEMPT'],
            'runner_os': 'Linux', 'runner_arch': 'X64', 'runner_environment': 'github-hosted',
            'source_file_sha256': hashes}


def tool_identity(session, supplied):
    session.check()
    path = Path(supplied).resolve(strict=True)
    require(str(path).startswith('/usr/') and len(str(path)) <= 512, 'tool-path')
    for ancestor in path.parents:
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'tool-ancestor')
    info, value, prefix = session.hashed_file(path, TOOL_BYTES)
    require(prefix == b'\x7fELF' and info.st_uid == 0 and info.st_mode & 0o111
            and not info.st_mode & 0o6022, 'tool-authority')
    try:
        caps = os.getxattr(path, 'security.capability', follow_symlinks=False)
    except OSError as error:
        require(error.errno == errno.ENODATA, 'tool-capability-unknown')
        caps = b''
    require(not caps, 'tool-capability')
    require(identity(info) == identity(path.lstat()), 'tool-changed')
    return {'path': str(path), 'sha256': value, 'bytes': info.st_size, 'dev': info.st_dev,
            'ino': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns,
            'ctime_ns': info.st_ctime_ns, 'root_ancestors': True, 'set_id': False,
            'file_capabilities': False, 'publisher_loader_libraries_attested': False}


def tools(session):
    result = {}
    for role, path in TOOLS.items():
        try:
            item = tool_identity(session, path)
        except FileNotFoundError:
            result[role] = {'status': 'missing'}
            continue
        except (OSError, Refusal):
            result[role] = {'status': 'unknown'}
            continue
        version = None
        provenance = 'fixed-executable-version-query'
        try:
            if role == 'ssh_keygen':
                provenance = 'installed-package:openssh-client; upstream numeric prefix only, not an executable-version assertion'
                package_query = tool_identity(session, '/usr/bin/dpkg-query')
                code, out, _err = session.run([package_query['path'], '--show', '--showformat=${Version}',
                                               'openssh-client'])
                match = re.match(rb'(?:[0-9]{1,6}:)?([0-9]{1,6}\.[0-9]{1,6}p[0-9]{1,6})(?:[-+~.]|$)', out) if code == 0 else None
                if match:
                    version = match.group(1).decode('ascii')
            else:
                code, out, err = session.run([item['path'], *VERSION_ARGS[role]])
                match = re.match(VERSION_PATTERNS[role], out or err) if code == 0 else None
                version = match.group(1).decode('ascii') if match else None
        except (OSError, Refusal):
            pass
        item.update(status='observed' if version is not None else 'unknown', version=version,
                    version_provenance=provenance)
        result[role] = item
    return result


def kvm(session):
    session.check()
    fd = None
    try:
        info = os.lstat('/dev/kvm')
        if not stat.S_ISCHR(info.st_mode):
            return {'status': 'unsupported'}
        fd = session.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        require(identity(info) == identity(os.fstat(fd)), 'kvm-changed')
        session.check()
        api = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION only; never KVM_CREATE_VM.
        return {'status': 'observed' if api == 12 else 'unsupported', 'api_version': api if api == 12 else None}
    except FileNotFoundError:
        return {'status': 'missing'}
    except PermissionError:
        return {'status': 'denied'}
    except (OSError, Refusal):
        return {'status': 'unknown'}
    finally:
        if fd is not None:
            session.close(fd)


def cgroup_path(raw):
    require(raw.startswith('/') and len(raw) <= 1024 and '\x00' not in raw, 'cgroup-path')
    require(all(part not in ('', '.', '..') for part in (raw.split('/')[1:] if raw != '/' else [])), 'cgroup-path')
    path = Path('/sys/fs/cgroup') / raw[1:]
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'cgroup-symlink')
    return path


def cgroup(session, raw):
    try:
        session.check()
        path = cgroup_path(raw)
        values = {}
        for name in ('cgroup.controllers', 'cgroup.subtree_control', 'cpu.max', 'memory.max',
                     'pids.max', 'cpuset.cpus.effective'):
            value = session.file(path / name).decode('ascii').strip()
            if name.startswith('cgroup.'):
                require(re.fullmatch(r'[a-z ]*', value) is not None, 'cgroup-value')
                values[name] = [v for v in value.split() if v in ('cpu', 'memory', 'pids', 'cpuset', 'io')]
            elif name == 'cpu.max':
                require(re.fullmatch(r'(max|[1-9][0-9]{0,19}) [1-9][0-9]{0,19}', value) is not None, 'cgroup-value')
                values[name] = value
            elif name == 'cpuset.cpus.effective':
                require(re.fullmatch(r'[0-9,-]{1,1024}', value) is not None, 'cgroup-value')
                values[name] = value
            else:
                require(re.fullmatch(r'max|0|[1-9][0-9]{0,19}', value) is not None, 'cgroup-value')
                values[name] = value
        writable = os.access(path / 'cgroup.subtree_control', os.W_OK, effective_ids=True)
        return {'status': 'observed', 'local_values': values, 'subtree_control_writable_indicator': writable,
                'required_controllers_present': {'cpu', 'memory', 'pids'} <= set(values['cgroup.controllers']),
                'ancestor_effective_cpu_memory_pids_limits': 'unknown-not-observed',
                'leaf_limits_are_global_effective_limits': False}
    except FileNotFoundError:
        return {'status': 'missing', 'ancestor_effective_cpu_memory_pids_limits': 'unknown-not-observed'}
    except (OSError, ValueError, Refusal):
        return {'status': 'unknown', 'ancestor_effective_cpu_memory_pids_limits': 'unknown-not-observed'}


def property_value(session, bus, address, object_path, interface, name, kind):
    code, out, err = session.run([bus, '--address=' + address, '--auto-start=no', '--no-pager',
                                  '--timeout=2s', '--json=short', 'call',
                                  'org.freedesktop.systemd1', object_path,
                                  'org.freedesktop.DBus.Properties', 'Get', 'ss', interface, name])
    if code:
        raise Refusal('manager-query-unknown')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'manager-query-invalid')
            result[key] = value
        return result
    try:
        data = json.loads(out, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as error:
        raise Refusal('manager-query-invalid') from error
    require(type(data) is dict and set(data) == {'type', 'data'} and data['type'] == 'v'
            and type(data['data']) is list and len(data['data']) == 1, 'manager-query-invalid')
    child = data['data'][0]
    require(type(child) is dict and set(child) == {'type', 'data'}
            and kind in ('s', 'b') and child['type'] == kind, 'manager-query-invalid')
    value = child['data']
    require(type(value) is (str if kind == 's' else bool), 'manager-query-invalid')
    return value


def manager(session, tool, uid):
    result = {'status': 'unknown', 'no_autostart': True,
              'scope': 'existing-own-UID-user-manager-init.scope', 'transient_unit_creation_proved': False,
              'diagnostics': []}
    def reason(error):
        if isinstance(error, FileNotFoundError):
            return 'missing'
        if isinstance(error, PermissionError):
            return 'denied'
        if isinstance(error, OSError):
            return 'os-error'
        # Lookup values are closed literals; never stringify or return exception data.
        known = {
            'manager-endpoint': 'unsafe-endpoint', 'manager-version': 'invalid-version',
            'manager-query-invalid': 'invalid-property', 'manager-query-unknown': 'query-failed',
            'manager-cgroup-scope': 'foreign-cgroup-scope',
            'observation-timeout': 'observation-timeout', 'cleanup-uncertain': 'cleanup-uncertain',
            'cancelled-or-deadline': 'cancelled-or-deadline', 'child-count-limit': 'child-count-limit',
            'child-timeout': 'child-timeout', 'child-output-limit': 'child-output-limit',
            'child-unavailable': 'child-unavailable', 'cgroup-path': 'invalid-cgroup-path',
            'cgroup-symlink': 'cgroup-symlink', 'cgroup-value': 'invalid-cgroup-value',
            'file-type': 'file-type', 'file-size': 'file-size', 'file-changed': 'file-changed',
        }
        code = error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else None
        return known.get(code, 'unknown')

    stage = 'deadline'
    try:
        session.check()
        stage = 'endpoint'
        path = Path('/run/user') / str(uid) / 'bus'
        parent, info = path.parent.lstat(), path.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == uid and not parent.st_mode & 0o077
                and stat.S_ISSOCK(info.st_mode) and info.st_uid == uid, 'manager-endpoint')
        address = 'unix:path=' + str(path)
        stage = 'version-query'
        property_value(session, tool, address, '/org/freedesktop/systemd1',
                       'org.freedesktop.systemd1.Manager', 'Version', 's')
        result['version_property'] = 'informational-string-observed-raw-omitted'
        unit = '/org/freedesktop/systemd1/unit/init_2escope'
        stage = 'cgroup-query'
        raw = property_value(session, tool, address, unit, 'org.freedesktop.systemd1.Scope', 'ControlGroup', 's')
        stage = 'cgroup-scope'
        require(raw.startswith(f'/user.slice/user-{uid}.slice/user@{uid}.service/'), 'manager-cgroup-scope')
        stage = 'cgroup-read'
        result['cgroup'] = cgroup(session, raw)
        if result['cgroup']['status'] != 'observed':
            # cgroup() intentionally keeps its underlying read error private.
            result['diagnostics'].append({'stage': 'cgroup-read', 'reason':
                                          {'missing': 'missing'}.get(result['cgroup']['status'], 'unknown')})
        stage = 'delegate-query'
        result['delegate_property'] = property_value(session, tool, address, unit,
                                                     'org.freedesktop.systemd1.Scope', 'Delegate', 'b')
        result['status'] = 'observed'
    except (OSError, Refusal) as error:
        if isinstance(error, FileNotFoundError):
            result['status'] = 'missing' if 'version_property' not in result else 'unknown'
        result['diagnostics'].append({'stage': stage, 'reason': reason(error)})
    return result


def observe(session, env):
    session.check()
    require(sys.platform == 'linux' and os.geteuid() > 0, 'host-platform')
    uname = os.uname()
    require(re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(?:-[0-9]{1,6})?(?:-(?:generic|azure|aws|gcp))?', uname.release) is not None, 'kernel-metadata')
    image = {}
    for name in ('ImageOS', 'ImageVersion'):
        value = env.get('HN_' + name, '')
        pattern = r'ubuntu[0-9]{2}' if name == 'ImageOS' else r'[0-9]{8}\.[0-9]{1,8}\.[0-9]{1,8}'
        require(not value or re.fullmatch(pattern, value) is not None, 'provider-metadata')
        image[name] = value or None
    inventory = tools(session)
    own = session.file('/proc/self/cgroup', 1024).decode('ascii')
    require(own.startswith('0::/') and own.endswith('\n') and own.count('\n') == 1, 'own-cgroup-v2')
    user = manager(session, inventory['busctl']['path'], os.geteuid()) if inventory['busctl']['status'] == 'observed' else {'status': 'unknown', 'no_autostart': True}
    return {'host': {'architecture': uname.machine if uname.machine in ('x86_64', 'aarch64') else 'unsupported',
                     'kernel_release': uname.release, 'image': image, 'provider_image_digest_attested': False,
                     'interpreter': {'version': '.'.join(map(str, sys.version_info[:3])),
                                     'executable_matches_python_role': os.path.realpath(sys.executable) == inventory.get('python', {}).get('path')}},
            'tools': inventory, 'kvm': kvm(session), 'user_manager': user,
            'job_cgroup': cgroup(session, own[3:].strip())}


def outcome(facts, cleanup, failure):
    if failure or not cleanup.get('complete') or not facts:
        return 'incomplete-invalid', 'unknown'
    rows = [*facts['tools'].values(), facts['kvm'], facts['user_manager'], facts['job_cgroup']]
    if facts['user_manager']['status'] == 'observed':
        rows.append(facts['user_manager']['cgroup'])
    if (not facts['host']['interpreter']['executable_matches_python_role']
            or any(row['status'] == 'unknown' for row in rows)):
        return 'incomplete-invalid', 'unknown'
    missing = any(row['status'] in ('missing', 'denied', 'unsupported') for row in rows)
    missing |= facts['host']['architecture'] != 'x86_64'
    for row in rows:
        if 'required_controllers_present' in row:
            missing |= not row['required_controllers_present'] or not row['subtree_control_writable_indicator']
    missing |= facts['user_manager'].get('delegate_property') is False
    return ('complete-missing-unsupported', 'missing') if missing else ('complete-compatible-indicators', 'unknown')


def frame(report):
    raw = encode(report)
    require(len(raw) <= REPORT_BYTES, 'report-output-limit')
    digest = hashlib.sha256(raw).hexdigest()
    payload = (b'HOSTED_NATIVE_PREREQUISITES_V1_BEGIN\n' + raw + b'\nsha256:' + digest.encode()
               + b'\nHOSTED_NATIVE_PREREQUISITES_V1_END\n')
    status = report.get('observation_outcome', 'incomplete-invalid')
    require(status in ('complete-compatible-indicators', 'complete-missing-unsupported', 'incomplete-invalid'), 'report-output-limit')
    payload += ('Hosted prerequisite observation: ' + status + '; native_admission=false\n').encode('ascii')
    require(len(payload) <= PUBLIC_BYTES, 'public-output-limit')
    return payload


def arm_deadline(deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'final-output-deadline')
    signal.setitimer(signal.ITIMER_REAL, remaining)


def output_check(deadline):
    require(not CANCELLED and time.monotonic() < deadline, 'final-output-deadline')


def write_stdout(payload, deadline):
    """Borrow stdout FD1 without buffering, flushing, closing or changing its flags."""
    offset = 0
    view = memoryview(payload)
    while offset < len(view):
        output_check(deadline)
        written = os.write(1, view[offset:offset + 4096])
        require(written > 0, 'final-output-unavailable')
        offset += written
    output_check(deadline)


def _collect(session, expected, env, emit):
    binding, facts, failure = None, {}, None
    try:
        session.begin()
        binding = candidate(session, expected, env)
        facts = observe(session, env)
        session.check()
    except Refusal as error:
        failure = str(error) if str(error) in {
            'candidate-binding', 'source-binding', 'observation-timeout', 'cleanup-uncertain',
            'child-timeout', 'child-output-limit', 'child-count-limit', 'child-unavailable',
            'host-platform', 'kernel-metadata', 'provider-metadata', 'own-cgroup-v2',
            'file-type', 'file-size', 'file-changed', 'hash-file-type-or-size',
            'hash-budget', 'hash-file-changed', 'cancelled-or-deadline'} else 'observation-unavailable'
    except (OSError, ValueError, UnicodeError, KeyError, RecursionError):
        failure = 'observation-unavailable'
    finally:
        session.cleanup_end = min(session.cleanup_end, time.monotonic() + CLEANUP_SECONDS)
        arm_deadline(session.cleanup_end)
        try:
            cleanup = session.cleanup()
        except (OSError, Refusal):
            cleanup = {'complete': False, 'children_reaped': False, 'owned_readers_closed': False,
                       'fds_closed': False, 'scratch_removed': False, 'children_started': session.children_started}
    arm_deadline(session.absolute_end)
    output_check(session.absolute_end)
    status, decision = outcome(facts, cleanup, failure)
    report = {'schema': 'kubernetes-lens-hosted-native-prerequisites-v1', 'binding': binding,
              'observation_outcome': status, 'prerequisite_decision': decision,
              'required_native_prerequisites': 'unknown', 'native_admission': False,
              'failure': failure, 'facts': facts, 'cleanup': cleanup, 'remaining_gaps': GAPS,
              'bounds': {'collection_seconds': COLLECTION_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
                         'child_seconds': CHILD_SECONDS, 'child_bytes': CHILD_BYTES, 'child_count': CHILD_MAX,
                         'tool_hash_bytes': TOOL_BYTES, 'total_hash_bytes': HASH_BYTES,
                         'report_bytes': REPORT_BYTES, 'public_bytes': PUBLIC_BYTES}}
    try:
        payload = frame(report)
    except (Refusal, ValueError) as error:
        if isinstance(error, Refusal) and str(error) != 'report-output-limit':
            raise
        output_check(session.absolute_end)
        report.update(facts={}, binding=None, observation_outcome='incomplete-invalid',
                      prerequisite_decision='unknown', failure='report-output-limit')
        payload = frame(report)
    output_check(session.absolute_end)
    emit(payload, session.absolute_end)
    output_check(session.absolute_end)
    return (1 if report['observation_outcome'] == 'incomplete-invalid' else 0), payload


def collect(expected, env, *, emit):
    try:
        return _collect(Session(), expected, env, emit)
    except (Refusal, OSError, ValueError, UnicodeError, RecursionError):
        # Finalization failure can leave no frame or a partial frame. Never retry
        # with a replacement complete record, and never leave buffered output.
        return 1, b''
    finally:
        # The original deadline remains armed through framing and every write.
        # Disarm only after successful emission or the failed outer exit path.
        signal.setitimer(signal.ITIMER_REAL, 0)


def cancelled(_number, _frame):
    global CANCELLED
    CANCELLED = True
    raise Refusal('cancelled-or-deadline')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source-sha', required=True)
    args = parser.parse_args()
    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, cancelled)
    signal.setitimer(signal.ITIMER_REAL, COLLECTION_SECONDS)
    code, _payload = collect(args.expected_source_sha, os.environ, emit=write_stdout)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
