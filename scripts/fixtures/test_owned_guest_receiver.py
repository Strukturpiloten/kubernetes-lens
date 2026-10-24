"""Pure finite receiver protocol checks using task-private files and Bash.

The test projection replaces only the guest/package/UID prerequisite prelude and
fixed guest paths. It is not an installed-guest or native-tool qualification.
No Podman, SSH, VM, service, registry or Kubernetes program is invoked.
"""
from copy import deepcopy
import gzip
import hashlib
import io
import os
from pathlib import Path
import subprocess
import signal
import select
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import owned_guest_stage as stage
import owned_qemu as vm


class OwnedPipeChild:
    """Test-only private group ownership held by an unreaped actual Popen child.

    WNOWAIT observes exit without releasing the session/group leader's PID. The
    only final wait occurs after signaling that still-owned group (or ESRCH).
    This controls these finite fixture programs; it is not a runtime observer or
    a guarantee against descendants deliberately leaving their private group.
    """
    def __init__(self, argv, register_cleanup):
        self.end = time.monotonic() + 5
        self.work_end = self.end - 1
        self.process = None
        self.retired = False
        self.output = {"stdout": bytearray(), "stderr": bytearray()}
        self.open_outputs = {"stdout", "stderr"}
        self.eof_outputs = set()
        self.result = None
        # Retain this owner even if pipe setup fails after Popen succeeds.
        register_cleanup(self.retire)
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        for stream in (self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)

    def remaining(self, *, cleanup=False):
        remaining = (self.end if cleanup else self.work_end) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("private test child original deadline expired")
        return remaining

    def running(self):
        if self.retired:
            return False
        if self.process.returncode is not None:
            raise AssertionError("private test leader reaped before group cleanup")
        try:
            status = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as error:
            raise AssertionError("private test leader wait ownership lost") from error
        return status is None

    def read_available(self, *, cleanup=False):
        self.open_outputs = {name for name in self.open_outputs if not getattr(self.process, name).closed}
        streams = {getattr(self.process, name).fileno(): name for name in self.open_outputs}
        if not streams:
            return
        ready, _, _ = select.select(list(streams), [], [], min(0.005, self.remaining(cleanup=cleanup)))
        for descriptor in ready:
            name = streams[descriptor]
            try:
                raw = os.read(descriptor, 65536)
            except (BlockingIOError, InterruptedError):
                continue
            if not raw:
                self.open_outputs.remove(name)
                self.eof_outputs.add(name)
            else:
                if len(self.output["stdout"]) + len(self.output["stderr"]) + len(raw) > 65536:
                    raise AssertionError("private test child output budget exceeded")
                self.output[name].extend(raw)

    def wait_exited(self):
        while self.running():
            self.remaining()
            self.read_available()
            time.sleep(min(0.005, self.remaining()))
        # Do not wait for descendants' pipe EOF before killing the owned group.
        return False

    def close_input(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()

    def retire(self):
        if self.retired:
            return self.result
        if self.process is None:
            self.retired = True
            return None
        failure = None
        signaled = False
        try:
            # Even after natural leader exit, retained wait ownership prevents
            # its PID/PGID from being recycled before this group signal.
            if self.process.returncode is not None:
                raise AssertionError("private test leader reaped before group cleanup")
            try:
                os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError as error:
                raise AssertionError("private test leader wait ownership lost") from error
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # Already absent group; leader still belongs to this wait.
            signaled = True
            status = self.process.wait(timeout=self.remaining(cleanup=True))
            self.retired = True
            while self.open_outputs:
                self.read_available(cleanup=True)
            self.result = subprocess.CompletedProcess(self.process.args, status,
                bytes(self.output["stdout"]), bytes(self.output["stderr"]))
        except BaseException as error:
            failure = error
        finally:
            # One close failure must not suppress the others. In particular,
            # signal/wait/read errors never skip closure of any owned stream.
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    failure = failure or error
            if not signaled:
                # Keep the actual leader unreaped and retain this object for a
                # bounded caller cleanup retry. Reaping here could lose the only
                # authority to signal descendants after a failed killpg attempt.
                self.retired = False
        if failure is not None:
            raise failure
        return self.result

    def finish(self):
        failure = None
        try:
            self.close_input()
            self.wait_exited()
        except BaseException as error:
            failure = error
        try:
            result = self.retire()
        except BaseException:
            if failure is None:
                raise
        if failure is not None:
            raise failure
        return result


class OwnedPipeChildControls(unittest.TestCase):
    """Ordinary child wait/signal tests; no VM, service or runtime tooling."""
    def child(self, code="pass"):
        child = OwnedPipeChild([sys.executable, "-I", "-B", "-c", code], self.addCleanup)
        return child

    def assert_closed(self, child):
        self.assertTrue(all(stream.closed for stream in
            (child.process.stdin, child.process.stdout, child.process.stderr)))

    def test_exited_unreaped_leader_retains_group_authority_over_live_descendant(self):
        descendant = ("import signal,sys,time; signal.alarm(5); "
                      "print('descendant-ready',flush=True); time.sleep(5); "
                      "print('descendant-survived',flush=True)")
        leader = ("import os,subprocess,sys; "
                  "subprocess.Popen([sys.executable,'-I','-B','-c'," + repr(descendant) + "]); os._exit(0)")
        child = self.child(leader)
        while b"descendant-ready\n" not in child.output["stdout"]:
            child.remaining()
            child.read_available()
        child.wait_exited()
        self.assertIsNone(child.process.returncode)  # WNOWAIT, never poll/reap.
        self.assertFalse(child.running())
        self.assertNotIn("stdout", child.eof_outputs)  # Descendant still holds it.
        called = []
        original_killpg = os.killpg
        def signal_owned(group, number):
            self.assertIsNone(child.process.returncode)
            called.append((group, number))
            return original_killpg(group, number)
        with patch.object(os, "killpg", side_effect=signal_owned):
            result = child.retire()
            self.assertIs(child.retire(), result)  # No numeric group reuse.
        self.assertEqual(called, [(child.process.pid, signal.SIGKILL)])
        self.assertEqual(result.returncode, 0)  # Natural leader exit preserved.
        self.assertEqual(result.stdout, b"descendant-ready\n")
        self.assertEqual(child.eof_outputs, {"stdout", "stderr"})
        self.assertLess(time.monotonic(), child.work_end)  # Before child's alarm.
        self.assert_closed(child)

    def test_absent_group_still_reaps_the_owned_leader_and_closes_every_stream(self):
        child = self.child()
        child.wait_exited()
        self.assertIsNone(child.process.returncode)
        with patch.object(os, "killpg", side_effect=ProcessLookupError) as kill:
            result = child.retire()
            self.assertIs(child.retire(), result)
        kill.assert_called_once_with(child.process.pid, signal.SIGKILL)
        self.assertEqual(result.returncode, 0)
        self.assert_closed(child)

    def test_signal_error_closes_all_streams_but_retains_wait_ownership_for_retry(self):
        child = self.child()
        child.wait_exited()
        with patch.object(os, "killpg", side_effect=PermissionError("injected test failure")):
            with self.assertRaises(PermissionError):
                child.retire()
        self.assertIsNone(child.process.returncode)
        self.assertFalse(child.retired)
        self.assert_closed(child)
        self.assertEqual(child.retire().returncode, 0)

    def test_wait_error_does_not_skip_stream_closure_or_reap_without_group_signal(self):
        child = self.child()
        child.wait_exited()
        with patch.object(child.process, "wait", side_effect=subprocess.TimeoutExpired("test-child", 0)):
            with self.assertRaises(subprocess.TimeoutExpired):
                child.retire()
        self.assertIsNone(child.process.returncode)
        self.assert_closed(child)
        self.assertEqual(child.retire().returncode, 0)

    def test_one_close_exception_cannot_skip_the_other_streams(self):
        child = self.child()
        child.wait_exited()
        original = child.process.stdin
        class FailingClose:
            @property
            def closed(self):
                return original.closed
            def close(self):
                original.close()
                raise OSError("injected close failure")
        child.process.stdin = FailingClose()
        with self.assertRaisesRegex(OSError, "injected close failure"):
            child.retire()
        self.assert_closed(child)
        self.assertEqual(child.retire().returncode, 0)

    def test_pipe_setup_exception_keeps_registered_owner_for_group_cleanup(self):
        cleanups = []
        with patch.object(os, "set_blocking", side_effect=OSError("injected pipe setup failure")):
            with self.assertRaisesRegex(OSError, "injected pipe setup failure"):
                OwnedPipeChild([sys.executable, "-I", "-B", "-c", "import time; time.sleep(2)"], cleanups.append)
        self.assertEqual(len(cleanups), 1)
        child = cleanups[0].__self__
        self.addCleanup(child.retire)
        self.assertIsNone(child.process.returncode)
        child.retire()
        self.assertTrue(child.retired)
        self.assert_closed(child)

    def test_detected_reaped_leader_never_authorizes_a_recycled_numeric_group(self):
        # Pure fake only: no real child is deliberately reaped early by this test.
        child = object.__new__(OwnedPipeChild)
        child.retired = False
        child.process = Mock(returncode=0, pid=424242,
            stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO())
        with patch.object(os, "killpg") as kill, patch.object(os, "waitid") as wait:
            with self.assertRaisesRegex(AssertionError, "leader reaped before group cleanup"):
                child.retire()
        kill.assert_not_called()
        wait.assert_not_called()
        self.assert_closed(child)


class ReceiverProtocol(unittest.TestCase):
    def setUp(self):
        self.prepare()

    def prepare(self, payload=b"abc"):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.plan_raw = vm.encode({"schema": "kubernetes-lens-owned-guest-stage-plan-v1", "owner": "a" * 32,
            "profile": "modern-1.37.0", "files": {role: {"path": "/tmp/" + role, "bytes": len(payload),
                "sha256": vm.digest(payload)} for role in stage.ROLES}})
        self.plan = stage.parse_plan(self.plan_raw, vm.digest(self.plan_raw))
        source = Path(stage.__file__).with_name("owned_guest_receiver.sh").read_text()
        self.original = source
        begin = source.index('[[ $# == 0')
        end = source.index('cd "$root"')
        source = source[:begin] + '[[ $# == 0 ]] || fail\n' + source[end:]
        source = source.replace('readonly root=/var/lib/kubernetes-lens-stage', 'readonly root=' + str(self.root))
        source = source.replace('readonly receiver=/var/lib/kubernetes-lens-stage/receiver',
                                'readonly receiver=' + str(self.root / "receiver"))
        source = source.replace('readonly boot_path=/proc/sys/kernel/random/boot_id',
                                'readonly boot_path=' + str(self.root / "boot"))
        source = source.replace('== 0:600:1', '== ' + str(os.getuid()) + ':600:1')
        files = stage.guest_files(self.plan_raw, source.encode())
        for path, (raw, mode) in files.items():
            if path.endswith("checks.sha256"):
                continue
            name = "receiver" if path.endswith("-receiver") else Path(path).name
            target = self.root / name
            target.write_bytes(raw)
            target.chmod(mode)
        self.boot = b"00000000-1111-2222-3333-444444444444\n"
        (self.root / "boot").write_bytes(self.boot)
        checks = "".join(vm.digest((self.root / ("receiver" if path.endswith("-receiver") else Path(path).name)).read_bytes())
                         + "  " + str(self.root / ("receiver" if path.endswith("-receiver") else Path(path).name)) + "\n"
                         for path in files if not path.endswith(("/lock", "/checks.sha256")))
        (self.root / "checks.sha256").write_text(checks)
        (self.root / "checks.sha256").chmod(0o400)

    def tearDown(self):
        self.temp.cleanup()

    def exchange(self, raw):
        return subprocess.run(["/usr/bin/bash", str(self.root / "receiver")], input=raw,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False)

    def test_actual_byte_protocol_in_order_and_complete_no_replay(self):
        for phase, role in zip(stage.PHASES, stage.ROLES):
            result = self.exchange(phase.encode() + b"\nabc")
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = stage.reply(result.stdout, self.plan, phase, self.plan.files[stage.ROLES.index(role)])
            self.assertEqual(parsed["state"], "stage-reply-observed")
            target = self.root / stage.GUEST_NAMES[role]
            self.assertEqual(target.read_bytes(), b"abc")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600 if role == "node-oci" else 0o700)
        self.assertIn(b" complete 3\n", (self.root / "state").read_bytes())
        self.assertNotEqual(self.exchange(b"stage-node-oci\nabc").returncode, 0)

    def test_header_nul_crlf_truncation_extra_and_wrong_cursor_poison(self):
        for wire in (b"stage-kin\x00\nabc", b"stage-kind\r\nabc", b"stage-kind\n\nabc", b"stage-kind", b"stage-kubectl\nabc",
                     b"stage-kind\nabc\x00", b"stage-kind\nab", b"stage-kind\nabd", b"stage-kind\nabcstage-kind\nabc"):
            with self.subTest(wire=wire):
                # Fresh private projection, never recovering a poisoned run.
                self.tearDown()
                self.setUp()
                result = self.exchange(wire)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertFalse((self.root / "kind").exists())
                self.assertIn(b" poisoned 0\n", (self.root / "state").read_bytes())
                self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)

    def test_reboot_inflight_foreign_state_and_existing_destination_refuse(self):
        for state in (b"inflight 0", b"poisoned 0", b"complete 3", b"ready 2"):
            self.tearDown()
            self.setUp()
            record = b"v1 " + b"a" * 32 + b" " + self.plan.sha256.encode() + b" modern-1.37.0 " + self.boot.strip() + b" " + state + b"\n"
            (self.root / "state").write_bytes(record)
            (self.root / "state").chmod(0o600)
            self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
        self.tearDown()
        self.setUp()
        self.assertEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
        (self.root / "boot").write_bytes(b"99999999-1111-2222-3333-444444444444\n")
        self.assertNotEqual(self.exchange(b"stage-kubectl\nabc").returncode, 0)
        self.assertFalse((self.root / "kubectl").exists())

    def test_persistent_state_binding_is_literal_and_exact_raw_bytes(self):
        for suffix in (b"\n\n", b"\x00\n"):
            self.tearDown()
            self.setUp()
            record = b"v1 " + b"a" * 32 + b" " + self.plan.sha256.encode() + b" modern-1.37.0 " + self.boot.strip() + b" ready 0"
            (self.root / "state").write_bytes(record + suffix)
            (self.root / "state").chmod(0o600)
            result = self.exchange(b"stage-kind\nabc")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"stage-receiver-refused\n")
            self.assertFalse((self.root / "kind").exists())

    def test_lock_contention_refuses_without_poisoning_owner(self):
        import fcntl
        with (self.root / "lock").open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
            self.assertFalse((self.root / "state").exists())
        self.assertEqual(self.exchange(b"stage-kind\nabc").returncode, 0)

    def test_bound_table_receiver_and_header_drift_refuse_before_state(self):
        for name in ("table", "receiver", "stage-kind.header"):
            self.tearDown()
            self.setUp()
            path = self.root / name
            path.chmod(0o600)
            path.write_bytes(path.read_bytes() + b"\n")
            self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
            self.assertFalse((self.root / "state").exists())

    def test_production_has_no_test_override_or_received_header_read_builtin(self):
        self.assertIn('$EUID == 0', self.original)
        self.assertIn('$BASH_VERSION == 5.3.9*', self.original)
        self.assertIn('sha256sum --check --status checks.sha256', self.original)
        self.assertNotIn('SSH_ORIGINAL_COMMAND', self.original)
        self.assertNotIn('read -', self.original)
        self.assertNotIn('eval ', self.original)
        self.assertNotIn('BOXFERRY', self.original)
        self.assertNotIn('TEST_', self.original)


    def test_successful_binary_payload_including_nul_and_every_byte_over_pump_boundary(self):
        payload = bytes(range(256)) * 300
        self.tearDown()
        self.prepare(payload)
        for phase, role in zip(stage.PHASES, stage.ROLES):
            result = self.exchange(phase.encode() + b"\n" + payload)
            self.assertEqual(result.returncode, 0, result.stderr)
            stage.reply(result.stdout, self.plan, phase, self.plan.files[stage.ROLES.index(role)])
            target = self.root / stage.GUEST_NAMES[role]
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600 if role == "node-oci" else 0o700)

    def start_exchange(self, wire):
        child = OwnedPipeChild(["/usr/bin/bash", str(self.root / "receiver")], self.addCleanup)
        child.process.stdin.write(wire)
        child.process.stdin.flush()
        while time.monotonic() < child.work_end:
            state = self.root / "state"
            if state.exists() and b" inflight 0\n" in state.read_bytes():
                return child
            self.assertTrue(child.running(), "receiver exited before inflight observation")
            time.sleep(0.005)
        self.fail("receiver did not persist inflight within bounded test wait")

    def test_withheld_eof_prevents_publication_until_the_same_connection_closes(self):
        child = self.start_exchange(b"stage-kind\nabc")
        while not (self.root / "payload.in").exists() or (self.root / "payload.in").stat().st_size != 3:
            child.remaining()
            self.assertTrue(child.running())
            time.sleep(0.005)
        self.assertTrue(child.running())
        self.assertFalse((self.root / "kind").exists())
        result = child.finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        stage.reply(result.stdout, self.plan, "stage-kind", self.plan.files[0])
        self.assertEqual((self.root / "kind").read_bytes(), b"abc")

    def test_killed_inflight_receiver_and_its_owned_group_cannot_resume_or_publish(self):
        child = self.start_exchange(b"stage-kind\nab")
        result = child.retire()
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertIn(b" inflight 0\n", (self.root / "state").read_bytes())
        self.assertFalse((self.root / "kind").exists())
        self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
        self.assertFalse((self.root / "kind").exists())

    def replace_projected_receiver(self, before, after):
        path = self.root / "receiver"
        raw = path.read_text()
        self.assertEqual(raw.count(before), 1)
        path.chmod(0o600)
        path.write_text(raw.replace(before, after))
        path.chmod(0o500)
        checks = self.root / "checks.sha256"
        lines = checks.read_text().splitlines()
        lines = [vm.digest(path.read_bytes()) + "  " + str(path) if line.endswith("  " + str(path)) else line for line in lines]
        checks.chmod(0o600)
        checks.write_text("\n".join(lines) + "\n")
        checks.chmod(0o400)

    def test_publication_failure_and_crash_after_publication_never_allow_replay(self):
        publication = '/usr/bin/mv -T payload.in "${names[cursor]}" || poison'
        for replacement, published in (('/usr/bin/false || poison', False),
                                       (publication + '\nkill -KILL "$$"', True)):
            self.tearDown()
            self.setUp()
            self.replace_projected_receiver(publication, replacement)
            result = self.exchange(b"stage-kind\nabc")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertEqual((self.root / "kind").exists(), published)
            if published:
                self.assertEqual((self.root / "kind").read_bytes(), b"abc")
                self.assertIn(b" inflight 0\n", (self.root / "state").read_bytes())
            else:
                self.assertIn(b" poisoned 0\n", (self.root / "state").read_bytes())
            self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)

    def test_broken_acknowledgment_after_cursor_commit_is_not_a_retry_permission(self):
        incoming, outgoing = os.pipe()
        os.close(incoming)
        try:
            result = subprocess.run(["/usr/bin/bash", str(self.root / "receiver")], input=b"stage-kind\nabc",
                stdout=outgoing, stderr=subprocess.PIPE, timeout=3, check=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        finally:
            os.close(outgoing)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "kind").read_bytes(), b"abc")
        state = (self.root / "state").read_bytes()
        self.assertTrue(b" ready 1\n" in state or b" poisoned 0\n" in state)
        self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
        self.assertEqual((self.root / "kind").read_bytes(), b"abc")

    def test_existing_file_or_symlink_destination_is_never_replaced(self):
        for linked in (False, True):
            self.tearDown()
            self.setUp()
            target = self.root / "kind"
            if linked:
                target.symlink_to(self.root / "outside")
            else:
                target.write_bytes(b"existing")
            self.assertNotEqual(self.exchange(b"stage-kind\nabc").returncode, 0)
            if linked:
                self.assertTrue(target.is_symlink())
                self.assertFalse((self.root / "outside").exists())
            else:
                self.assertEqual(target.read_bytes(), b"existing")

    def test_nul_at_every_header_offset_is_rejected_at_each_cursor(self):
        for cursor, phase in enumerate(stage.PHASES):
            header = phase.encode() + b"\n"
            for offset in range(len(header)):
                with self.subTest(cursor=cursor, offset=offset):
                    self.tearDown()
                    self.setUp()
                    for preceding in stage.PHASES[:cursor]:
                        self.assertEqual(self.exchange(preceding.encode() + b"\nabc").returncode, 0)
                    corrupted = header[:offset] + b"\x00" + header[offset + 1:]
                    result = self.exchange(corrupted + b"abc")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((self.root / stage.GUEST_NAMES[stage.ROLES[cursor]]).exists())


class OciAdmission(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.payload = b"original fake layer bytes; never extracted" * 20
        self.layer = gzip.compress(self.payload, mtime=0)
        self.config = vm.encode({"architecture": "amd64", "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + vm.digest(self.payload)]}})
        def desc(raw, media):
            return {"mediaType": media, "size": len(raw), "digest": "sha256:" + vm.digest(raw)}
        self.manifest = vm.encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": desc(self.config, "application/vnd.oci.image.config.v1+json"),
            "layers": [desc(self.layer, "application/vnd.oci.image.layer.v1.tar+gzip")]})
        self.child = {**desc(self.manifest, "application/vnd.oci.image.manifest.v1+json"),
                      "platform": {"os": "linux", "architecture": "amd64"}}
        self.parent = vm.encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                 "manifests": [self.child]})
        self.members = {"oci-layout": vm.encode({"imageLayoutVersion": "1.0.0"}),
            "index.json": vm.encode(vm.strict_json(self.parent))}
        for raw in (self.config, self.manifest, self.layer):
            self.members["blobs/sha256/" + vm.digest(raw)] = raw

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, members=None, *, duplicate=False, special=None):
        path = self.root / "node.oci.tar"
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in (self.members if members is None else members).items():
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                if special:
                    info.type = special
                archive.addfile(info, io.BytesIO(raw))
            if duplicate:
                info = tarfile.TarInfo("oci-layout")
                info.size = len(self.members["oci-layout"])
                archive.addfile(info, io.BytesIO(self.members["oci-layout"]))
        return path

    def admit(self, path=None, *, parent=None, manifest=None, config=None):
        parent = self.parent if parent is None else parent
        return stage.admit_oci(self.archive() if path is None else path, parent,
            self.manifest if manifest is None else manifest, self.config if config is None else config,
            {"node_image": "kindest/node:v0.0.0@sha256:" + vm.digest(parent)}, vm.Budget(time.monotonic() + 5, 1))

    def test_original_manifest_archive_and_diffids_are_independently_authenticated(self):
        path = self.archive()
        file, proof = self.admit(path)
        self.assertEqual(file.sha256, vm.digest(path.read_bytes()))
        self.assertEqual(proof["manifest_sha256"], vm.digest(self.manifest))
        self.assertEqual(proof["expanded_bytes_hashed"], len(self.payload))
        self.assertEqual(proof["import"], "not-performed")

    def test_extra_duplicate_missing_link_and_trailing_members_refuse(self):
        scenarios = [dict(self.members, **{"../escape": b"bad"}), {key: raw for key, raw in self.members.items() if key != "oci-layout"}]
        for members in scenarios:
            with self.assertRaises(vm.Refusal):
                self.admit(self.archive(members))
        with self.assertRaises(vm.Refusal):
            self.admit(self.archive(duplicate=True))
        with self.assertRaises(vm.Refusal):
            self.admit(self.archive(special=tarfile.SYMTYPE))
        path = self.archive()
        with path.open("ab") as output:
            output.write(b"x" * 512)
        with self.assertRaises(vm.Refusal):
            self.admit(path)

    def test_corrupt_blob_config_platform_wrong_diffid_and_ambiguous_parent_refuse(self):
        members = dict(self.members)
        layer_name = "blobs/sha256/" + vm.digest(self.layer)
        members[layer_name] = self.layer[:-1] + bytes([self.layer[-1] ^ 1])
        with self.assertRaises(vm.Refusal):
            self.admit(self.archive(members))
        for field in ("architecture", "os"):
            config = vm.strict_json(self.config)
            config[field] = "unavailable"
            with self.assertRaises(vm.Refusal):
                self.admit(config=vm.encode(config))
        config = vm.strict_json(self.config)
        config["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
        with self.assertRaises(vm.Refusal):
            self.admit(config=vm.encode(config))
        parent = vm.strict_json(self.parent)
        parent["manifests"].append(deepcopy(parent["manifests"][0]))
        with self.assertRaises(vm.Refusal):
            self.admit(parent=vm.encode(parent))
        parent["manifests"] = [{**self.child, "platform": {"os": "linux", "architecture": "amd64", "variant": "v2"}}]
        with self.assertRaises(vm.Refusal):
            self.admit(parent=vm.encode(parent))

    def rebind(self):
        manifest = vm.strict_json(self.manifest)
        manifest["config"].update({"digest": "sha256:" + vm.digest(self.config), "size": len(self.config)})
        manifest["layers"][0].update({"digest": "sha256:" + vm.digest(self.layer), "size": len(self.layer)})
        self.manifest = vm.encode(manifest)
        self.child.update({"digest": "sha256:" + vm.digest(self.manifest), "size": len(self.manifest)})
        self.parent = vm.encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [self.child]})
        self.members = {"oci-layout": vm.encode({"imageLayoutVersion": "1.0.0"}), "index.json": self.parent}
        for raw in (self.config, self.manifest, self.layer):
            self.members["blobs/sha256/" + vm.digest(raw)] = raw

    def test_fully_digest_consistent_wrong_diffid_and_gzip_trailing_refuse(self):
        changed = vm.strict_json(self.config)
        changed["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
        self.config = vm.encode(changed)
        self.rebind()
        with self.assertRaisesRegex(vm.Refusal, "stage-oci-diffid-integrity"):
            self.admit()
        changed["rootfs"]["diff_ids"] = ["sha256:" + vm.digest(self.payload)]
        self.config = vm.encode(changed)
        self.layer += b"extra gzip member or trailer"
        self.rebind()
        with self.assertRaisesRegex(vm.Refusal, "stage-oci-gzip-trailing"):
            self.admit()

    def test_bounded_inflation_is_enforced_without_extraction(self):
        with patch.object(stage, "LAYER_EXPANDED_MAX", 16):
            with self.assertRaisesRegex(vm.Refusal, "stage-oci-inflation-budget"):
                self.admit()
        with patch.object(stage, "EXPANDED_TOTAL_MAX", 16):
            with self.assertRaisesRegex(vm.Refusal, "stage-oci-inflation-budget"):
                self.admit()

    def test_consistent_digest_bad_platform_and_manifest_conversion_are_unavailable(self):
        changed = vm.strict_json(self.config)
        changed["variant"] = "v2"
        self.config = vm.encode(changed)
        self.rebind()
        with self.assertRaisesRegex(vm.Refusal, "stage-oci-config"):
            self.admit()
        changed.pop("variant")
        self.config = vm.encode(changed)
        manifest = vm.strict_json(self.manifest)
        manifest["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
        self.manifest = vm.encode(manifest)
        self.rebind()
        with self.assertRaisesRegex(vm.Refusal, "stage-oci-preserved-manifest-unavailable"):
            self.admit()

    def test_original_docker_schema2_bytes_can_be_staged_without_import_claim(self):
        manifest = vm.strict_json(self.manifest)
        manifest["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
        manifest["config"]["mediaType"] = "application/vnd.docker.container.image.v1+json"
        manifest["layers"][0]["mediaType"] = "application/vnd.docker.image.rootfs.diff.tar.gzip"
        self.child["mediaType"] = manifest["mediaType"]
        self.manifest = vm.encode(manifest)
        self.rebind()
        # Original parent is a Docker list; archive index stays a new OCI index.
        original_parent = vm.strict_json(self.parent)
        original_parent["mediaType"] = "application/vnd.docker.distribution.manifest.list.v2+json"
        self.parent = vm.encode(original_parent)
        _file, evidence = self.admit()
        self.assertEqual(evidence["transport"], "source-preserved-docker-manifest")
        self.assertFalse(evidence["archive_index_is_original_parent"])
        self.assertEqual(evidence["manifest_sha256"], vm.digest(self.manifest))
        self.assertEqual(evidence["import"], "not-performed")
        self.assertEqual(evidence["repo_digest_behavior"], "unavailable")


class InputAuthority(unittest.TestCase):
    def setUp(self):
        import kind_runtime
        self.select_profile = kind_runtime.select_profile
        self.native_refusal = kind_runtime.Refusal
        vm.CANCELLED = 0
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        owner = b'  x86_64)\n    readonly kind_checksum="' + vm.digest(b"\x7fELFkind").encode() + b'"\n    readonly kubectl_checksum="' + vm.digest(b"\x7fELFkubectl").encode() + b'"\n    ;;\nreadonly kind_version="0.33.0"\nreadonly kubectl_version="1.37.0"\n'
        self.ledger = {"runtime_profiles": [{"id": "modern-1.37.0", "kind_profile": "kind-0.33.0",
            "kubectl_profile": "kubectl-1.37.0", "node_image": "kindest/node:v1.37.0@sha256:" + "a" * 64}],
            "canonical_tool_owner": {"sha256": vm.digest(owner)}, "tool_profiles": [
                {"id": role + "-" + version, "version": version, "version_variable": role + "_version"}
                for role, version in (("kind", "0.33.0"), ("kubectl", "1.37.0"))]}
        for name, raw in (("kind", b"\x7fELFkind"), ("kubectl", b"\x7fELFkubectl"), ("owner", owner),
                          ("parent", b"{}"), ("manifest", b"{}"), ("config", b"{}"), ("archive", b"abc")):
            (self.root / name).write_bytes(raw)
        self.args = SimpleNamespace(profile="modern-1.37.0", kind=str(self.root / "kind"),
            kubectl=str(self.root / "kubectl"), canonical_owner=str(self.root / "owner"),
            node_parent=str(self.root / "parent"), node_manifest=str(self.root / "manifest"),
            node_config=str(self.root / "config"), node_archive=str(self.root / "archive"))

    def tearDown(self):
        self.temp.cleanup()

    def run_admission(self):
        original = vm.read
        ledger_path = vm.ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json"
        def read(path, maximum=vm.META_MAX):
            return vm.encode(self.ledger) if Path(path) == ledger_path else original(path, maximum)
        archive = stage.FilePlan("node-oci", self.args.node_archive, 3, vm.digest(b"abc"))
        with patch.object(vm, "read", side_effect=read), patch.object(stage, "admit_oci", return_value=(archive, {})):
            return stage.admit_inputs(self.args, "a" * 32, vm.Budget(time.monotonic() + 5, 1), self.select_profile)

    def test_plan_uses_existing_canonical_owner_selector_not_supplied_binary_hashes(self):
        raw, plan, evidence = self.run_admission()
        self.assertEqual(plan.sha256, vm.digest(raw))
        self.assertEqual(plan.files[0].sha256, vm.digest(b"\x7fELFkind"))
        self.assertEqual(evidence["canonical_owner_sha256"], self.ledger["canonical_tool_owner"]["sha256"])
        self.assertEqual(evidence["ledger_sha256"], vm.digest(vm.encode(self.ledger)))

    def test_changed_owner_and_client_bytes_refuse_without_self_admission(self):
        (self.root / "owner").write_bytes(b"observed but not canonical")
        with self.assertRaisesRegex(self.native_refusal, "canonical-owner-integrity"):
            self.run_admission()
        self.tearDown()
        self.setUp()
        (self.root / "kind").write_bytes(b"\x7fELFnew!")
        with self.assertRaisesRegex(vm.Refusal, "stage-source-integrity"):
            self.run_admission()

    def test_unknown_profile_and_duplicate_profile_cannot_select_another_image(self):
        self.args.profile = "unknown"
        with self.assertRaisesRegex(self.native_refusal, "unknown-runtime-profile"):
            self.run_admission()
        self.args.profile = "modern-1.37.0"
        self.ledger["runtime_profiles"].append(deepcopy(self.ledger["runtime_profiles"][0]))
        with self.assertRaisesRegex(self.native_refusal, "unknown-runtime-profile"):
            self.run_admission()


if __name__ == "__main__":
    unittest.main()
