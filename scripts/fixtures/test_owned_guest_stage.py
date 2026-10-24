"""Finite pipe peers; no real SSH, VM, service or guest operation runs."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import owned_guest_stage as stage
import owned_qemu as vm

ABC_SHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class CountedFile:
    def __init__(self, descriptor, mode):
        self.file = os.fdopen(descriptor, mode, buffering=0)
        self.closes = 0

    def fileno(self):
        return self.file.fileno()

    def close(self):
        self.closes += 1
        self.file.close()


class Peer:
    """A bounded in-process pipe peer substituted for Popen, never a program."""
    def __init__(self, response, *, stderr=b"", reject=False, stalled=False):
        incoming, sender = os.pipe()
        receiver, outgoing = os.pipe()
        errors, diagnostics = os.pipe()
        self.stdin, self.stdout, self.stderr = CountedFile(sender, "wb"), CountedFile(receiver, "rb"), CountedFile(errors, "rb")
        self.pid, self.returncode = 424242, None
        self.wire, self.error = bytearray(), None
        self.stopped = threading.Event()
        self.wait_calls = []
        def serve():
            try:
                if reject:
                    return
                if stalled:
                    self.stopped.wait(2)
                    return
                # More than pipe capacity before consuming input forces genuine
                # output/input multiplexing rather than a blocking sendall.
                offset = 0
                while offset < len(stderr):
                    offset += os.write(diagnostics, stderr[offset:offset + 16384])
                while True:
                    raw = os.read(incoming, 4096)
                    if not raw:
                        break
                    self.wire.extend(raw)
                    if len(self.wire) > 1024**2:
                        raise AssertionError("test peer input cap")
                for offset in range(0, len(response), 7):
                    os.write(outgoing, response[offset:offset + 7])
            except (OSError, AssertionError) as error:
                self.error = type(error).__name__
            finally:
                for descriptor in (incoming, outgoing, diagnostics):
                    os.close(descriptor)
                self.returncode = 1 if reject else 0
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.wait_calls.append(timeout)
        self.thread.join(timeout)
        if self.thread.is_alive():
            raise subprocess.TimeoutExpired("fake peer", timeout)
        return self.returncode

    def abort(self, *_args):
        self.stopped.set()


class StageControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.item = {"schema": "kubernetes-lens-owned-guest-stage-plan-v1", "owner": "a" * 32,
                     "profile": "legacy-1.20.15", "files": {}}
        for role in ("kind", "kubectl", "node-oci"):
            path = self.directory / role
            path.write_bytes(b"abc")
            self.item["files"][role] = {"path": str(path), "bytes": 3, "sha256": ABC_SHA}
        self.make_session()

    def make_session(self):
        raw = vm.encode(self.item)
        self.plan = stage.parse_plan(raw, vm.digest(raw))
        self.budget = vm.Budget(time.monotonic() + 3, 0.5)
        self.cap = sum(record["bytes"] for record in self.item["files"].values()) + 40
        # Literal phases carry 11,14,15 bytes including their linefeeds.
        self.session = stage.Session(self.plan, self.budget, self.cap)
        self.config = {"owner": "a" * 32, "stage_plan_sha256": self.plan.sha256,
                       "end": self.budget.end, "work_end": self.budget.work_end,
                       "source": {str(Path(stage.__file__).resolve()): "source-bound-by-owning-caller"},
                       "tools": {"ssh": {"path": "/reviewed/ssh"}}, "directory": str(self.directory), "port": 22222}

    def response(self, phase="stage-kind", **changes):
        index = stage.PHASES.index(phase)
        file = self.plan.files[index]
        return vm.encode({"schema": "kubernetes-lens-owned-guest-stage-reply-v1", "owner": "a" * 32,
                          "plan_sha256": self.plan.sha256, "phase": phase, "role": file.role,
                          "bytes": file.size, "sha256": file.sha256, "state": "staged", **changes}) + b"\n"

    def transfer(self, peer, phase="stage-kind"):
        with patch.object(stage.subprocess, "Popen", return_value=peer) as popen, \
             patch.object(vm, "verify_source") as verify, patch.object(stage.os, "killpg", side_effect=peer.abort):
            result = stage.transfer(self.session, phase, self.config, on_start=Mock())
        verify.assert_called_once_with(self.config, self.budget)
        self.assertEqual(popen.call_args.args[0][-1], stage.RECEIVER_COMMAND)
        self.assertNotIn("-n", popen.call_args.args[0])
        self.assertEqual(peer.stdin.closes, 1)
        self.assertIsNone(peer.error)
        return result

    def test_literal_binary_bytes_and_digest_and_one_stdin_eof(self):
        peer = Peer(self.response())
        result = self.transfer(peer)
        self.assertEqual(bytes(peer.wire), b"stage-kind\nabc")
        self.assertEqual(self.session.input_sent, 14)
        self.assertEqual(result["bytes"], 3)
        self.assertEqual(result["sha256"], ABC_SHA)
        self.assertEqual(result["state"], "stage-reply-observed")
        self.assertEqual(result["vm_retirement"], "not-established")
        self.assertEqual(self.budget.commands_left, 127)
        self.assertEqual(self.budget.output_left, vm.OUTPUT_MAX - len(self.response()))

    def test_all_three_roles_share_one_input_cap_and_command_budget(self):
        expected_wire = (b"stage-kind\nabc", b"stage-kubectl\nabc", b"stage-node-oci\nabc")
        for phase, wire in zip(stage.PHASES, expected_wire):
            peer = Peer(self.response(phase))
            self.transfer(peer, phase)
            self.assertEqual(bytes(peer.wire), wire)
        self.assertEqual(self.session.input_sent, sum(len(wire) for wire in expected_wire))
        self.assertEqual(self.budget.commands_left, 125)
        with patch.object(stage.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(vm.Refusal, "stage-phase-order"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        popen.assert_not_called()

    def test_stdout_stderr_and_qemu_backpressure_do_not_block_input(self):
        data = b"x" * 200000
        (self.directory / "kind").write_bytes(data)
        self.item["files"]["kind"].update({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.make_session()
        peer = Peer(self.response(), stderr=b"d" * 200000)
        qemu_reader, qemu_writer = os.pipe()
        qemu = os.fdopen(qemu_reader, "rb", buffering=0)
        self.addCleanup(qemu.close)
        os.write(qemu_writer, b"QEMU console\n")
        os.close(qemu_writer)
        with patch.object(stage.subprocess, "Popen", return_value=peer), patch.object(vm, "verify_source"), \
             patch.object(stage.os, "killpg", side_effect=peer.abort):
            stage.transfer(self.session, "stage-kind", self.config, extra_streams=(qemu,), on_start=Mock())
        self.assertEqual(bytes(peer.wire), b"stage-kind\n" + data)
        self.assertEqual(self.budget.output_left, vm.OUTPUT_MAX - 200000 - len(b"QEMU console\n") - len(self.response()))
        self.assertTrue(os.get_blocking(qemu.fileno()))
        self.assertEqual(peer.stdin.closes, 1)

    def test_partial_and_eagain_writes_preserve_literal_payload_and_counts(self):
        peer = Peer(self.response())
        descriptor = peer.stdin.fileno()
        original = os.write
        calls = []
        def partial(target, raw):
            if target == descriptor:
                calls.append(len(raw))
                if len(calls) == 1:
                    raise BlockingIOError
                return original(target, raw[:2])
            return original(target, raw)
        with patch.object(stage.os, "write", side_effect=partial):
            self.transfer(peer)
        self.assertEqual(bytes(peer.wire), b"stage-kind\nabc")
        self.assertEqual(self.session.input_sent, 14)
        self.assertTrue(all(0 < size <= 65536 for size in calls))

    def test_bad_source_hash_never_spawns_and_poisons_session(self):
        (self.directory / "kind").write_bytes(b"abd")
        with patch.object(stage.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(stage.StageRefusal, "stage-source-integrity"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        popen.assert_not_called()
        self.assertTrue(self.session.failed)
        self.assertEqual(self.session.input_sent, 0)
        self.assertEqual(self.budget.commands_left, 128)

    def test_symlink_source_and_symlink_parent_never_spawn(self):
        path = self.directory / "kind"
        path.unlink()
        path.symlink_to(self.directory / "kubectl")
        with patch.object(stage.subprocess, "Popen") as popen:
            with self.assertRaises(stage.StageRefusal):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        popen.assert_not_called()
        link = self.directory / "linked-directory"
        link.symlink_to(self.directory, target_is_directory=True)
        file = stage.FilePlan("kind", str(link / "kubectl"), 3, ABC_SHA)
        with self.assertRaises(OSError):
            stage.open_source(file)

    def test_same_size_mutation_after_pre_hash_cannot_be_acknowledged(self):
        peer = Peer(self.response())
        def changed(_config, _budget):
            (self.directory / "kind").write_bytes(b"abd")
        with patch.object(stage.subprocess, "Popen", return_value=peer), \
             patch.object(vm, "verify_source", side_effect=changed), patch.object(stage.os, "killpg", side_effect=peer.abort):
            with self.assertRaisesRegex(stage.StageRefusal, "stage-transmitted-integrity"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        self.assertTrue(self.session.failed)
        self.assertEqual(peer.stdin.closes, 1)

    def test_epipe_is_fixed_failure_and_never_retried(self):
        peer = Peer(b"", reject=True)
        peer.thread.join(1)
        with patch.object(stage.subprocess, "Popen", return_value=peer) as popen, \
             patch.object(vm, "verify_source"), patch.object(stage.os, "killpg", side_effect=peer.abort):
            with self.assertRaisesRegex(stage.StageRefusal, "stage-stdin-broken-pipe"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        popen.assert_called_once()
        self.assertTrue(self.session.failed)
        self.assertEqual(peer.stdin.closes, 1)

    def test_cancelled_transport_reaps_only_its_peer_without_renewing_end(self):
        peer = Peer(b"", stalled=True)
        end = self.budget.end
        def cancel(_process):
            vm.CANCELLED = signal.SIGTERM
        with patch.object(stage.subprocess, "Popen", return_value=peer), patch.object(vm, "verify_source"), \
             patch.object(stage.os, "killpg", side_effect=peer.abort) as kill:
            with self.assertRaisesRegex(stage.StageRefusal, "cancelled"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=cancel)
        kill.assert_called_once_with(peer.pid, signal.SIGKILL)
        self.assertEqual(self.budget.end, end)
        self.assertEqual(peer.stdin.closes, 1)
        self.assertTrue(peer.wait_calls and peer.wait_calls[0] <= 3)
        self.assertTrue(self.session.failed)

    def test_original_work_end_expires_stalled_input_and_retains_cleanup_end(self):
        self.budget = vm.Budget(time.monotonic() + 0.15, 0.05)
        self.session = stage.Session(self.plan, self.budget, self.cap)
        self.config.update({"end": self.budget.end, "work_end": self.budget.work_end})
        peer = Peer(b"", stalled=True)
        original_end = self.budget.end
        with patch.object(stage.subprocess, "Popen", return_value=peer), patch.object(vm, "verify_source"), \
             patch.object(stage.os, "killpg", side_effect=peer.abort) as kill:
            with self.assertRaisesRegex(stage.StageRefusal, "original-deadline-expired"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        kill.assert_called_once_with(peer.pid, signal.SIGKILL)
        self.assertEqual(self.budget.end, original_end)
        self.assertEqual(peer.stdin.closes, 1)
        self.assertTrue(peer.wait_calls and peer.wait_calls[0] <= 0.05)

    def test_output_limit_refuses_without_logging_remote_body(self):
        self.budget.output_left = 1
        peer = Peer(self.response())
        with self.assertRaisesRegex(stage.StageRefusal, "output-budget"):
            self.transfer(peer)
        self.assertTrue(self.session.failed)

    def test_earliest_failure_and_separate_unproved_reap_are_preserved(self):
        peer = Peer(self.response(owner="b" * 32))
        peer.wait = Mock(side_effect=subprocess.TimeoutExpired("fake peer", 0))
        with patch.object(stage.subprocess, "Popen", return_value=peer), patch.object(vm, "verify_source"), \
             patch.object(stage.os, "killpg", side_effect=peer.abort):
            with self.assertRaises(stage.StageRefusal) as raised:
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
        peer.thread.join(1)
        self.assertEqual(raised.exception.code, "stage-reply-mismatch")
        self.assertEqual(raised.exception.retirement_error, "stage-ssh-retirement-unproved")
        self.assertTrue(self.session.failed)

    def test_another_transfer_cannot_reenter_the_same_session(self):
        self.session._lock.acquire()
        try:
            with patch.object(stage.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(vm.Refusal, "stage-session-busy"):
                    stage.transfer(self.session, "stage-kind", self.config, on_start=Mock())
            popen.assert_not_called()
        finally:
            self.session._lock.release()

    def test_failed_or_foreign_reply_never_advances_phase(self):
        peer = Peer(self.response(owner="b" * 32))
        with self.assertRaisesRegex(stage.StageRefusal, "stage-reply-mismatch"):
            self.transfer(peer)
        self.assertEqual(self.session.next_phase, 0)
        self.assertTrue(self.session.failed)

    def test_plan_rejects_unknown_paths_sizes_hashes_and_replays(self):
        for alter in (lambda item: item.update({"argv": ["arbitrary"]}),
                      lambda item: item["files"]["kind"].update({"path": "relative"}),
                      lambda item: item["files"]["kind"].update({"bytes": True}),
                      lambda item: item["files"]["kind"].update({"bytes": 128 * 1024**2 + 1}),
                      lambda item: item["files"]["node-oci"].update({"bytes": 2 * 1024**3 + 1}),
                      lambda item: item["files"]["kind"].update({"sha256": "X" * 64}),
                      lambda item: item.update({"profile": "floating-latest"})):
            item = deepcopy(self.item)
            alter(item)
            raw = vm.encode(item)
            with self.assertRaises(vm.Refusal):
                stage.parse_plan(raw, vm.digest(raw))
        with self.assertRaisesRegex(vm.Refusal, "stage-cumulative-input-cap"):
            stage.Session(self.plan, self.budget, 1)
        with patch.object(stage.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(vm.Refusal, "stage-phase-order"):
                stage.transfer(self.session, "stage-kubectl", self.config, on_start=Mock())
        popen.assert_not_called()

    def test_reply_framing_unknown_keys_duplicates_and_boolean_bytes_refuse(self):
        good = self.response()
        for raw in (good + good, good[:-1], good + b"\n", self.response(extra=True),
                    self.response(bytes=True), good.replace(b'"bytes":3', b'"bytes":3,"bytes":3')):
            with self.assertRaises(vm.Refusal):
                stage.reply(raw, self.plan, "stage-kind", self.plan.files[0])

    def test_fixed_ssh_command_has_no_argument_or_original_command_interpolation(self):
        argv = stage.ssh_arguments(self.config)
        self.assertEqual(argv[-1], "/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin /var/lib/kubernetes-lens-stage/receiver")
        self.assertEqual(argv[-2], "core@127.0.0.1")
        self.assertNotIn("-n", argv)
        for option in ("IdentityAgent=none", "StrictHostKeyChecking=yes", "ControlPath=none",
                       "ProxyCommand=none", "ClearAllForwardings=yes", "PermitLocalCommand=no"):
            self.assertIn(option, argv)
        self.assertNotIn("SSH_ORIGINAL_COMMAND", " ".join(argv))

    def test_authenticated_worker_callback_replaces_only_inapplicable_parent_tool_view(self):
        peer = Peer(self.response())
        callback = Mock()
        with patch.object(stage.subprocess, "Popen", return_value=peer), patch.object(vm, "verify_source") as parent_view:
            stage.transfer(self.session, "stage-kind", self.config, on_start=Mock(), pre_child=callback)
        callback.assert_called_once_with()
        parent_view.assert_not_called()
        self.assertEqual(self.session.next_phase, 1)

    def test_worker_source_callback_failure_never_starts_child_or_retries(self):
        with patch.object(stage.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(vm.Refusal, "host-view-local-drift"):
                stage.transfer(self.session, "stage-kind", self.config, on_start=Mock(),
                               pre_child=Mock(side_effect=vm.Refusal("host-view-local-drift")))
        popen.assert_not_called()
        self.assertTrue(self.session.failed)


if __name__ == "__main__":
    unittest.main()
