"""Pure lifecycle controls. Never starts systemd, QEMU, SSH, Podman or a VM."""
from copy import deepcopy
from contextlib import ExitStack
import base64
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import signal
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import owned_qemu as vm
import owned_host_view as host_view


_HOST_VIEW_DIAGNOSTIC_HUNKS = (('D01', 'EXPANDED_MAX = 4 * 1024**3\nMETA_MAX = 65536\nOUTPUT_MAX = 2 * 1024**2\nDIAGNOSTIC_CREDIT_PROFILE = "host-view-diagnostic-credit-v1"\nDIAGNOSTIC_CREDIT_BYTES = 2053\nDIAGNOSTIC_FRAME_BYTES = 2052\nDIAGNOSTIC_BODY_BYTES = 2048\nFIXED_COMMAND = ("/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin "\n                 "/usr/bin/podman --remote=false info --format=json")\nEXPECTED_PODMAN = "5.8.7"  # Historical prerequisite profile, not an operational tool pin.\n', 'EXPANDED_MAX = 4 * 1024**3\nMETA_MAX = 65536\nOUTPUT_MAX = 2 * 1024**2\nFIXED_COMMAND = ("/usr/bin/sudo -n /usr/bin/env -i HOME=/root PATH=/usr/bin:/usr/sbin "\n                 "/usr/bin/podman --remote=false info --format=json")\nEXPECTED_PODMAN = "5.8.7"  # Historical prerequisite profile, not an operational tool pin.\n', '10653b964a241cf91d2318c48a874838c27cdfb5139b0e9926308c249e02686b', '0cba0c8fc1b750727f2a67dc47ebc3864737110b14f58f74047fb428d669bfea'), ('D02', '\ndef encode(value):\n    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()\n\n\nHOST_VIEW_MISMATCH_SCHEMA = "kubernetes-lens-host-view-mismatch-v3"\nHOST_VIEW_MISMATCH_SITES = {"parent-attest", "parent-recheck", "worker-local"}\nHOST_VIEW_MISMATCH_OBJECTS = {"root", "usr", "bin", "tool-busctl", "tool-python", "tool-qemu",\n                              "tool-qemu_img", "tool-ssh", "tool-ssh_keygen", "tool-systemctl", "tool-systemd_run"}\nHOST_VIEW_IDENTITY_MEMBERS = {"dev", "ino", "size", "mtime_ns", "ctime_ns"}\nHOST_VIEW_MISMATCH_FIELDS = {"identity", "type", "mode", "uid", "gid", "sha256"}\n\n\ndef validated_host_view_mismatch(value):\n    """Return a closed, bounded private mismatch record or refuse it."""\n    require(type(value) is dict and set(value) == {"schema", "site", "object", "differences"}\n            and value["schema"] == HOST_VIEW_MISMATCH_SCHEMA\n            and type(value["site"]) is str and value["site"] in HOST_VIEW_MISMATCH_SITES\n            and type(value["object"]) is str and value["object"] in HOST_VIEW_MISMATCH_OBJECTS\n            and type(value["differences"]) is list and 1 <= len(value["differences"]) <= 11,\n            "host-view-mismatch-schema")\n    differences = []\n    previous = None\n    for row in value["differences"]:\n        require(type(row) is dict and type(row.get("field")) is str\n                and row["field"] in HOST_VIEW_MISMATCH_FIELDS,\n                "host-view-mismatch-difference-schema")\n        field = row["field"]\n        if field == "identity":\n            require(set(row) == {"field", "member", "expected", "observed"}\n                    and type(row["member"]) is str and row["member"] in HOST_VIEW_IDENTITY_MEMBERS,\n                    "host-view-mismatch-identity-schema")\n            member = row["member"]\n            low, high = (0, 2**64 - 1) if member in ("dev", "ino", "size") else (-(2**63), 2**63 - 1)\n        else:\n            require(set(row) == {"field", "expected", "observed"},\n                    "host-view-mismatch-value-schema")\n            member = ""\n            low, high = None, None\n        expected, observed = row["expected"], row["observed"]\n        require(expected != observed, "host-view-mismatch-equal-values")\n        if field == "identity" or field in ("mode", "uid", "gid"):\n            require(type(expected) is int and type(observed) is int, "host-view-mismatch-integer")\n            if field == "mode":\n                low, high = 0, 0o7777\n            elif field in ("uid", "gid"):\n                low, high = 0, 2**32 - 1\n            require(low <= expected <= high and low <= observed <= high, "host-view-mismatch-integer-range")\n        elif field == "type":\n            require(type(expected) is str and type(observed) is str\n                    and expected in ("directory", "regular") and observed in ("directory", "regular"),\n                    "host-view-mismatch-type")\n        elif field == "sha256":\n            require(type(expected) is str and type(observed) is str\n                    and HEX.fullmatch(expected) and HEX.fullmatch(observed), "host-view-mismatch-digest")\n        key = (field, member)\n        require(previous is None or previous < key, "host-view-mismatch-order")\n        previous = key\n        differences.append({"field": field, **({"member": member} if field == "identity" else {}),\n                            "expected": expected, "observed": observed})\n    result = {"schema": HOST_VIEW_MISMATCH_SCHEMA, "site": value["site"],\n              "object": value["object"], "differences": differences}\n    try:\n        require(len(encode(result)) <= 2048, "host-view-mismatch-budget")\n    except (TypeError, ValueError, RecursionError) as error:\n        raise Refusal("host-view-mismatch-budget") from error\n    return result\n\n\ndef with_optional_host_view_mismatch(envelope, value):\n    """Preflight optional private detail against the existing single-message cap."""\n    if type(envelope) is not dict or "host_view_mismatch" in envelope or value is None:\n        return envelope\n    try:\n        detail = validated_host_view_mismatch(value)\n        candidate = {**envelope, "host_view_mismatch": detail}\n        if len(encode(candidate)) <= META_MAX:\n            return candidate\n    except (Refusal, TypeError, ValueError, RecursionError):\n        pass\n    return envelope\n\n\ndef diagnostic_credit_profile(config):\n    keys = {"host_view_diagnostic_profile", "host_view_diagnostic_credit_bytes"}\n    present = keys.intersection(config)\n    if not present:\n        return None\n    require(present == keys and config["host_view_diagnostic_profile"] == DIAGNOSTIC_CREDIT_PROFILE\n            and type(config["host_view_diagnostic_credit_bytes"]) is int\n            and config["host_view_diagnostic_credit_bytes"] == DIAGNOSTIC_CREDIT_BYTES,\n            "host-view-diagnostic-profile")\n    return DIAGNOSTIC_CREDIT_PROFILE\n\n\ndef canonical(path):\n', '\ndef encode(value):\n    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()\n\n\ndef canonical(path):\n', '0fbe75373252f18349bb4239c6df3ce2ada8f718489a1e1a286f787e74fa728f', '400298325f9df9fb70e6b527a00665addb5e66d190bc212c99baa51034fdf06a'), ('D03', '    return process_identity(pid)\n\n\ndef verify_source(config, budget, *, host_view=None, helper=None, helper_ref=None):\n    check_source_bindings(config, budget)\n    if host_view is None:\n        require(admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-tools-drift")\n    else:\n        worker_pre_child(config, budget, host_view, helper=helper, helper_ref=helper_ref)\n    for name, expected in config["input_files"].items():\n        target = canonical(Path(config["directory"]) / name)\n        if name != "image.qcow2":\n', '    return process_identity(pid)\n\n\ndef verify_source(config, budget, *, host_view=None):\n    check_source_bindings(config, budget)\n    if host_view is None:\n        require(admit_tools(config["manifest"], config["manifest_sha256"]) == config["tools"], "host-tools-drift")\n    else:\n        worker_pre_child(config, budget, host_view)\n    for name, expected in config["input_files"].items():\n        target = canonical(Path(config["directory"]) / name)\n        if name != "image.qcow2":\n', '111ec0275b5bec2a22e7a62bcaa6d012cc9220012bf67b07ffed8233a78eddaa', '24c7d53ed0b0692ce9311ee8b132479acc921268b9bf223abecd2e30c165b419'), ('D04', '        raise\n\n\ndef worker_pre_child(config, budget, frame, *, helper=None, helper_ref=None):\n    check_source_bindings(config, budget)\n    require(digest(read(config["manifest"])) == config["manifest_sha256"], "host-tools-manifest-drift")\n    host_view = helper\n    if host_view is None:\n        host_view = host_view_module(config, budget)\n        if helper_ref is not None:\n            require(type(helper_ref) is list and len(helper_ref) == 1 and helper_ref[0] is None,\n                    "host-view-helper-reference")\n            helper_ref[0] = host_view\n    host_view.validate_local(frame, config, budget)\n    if config.get("phase") in ("stage-inputs", "run-rootful-kind"):\n        for name, expected in config["input_files"].items():\n            budget.remaining()\n', '        raise\n\n\ndef worker_pre_child(config, budget, frame):\n    check_source_bindings(config, budget)\n    require(digest(read(config["manifest"])) == config["manifest_sha256"], "host-tools-manifest-drift")\n    host_view_module(config, budget).validate_local(frame, config, budget)\n    if config.get("phase") in ("stage-inputs", "run-rootful-kind"):\n        for name, expected in config["input_files"].items():\n            budget.remaining()\n', 'ce4d3d6817e797967e890a45b886fbd42dd026d25ab0c52d8876a259d7692b87', '5fd82bd0e9ecacd99bca877aff6e2a27a3f5d30e1987a9fe9d79929a13f2758c'), ('D05', '                require(file_id(target.stat()) == expected["identity"], "expanded-input-identity")\n            else:\n                require(digest(read(target)) == expected["sha256"], "private-input-drift")\n    return host_view\n\n\ndef reap(process, budget):\n', '                require(file_id(target.stat()) == expected["identity"], "expanded-input-identity")\n            else:\n                require(digest(read(target)) == expected["sha256"], "private-input-drift")\n\n\ndef reap(process, budget):\n', '7b117d35a55a6fe403bee8b035f0ac8204e1390668d2e8327eaa6967386c77e4', 'ae48e1a1440b12c9d0a13db94eb2d1fb37ee8502c70159d2e35473408ed9bf32'), ('D06', '    raw = read(path)\n    require(digest(raw) == expected, "worker-config-integrity")\n    config = strict_json(raw)\n    diagnostic_profile = diagnostic_credit_profile(config)\n    budget = Budget(config["end"], config["cleanup_seconds"])\n    require(time.monotonic() >= config["start"] and config["work_end"] == budget.work_end, "worker-original-deadline")\n    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n    qemu = None\n    selector = None\n    outcome, failure, qemu_record, ssh_record = None, None, None, None\n    host_view_mismatch = None\n    producers, producer_records, stage_result = [], [], None\n    is_rootful = config.get("phase") == "run-rootful-kind"\n    is_stage = config.get("phase") in ("stage-inputs", "run-rootful-kind")\n    rootful_result = None\n    guest_info_command = None\n    guest_info_capture = command_outcome() if is_rootful else None\n    diagnostic_helper = None\n    diagnostic_helper_ref = [None] if diagnostic_profile is not None else None\n    try:\n        channel.settimeout(min(1, budget.remaining()))\n        channel.connect(str(Path(config["directory"]) / "control.sock"))\n', '    raw = read(path)\n    require(digest(raw) == expected, "worker-config-integrity")\n    config = strict_json(raw)\n    budget = Budget(config["end"], config["cleanup_seconds"])\n    require(time.monotonic() >= config["start"] and config["work_end"] == budget.work_end, "worker-original-deadline")\n    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n    qemu = None\n    selector = None\n    outcome, failure, qemu_record, ssh_record = None, None, None, None\n    producers, producer_records, stage_result = [], [], None\n    is_rootful = config.get("phase") == "run-rootful-kind"\n    is_stage = config.get("phase") in ("stage-inputs", "run-rootful-kind")\n    rootful_result = None\n    guest_info_command = None\n    guest_info_capture = command_outcome() if is_rootful else None\n    try:\n        channel.settimeout(min(1, budget.remaining()))\n        channel.connect(str(Path(config["directory"]) / "control.sock"))\n', '73fb3d6ae59c9010783930639b173e3b7a27a864f9283200b790abb3eaca0537', 'ba342202e43b4e729ea0d91e830a758204e914afa4a4c22669cad548c047216a'), ('D07', '        require(cgroup_snapshot(process_cgroup(os.getpid()), config) == gate["cgroup"], "worker-gate-cgroup")\n        require(os.environ.get("INVOCATION_ID") == gate["invocation"], "worker-invocation-identity")\n        require(digest(encode(gate["host_view"])) == gate["host_view_sha256"], "worker-host-view-integrity")\n        verify_source(config, budget, host_view=gate["host_view"], helper_ref=diagnostic_helper_ref)\n        if diagnostic_helper_ref is not None:\n            diagnostic_helper = diagnostic_helper_ref[0]\n        directory = Path(config["directory"])\n        if is_rootful:\n            rootful = authenticated_module("owned_guest_rootful", config, budget)\n', '        require(cgroup_snapshot(process_cgroup(os.getpid()), config) == gate["cgroup"], "worker-gate-cgroup")\n        require(os.environ.get("INVOCATION_ID") == gate["invocation"], "worker-invocation-identity")\n        require(digest(encode(gate["host_view"])) == gate["host_view_sha256"], "worker-host-view-integrity")\n        verify_source(config, budget, host_view=gate["host_view"])\n        directory = Path(config["directory"])\n        if is_rootful:\n            rootful = authenticated_module("owned_guest_rootful", config, budget)\n', '47a9d745f8f467ff3c44a7bdd3b2feac4eb8f14c09b20d9ea4fd844d0a7b1ae4', 'bed901888c671fbb1c7d38cb7d2d4c04cb8f8ac4de24d42e16e1677916a586fc'), ('D08', '                and 0 < image["virtual-size"] <= 32 * 1024**3\n                and not any(key in image for key in ("backing-filename", "full-backing-filename", "encrypted")),\n                "qemu-image-profile")\n        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)\n        status, _ = run([config["tools"]["qemu_img"]["path"], "create", "-f", "qcow2", "-F", "qcow2", "-b",\n                         str(directory / "image.qcow2"), str(directory / "overlay.qcow2")], budget, directory,\n                        file_bytes=config["overlay_max"])\n        require(status == 0, "overlay-create-failed")\n        budget.remaining()\n        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)\n        if is_rootful:\n            budget.commands_left -= 1\n            require(budget.commands_left >= 0, "command-budget")\n', '                and 0 < image["virtual-size"] <= 32 * 1024**3\n                and not any(key in image for key in ("backing-filename", "full-backing-filename", "encrypted")),\n                "qemu-image-profile")\n        worker_pre_child(config, budget, gate["host_view"])\n        status, _ = run([config["tools"]["qemu_img"]["path"], "create", "-f", "qcow2", "-F", "qcow2", "-b",\n                         str(directory / "image.qcow2"), str(directory / "overlay.qcow2")], budget, directory,\n                        file_bytes=config["overlay_max"])\n        require(status == 0, "overlay-create-failed")\n        budget.remaining()\n        worker_pre_child(config, budget, gate["host_view"])\n        if is_rootful:\n            budget.commands_left -= 1\n            require(budget.commands_left >= 0, "command-budget")\n', 'fe9d280d3c801bd692a1a1608fb5216f42e213f0efe02317104eb48a7918fa55', 'fea2fd3b4219176e71b3a4c8be64496d2c33ed30af1fd6d8d97bc53a51ec777f'), ('D09', '                send(channel, {"stage": "ssh-started", "ssh": ssh_record}, budget)\n        if is_rootful:\n            rootful.consume_record_purpose(budget, "guest-info")\n        worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)\n        status, raw_info = run(rootful.ssh_arguments(config) if is_rootful else ssh_arguments(config), budget, directory, extra_streams=(qemu.stdout, qemu.stderr), on_start=ssh_started,\n            **({"outcome_capture": guest_info_capture} if is_rootful else {}))\n        require(status == 0, "authenticated-guest-check-failed")\n', '                send(channel, {"stage": "ssh-started", "ssh": ssh_record}, budget)\n        if is_rootful:\n            rootful.consume_record_purpose(budget, "guest-info")\n        worker_pre_child(config, budget, gate["host_view"])\n        status, raw_info = run(rootful.ssh_arguments(config) if is_rootful else ssh_arguments(config), budget, directory, extra_streams=(qemu.stdout, qemu.stderr), on_start=ssh_started,\n            **({"outcome_capture": guest_info_capture} if is_rootful else {}))\n        require(status == 0, "authenticated-guest-check-failed")\n', '3db98660115b5f143da3e59741dc209a10fbdc2856261a3d7a9d0fba1236c37f', '0e923670249fe8b4d28c685aa4866cae57bf1cda98a506af3cb75d59c0bd5fbe'), ('D10', '                results.append(stage.transfer(session, phase, config,\n                    extra_streams=(qemu.stdout, qemu.stderr),\n                    on_start=lambda process, selected=phase: producer_started(process, selected),\n                    pre_child=lambda: worker_pre_child(config, budget, gate["host_view"],\n                                                       helper=diagnostic_helper)))\n            require(session.next_phase == 3 and not session.failed\n                    and session.input_sent == config["stage_input_limit"], "stage-cumulative-proof")\n            stage_result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256,\n', '                results.append(stage.transfer(session, phase, config,\n                    extra_streams=(qemu.stdout, qemu.stderr),\n                    on_start=lambda process, selected=phase: producer_started(process, selected),\n                    pre_child=lambda: worker_pre_child(config, budget, gate["host_view"])))\n            require(session.next_phase == 3 and not session.failed\n                    and session.input_sent == config["stage_input_limit"], "stage-cumulative-proof")\n            stage_result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256,\n', 'd25139e2dd7671238cf339b62b2263b0401827185129af3f829a1a00928df86a', 'd1f1eebd61179dce123fe33973c69d4f5860bb408b8db06a7252798ef662f485'), ('D11', '            rootful.consume_record_purpose(budget, "rootful-kind")\n            packet = rootful.request(config["owner"], config["stage_plan_sha256"], budget, config["rootful_spec"])\n            require(len(packet) <= config["rootful_input_reserved"] == 4096, "rootful-input-reservation")\n            worker_pre_child(config, budget, gate["host_view"], helper=diagnostic_helper)\n            rootful_input = {"limit": config["rootful_input_reserved"], "written": 0}\n            status, raw_result = run(rootful.ssh_arguments(config, execute=True), budget, directory,\n                extra_streams=(qemu.stdout, qemu.stderr), input_bytes=packet, input_account=rootful_input,\n', '            rootful.consume_record_purpose(budget, "rootful-kind")\n            packet = rootful.request(config["owner"], config["stage_plan_sha256"], budget, config["rootful_spec"])\n            require(len(packet) <= config["rootful_input_reserved"] == 4096, "rootful-input-reservation")\n            worker_pre_child(config, budget, gate["host_view"])\n            rootful_input = {"limit": config["rootful_input_reserved"], "written": 0}\n            status, raw_result = run(rootful.ssh_arguments(config, execute=True), budget, directory,\n                extra_streams=(qemu.stdout, qemu.stderr), input_bytes=packet, input_account=rootful_input,\n', '6f662399df548c7d20eb470bc16fb9613d98c500963d53d2724c67449ccd2291', '78b07174a867c839b9e01a5a2410f5a4450b0c559c222fc22f980d05dead343f'), ('D12', '        require(qemu.poll() is None and process_identity(qemu.pid) == qemu_record, "qemu-identity-before-retirement")\n    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:\n        failure = str(error) if isinstance(error, Refusal) else "worker-prerequisite-unavailable"\n        if isinstance(error, Refusal) and failure == "host-view-object-not-equivalent":\n            try:\n                host_view_mismatch = validated_host_view_mismatch(getattr(error, "host_view_mismatch", None))\n                require(host_view_mismatch["site"] == "worker-local", "worker-host-view-mismatch-site")\n            except (Refusal, TypeError, ValueError, RecursionError):\n                host_view_mismatch = None\n    finally:\n        if diagnostic_helper is None and diagnostic_helper_ref is not None:\n            diagnostic_helper = diagnostic_helper_ref[0]\n        try:\n            producer_reaped = []\n            for process in producers:\n', '        require(qemu.poll() is None and process_identity(qemu.pid) == qemu_record, "qemu-identity-before-retirement")\n    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:\n        failure = str(error) if isinstance(error, Refusal) else "worker-prerequisite-unavailable"\n    finally:\n        try:\n            producer_reaped = []\n            for process in producers:\n', '57aac8fc472ff6990e35e3f85dd2264aebb36d48f60ff25431029125d2e59d30', '695eb0aa1e5964924bd2aba8267c9eac843acea8fcfd8e022ad97ba8a3c60462'), ('D13', '                barrier["rootful_record_guards"] = (rootful.record_schedule(budget)\n                    if hasattr(budget, "_rootful_record_purposes") else None)\n            send(channel, barrier, budget, cleanup=True)\n            if diagnostic_helper is not None:\n                diagnostic_helper.send_optional_diagnostic(channel, host_view_mismatch, diagnostic_profile)\n        finally:\n            channel.close()\n\n', '                barrier["rootful_record_guards"] = (rootful.record_schedule(budget)\n                    if hasattr(budget, "_rootful_record_purposes") else None)\n            send(channel, barrier, budget, cleanup=True)\n        finally:\n            channel.close()\n\n', '37ccb37f19ae7cfc072105377a170d2baf282bdbec208ff43564a4c9f96a888e', 'd901391cf092500b73c8a1bbdede729dae19f9fd2a714d04dea929fa3c960399'), ('D14', '            and not process_cgroup(os.getpid()).startswith(target + "/"), "outside-controller-placement")\n    snapshot = cgroup_snapshot(target, config)\n    require(process_identity(peer["pid"]) == peer and boot_id() == config["boot"], "barrier-kernel-drift")\n    return invocation, snapshot\n\n\ndef attest_barrier_and_bind(row, hello, peer, config, config_sha, *, reservation=None, budget=None, channel=None):\n    invocation, snapshot = attest_barrier(row, hello, peer, config, config_sha)\n    if reservation is not None:\n        reservation.bind_authenticated(budget, channel, peer, config_sha)\n    return invocation, snapshot\n\n\n', '            and not process_cgroup(os.getpid()).startswith(target + "/"), "outside-controller-placement")\n    snapshot = cgroup_snapshot(target, config)\n    require(process_identity(peer["pid"]) == peer and boot_id() == config["boot"], "barrier-kernel-drift")\n    return invocation, snapshot\n\n\n', '763a7a4ceacce127602f809022402eca57f15cfd1cb2cafe957d98f6922e58d3', 'db1e9e614f2ce7386fee8ef72b08f5d34facc8943f326126ea69527130b4fcbe'), ('D15', '\ndef qualify(args, *, start=None):\n    start = time.monotonic() if start is None else start\n    diagnostic_profile = getattr(args, "host_view_diagnostic_profile", None)\n    require(diagnostic_profile in (None, DIAGNOSTIC_CREDIT_PROFILE), "host-view-diagnostic-profile")\n    parent = validate_config_args(args)\n    budget = Budget(start + args.deadline_seconds, args.cleanup_seconds)\n    tools = admit_tools(args.host_tools, args.host_tools_sha256)\n', '\ndef qualify(args, *, start=None):\n    start = time.monotonic() if start is None else start\n    parent = validate_config_args(args)\n    budget = Budget(start + args.deadline_seconds, args.cleanup_seconds)\n    tools = admit_tools(args.host_tools, args.host_tools_sha256)\n', 'db5bf38b7036747bd003adf8e3c4402845bb0da341119c5cf95af17adf0cedcc', 'c7653d8d3ff6896979833da0aa67d04a9ff8558d8e213e25f304c454cbd18a35'), ('D16', '    error, cleanup_error, retirement = None, None, None\n    attempted = False\n    view, view_frame = None, None\n    view_impl, reservation = None, None\n    host_view_mismatch = None\n    host_view_failure_site = None\n    config = {"owner": owner, "unit": "kubernetes-lens-vm-" + owner + ".service",\n              "directory": str(directory), "start": start, "end": budget.end, "work_end": budget.work_end,\n              "cleanup_seconds": args.cleanup_seconds, "cpus": args.cpus, "pids": args.pids,\n', '    error, cleanup_error, retirement = None, None, None\n    attempted = False\n    view, view_frame = None, None\n    config = {"owner": owner, "unit": "kubernetes-lens-vm-" + owner + ".service",\n              "directory": str(directory), "start": start, "end": budget.end, "work_end": budget.work_end,\n              "cleanup_seconds": args.cleanup_seconds, "cpus": args.cpus, "pids": args.pids,\n', 'c67079f2fc79f4446478f50c8dc062f794736b9e3aa932bd6bb123115e7a25f6', 'f73e58a114816d78cc0156c553d576f6943468a4486fd5035bfe4f2b718e60d8'), ('D17', '                                             str(ROOT / "scripts/fixtures/kind_runtime.py"): digest(read(ROOT / "scripts/fixtures/kind_runtime.py", 4 * 1024**2)),\n                                             str(PIN): pin_sha,\n                                             str(ROOT / "scripts/fixtures/owned_host_view.py"): digest(read(ROOT / "scripts/fixtures/owned_host_view.py", 4 * 1024**2))}}\n    if diagnostic_profile is not None:\n        config.update(host_view_diagnostic_profile=diagnostic_profile,\n                      host_view_diagnostic_credit_bytes=DIAGNOSTIC_CREDIT_BYTES)\n    image_evidence, stage_evidence, guest_summary = None, None, None\n    producer_records = []\n    rootful_durable = None\n', '                                             str(ROOT / "scripts/fixtures/kind_runtime.py"): digest(read(ROOT / "scripts/fixtures/kind_runtime.py", 4 * 1024**2)),\n                                             str(PIN): pin_sha,\n                                             str(ROOT / "scripts/fixtures/owned_host_view.py"): digest(read(ROOT / "scripts/fixtures/owned_host_view.py", 4 * 1024**2))}}\n    image_evidence, stage_evidence, guest_summary = None, None, None\n    producer_records = []\n    rootful_durable = None\n', '689d32380a184d3ae51d88dd4a4158bc2e31dabe0889ec5a1d85fb3e472ec994', 'e13929d8a5a94e7d841a0ad6a542b6cca0b0d78e4fbeaa0e27b90a8ea163b9e2'), ('D18', '            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key), "user-manager-environment-schema")\n            manager_keys.append(key)\n        verify_source(config, budget)\n        view_impl = host_view_module(config, budget)\n        view = view_impl.ParentView(config, budget)\n        parent_pre_child(config, budget)\n        if diagnostic_profile is not None:\n            reservation = view_impl.PendingDiagnosticReservation(budget, config_sha)\n        attempted = True\n        status, _ = run(unit_arguments(config, config_path, config_sha, manager_keys), budget, directory, manager=True)\n        require(status == 0, "owned-unit-start-failed")\n', '            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key), "user-manager-environment-schema")\n            manager_keys.append(key)\n        verify_source(config, budget)\n        view = host_view_module(config, budget).ParentView(config, budget)\n        parent_pre_child(config, budget)\n        attempted = True\n        status, _ = run(unit_arguments(config, config_path, config_sha, manager_keys), budget, directory, manager=True)\n        require(status == 0, "owned-unit-start-failed")\n', '547f92413e41a0adb7cce5d73a2f8dec055ea9a82e67b5f79723d2d5c9f17274', 'c23d037069e089328bbda6d5b67477faa6913af92daaa2aa888b6a52e736519c'), ('D19', '        worker_record = peer_identity(channel)\n        hello = receive(channel, budget)\n        row = unit_show(config, budget)\n        invocation, snapshot = attest_barrier_and_bind(row, hello, worker_record, config, config_sha,\n            reservation=reservation, budget=budget, channel=channel)\n        verify_source(config, budget)\n        host_view_failure_site = "parent-attest"\n        view_frame = view.attest(worker_record, invocation, snapshot, config_sha)\n        host_view_failure_site = "parent-recheck"\n        view.recheck()\n        host_view_failure_site = None\n        send(channel, {"stage": "go", "config_sha256": config_sha, "invocation": invocation, "cgroup": snapshot,\n                       "host_view": view_frame if view_frame is not None else view.partial if view is not None else None, "host_view_sha256": digest(encode(view_frame))}, budget)\n        if reservation is not None:\n            reservation.activate(budget, channel, config_sha)\n        while True:\n            event = receive(channel, budget)\n            if event.get("stage") == "qemu-started":\n', '        worker_record = peer_identity(channel)\n        hello = receive(channel, budget)\n        row = unit_show(config, budget)\n        invocation, snapshot = attest_barrier(row, hello, worker_record, config, config_sha)\n        verify_source(config, budget)\n        view_frame = view.attest(worker_record, invocation, snapshot, config_sha)\n        view.recheck()\n        send(channel, {"stage": "go", "config_sha256": config_sha, "invocation": invocation, "cgroup": snapshot,\n                       "host_view": view_frame if view_frame is not None else view.partial if view is not None else None, "host_view_sha256": digest(encode(view_frame))}, budget)\n        while True:\n            event = receive(channel, budget)\n            if event.get("stage") == "qemu-started":\n', '8c9a931f9c738ba1c372a15394ef2706d40db87e28ee2fa594d440337ed74567', '208853e54ee3b68d53313a4925d85cdf5274477b9c9e5dc490cc89382d503981'), ('D20', '            require(type(event.get("rootful_input_bytes")) is int and 0 < event["rootful_input_bytes"] <= 4096, "rootful-input-completion")\n    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:\n        error = str(caught) if isinstance(caught, Refusal) else "vm-prerequisite-unavailable"\n        if diagnostic_profile is not None and isinstance(caught, Refusal) and error == "host-view-object-not-equivalent":\n            detail = getattr(caught, "host_view_mismatch", None)\n            if detail is not None:\n                try:\n                    host_view_mismatch = validated_host_view_mismatch(detail)\n                    require(host_view_mismatch["site"] == host_view_failure_site,\n                            "parent-host-view-mismatch-site")\n                except (Refusal, TypeError, ValueError, RecursionError):\n                    host_view_mismatch = None\n    finally:\n        if reservation is not None and reservation.state in ("pending", "bound"):\n            reservation.finalize()\n        server.close()\n        if view is not None:\n            view.close()\n', '            require(type(event.get("rootful_input_bytes")) is int and 0 < event["rootful_input_bytes"] <= 4096, "rootful-input-completion")\n    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:\n        error = str(caught) if isinstance(caught, Refusal) else "vm-prerequisite-unavailable"\n    finally:\n        server.close()\n        if view is not None:\n            view.close()\n', '2feea0c1fa8e5d517abb51dae37959c7efa0af6e1faa6cce98389996d78ba31f', 'ce9cc2f21db1c4e8c22bbb9427e607112dea7783920ab2c1506ff2e59d7185da'), ('D21', '            except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:\n                cleanup_error = str(caught) if isinstance(caught, Refusal) else "outside-retirement-unavailable"\n        if channel:\n            if reservation is not None:\n                if (retirement is not None and cleanup_error is None and error == "host-view-object-not-equivalent"\n                        and host_view_mismatch is None and reservation.state == "active"):\n                    try:\n                        host_view_mismatch = reservation.drain_once(budget, channel)\n                    except (Refusal, OSError, TypeError, ValueError, RecursionError):\n                        host_view_mismatch = None\n                if reservation.state in ("pending", "bound", "active"):\n                    reservation.finalize()\n            channel.close()\n        elif reservation is not None and reservation.state in ("pending", "bound", "active"):\n            reservation.finalize()\n        # No target was started: removal is safe. Once started, uncertainty keeps\n        # the private lease/evidence and forbids a positive receipt or deletion.\n        if not attempted or retirement is not None:\n', '            except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as caught:\n                cleanup_error = str(caught) if isinstance(caught, Refusal) else "outside-retirement-unavailable"\n        if channel:\n            channel.close()\n        # No target was started: removal is safe. Once started, uncertainty keeps\n        # the private lease/evidence and forbids a positive receipt or deletion.\n        if not attempted or retirement is not None:\n', 'cbca9773ffc546ef2db1f3d14db8513d3a2003e4f9fbc652e03e1dff3137f8f7', '2706d811c15f362cd1ece6fb7b76f36544162989544fcfd29ff0c46da7681aab'), ('D22', '        private["rootful_input_bytes"] = barrier.get("rootful_input_bytes") if type(barrier) is dict else None\n        private["runtime_conformance"] = "source-deployment-positive-only" if success else "not-established"\n        private["kubernetes_readiness"] = "owned-node-observed" if success else "not-established"\n    if diagnostic_profile is not None and error == "host-view-object-not-equivalent":\n        private = with_optional_host_view_mismatch(private, host_view_mismatch)\n    # The receipt contains identities, never key material, raw guest JSON or logs.\n    receipt_path = parent / ("kubernetes-lens-vm-" + owner + ".receipt.json")\n    budget.remaining(cleanup=True)\n', '        private["rootful_input_bytes"] = barrier.get("rootful_input_bytes") if type(barrier) is dict else None\n        private["runtime_conformance"] = "source-deployment-positive-only" if success else "not-established"\n        private["kubernetes_readiness"] = "owned-node-observed" if success else "not-established"\n    # The receipt contains identities, never key material, raw guest JSON or logs.\n    receipt_path = parent / ("kubernetes-lens-vm-" + owner + ".receipt.json")\n    budget.remaining(cleanup=True)\n', '73454a5b5c6964afc6a6eb19d7fb1801f209a143255f3916eb9a02a4595ea6d9', '9f8bdc34c1d78139547796d761de66db9078337c5a48865dcb86ec1cb79dff75'), ('D23', '                signal.signal(number, handler)\n    parser = argparse.ArgumentParser(description=__doc__)\n    parser.add_argument("--phase", choices=["qualify-vm", "stage-inputs", "run-rootful-kind"], required=True)\n    parser.add_argument("--host-view-diagnostic-profile", choices=[DIAGNOSTIC_CREDIT_PROFILE])\n    for name in ("image", "host-tools", "host-tools-sha256", "output-parent"):\n        parser.add_argument("--" + name, required=True)\n    for name in ("cpus", "memory-mib", "guest-memory-mib", "pids", "disk-gib", "deadline-seconds", "cleanup-seconds", "ssh-port"):\n', '                signal.signal(number, handler)\n    parser = argparse.ArgumentParser(description=__doc__)\n    parser.add_argument("--phase", choices=["qualify-vm", "stage-inputs", "run-rootful-kind"], required=True)\n    for name in ("image", "host-tools", "host-tools-sha256", "output-parent"):\n        parser.add_argument("--" + name, required=True)\n    for name in ("cpus", "memory-mib", "guest-memory-mib", "pids", "disk-gib", "deadline-seconds", "cleanup-seconds", "ssh-port"):\n', '2f5db1b7f7954be5d8dabbb4c5e2d2ec3b7b8c0038bd7d9047559ca0a9993965', '11832ca2f0958f462c37dd5ef92ccc5ef8fedfc7e857cfa4cac9697c0c95684d'))


def _apply_host_view_diagnostic_hunk(source, identity, current, historical, current_sha, historical_sha):
    """Apply one exact fixed-data hunk; shared by the actual fold and controls."""
    if (hashlib.sha256(current.encode()).hexdigest() != current_sha
            or hashlib.sha256(historical.encode()).hexdigest() != historical_sha):
        raise AssertionError('diagnostic hunk literal integrity: ' + identity)
    if source.count(current) != 1:
        raise AssertionError('diagnostic hunk occurrence: ' + identity)
    return source.replace(current, historical, 1)


def before_host_view_diagnostics(source):
    """Exact diagnostic-only historical comparison DATA, never execution source."""
    if (type(source) is not str or len(source.encode()) != 140693
            or hashlib.sha256(source.encode()).hexdigest() !=
            'b857fb2f20d98483466ab252c0580b9bcfab0d81d4b7c3a47d8748326d8ab682'):
        raise AssertionError('unknown actual diagnostic source')
    for hunk in _HOST_VIEW_DIAGNOSTIC_HUNKS:
        source = _apply_host_view_diagnostic_hunk(source, *hunk)
    if (len(source.encode()) != 131127 or hashlib.sha256(source.encode()).hexdigest() !=
            '4ede9ab56d7c850fc8c80f6bbdbf9b70992c532a073b46b1d3df7a655957344a'):
        raise AssertionError('independent historical target mismatch')
    return source

_HISTORICAL_DIAGNOSTIC_SOURCE_PATH = (Path(__file__).resolve().parents[2]
                                      / "fixtures" / "owned_vm_history" / "owned_qemu-b857fb2.source")
_HISTORICAL_DIAGNOSTIC_SOURCE_BYTES = 140693
_HISTORICAL_DIAGNOSTIC_SOURCE_SHA256 = "b857fb2f20d98483466ab252c0580b9bcfab0d81d4b7c3a47d8748326d8ab682"
_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256 = '744d3673eb1a44419e91e9c34614b8225c71b05937c7b1476add1e2a4931444f'


def _historical_diagnostic_source(*, path=None):
    """Read retained project-owned source DATA; never fall back to the runtime module."""
    target = _HISTORICAL_DIAGNOSTIC_SOURCE_PATH if path is None else Path(path)
    try:
        with target.open("rb") as source_file:
            raw = source_file.read(_HISTORICAL_DIAGNOSTIC_SOURCE_BYTES + 1)
    except OSError as error:
        raise AssertionError("historical diagnostic fixture unavailable") from error
    if (len(raw) != _HISTORICAL_DIAGNOSTIC_SOURCE_BYTES
            or hashlib.sha256(raw).hexdigest() != _HISTORICAL_DIAGNOSTIC_SOURCE_SHA256):
        raise AssertionError("historical diagnostic fixture integrity")
    return raw.decode("utf-8")


def before_boot_settling(source):
    """Reverse only the exact scheduling delta before historical identity checks."""
    anchor = "def settle_guest_check("
    call = "        if is_rootful:\n            settle_guest_check(qemu, selector, budget)\n"
    if source.count(anchor) != 1 or source.count(call) != 1:
        raise AssertionError("exact single scheduling helper and call required")
    prefix, tail = source.split(anchor, 1)
    helper, remainder = tail.split("def worker(", 1)
    if hashlib.sha256((anchor + helper).encode()).hexdigest() != \
            "37aa627e25a4085447ecdaa2a433152ffddd8bec5ee78067552a2a6fc5e5f658":
        raise AssertionError("scheduling helper bytes changed")
    return (prefix + "def worker(" + remainder).replace(call, "", 1)


def config():
    return {"unit": "kubernetes-lens-vm-" + "a" * 32 + ".service", "owner": "a" * 32,
            "directory": "/private/owned", "tools": {name: {"path": "/usr/bin/" + name} for name in vm.ROLES},
            "cpus": 2, "memory_bytes": 4 * 1024**3, "guest_memory_mib": 2048, "pids": 256,
            "overlay_max": 8 * 1024**3, "start": 100.0, "work_end": 650.0, "end": 700.0,
            "port": 22222, "boot": "boot", "cleanup_seconds": 50}


def unit():
    row = dict.fromkeys(vm.SHOW_FIELDS, "")
    row.update({"Id": config()["unit"], "Description": "KubernetesLens owned VM " + "a" * 32,
                "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "Transient": "yes",
                "MainPID": "321", "InvocationID": "b" * 32, "ControlGroup": "/owned/" + config()["unit"],
                "Restart": "no", "KillMode": "control-group", "RemainAfterExit": "yes", "NRestarts": "0",
                "RuntimeMaxUSec": "8min", "TimeoutStopUSec": "1s", "ExecMainStartTimestampMonotonic": "100000000",
                "FailureAction": "none", "SuccessAction": "none", "StartLimitAction": "none", "RuntimeRandomizedExtraUSec": "0"})
    return row


def identity(pid=321):
    return {"pid": pid, "group": pid, "session": pid, "start": 123}


def barrier():
    return {"stage": "producer-stopped", "error": None, "guest": {"rootful": True, "local": True,
            "cgroup_version": "v2", "podman_version": "5.8.7"}, "qemu": identity(444), "ssh": None,
            "qemu_reaped": True, "ssh_reaped": True, "original_end": 700.0}


def simple_unit_text(row):
    return "".join(name + "=" + row[name] + "\n" for name in vm.SIMPLE_FIELDS).encode()


def empty_stop_properties():
    line = vm.encode({"type": "a(sasbttttuii)", "data": []}) + b"\n"
    return line + line


class ObservedParentRetirement:
    """Fake raw I/O for the real parent observer, trace validator and publication."""
    BOOT = "11111111-1111-1111-1111-111111111111"

    def __init__(self, case, controller_run):
        self.case, self.controller_run = case, controller_run
        self.now, self.stopped, self.config = 100.0, False, None
        self.commands, self.output_charges = [], []
        self.actual_evidence, self.actual_retire = vm.RetirementEvidence, vm.retire
        self.actual_identity, self.actual_cgroup, self.actual_boot = vm.process_identity, vm.process_cgroup, vm.boot_id
        self.actual_unit_show = vm.unit_show

    def evidence(self, parent, config, budget):
        self.config = config
        return self.actual_evidence(parent, config, budget, kernel=self)

    def sleep(self, seconds):
        self.case.assertGreaterEqual(seconds, 0)
        self.now += seconds

    def snapshot(self):
        return {"path": "/sys/fs/cgroup/owned/" + self.config["unit"], "device": 7, "inode": 23,
                "cpu_max": str(self.config["cpus"] * 100000) + " 100000",
                "memory_max": self.config["memory_bytes"], "pids_max": self.config["pids"], "swap_max": 0}

    def attest(self, *_args, **_kwargs):
        return "b" * 32, self.snapshot()

    def process_identity(self, pid, *, evidence=None):
        return identity(pid) if evidence is None else self.actual_identity(pid, evidence=evidence)

    def process_cgroup(self, pid, *, evidence=None):
        if evidence is None:
            return "/sys/fs/cgroup/owned/" + config()["unit"]
        return self.actual_cgroup(pid, evidence=evidence)

    def boot_id(self, *, evidence=None):
        return self.BOOT if evidence is None else self.actual_boot(evidence=evidence)

    def row(self):
        row = {**unit(), "RuntimeMaxUSec": "1min"}
        if self.stopped:
            row.update(ActiveState="inactive", SubState="dead", MainPID="0", InvocationID="")
        return row

    def unit_show(self, config, budget, **kwargs):
        return self.row() if kwargs.get("evidence") is None else self.actual_unit_show(config, budget, **kwargs)

    def read(self, path):
        path = str(path)
        snapshot = self.snapshot()
        if path == "/proc/sys/kernel/random/boot_id":
            raw = (self.BOOT + "\n").encode()
        elif path.startswith("/proc/") and path.endswith(("/stat", "/cgroup")):
            pid = int(Path(path).parent.name)
            if self.stopped:
                raise FileNotFoundError(2, "fixture process retired", path)
            if path.endswith("/stat"):
                fields = ["S", "0", str(pid), str(pid)] + ["0"] * 15 + ["123"]
                raw = (str(pid) + " (fixture) " + " ".join(fields) + "\n").encode()
            else:
                raw = ("0::" + snapshot["path"].removeprefix("/sys/fs/cgroup") + "\n").encode()
        else:
            self.case.assertEqual(str(Path(path).parent), snapshot["path"])
            values = {"cpu.max": snapshot["cpu_max"], "memory.max": str(snapshot["memory_max"]),
                      "pids.max": str(snapshot["pids_max"]), "memory.swap.max": "0",
                      "cgroup.events": "populated 0\nfrozen 0", "cgroup.procs": ""}
            self.case.assertIn(Path(path).name, values)
            raw = (values[Path(path).name] + "\n").encode()
        self.output_charges.append(len(raw))
        return raw

    def canonical(self, path):
        self.case.assertEqual(str(path), self.snapshot()["path"])
        self.output_charges.append(len(vm.encode(str(path))))
        return Path(path)

    def stat(self, path):
        self.case.assertEqual(str(path), self.snapshot()["path"])
        info = SimpleNamespace(st_mode=vm.stat.S_IFDIR | 0o700, st_uid=os.getuid(), st_gid=os.getgid(),
            st_dev=7, st_ino=23, st_nlink=1, st_size=0, st_atime_ns=0, st_mtime_ns=0, st_ctime_ns=0)
        self.output_charges.append(len(vm.encode(vm._retirement_stat(info))))
        return info

    def exists(self, path):
        self.case.assertEqual(str(path), self.snapshot()["path"])
        self.output_charges.append(len(vm.encode(True)))
        return True

    def run(self, argv, budget, directory, **kwargs):
        if kwargs.get("outcome_capture") is None:
            return self.controller_run(argv, budget, directory, **kwargs)
        self.case.assertTrue(kwargs["manager"])
        self.case.assertLessEqual(kwargs["deadline"], min(self.now + 5.0, budget.end))
        self.commands.append(list(argv))
        budget.commands_left -= 1
        vm.require(budget.commands_left >= 0, "command-budget")
        if "stop" in argv:
            self.stopped, raw = True, b""
        elif argv[0] == self.config["tools"]["busctl"]["path"]:
            raw = empty_stop_properties()
        else:
            raw = simple_unit_text(self.row())
        budget.charge(len(raw))
        self.output_charges.append(len(raw))
        outcome = kwargs["outcome_capture"]
        outcome.update(classification="exit", returncode=0)
        for name, data in (("stdout", raw), ("stderr", b"")):
            outcome[name].update(charged_bytes=len(data), charged_sha256=vm.digest(data), eof=True)
        if raw:
            kwargs["stdout_capture"](raw)
        self.now += 0.001
        return 0, raw


class TypedStopPropertyControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def unloaded(self):
        return {**unit(), "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead",
                "MainPID": "0", "InvocationID": "", "ControlGroup": ""}

    def test_loaded_unit_gets_full_semantic_fields_only_after_typed_empty_arrays(self):
        with patch.object(vm, "run", side_effect=[(0, simple_unit_text(unit())), (0, empty_stop_properties()),
                                                (0, simple_unit_text(unit()))]) as run:
            row = vm.unit_show(config(), self.budget)
        self.assertEqual(set(row), set(vm.SHOW_FIELDS))
        self.assertEqual(row["ExecStop"], "")
        self.assertEqual(row["ExecStopPost"], "")
        text_argument = next(value for value in run.call_args_list[0].args[0] if value.startswith("--property="))
        self.assertNotIn("ExecStop", text_argument)
        argv = run.call_args_list[1].args[0]
        self.assertEqual(argv, [config()["tools"]["busctl"]["path"], "--user", "--no-pager", "--timeout=5s",
                               "--json=short", "get-property", "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1/unit/kubernetes_2dlens_2dvm_2d" + "a" * 32 + "_2eservice",
                               "org.freedesktop.systemd1.Service", "ExecStop", "ExecStopPost"])
        self.assertTrue(run.call_args_list[1].kwargs["manager"])

    def test_replacement_or_disappearance_cannot_inherit_typed_proof(self):
        for after in ({**unit(), "InvocationID": "c" * 32}, self.unloaded(),
                      {**unit(), "Restart": "always"}, {**unit(), "UpheldBy": "foreign.service"}):
            replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(after))]
            with self.subTest(after=after), patch.object(vm, "run", side_effect=replies):
                with self.assertRaisesRegex(vm.Refusal, "unit-changed-during-stop-proof"):
                    vm.unit_show(config(), self.budget)

    def test_unsupported_nonempty_malformed_and_ambiguous_typed_proofs_refuse(self):
        empty = vm.encode({"type": "a(sasbttttuii)", "data": []}) + b"\n"
        cases = [(1, empty_stop_properties()), (0, b""), (0, empty), (0, empty * 3),
                 (0, empty + b'{"type":"a(sasbttttuii)","data":['),
                 (0, empty + b'{"type":"a(sasbttttuii)","data":[],"data":[]}\n'),
                 (0, empty + vm.encode({"type": "as", "data": []}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": {}}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": [["/unexpected/stop"]]}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)", "data": [], "extra": True}) + b"\n"),
                 (0, empty + vm.encode({"type": "a(sasbttttuii)"}) + b"\n")]
        for status, raw in cases:
            with self.subTest(status=status, raw=raw), patch.object(vm, "run", return_value=(status, raw)):
                with self.assertRaises(vm.Refusal):
                    vm.prove_no_stop_commands(config(), self.budget)

    def test_object_path_cannot_be_substituted_with_a_foreign_unit(self):
        c = {**config(), "unit": "kubernetes-lens-vm-" + "b" * 32 + ".service"}
        with patch.object(vm, "run") as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-object-path-identity"):
                vm.prove_no_stop_commands(c, self.budget)
        run.assert_not_called()

    def test_typed_call_timeout_shrinks_inside_original_end(self):
        with patch.object(vm.time, "monotonic", return_value=99.75), \
             patch.object(vm, "run", return_value=(0, empty_stop_properties())) as run:
            vm.prove_no_stop_commands(config(), vm.Budget(100.0, 0), cleanup=True)
        self.assertIn("--timeout=250000us", run.call_args.args[0])
        self.assertTrue(run.call_args.kwargs["cleanup"])

    def test_simple_typed_confirm_chain_shares_one_shorter_end_and_budget(self):
        replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(unit()))]
        cutoff = time.monotonic() + 2
        with patch.object(vm, "run", side_effect=replies) as run:
            vm.unit_show(config(), self.budget, deadline=cutoff)
        self.assertEqual(len(run.call_args_list), 3)
        self.assertTrue(all(call.args[1] is self.budget for call in run.call_args_list))
        self.assertTrue(all(call.kwargs["deadline"] == cutoff for call in run.call_args_list))

    def test_missing_simple_property_is_not_replaced_by_empty_value(self):
        text = simple_unit_text(unit()).replace(b"Restart=no\n", b"")
        with patch.object(vm, "run", return_value=(0, text)) as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-state-incomplete"):
                vm.unit_show(config(), self.budget)
        run.assert_called_once()

    def test_unloaded_terminal_case_has_no_asserted_complex_property_values(self):
        with patch.object(vm, "run", return_value=(4, simple_unit_text(self.unloaded()))) as run:
            row = vm.unit_show(config(), self.budget, cleanup=True)
        self.assertEqual(row["LoadState"], "not-found")
        self.assertEqual(set(row), set(vm.SIMPLE_FIELDS))
        self.assertNotIn("ExecStop", row)
        self.assertNotIn("ExecStopPost", row)
        run.assert_called_once()

    def test_not_found_with_an_invocation_process_cgroup_or_job_refuses(self):
        for name, value in (("MainPID", "123"), ("InvocationID", "c" * 32), ("ControlGroup", "/foreign"),
                            ("Job", "3 /job/3"), ("ActiveState", "active")):
            row = {**self.unloaded(), name: value}
            with self.subTest(name=name), patch.object(vm, "run", return_value=(0, simple_unit_text(row))):
                with self.assertRaisesRegex(vm.Refusal, "unit-not-found-state-inconsistent"):
                    vm.unit_show(config(), self.budget, cleanup=True)

    def test_retirement_handles_unloaded_service_after_previously_typed_loaded_proof(self):
        replies = [(0, simple_unit_text(unit())), (0, empty_stop_properties()), (0, simple_unit_text(unit())), (0, b""),
                   (4, simple_unit_text(self.unloaded())), (4, simple_unit_text(self.unloaded()))]
        with patch.object(vm, "run", side_effect=replies) as run, \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", return_value="removed") as empty, patch.object(vm.time, "sleep"):
            receipt = vm.retire(config(), self.budget, "b" * 32, {"path": "/target"}, identity(), identity(444), barrier())
        self.assertEqual(receipt["state"], "retired")
        self.assertEqual(empty.call_count, 2)
        self.assertEqual(sum(call.args[0][0] == config()["tools"]["busctl"]["path"] for call in run.call_args_list), 1)

    def test_busctl_is_required_in_the_reviewed_manifest_without_auto_installation(self):
        document = {"schema": "kubernetes-lens-owned-vm-tools-v1",
                    "tools": {name: {} for name in vm.ROLES - {"busctl"}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_bytes(vm.encode(document))
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-schema"):
                vm.admit_tools(path, vm.digest(path.read_bytes()))


class PublicationControls(unittest.TestCase):
    def test_full_undrained_pipe_cannot_extend_original_end(self):
        reader, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b"x" * 65536)
                except BlockingIOError:
                    break
            start = time.monotonic()
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, start + 0.025,
                                               descriptor=writer))
            self.assertLess(time.monotonic() - start, 1)
            self.assertFalse(os.get_blocking(writer))
        finally:
            os.close(writer)
            os.close(reader)

    def test_partial_nonblocking_writes_keep_exact_receipt_bytes(self):
        collected = bytearray()
        def partial(_descriptor, data):
            count = min(3, len(data))
            collected.extend(data[:count])
            return count
        with patch.object(vm.os, "get_blocking", return_value=True), \
             patch.object(vm.os, "set_blocking") as blocking, \
             patch.object(vm.os, "write", side_effect=partial):
            self.assertTrue(vm.publish_receipt({"state": "vm-qualified-retired"},
                                              time.monotonic() + 1, descriptor=123))
        self.assertEqual(blocking.call_args_list, [((123, False),), ((123, True),)])
        self.assertEqual(bytes(collected), b'{"state":"vm-qualified-retired"}\n')

    def test_expired_end_and_broken_output_never_publish_success(self):
        with patch.object(vm.os, "get_blocking", return_value=True), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "write") as output:
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, time.monotonic() - 1))
            output.assert_not_called()
            output.side_effect = BrokenPipeError
            self.assertFalse(vm.publish_receipt({"state": "failed-retired"}, time.monotonic() + 1))


class InputControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def test_overlong_control_socket_parent_refuses_before_image_or_runtime(self):
        args = SimpleNamespace(deadline_seconds=900, cleanup_seconds=90, cpus=2,
                               memory_mib=8192, guest_memory_mib=4096, pids=256,
                               disk_gib=16, ssh_port=22222, output_parent="/tmp/" + "p" * 80)
        with patch.object(vm, "canonical", return_value=Path(args.output_parent)), \
             patch.object(vm.Path, "stat") as inspection:
            with self.assertRaisesRegex(vm.Refusal, "private-control-socket-path-budget"):
                vm.validate_config_args(args)
        inspection.assert_not_called()

    def test_pin_strict_schema_and_immutable_url(self):
        item = {"schema": "kubernetes-lens-owned-vm-image-v1", "release": "44.20260928.3.2", "archive_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pin.json"
            path.write_bytes(vm.encode(item))
            observed, sha = vm.pin_document(path)
            self.assertEqual(observed, item)
            self.assertEqual(sha, vm.digest(path.read_bytes()))
            self.assertEqual(vm.official_url(item), "https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.2/x86_64/fedora-coreos-44.20260928.3.2-qemu.x86_64.qcow2.xz")
            for key, value in (("release", "latest"), ("archive_sha256", "X" * 64), ("url", "https://attacker")):
                invalid = {**item, key: value}
                path.write_bytes(vm.encode(invalid))
                with self.assertRaises(vm.Refusal):
                    vm.pin_document(path)

    def test_duplicate_and_nonfinite_json_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(vm.Refusal):
                vm.strict_json(raw)

    def test_symlink_input_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "real").write_text("safe")
            (path / "link").symlink_to(path / "real")
            with self.assertRaisesRegex(vm.Refusal, "symlink-path-refused"):
                vm.read(path / "link")

    def test_archive_authenticates_before_decompression(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / "bad.xz"
            source.write_bytes(b"not XZ")
            with patch.object(vm.lzma, "LZMADecompressor") as decoder:
                with self.assertRaisesRegex(vm.Refusal, "archive-integrity"):
                    vm.admit_archive(source, path, {"archive_sha256": "a" * 64}, vm.Budget(time.monotonic() + 60, 10))
                decoder.assert_not_called()

    def test_bounded_authenticated_qcow2_expansion(self):
        header = bytearray(104)
        header[:4] = b"QFI\xfb"
        struct.pack_into(">I", header, 4, 3)
        compressed = lzma.compress(bytes(header))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / "source.xz"
            source.write_bytes(compressed)
            pin = {"archive_sha256": vm.digest(compressed), "release": "44.20260928.3.2"}
            result = vm.admit_archive(source, path, pin, vm.Budget(time.monotonic() + 60, 10))
            self.assertEqual(result["expanded_bytes"], 104)
            self.assertEqual(result["expanded_sha256"], vm.digest(header))
            self.assertEqual((path / "image.qcow2").stat().st_mode & 0o777, 0o400)
            self.assertFalse((path / "image.qcow2.xz").exists())

    def test_concatenated_truncated_overbudget_and_backing_xz_refuse(self):
        header = bytearray(104)
        header[:4] = b"QFI\xfb"
        struct.pack_into(">I", header, 4, 3)
        good = lzma.compress(header)
        bad_backing = bytearray(header)
        struct.pack_into(">Q", bad_backing, 8, 64)
        cases = [(good + good, "trailing-xz-data", vm.EXPANDED_MAX),
                 (good[:-8], "truncated-xz", vm.EXPANDED_MAX),
                 (good, "expanded-image-budget", 32),
                 (lzma.compress(bad_backing), "qcow2-external-or-unsupported-features", vm.EXPANDED_MAX)]
        for compressed, code, maximum in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.xz"
                source.write_bytes(compressed)
                with patch.object(vm, "EXPANDED_MAX", maximum):
                    with self.assertRaisesRegex(vm.Refusal, code):
                        vm.admit_archive(source, directory, {"archive_sha256": vm.digest(compressed)}, vm.Budget(time.monotonic() + 60, 10))

    def test_unreviewed_manifest_and_missing_role_refuse_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tools.json"
            path.write_text('{"schema":"kubernetes-lens-owned-vm-tools-v1","tools":{}}')
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-integrity"):
                vm.admit_tools(path, "a" * 64)
            with self.assertRaisesRegex(vm.Refusal, "host-tools-manifest-schema"):
                vm.admit_tools(path, vm.digest(path.read_bytes()))


class InvocationControls(unittest.TestCase):
    def test_ignition_restricts_the_key_masks_zincati_and_pins_host_identity(self):
        document = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE TEST KEY", "ssh-ed25519 BBBB\n")
        self.assertEqual(document["systemd"]["units"], [{"name": "zincati.service", "mask": True}])
        key = document["passwd"]["users"][0]["sshAuthorizedKeys"][0]
        self.assertEqual(key, 'restrict,command="' + vm.FIXED_COMMAND + '" ssh-ed25519 AAAA')
        self.assertEqual(document["storage"]["files"][0]["mode"], 0o600)
        self.assertNotIn("python", json.dumps(document))
        self.assertNotIn("http", json.dumps(document))

    def test_qemu_has_only_restricted_user_network_and_one_loopback_forward(self):
        argv = vm.qemu_arguments(config())
        network = argv[argv.index("-nic") + 1]
        self.assertEqual(network, "user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:22222-:22")
        self.assertEqual(argv.count("-nic"), 1)
        for denied in ("-daemonize", "-virtfs", "-fsdev", "-chardev", "-qmp", "-netdev", "-pidfile"):
            self.assertNotIn(denied, argv)
        self.assertEqual(argv[argv.index("-monitor") + 1], "none")
        self.assertIn("spawn=deny", " ".join(argv))

    def test_ssh_exactly_one_fixed_command_and_no_ambient_sources(self):
        argv = vm.ssh_arguments(config())
        self.assertEqual(argv[-2:], ["core@127.0.0.1", vm.FIXED_COMMAND])
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ControlPath=none", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ConnectionAttempts=1", argv)
        self.assertEqual(argv[argv.index("-F") + 1], "/dev/null")
        self.assertNotIn("SSH_AUTH_SOCK", vm.clean_environment("/private"))

    def test_guest_positive_and_independent_failure_variants(self):
        info = {"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                         "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}}
        self.assertEqual(vm.guest_info(vm.encode(info)), barrier()["guest"])
        for section, key, value in (("security", "rootless", True), ("host", "serviceIsRemote", True),
                                    ("host", "cgroupVersion", "v1"), ("host", "arch", "arm64"),
                                    ("version", "Version", "5.8.8")):
            invalid = deepcopy(info)
            destination = invalid["host"]["security"] if section == "security" else invalid[section]
            destination[key] = value
            with self.subTest(key=key), self.assertRaises(vm.Refusal):
                vm.guest_info(vm.encode(invalid))
        with self.assertRaises(vm.Refusal):
            vm.guest_info(b"{}")

    def test_unit_has_real_caps_no_respawn_no_ambient_credentials(self):
        with patch.object(vm.time, "monotonic", return_value=100):
            argv = vm.unit_arguments(config(), "/private/config.json", "c" * 64,
                                     ["SSH_AUTH_SOCK", "LD_PRELOAD", "MALICIOUS_VARIABLE"])
        for item in ("CPUQuota=200%", "MemoryMax=4294967296", "MemorySwapMax=0", "TasksMax=256",
                     "Restart=no", "KillMode=control-group", "NoNewPrivileges=yes", "ReadOnlyPaths=/sys/fs/cgroup", "PrivateUsers=self", "DynamicUser=no",
                     "RestrictNamespaces=yes", "SystemCallArchitectures=native", "CapabilityBoundingSet=",
                     "AmbientCapabilities=", "SystemCallErrorNumber=ENOSYS",
                     "StandardOutput=null", "StandardError=null"):
            self.assertIn("--property=" + item, argv)
        unset = next(item for item in argv if item.startswith("--property=UnsetEnvironment="))
        self.assertIn("MALICIOUS_VARIABLE", unset)
        self.assertIn("SSH_AUTH_SOCK", unset)
        self.assertEqual(argv[-3:], ["--_worker", "/private/config.json", "c" * 64])

    def test_unit_authenticates_invocation_and_rejects_pending_or_restart(self):
        self.assertEqual(vm.validate_unit(unit(), config()), "b" * 32)
        for key, value in (("InvocationID", "c" * 32), ("Restart", "always"), ("Job", "123 /job/123"),
                           ("NRestarts", "1"), ("UpheldBy", "foreign.service"), ("OnFailure", "foreign.service"),
                           ("RuntimeMaxUSec", "infinity"), ("RuntimeMaxUSec", "1h"),
                           ("RuntimeRandomizedExtraUSec", "1s"), ("Transient", "no")):
            row = {**unit(), key: value}
            with self.subTest(key=key), self.assertRaises(vm.Refusal):
                vm.validate_unit(row, config(), invocation="b" * 32)

    def test_timer_parses_official_timespans_without_infinity(self):
        self.assertEqual(vm.duration_seconds("2min 3s 400ms"), 123.4)
        self.assertEqual(vm.duration_seconds("0"), 0)
        for text in ("infinity", "NaN", "-1s", "2s garbage", "2seconds"):
            with self.assertRaises(vm.Refusal):
                vm.duration_seconds(text)

    def test_barrier_wrong_placement_refuses_before_go(self):
        hello = {"stage": "barrier", "worker": identity(), "config_sha256": "c" * 64}
        with patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", return_value="/sys/fs/cgroup/foreign.service"), \
             patch.object(vm, "cgroup_snapshot") as snapshot:
            with self.assertRaisesRegex(vm.Refusal, "outside-controller-placement"):
                vm.attest_barrier(unit(), hello, identity(), config(), "c" * 64)
            snapshot.assert_not_called()

    def test_valid_external_barrier_keeps_actual_kernel_identity(self):
        target = "/sys/fs/cgroup" + unit()["ControlGroup"]
        hello = {"stage": "barrier", "worker": identity(), "config_sha256": "c" * 64}
        with patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", side_effect=lambda pid: target if pid == 321 else "/sys/fs/cgroup/outside"), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target, "inode": 42}), \
             patch.object(vm, "boot_id", return_value="boot"):
            invocation, observed = vm.attest_barrier(unit(), hello, identity(), config(), "c" * 64)
        self.assertEqual(invocation, "b" * 32)
        self.assertEqual(observed["inode"], 42)

    def test_actual_cgroup_caps_must_be_finite_and_exact(self):
        c = config()
        path = Path("/sys/fs/cgroup/owned") / c["unit"]
        original = {"cpu.max": "200000 100000", "memory.max": str(c["memory_bytes"]),
                    "pids.max": "256", "memory.swap.max": "0"}
        cases = [(None, None), ("cpu.max", "max 100000"), ("cpu.max", "300000 100000"),
                 ("memory.max", "max"), ("memory.max", str(c["memory_bytes"] + 1)),
                 ("pids.max", "max"), ("pids.max", "257"), ("memory.swap.max", "1")]
        for key, value in cases:
            contents = {**original, **({key: value} if key else {})}
            with self.subTest(key=key), patch.object(vm, "canonical", return_value=path), \
                 patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o40755, st_uid=os.getuid(), st_dev=1, st_ino=2)), \
                 patch.object(Path, "read_text", lambda item: contents[item.name]), \
                 patch.object(Path, "read_bytes", lambda item: contents[item.name].encode()):
                if key:
                    with self.assertRaises(vm.Refusal):
                        vm.cgroup_snapshot(path, c)
                else:
                    self.assertEqual(vm.cgroup_snapshot(path, c)["memory_max"], c["memory_bytes"])


class RetirementControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0
        self.budget = vm.Budget(time.monotonic() + 60, 10)

    def inactive(self):
        return {**unit(), "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "InvocationID": ""}

    def test_outside_retirement_stops_exact_unit_then_twice_proves_empty(self):
        row = unit()
        calls = []
        with patch.object(vm, "unit_show", side_effect=[row, self.inactive(), self.inactive()]), \
             patch.object(vm, "run", side_effect=lambda *a, **kw: (calls.append(a[0]) or (0, b""))), \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", return_value="removed") as empty, \
             patch.object(vm.time, "sleep"):
            receipt = vm.retire(config(), self.budget, "b" * 32, {"path": "/target"}, identity(), identity(444), barrier())
        self.assertEqual(receipt["state"], "retired")
        self.assertEqual(empty.call_count, 2)
        self.assertEqual(calls[0][-3:], ["stop", "--no-block", config()["unit"]])

    def test_optional_host_view_mismatch_uses_bare_envelope_when_detail_would_exceed_cap(self):
        detail = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                  "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}
        envelope = {"payload": "x" * (vm.META_MAX - 100)}
        self.assertLessEqual(len(vm.encode(envelope)), vm.META_MAX)
        self.assertIs(vm.with_optional_host_view_mismatch(envelope, detail), envelope)

    def test_outside_retirement_rejects_removed_v2_optional_barrier_member(self):
        detail = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                  "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}
        stopped = {**barrier(), "error": "host-view-object-not-equivalent", "host_view_mismatch": detail}
        with patch.object(vm, "unit_show", side_effect=[unit(), self.inactive(), self.inactive()]), \
             patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), patch.object(vm, "empty_cgroup", return_value="removed"), \
             patch.object(vm.time, "sleep"):
            with self.assertRaisesRegex(vm.Refusal, "producer-barrier-unproved"):
                vm.retire(config(), self.budget, "b" * 32, {"path": "/target"}, identity(),
                          identity(444), stopped)

    def test_rootful_retirement_receipt_retains_all_five_ordered_producers(self):
        c = {**config(), "phase": "run-rootful-kind", "rootful_input_reserved": 4096}
        # Independently literal expected identities/order, not a production phase list.
        records = [
            {"phase": "guest-info", "process": {"pid": 551, "group": 551, "session": 551, "start": 101}},
            {"phase": "stage-kind", "process": {"pid": 552, "group": 552, "session": 552, "start": 102}},
            {"phase": "stage-kubectl", "process": {"pid": 553, "group": 553, "session": 553, "start": 103}},
            {"phase": "stage-node-oci", "process": {"pid": 554, "group": 554, "session": 554, "start": 104}},
            {"phase": "rootful-kind", "process": {"pid": 555, "group": 555, "session": 555, "start": 105}},
        ]
        stopped = {**barrier(), "producers": deepcopy(records),
                   "producers_reaped": [True, True, True, True, True], "staging": None,
                   "rootful": None, "rootful_input_bytes": 20, "rootful_wire": None,
                   "rootful_record_guards": {"prepaid":24,"consumed_purposes":[
                       "guest-info","stage-kind","stage-kubectl","stage-node-oci","rootful-kind"],
                       "comparisons_attempted":None}}
        snapshot = {"path": "/target"}
        with patch.object(vm, "unit_show", side_effect=[unit(), self.inactive(), self.inactive()]), \
             patch.object(vm, "run", return_value=(0, b"")), \
             patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True) as retired, \
             patch.object(vm, "empty_cgroup", side_effect=["held-empty", "held-empty"]) as empty, \
             patch.object(vm.time, "sleep"):
            receipt = vm.retire(c, self.budget, "b" * 32, snapshot,
                                identity(), identity(444), stopped, producers=deepcopy(records))
        self.assertEqual(receipt["state"], "retired")
        self.assertEqual(receipt["producers"], records)
        self.assertEqual([item["phase"] for item in receipt["producers"]],
                         ["guest-info", "stage-kind", "stage-kubectl", "stage-node-oci", "rootful-kind"])
        self.assertEqual([item["cgroup"] for item in receipt["observations"]], ["held-empty", "held-empty"])
        self.assertEqual(empty.call_count, 2)
        for item in records:
            self.assertEqual(sum(call.args[0] == item["process"] for call in retired.call_args_list), 2)

    def test_stale_invocation_cannot_be_stopped(self):
        with patch.object(vm, "unit_show", return_value={**unit(), "InvocationID": "c" * 32}), \
             patch.object(vm, "run") as run:
            with self.assertRaisesRegex(vm.Refusal, "unit-invocation-drift"):
                vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), barrier())
            run.assert_not_called()

    def test_subtree_repopulation_quarantines_even_after_one_empty(self):
        with patch.object(vm, "unit_show", side_effect=[unit(), self.inactive(), self.inactive()]), \
             patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
             patch.object(vm, "process_retired", return_value=True), \
             patch.object(vm, "empty_cgroup", side_effect=["held-empty", vm.Refusal("retirement-cgroup-populated")]), \
             patch.object(vm.time, "sleep"):
            with self.assertRaisesRegex(vm.Refusal, "retirement-cgroup-populated"):
                vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), barrier())

    def test_restart_producer_and_missing_barrier_each_refuse(self):
        for changed, producer in (({**self.inactive(), "TriggeredBy": "foreign.socket"}, barrier()),
                                  (self.inactive(), None)):
            with self.subTest(changed=changed["TriggeredBy"]), \
                 patch.object(vm, "unit_show", side_effect=[unit(), changed, changed]), \
                 patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
                 patch.object(vm, "process_retired", return_value=True), patch.object(vm, "empty_cgroup", return_value="removed"), \
                 patch.object(vm.time, "sleep"):
                with self.assertRaises(vm.Refusal):
                    vm.retire(config(), self.budget, "b" * 32, {}, identity(), identity(444), producer)

    def test_pid_reuse_is_uncertain_not_absence(self):
        with patch.object(vm, "process_identity", return_value=identity(999)):
            with self.assertRaisesRegex(vm.Refusal, "retirement-pid-reused"):
                vm.process_retired(identity())
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            self.assertTrue(vm.process_retired(identity()))

    def test_cgroup_descendant_population_cannot_hide_behind_empty_direct_procs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            (path / "cgroup.procs").write_text("")
            snapshot = {"path": str(path)}
            with patch.object(vm, "cgroup_snapshot", return_value=snapshot):
                with self.assertRaisesRegex(vm.Refusal, "retirement-cgroup-populated"):
                    vm.empty_cgroup(snapshot, config())

    def test_deadline_and_cancellation_are_never_renewed_for_cleanup(self):
        budget = vm.Budget(100, 20)
        with patch.object(vm.time, "monotonic", return_value=75):
            self.assertEqual(budget.remaining(), 5)
            vm.CANCELLED = signal.SIGINT
            with self.assertRaisesRegex(vm.Refusal, "cancelled"):
                budget.remaining()
            self.assertEqual(budget.remaining(cleanup=True), 25)
        with patch.object(vm.time, "monotonic", return_value=101):
            with self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                budget.remaining(cleanup=True)


class WorkerControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def test_gate_failure_starts_no_child(self):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60, "cleanup_seconds": 10})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel = Mock()
        with patch.object(vm, "read", return_value=raw), patch.object(vm, "verify_source"), \
             patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c.get("controller")), \
             patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "send") as send, patch.object(vm, "receive", return_value={"stage": "forged"}), \
             patch.object(vm, "run") as run, patch.object(vm.subprocess, "Popen") as popen:
            c["controller"] = identity(111)
            raw = vm.encode(c)
            with patch.object(vm, "read", return_value=raw), patch.object(vm, "peer_identity", return_value=c["controller"]):
                self.assertEqual(vm.worker("/private/config", vm.digest(raw)), 1)
            run.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(send.call_args.args[1]["error"], "worker-gate-schema")

    def test_source_refusal_is_authenticated_reported_and_precedes_every_child(self):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60,
                  "cleanup_seconds": 10, "controller": identity(111)})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32,
                "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        events = []
        def peer(_channel):
            events.append("authenticated-parent")
            return c["controller"]
        def receive(_channel, _budget):
            events.append("received-go")
            return gate
        def verify(_config, _budget, **_kwargs):
            self.assertEqual(events, ["authenticated-parent", "received-go"])
            raise vm.Refusal("host-tool-writable")
        with patch.object(vm, "read", return_value=raw), \
             patch.object(vm.socket, "socket", return_value=Mock()), \
             patch.object(vm, "peer_identity", side_effect=peer), \
             patch.object(vm, "receive", side_effect=receive), patch.object(vm, "send") as send, \
             patch.object(vm, "process_identity", return_value=identity()), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "verify_source", side_effect=verify) as verify_source, \
             patch.object(vm, "run") as run, patch.object(vm.subprocess, "Popen") as popen:
            self.assertEqual(vm.worker("/private/config", vm.digest(raw)), 1)
        verify_source.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()
        self.assertEqual([call.args[1]["stage"] for call in send.call_args_list], ["barrier", "producer-stopped"])
        self.assertEqual(send.call_args.args[1]["error"], "host-tool-writable")
        self.assertIsNone(send.call_args.args[1]["qemu"])

    def test_bounded_ssh_capture_does_not_wait_for_live_qemu_console_eof(self):
        process, console, selector = Mock(), Mock(), Mock()
        process.returncode = 0
        process.poll.return_value = 0
        stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
        stderr = SimpleNamespace(fd=12, fileobj=process.stderr)
        serial = SimpleNamespace(fd=13, fileobj=console)
        selector.select.side_effect = [[(stdout, None), (stderr, None), (serial, None)], [(stdout, None)]]
        with patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), \
             patch.object(vm.os, "read", side_effect=[b"{}", b"", b"console remains open", b""]):
            status, raw = vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic() + 60, 10), "/private", extra_streams=(console,))
        self.assertEqual((status, raw), (0, b"{}"))
        self.assertEqual(selector.select.call_count, 2)
        process.kill.assert_not_called()

    def test_short_command_cutoff_reuses_counters_and_original_retirement_reservation(self):
        clock = [100.0]
        process, selector = Mock(), Mock()
        process.pid = 444
        process.poll.return_value = None
        def stalled(_timeout):
            clock[0] = 101.1
            return []
        selector.select.side_effect = stalled
        budget = vm.Budget(200.0, 20)
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "killpg") as kill:
            with self.assertRaisesRegex(vm.Refusal, "command-deadline-expired"):
                vm.run(["/reviewed/systemctl"], budget, "/private", deadline=101.0)
        kill.assert_called_once_with(444, signal.SIGKILL)
        self.assertAlmostEqual(process.wait.call_args.kwargs["timeout"], 98.9)
        self.assertEqual(budget.end, 200.0)
        self.assertEqual(budget.work_end, 180.0)
        self.assertEqual(budget.commands_left, 127)
        self.assertEqual(budget.output_left, vm.OUTPUT_MAX)

    def test_optional_command_end_cannot_widen_original_work_or_cleanup_end(self):
        budget = vm.Budget(200.0, 20)
        with patch.object(vm.time, "monotonic", return_value=100.0):
            self.assertEqual(vm.command_remaining(budget, deadline=1000.0), 80.0)
            self.assertEqual(vm.command_remaining(budget, cleanup=True, deadline=1000.0), 100.0)

    def _worker_ssh_case(self, ssh_status, guest, *, guard_error_at=None, view_mismatch=None, reap_error=False,
                         diagnostic_profile=False):
        c = config()
        c.update({"start": time.monotonic() - 1, "end": time.monotonic() + 60, "cleanup_seconds": 10,
                  "controller": identity(111)})
        if diagnostic_profile:
            source_path = str(vm.ROOT / "scripts/fixtures/owned_host_view.py")
            c["source"] = {source_path: "d" * 64}
            c["host_view_diagnostic_profile"] = vm.DIAGNOSTIC_CREDIT_PROFILE
            c["host_view_diagnostic_credit_bytes"] = vm.DIAGNOSTIC_CREDIT_BYTES
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel, qemu, selector = Mock(), Mock(), Mock()
        send_events = []
        channel.send.side_effect = lambda raw, flags: (send_events.append(("optional", raw)) or len(raw))
        qemu.pid = 444
        qemu.poll.return_value = None
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32, "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        key = SimpleNamespace(fd=123, fileobj=qemu.stdout)
        selector.select.return_value = [(key, None)]
        def execute(argv, *_args, **kwargs):
            if argv[0] == c["tools"]["ssh"]["path"]:
                kwargs["on_start"](SimpleNamespace(pid=555))
                return ssh_status, guest
            return (0, b'{"format":"qcow2","virtual-size":1024}') if argv[1] == "info" else (0, b"")
        def guard_result(index):
            if index != guard_error_at:
                return None
            error = vm.Refusal("host-view-object-not-equivalent" if view_mismatch is not None
                               else "host-view-local-drift")
            if view_mismatch is not None:
                error.host_view_mismatch = view_mismatch
            return error
        def verify_source(*_args, **kwargs):
            helper_ref = kwargs.get("helper_ref")
            if helper_ref is not None:
                helper_ref[0] = host_view
        with patch.object(vm, "read", return_value=raw), patch.object(vm, "verify_source", side_effect=verify_source), \
             patch.object(vm, "worker_pre_child", side_effect=[guard_result(index) for index in range(1, 4)]) as guard, \
             patch.object(vm, "host_view_module", return_value=host_view), \
             patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c["controller"]), \
             patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "send") as send, patch.object(vm, "receive", return_value=gate), \
             patch.object(vm, "run", side_effect=execute) as run, \
             patch.object(vm.subprocess, "Popen", return_value=qemu), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "read", return_value=b"Reached target Multi-User System\n"), \
             patch.object(vm, "reap", side_effect=vm.Refusal("synthetic-reap-failure") if reap_error else None,
                          return_value=True) as reap:
            send.side_effect = lambda _channel, value, *_args, **_kwargs: send_events.append(("mandatory", value["stage"]))
            result = vm.worker("/private/config", vm.digest(raw))
        self.last_native_calls = [call.args[0] for call in run.call_args_list]
        self.last_guard_count = guard.call_count
        sent_budget = send.call_args.args[2]
        self.last_worker_budget = (sent_budget.commands_left, sent_budget.output_left)
        self.last_optional_frame = channel.send.call_args.args[0] if channel.send.called else None
        self.last_send_events = send_events
        if guard_error_at is None:
            self.assertEqual(guard.call_count, 3)
            self.assertTrue(all(call.args[1] is guard.call_args_list[0].args[1] for call in guard.call_args_list))
            self.assertEqual(sum(call.args[0][0] == c["tools"]["ssh"]["path"] for call in run.call_args_list), 1)
            self.assertEqual([call.args[1]["stage"] for call in send.call_args_list],
                             ["barrier", "qemu-started", "ssh-started", "producer-stopped"])
        reap.assert_called_once()
        return result, send.call_args.args[1]

    def test_refused_pre_child_view_never_starts_that_or_any_later_child(self):
        for index in (1, 2, 3):
            with self.subTest(index=index):
                result, producer = self._worker_ssh_case(0, b"", guard_error_at=index)
                self.assertEqual(result, 1)
                self.assertEqual(producer["error"], "host-view-local-drift")
                self.assertEqual(self.last_guard_count, index)
                self.assertEqual(len(self.last_native_calls), min(index, 2))
                self.assertFalse(any(argv[0] == config()["tools"]["ssh"]["path"] for argv in self.last_native_calls))
                self.assertIsNone(producer["guest"])
                self.assertEqual(producer["qemu"] is None, index < 3)

    def test_ambiguous_ssh_disconnect_is_not_retried(self):
        result, producer = self._worker_ssh_case(255, b"")
        self.assertEqual(result, 1)
        self.assertEqual(producer["error"], "authenticated-guest-check-failed")

    def test_positive_production_worker_still_returns_only_provisional_guest_evidence(self):
        info = {"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                         "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}}
        result, producer = self._worker_ssh_case(0, vm.encode(info))
        self.assertEqual(result, 0)
        self.assertIsNone(producer["error"])
        self.assertEqual(producer["ssh"], identity(555))
        self.assertEqual(producer["guest"], barrier()["guest"])
        self.assertNotIn("vm-qualified-retired", json.dumps(producer))


class OutsideLifecycleControls(unittest.TestCase):
    """Run the production outside lifecycle against finite fake unit/worker peers."""
    def setUp(self):
        vm.CANCELLED = 0

    def test_failed_worker_is_detected_before_long_original_deadline(self):
        server = Mock()
        server.accept.side_effect = socket.timeout
        budget = vm.Budget(time.monotonic() + 900, 60)
        row = {**unit(), "ActiveState": "failed", "SubState": "failed", "MainPID": "0"}
        with patch.object(vm, "unit_show", return_value=row) as show:
            with self.assertRaisesRegex(vm.Refusal, "owned-worker-exited-before-barrier"):
                vm.await_worker_connection(server, config(), budget)
        show.assert_called_once()
        server.accept.assert_called_once()

    def test_startup_cutoff_does_not_renew_original_budget_or_poll_forever(self):
        clock = [100.0]
        server = Mock()
        def timeout():
            clock[0] += 0.1
            raise socket.timeout
        server.accept.side_effect = timeout
        budget = vm.Budget(1000.0, 60)
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm, "unit_show", return_value=unit()) as show:
            with self.assertRaisesRegex(vm.Refusal, "owned-worker-startup-cutoff"):
                vm.await_worker_connection(server, config(), budget)
        self.assertEqual(budget.end, 1000.0)
        self.assertEqual(budget.work_end, 940.0)
        self.assertLess(clock[0], 111)
        self.assertLessEqual(show.call_count, 21)

    def test_startup_acceptance_alone_does_not_fabricate_health_or_native_permission(self):
        server, channel = Mock(), Mock()
        server.accept.return_value = (channel, None)
        with patch.object(vm, "unit_show") as show, patch.object(vm, "send") as send:
            self.assertIs(vm.await_worker_connection(server, config(), vm.Budget(time.monotonic() + 60, 10)), channel)
        show.assert_not_called()
        send.assert_not_called()

    def exercise(self, parent, *, guest_error=None, retirement_failure=False, view_error=None,
                 view_diagnostic=None, view_failure_at="attest", diagnostic_profile=None):
        c = config()
        target = "/sys/fs/cgroup/owned/" + c["unit"]
        tools = c["tools"]
        server, probe, channel = MagicMock(), MagicMock(), Mock()
        server.accept.return_value = (channel, None)
        args = SimpleNamespace(deadline_seconds=120, cleanup_seconds=20, cpus=2, pids=256,
                               memory_mib=4096, guest_memory_mib=2048, disk_gib=16, ssh_port=22222,
                               host_tools=str(parent / "tools.json"), host_tools_sha256="a" * 64,
                               image=str(parent / "input.xz"), output_parent=str(parent))
        if diagnostic_profile is not None:
            args.host_view_diagnostic_profile = diagnostic_profile
        channel.recv.return_value = b""
        def archive(_source, directory, _pin, _budget):
            (directory / "image.qcow2").write_bytes(b"private base")
            return {"expanded_sha256": vm.digest(b"private base"), "expanded_bytes": 12, "archive_bytes": 21}
        clock, stopped = [1000.0], [False]
        boot = "11111111-1111-1111-1111-111111111111"
        snapshot = {"path": target, "device": 7, "inode": 23, "cpu_max": "100000 100000",
                    "memory_max": 4 * 1024**3, "pids_max": 256, "swap_max": 0}
        actual_boot, actual_process, actual_group = vm.boot_id, vm.process_identity, vm.process_cgroup
        class Kernel:
            def read(self, path):
                name = str(path)
                if name == "/proc/sys/kernel/random/boot_id":return (boot + "\n").encode()
                if name.startswith("/proc/") and name.endswith("/stat"):
                    if stopped[0]:raise FileNotFoundError(2, "fixture absent", name)
                    pid = int(name.split("/")[2])
                    tail = ["S", "1", str(pid), str(pid), *(["0"] * 15), "123"]
                    return (str(pid) + " (fixture) " + " ".join(tail) + "\n").encode()
                if name.startswith("/proc/") and name.endswith("/cgroup"):
                    return ("0::/owned/" + c["unit"] + "\n").encode()
                raw = {"cpu.max":b"100000 100000\n", "memory.max":b"4294967296\n", "pids.max":b"256\n",
                       "memory.swap.max":b"0\n", "cgroup.events":b"populated 1\nfrozen 0\n" if retirement_failure else b"populated 0\nfrozen 0\n",
                       "cgroup.procs":b""}
                if str(Path(name).parent) == target and Path(name).name in raw:return raw[Path(name).name]
                raise AssertionError("unexpected fixture kernel source")
            def canonical(self, path):return Path(path)
            def stat(self, _path):
                return SimpleNamespace(st_mode=vm.stat.S_IFDIR | 0o700, st_dev=7, st_ino=23,
                    st_uid=os.getuid(), st_gid=os.getgid(), st_nlink=1, st_size=0,
                    st_atime_ns=0, st_mtime_ns=0, st_ctime_ns=0)
            def exists(self, _path):return True
        def execute(argv, budget, directory, **kwargs):
            budget.remaining(cleanup=kwargs.get("cleanup", False))
            budget.commands_left -= 1
            vm.require(budget.commands_left >= 0, "command-budget")
            raw = b""
            if argv[0] == tools["ssh_keygen"]["path"]:
                path = Path(argv[-1])
                path.write_text("PRIVATE TEST KEY")
                Path(str(path) + ".pub").write_text("ssh-ed25519 AAAA\n")
            elif argv[0] == tools["busctl"]["path"]:
                raw = empty_stop_properties()
            elif argv[0] == tools["systemctl"]["path"] and "stop" in argv:
                stopped[0] = True
            elif argv[0] == tools["systemctl"]["path"] and "show" in argv:
                row = unit()
                if stopped[0]:row.update(ActiveState="inactive", MainPID="0", InvocationID="")
                raw = simple_unit_text(row)
            outcome = kwargs.get("outcome_capture")
            if outcome is not None:
                outcome.update(classification="exit", returncode=0)
                for name,value in (("stdout",raw),("stderr",b"")):
                    outcome[name].update(charged_bytes=len(value), charged_sha256=vm.digest(value), eof=True)
            try:
                budget.charge(len(raw))
            finally:
                if raw and kwargs.get("stdout_capture") is not None:kwargs["stdout_capture"](raw)
            clock[0] += 0.001
            return 0, raw
        events = []
        def receive(_channel, budget, **_kwargs):
            index = len(events)
            if index == 0:
                event = {"stage": "barrier", "worker": identity(), "config_sha256": "unused"}
            elif index == 1:
                event = {"stage": "qemu-started", "qemu": identity(444)}
            elif index == 2:
                event = {"stage": "ssh-started", "ssh": identity(555)}
            else:
                event = {**barrier(), "error": guest_error, "ssh": identity(555), "original_end": budget.end}
            events.append(event)
            return event
        fake_view = Mock()
        fake_view.PendingDiagnosticReservation = host_view.PendingDiagnosticReservation
        fake_view.ParentView.return_value.attest.return_value = {"test": "parent-bound-view"}
        parent_view_error = vm.Refusal(view_error) if view_error else None
        if parent_view_error is not None and view_diagnostic is not None:
            parent_view_error.host_view_mismatch = view_diagnostic
        fake_view.ParentView.return_value.attest.side_effect = (parent_view_error
            if view_error and view_failure_at == "attest" else None)
        fake_view.ParentView.return_value.recheck.side_effect = (parent_view_error
            if view_error and view_failure_at == "recheck" else None)
        fake_view.ParentView.return_value.partial = {"schema": "kubernetes-lens-owned-host-view-partial-v1", "qualification": "incomplete"}
        with patch.object(vm, "host_view_module", return_value=fake_view), \
             patch.object(vm, "validate_config_args", return_value=parent), \
             patch.object(vm, "admit_tools", return_value=tools), \
             patch.object(vm, "pin_document", return_value=({"release": "44.20260928.3.2"}, "c" * 64)), \
             patch.object(vm.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)), \
             patch.object(vm, "boot_id", side_effect=lambda **kw: actual_boot(**kw) if kw.get("evidence") is not None else boot), \
             patch.object(vm.socket, "socket", side_effect=[server, probe]), \
             patch.object(vm, "admit_archive", side_effect=archive), \
             patch.multiple(vm, verify_source=Mock(), check_source_bindings=Mock()), patch.object(vm, "run", side_effect=execute) as run, \
             patch.object(vm, "peer_identity", return_value=identity()), \
             patch.object(vm, "receive", side_effect=receive), \
             patch.object(vm, "attest_barrier", return_value=("b" * 32, snapshot)), \
             patch.object(vm, "process_identity", side_effect=lambda pid, **kw: actual_process(pid, **kw) if kw.get("evidence") is not None else identity(pid)), \
             patch.object(vm, "process_cgroup", side_effect=lambda pid, **kw: actual_group(pid, **kw) if kw.get("evidence") is not None else target), \
             patch.object(vm, "_RetirementKernel", return_value=Kernel()), \
             patch.object(vm.time, "monotonic", side_effect=lambda:clock[0]), \
             patch.object(vm.time, "sleep", side_effect=lambda seconds:clock.__setitem__(0, clock[0] + seconds)), \
             patch.object(vm, "send") as send:
            receipt, status = vm.qualify(args)
        private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
        return receipt, status, private, run.call_args_list, send.call_args_list


    def test_refused_parent_host_view_never_sends_go_and_still_requires_outside_retirement(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, status, private, _calls, sends = self.exercise(Path(directory), view_error="host-view-object-not-equivalent")
        self.assertEqual(status, 1)
        self.assertEqual(receipt["error"], "host-view-object-not-equivalent")
        self.assertEqual(receipt["state"], "failed-retired")
        self.assertFalse(any(call.args[1].get("stage") == "go" for call in sends))
        self.assertEqual(private["host_view"]["qualification"], "incomplete")
        self.assertEqual(private["retirement"]["state"], "retired")

    def test_only_outside_retirement_promotes_positive_prerequisite(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            receipt, status, private, calls, sends = self.exercise(parent)
            self.assertEqual(status, 0)
            self.assertEqual(receipt["state"], "vm-qualified-retired")
            self.assertEqual(private["retirement"]["state"], "retired")
            self.assertEqual(len(private["retirement"]["observations"]), 2)
            self.assertEqual(private["retirement"]["ssh"], identity(555))
            self.assertFalse(private["control_plane"]["target_limits_cover_controller"])
            self.assertEqual(sends[0].args[1]["stage"], "go")
            self.assertFalse((parent / ("kubernetes-lens-vm-" + "a" * 32)).exists())
            self.assertNotIn("PRIVATE TEST KEY", json.dumps(private))
            self.assertEqual(private["kubernetes_readiness"], "not-performed")
            self.assertEqual(private["guest_info"], barrier()["guest"])
            self.assertTrue(any("stop" in call.args[0] for call in calls))

    def test_earliest_guest_failure_survives_retirement_failure_and_keys_are_quarantined(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            receipt, status, private, _calls, _sends = self.exercise(parent, guest_error="authenticated-guest-check-failed", retirement_failure=True)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["state"], "failed-quarantined")
            self.assertEqual(receipt["error"], "authenticated-guest-check-failed")
            self.assertEqual(receipt["retirement_error"], "retirement-cgroup-populated")
            self.assertTrue((parent / ("kubernetes-lens-vm-" + "a" * 32)).is_dir())
            self.assertIsNone(private["retirement"])
            self.assertIsNone(private["guest_info"])

    def test_validated_guest_summary_remains_observation_when_retirement_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, status, private, _calls, _sends = self.exercise(Path(directory), retirement_failure=True)
        self.assertEqual(status, 1)
        self.assertEqual(receipt["state"], "failed-quarantined")
        self.assertEqual(private["guest_info"], barrier()["guest"])
        self.assertEqual(set(private["guest_info"]), {"rootful", "local", "cgroup_version", "podman_version"})
        self.assertIsNone(private["retirement"])



class RootfulIgnitionRepresentationControls(unittest.TestCase):
    """Assemble the actual production object using both real receiver sources."""
    def payloads(self):
        import owned_guest_rootful
        import owned_guest_stage
        rootful, stage = owned_guest_rootful, owned_guest_stage
        plan_raw = vm.encode({'schema': 'kubernetes-lens-owned-guest-stage-plan-v1', 'owner': 'a'*32,
            'profile': 'legacy-1.20.15', 'files': {role: {'path': '/tmp/'+role, 'bytes': 3,
            'sha256': vm.digest(b'abc')} for role in ('kind', 'kubectl', 'node-oci')}})
        plan = stage.parse_plan(plan_raw, vm.digest(plan_raw))
        old_receiver = vm.read(vm.ROOT/'scripts/fixtures/owned_guest_receiver.sh', 4*1024**2)
        receiver = Path(__file__).with_name('owned_guest_rootful.sh').read_bytes()
        stage_files = stage.guest_files(plan_raw, old_receiver, rootful=True)
        evidence = {'manifest_sha256': 'c'*64, 'config_sha256': 'c'*64, 'parent_sha256': 'd'*64,
            'expanded_bytes_hashed': 10, 'archive_bytes': 3,
            'catalogue': {'blobs/sha256/'+'c'*64: {'bytes': 100}}}
        rootful_files, spec = rootful.guest_files(plan, evidence, receiver)
        return rootful, stage, stage_files, rootful_files, spec, receiver

    def assemble(self, stage_files, rootful_files):
        import owned_guest_rootful
        import owned_guest_stage
        modules = {'owned_guest_rootful': owned_guest_rootful, 'owned_guest_stage': owned_guest_stage}
        with patch.object(vm, 'authenticated_module', side_effect=lambda name: modules[name]):
            return vm.ignition('ssh-ed25519 AAAA\n', 'PRIVATE TEST KEY', 'ssh-ed25519 BBBB\n',
                stage_public='ssh-ed25519 CCCC\n', stage_files=stage_files, rootful_files=rootful_files)

    def test_real_combined_ignition_fits_original_cap_and_restores_exact_receiver(self):
        rootful, _stage, stage_files, rootful_files, _spec, receiver = self.payloads()
        result = self.assemble(stage_files, rootful_files)
        self.assertLessEqual(len(vm.encode(result)), 65536)
        self.assertEqual(vm.META_MAX, 65536)
        self.assertEqual(result['ignition']['version'], '3.4.0')
        files = {row['path']: row for row in result['storage']['files']}
        receiver_path = rootful.ROOT+'/receiver'
        row = files[receiver_path]
        self.assertEqual(row['mode'], 0o500)
        self.assertEqual(row['contents']['compression'], 'gzip')
        compressed = base64.b64decode(row['contents']['source'].removeprefix('data:;base64,'), validate=True)
        self.assertEqual(gzip.decompress(compressed), receiver)
        self.assertEqual(rootful_files[receiver_path][0], receiver)
        checks = rootful_files[rootful.ROOT+'/checks.sha256'][0]
        self.assertIn((vm.digest(receiver)+'  '+receiver_path+'\n').encode(), checks)
        # Exact old representation exceeds the unchanged cap even with short keys.
        expanded = deepcopy(result)
        expanded_row = next(item for item in expanded['storage']['files'] if item['path']==receiver_path)
        expanded_row['contents'] = {'source': 'data:;base64,'+base64.b64encode(receiver).decode('ascii')}
        self.assertGreater(len(vm.encode(expanded)), 65536)
        # Compression applies only to the new receiver; all stage bytes/modes stay exact.
        for path, (raw, mode) in stage_files.items():
            self.assertEqual(files[path], {'path': path, 'mode': mode,
                'contents': {'source': 'data:;base64,'+base64.b64encode(raw).decode('ascii')}})
        self.assertEqual([row['path'] for row in result['storage']['files'] if 'compression' in row['contents']],
                         [receiver_path])
        self.assertEqual(result, self.assemble(stage_files, rootful_files))

    def test_rootful_sysctl_same_file_requests_exact_existing_guest_ceiling(self):
        import base64
        _rootful, _stage, stage_files, rootful_files, _spec, _receiver = self.payloads()
        result = self.assemble(stage_files, rootful_files)
        path = '/etc/sysctl.d/99-kubernetes-lens.conf'
        rows = [row for row in result['storage']['files'] if row['path'] == path]
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), {'path', 'mode', 'contents'})
        self.assertEqual(rows[0]['mode'], 0o600)
        self.assertEqual(set(rows[0]['contents']), {'source'})
        self.assertEqual(base64.b64decode(rows[0]['contents']['source'].removeprefix('data:;base64,'), validate=True),
            b'kernel.pid_max=32768\nfs.nr_open=1073741816\n')
        self.assertEqual(len(result['storage']['files']), 3+len(stage_files)+len(rootful_files)+1)
        self.assertEqual(vm.META_MAX, 65536)
        self.assertLessEqual(len(vm.encode(result)), 65536)

    def test_qualify_and_stage_ignition_remain_exact_v13_without_rootful_sysctl(self):
        _rootful, _stage, stage_files, _rootful_files, _spec, _receiver = self.payloads()
        old_plan = stage_files['/var/lib/kubernetes-lens-stage/plan.json'][0]
        stage_files = _stage.guest_files(old_plan, Path(_stage.__file__).with_name('owned_guest_receiver.sh').read_bytes())
        args = ('ssh-ed25519 AAAA\n', 'PRIVATE TEST KEY', 'ssh-ed25519 BBBB\n')
        cases = [({}, 971, 'ebd01fa2f81dc026e9cfe496d568aa7cab1aed4943596734e39839107fb9f26b'),
            ({'stage_public': 'ssh-ed25519 CCCC\n', 'stage_files': stage_files}, 11689,
             'f12793e3b09cf254ab096738310d086291405a0aa4d0dc5eed53214a678bb1cd')]
        for kwargs, size, digest in cases:
            with self.subTest(stage=bool(kwargs)):
                result = vm.ignition(*args, **kwargs)
                raw = vm.encode(result)
                self.assertEqual((len(raw), vm.digest(raw)), (size, digest))
                self.assertFalse(any(row['path'].startswith('/etc/sysctl.d/') for row in result['storage']['files']))

    def test_rootful_ignition_preserves_budget_refusal_for_other_oversize_data(self):
        rootful, _stage, stage_files, rootful_files, _spec, _receiver = self.payloads()
        rootful_files[rootful.ROOT+'/deployment.json'] = (b'x'*65536, 0o400)
        with self.assertRaisesRegex(vm.Refusal, 'ignition-budget'):
            self.assemble(stage_files, rootful_files)

    def test_rootful_receiver_representation_refuses_malformed_or_over_cap_source(self):
        rootful, _stage, stage_files, rootful_files, _spec, _receiver = self.payloads()
        for bad in ((b'', 0o500), ('not-bytes', 0o500), (b'x'*65537, 0o500), (b'source', 0o600), (b'source', 320.0)):
            changed = dict(rootful_files)
            changed[rootful.ROOT+'/receiver'] = bad
            with self.subTest(bad_type=type(bad[0]).__name__, size=len(bad[0])), \
                 self.assertRaisesRegex(vm.Refusal, 'rootful-ignition-receiver-contract'):
                self.assemble(stage_files, changed)


class RootfulBootProfileControls(unittest.TestCase):
    def test_only_rootful_phase_omits_no_reboot_with_every_other_argument_exact(self):
        reference = vm.qemu_arguments(config())
        self.assertIn('-no-reboot', reference)
        for phase in ('qualify-vm', 'stage-inputs', 'run-rootful-kind', 'unknown', None):
            selected = config(); selected['phase'] = phase
            expected = [arg for arg in reference if arg != '-no-reboot'] if phase == 'run-rootful-kind' else reference
            self.assertEqual(vm.qemu_arguments(selected), expected)
            self.assertEqual(selected['end'], 700.0)

    def test_rootful_only_kargs_and_actual_forced_key_commands(self):
        import owned_guest_rootful as rootful
        import owned_guest_stage as stage
        fixture = RootfulIgnitionRepresentationControls()
        _,_,stage_files,rootful_files,_,_ = fixture.payloads()
        result = fixture.assemble(stage_files,rootful_files)
        self.assertEqual(result['kernelArguments'], {'shouldExist':['ostree.prepare-root.composefs=0']})
        keys = result['passwd']['users'][0]['sshAuthorizedKeys']
        self.assertEqual(keys[0], 'restrict,command="'+rootful.COMMAND+'" ssh-ed25519 AAAA')
        self.assertEqual(keys[1], 'restrict,command="'+stage.ROOTFUL_RECEIVER_COMMAND+'" ssh-ed25519 CCCC')
        self.assertNotIn('kernelArguments',vm.ignition('ssh-ed25519 AAAA\n','PRIVATE TEST KEY','ssh-ed25519 BBBB\n'))

    def test_actual_forced_key_dispatches_literal_intents_and_scrubs_environment(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_receiver import OwnedPipeChild
        fixture = RootfulIgnitionRepresentationControls()
        _,_,stage_files,rootful_files,_,_ = fixture.payloads()
        key = fixture.assemble(stage_files,rootful_files)['passwd']['users'][0]['sshAuthorizedKeys'][0]
        command = key.split('command="',1)[1].split('" ',1)[0]
        self.assertEqual(command,rootful.COMMAND)
        self.assertNotIn('"',command)
        with tempfile.TemporaryDirectory(prefix='rootful-dispatch-pure-') as directory:
            directory = Path(directory); receiver = directory/'receiver'; sudo = directory/'sudo'
            receiver.write_text('#!/usr/bin/bash\nif declare -F injected > /dev/null; then exit 4; fi\n[[ $# == 1 && ${SSH_ORIGINAL_COMMAND+x} != x && ${HOSTILE_VALUE+x} != x ]] || exit 2\nprintf "%s|%s|%s" "$1" "$HOME" "$PATH"\n')
            sudo.write_text('#!/usr/bin/bash\n[[ $1 == -n ]] || exit 3\nshift\nexec "$@"\n')
            receiver.chmod(0o700); sudo.chmod(0o700)
            projected = command.replace('/usr/bin/sudo',str(sudo)).replace(rootful.ROOT+'/receiver',str(receiver))
            def run(intent):
                script = directory/'dispatch'
                quote = lambda value: "'"+value.replace("'", "'\\''")+"'"
                script.write_text('export HOSTILE_VALUE=private\ninjected() { printf forbidden; }; export -f injected\n'+('unset SSH_ORIGINAL_COMMAND\n' if intent is None else 'export SSH_ORIGINAL_COMMAND='+quote(intent)+'\n')+projected+'\n')
                return OwnedPipeChild(['/usr/bin/bash',str(script)],self.addCleanup).finish()
            for intent,selected in ((rootful.PREREQUISITE_INTENT,'prerequisite-v1'),(rootful.EXECUTION_INTENT,'execution-v1')):
                result = run(intent)
                self.assertEqual((result.returncode,result.stdout,result.stderr),(0,(selected+'|/root|/usr/bin:/usr/sbin').encode(),b''))
            marker = directory/'caller-code-ran'
            for intent in (None,'','unknown',rootful.PREREQUISITE_INTENT+' ', ' '+rootful.EXECUTION_INTENT,
                           rootful.EXECUTION_INTENT+' extra',rootful.EXECUTION_INTENT+'\n',
                           '$(touch '+str(marker)+')',"'; touch "+str(marker)+"; #",'`touch '+str(marker)+'`'):
                with self.subTest(intent=intent):
                    result=run(intent)
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b''))
                    self.assertFalse(marker.exists())

    def test_actual_generated_source_config_and_ignition_closure_refuse_mutations(self):
        import owned_guest_stage as stage
        fixture = RootfulIgnitionRepresentationControls()
        _,_,stage_files,rootful_files,_,_ = fixture.payloads()
        base_path = vm.ROOT/'scripts/fixtures/owned_guest_receiver.sh'; base = base_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix='rootful-binding-pure-') as directory:
            directory=Path(directory)
            (directory/'stage-plan.json').write_bytes(stage_files['/var/lib/kubernetes-lens-stage/plan.json'][0])
            document = fixture.assemble(stage_files,rootful_files)
            selected = {'directory':str(directory),'source':{str(base_path):vm.digest(base)},
                'rootful_stage_receiver':stage.rootful_receiver_binding(base,stage.rootful_receiver(base))}
            def verify():
                with patch.object(vm,'authenticated_module',return_value=stage):
                    vm.verify_rootful_stage_source(selected,vm.Budget(time.monotonic()+5,1))
            (directory/'ignition.json').write_bytes(vm.encode(document)); verify()
            for path in ('receiver','checks.sha256','table'):
                mutated=deepcopy(document)
                row=next(row for row in mutated['storage']['files'] if row['path']=='/var/lib/kubernetes-lens-stage/'+path)
                row['contents']['source']='data:;base64,'+base64.b64encode(b'wrong').decode()
                (directory/'ignition.json').write_bytes(vm.encode(mutated))
                with self.subTest(path=path),self.assertRaisesRegex(vm.Refusal,'rootful-stage-ignition-source'): verify()
            (directory/'ignition.json').write_bytes(vm.encode(document))
            selected['rootful_stage_receiver']['generated']['sha256']='f'*64
            with self.assertRaisesRegex(vm.Refusal,'rootful-stage-generated-binding'): verify()
            selected['source'][str(base_path)]='f'*64
            with self.assertRaisesRegex(vm.Refusal,'rootful-stage-base-binding'): verify()


class RootfulV14SourceControls(unittest.TestCase):
    def test_v14_source_cannot_authenticate_new_or_historical_frames(self):
        fixture=GuestInfoStderrPatternControls()
        stale='1bacb099951ab5fea4aa8d84e8ed8f7e555766b7f01b77b98b351713375d909d'
        self.assertNotEqual(stale,fixture.SOURCE)
        for code in fixture.EXPECTED:
            self.assertEqual(vm.guest_info_stderr_pattern(fixture.command(code),stale),
                fixture.expected('not-established',source=stale))
            with self.assertRaises(vm.Refusal):
                vm.validated_guest_info_stderr_pattern(fixture.expected(
                    'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes',code,stale))


class RootfulRecordReceiptControls(unittest.TestCase):
    def test_unreported_cmp_attempts_stay_unknown_and_malformed_or_replayed_schedule_refuses(self):
        phases=['guest-info','stage-kind','stage-kubectl','stage-node-oci','rootful-kind']
        for count in range(6):
            producers=[{'phase':phase} for phase in phases[:count]]
            value={'prepaid':24,'consumed_purposes':phases[:count],'comparisons_attempted':None}
            self.assertEqual(vm.validated_rootful_record_guards(value,producers),value)
            for change in ({'prepaid':True},{'prepaid':25},{'comparisons_attempted':24},
                           {'consumed_purposes':['guest-info']*6},{'consumed_purposes':['unknown']}):
                with self.assertRaises(vm.Refusal): vm.validated_rootful_record_guards({**value,**change},producers)
        self.assertIsNone(vm.validated_rootful_record_guards(None,[]))
        with self.assertRaises(vm.Refusal): vm.validated_rootful_record_guards(None,[{'phase':'guest-info'}])


class RootfulConsumedSourceControls(unittest.TestCase):
    """Real parent dispatch/helper consumption; all native/preparation calls mocked."""
    def consumed_reread_case(self, which):
        import owned_guest_rootful
        import owned_guest_stage
        vm.CANCELLED = 0
        rootful, stage = owned_guest_rootful, owned_guest_stage
        plan_raw = vm.encode({'schema': 'kubernetes-lens-owned-guest-stage-plan-v1', 'owner': 'a'*32,
            'profile': 'legacy-1.20.15', 'files': {role: {'path': '/tmp/'+role, 'bytes': 3,
            'sha256': vm.digest(b'abc')} for role in ('kind', 'kubectl', 'node-oci')}})
        plan = stage.parse_plan(plan_raw, vm.digest(plan_raw))
        original_read = vm.read
        shell = vm.ROOT/'scripts/fixtures/owned_guest_rootful.sh'
        scenarios = vm.ROOT/'schemas/capabilities/kubernetes-native-scenarios.json'
        selected = shell if which == 'shell' else scenarios
        original = original_read(selected, 4*1024**2)
        if which == 'shell':
            transient = original + b'\n# transient consumed receiver bytes\n'
        else:
            value = vm.strict_json(original)
            document = next(row['positive_document'] for row in value['kind_scenarios'] if row['kind']=='Deployment')
            document['metadata']['name'] = 'transient-consumed-source'
            transient = vm.encode(value)
        reads, generated = [], []
        def read(path, maximum=vm.META_MAX):
            if Path(path) == selected:
                reads.append(str(path))
                if len(reads) == 2:
                    return transient
            return original_read(path, maximum)
        original_guest_files = rootful.guest_files
        def consume(*args):
            result = original_guest_files(*args)
            generated.append(result)
            return result
        ledger = vm.ROOT/'schemas/capabilities/kubernetes-1.20-1.37.json'
        evidence = {'ledger_sha256': vm.digest(original_read(ledger, 32*1024**2)),
            'manifest_sha256': 'c'*64, 'config_sha256': 'c'*64, 'parent_sha256': 'd'*64,
            'expanded_bytes_hashed': 10, 'archive_bytes': 3,
            'catalogue': {'blobs/sha256/'+'c'*64: {'bytes': 100}}}
        native = SimpleNamespace(select_profile=Mock(), Refusal=vm.Refusal)
        modules = {'owned_guest_stage': stage, 'kind_runtime': native, 'owned_guest_rootful': rootful}
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            args = SimpleNamespace(phase='run-rootful-kind', deadline_seconds=1800, cleanup_seconds=120,
                cpus=2, pids=256, memory_mib=8192, guest_memory_mib=4096, disk_gib=24, ssh_port=22222,
                host_tools=str(parent/'tools.json'), host_tools_sha256='a'*64,
                image=str(parent/'not-admitted.xz'), output_parent=str(parent))
            with patch.object(vm, 'ROOT', vm.ROOT), \
                 patch.object(vm, 'validate_config_args', return_value=parent), \
                 patch.object(vm, 'admit_tools', return_value=config()['tools']), \
                 patch.object(vm, 'pin_document', return_value=({'release': '44.20260928.3.2'}, 'c'*64)), \
                 patch.object(vm.uuid, 'uuid4', return_value=SimpleNamespace(hex='a'*32)), \
                 patch.object(vm, 'process_identity', return_value=identity()), \
                 patch.object(vm, 'boot_id', return_value='boot'), \
                 patch.object(vm, 'authenticated_module', side_effect=lambda name,*_args: modules[name]), \
                 patch.object(stage, 'admit_inputs', return_value=(plan_raw, plan, evidence)), \
                 patch.object(rootful, 'admit_live_resource_profile'), \
                 patch.object(rootful, 'guest_files', side_effect=consume), \
                 patch.object(vm, 'read', side_effect=read), \
                 patch.object(vm, 'admit_archive') as prepare, \
                 patch.object(vm, 'run') as child, \
                 patch.object(vm.socket, 'socket') as listener:
                receipt, status = vm.qualify(args)
                prepare.assert_not_called()
                child.assert_not_called()  # Covers keygen and all manager/SSH commands.
                listener.return_value.bind.assert_not_called()
                self.assertEqual(len(reads), 2)
                # Later guards would see the original again; this is consumed-only drift.
                self.assertEqual(vm.read(selected, 4*1024**2), original)
            self.assertEqual(status, 1)
            expected = 'rootful-receiver-source-drift' if which == 'shell' else 'rootful-scenarios-source-drift'
            self.assertEqual(receipt['error'], expected)
        if which == 'shell':
            self.assertEqual(generated, [])
        else:
            self.assertEqual(len(generated), 1)
            files, spec = generated[0]
            self.assertEqual(spec['scenarios_sha256'], vm.digest(transient))
            self.assertNotEqual(spec['scenarios_sha256'], vm.digest(original))
            fixture = files[rootful.ROOT+'/deployment.json'][0]
            self.assertEqual(vm.strict_json(fixture)['metadata']['name'], 'transient-consumed-source')

    def test_transient_consumed_receiver_reread_refuses_before_preparation_or_child(self):
        self.consumed_reread_case('shell')

    def test_transient_consumed_scenarios_reread_refuses_before_preparation_or_child(self):
        self.consumed_reread_case('scenarios')


class StagePhaseControls(unittest.TestCase):
    """Fake caller/worker paths, with no systemd, QEMU, SSH or native program."""
    def setUp(self):
        vm.CANCELLED = 0
        import owned_guest_stage
        self.stage = owned_guest_stage

    def plan(self):
        raw = vm.encode({"schema": "kubernetes-lens-owned-guest-stage-plan-v1", "owner": "a" * 32,
            "profile": "modern-1.37.0", "files": {role: {"path": "/tmp/" + role, "bytes": 3,
                "sha256": vm.digest(b"abc")} for role in self.stage.ROLES}})
        return raw, self.stage.parse_plan(raw, vm.digest(raw))

    def test_parent_guard_is_strict_and_works_before_private_inputs_exist(self):
        c = {**config(), "manifest": "/private/tools.json", "manifest_sha256": "a" * 64}
        budget = vm.Budget(time.monotonic() + 60, 10)
        self.assertNotIn("input_files", c)
        seen = []
        with patch.object(vm, "check_source_bindings", side_effect=lambda *args: seen.append(("source", args))), \
             patch.object(vm, "admit_tools", side_effect=lambda *args: seen.append(("tools", args)) or c["tools"]):
            vm.parent_pre_child(c, budget)
        self.assertEqual([item[0] for item in seen], ["source", "tools"])
        self.assertIs(seen[0][1][1], budget)
        with patch.object(vm, "check_source_bindings"), patch.object(vm, "admit_tools", return_value={}):
            with self.assertRaisesRegex(vm.Refusal, "host-tools-drift"):
                vm.parent_pre_child(c, budget)
        with patch.object(vm, "check_source_bindings", side_effect=vm.Refusal("host-boot-changed")), \
             patch.object(vm, "admit_tools") as tools:
            with self.assertRaisesRegex(vm.Refusal, "host-boot-changed"):
                vm.parent_pre_child(c, budget)
        tools.assert_not_called()

    def test_ignition_separates_info_and_stage_keys_and_source_bound_files(self):
        raw, _plan = self.plan()
        files = self.stage.guest_files(raw, b"original receiver bytes")
        basic = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE", "ssh-ed25519 BBBB\n")
        extended = vm.ignition("ssh-ed25519 AAAA\n", "PRIVATE", "ssh-ed25519 BBBB\n",
                              stage_public="ssh-ed25519 CCCC\n", stage_files=files)
        original_key = basic["passwd"]["users"][0]["sshAuthorizedKeys"][0]
        keys = extended["passwd"]["users"][0]["sshAuthorizedKeys"]
        self.assertEqual(keys[0], original_key)
        self.assertIn(vm.FIXED_COMMAND, keys[0])
        self.assertIn(self.stage.RECEIVER_COMMAND, keys[1])
        self.assertNotIn("directories", basic["storage"])
        self.assertEqual(extended["storage"]["directories"], [{"path": "/var/lib/kubernetes-lens-stage", "mode": 0o700}])
        self.assertEqual({item["path"] for item in extended["storage"]["files"]} - {item["path"] for item in basic["storage"]["files"]}, set(files))

    def test_stage_ssh_retains_isolation_and_uses_only_separate_stage_key(self):
        c = config()
        before = vm.ssh_arguments(c)
        actual = self.stage.ssh_arguments(c)
        expected = before.copy()
        expected.remove("-n")
        expected[expected.index("-i") + 1] = "/private/owned/stage_key"
        expected[-1] = self.stage.RECEIVER_COMMAND
        self.assertEqual(actual, expected)
        self.assertEqual(vm.ssh_arguments(c), before)

    def test_every_real_producer_requires_parent_identity_before_acknowledgment(self):
        records, target = [], {"path": "/owned"}
        for index, phase in enumerate(("guest-info", *self.stage.PHASES)):
            process = identity(555 + index)
            event = {"stage": "stage-producer-started", "index": index, "phase": phase, "ssh": process}
            with patch.object(vm, "process_identity", return_value=process), patch.object(vm, "process_cgroup", return_value="/owned"):
                vm.admit_producer_event(event, records, identity(444), target)
        self.assertEqual(len(records), 4)
        with self.assertRaises(vm.Refusal):
            vm.admit_producer_event(event, records, identity(444), target)
        records = []
        event = {"stage": "stage-producer-started", "index": 0, "phase": "guest-info", "ssh": identity(555)}
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(vm.Refusal, "stage-producer-disappeared-before-admission"):
                vm.admit_producer_event(event, records, identity(444), target)
        self.assertEqual(records, [{"phase": "guest-info", "process": identity(555)}])
        with patch.object(vm, "process_identity", side_effect=FileNotFoundError):
            vm.admit_producer_event(event, [], identity(444), target, allow_retired=True)

    def worker_case(self, *, transfer_error=None, acknowledgment_error=False, reap_error=False):
        raw_plan, plan = self.plan()
        c = config()
        c.update({"phase": "stage-inputs", "start": time.monotonic() - 1, "end": time.monotonic() + 60,
                  "cleanup_seconds": 10, "controller": identity(111), "stage_plan_sha256": plan.sha256,
                  "stage_input_limit": 49})
        c["work_end"] = c["end"] - 10
        raw = vm.encode(c)
        channel, qemu, selector = Mock(), Mock(), Mock()
        qemu.pid = 444
        qemu.poll.return_value = None
        target = "/sys/fs/cgroup/" + c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b" * 32,
            "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        pending, sends, budgets, sessions = [], [], [], []
        selector.select.return_value = [(SimpleNamespace(fd=123, fileobj=qemu.stdout), None)]
        def sent(_channel, event, _budget, **_kwargs):
            sends.append(event)
            if event["stage"] == "stage-producer-started":
                pending.append({**event, "stage": "stage-producer-admitted"})
        def received(_channel, _budget, **_kwargs):
            if not pending:
                return gate
            item = pending.pop(0)
            return {**item, "phase": "wrong"} if acknowledgment_error else item
        def execute(argv, budget, _directory, **kwargs):
            budgets.append(budget)
            if argv[0] == c["tools"]["ssh"]["path"]:
                kwargs["on_start"](Mock(pid=555))
                return 0, vm.encode({"host": {"security": {"rootless": False}, "serviceIsRemote": False,
                    "cgroupVersion": "v2", "os": "linux", "arch": "amd64"}, "version": {"Version": "5.8.7"}})
            return (0, b'{"format":"qcow2","virtual-size":1024}') if argv[1] == "info" else (0, b"")
        def transfer(session, phase, _config, *, extra_streams, on_start, pre_child):
            sessions.append(session)
            self.assertIs(session.budget, budgets[0])
            pre_child()
            on_start(Mock(pid=556 + self.stage.PHASES.index(phase)))
            if transfer_error:
                raise vm.Refusal(transfer_error)
            file = plan.files[session.next_phase]
            reply = self.stage.reply(vm.encode({"schema": "kubernetes-lens-owned-guest-stage-reply-v1",
                "owner": plan.owner, "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                "bytes": file.size, "sha256": file.sha256, "state": "staged"}) + b"\n", plan, phase, file)
            session.charge(file.size + len(phase) + 1)
            session.next_phase += 1
            return reply
        def reaped(process, _budget):
            if reap_error and process.pid == 556:
                raise vm.Refusal("synthetic-reap-failure")
            return True
        def read(path, *_args):
            return raw_plan if str(path).endswith("stage-plan.json") else raw
        with patch.object(vm, "read", side_effect=read), patch.object(vm, "verify_source"), \
             patch.object(vm, "worker_pre_child") as guard, patch.object(vm.socket, "socket", return_value=channel), \
             patch.object(vm, "peer_identity", return_value=c["controller"]), \
             patch.object(vm, "process_identity", side_effect=lambda pid: identity(pid)), \
             patch.object(vm, "process_cgroup", return_value=target), \
             patch.object(vm, "cgroup_snapshot", return_value={"path": target}), \
             patch.dict(vm.os.environ, {"INVOCATION_ID": "b" * 32}), \
             patch.object(vm, "send", side_effect=sent), patch.object(vm, "receive", side_effect=received), \
             patch.object(vm, "run", side_effect=execute), patch.object(vm.subprocess, "Popen", return_value=qemu), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), patch.object(vm.os, "set_blocking"), \
             patch.object(vm.os, "read", return_value=b"Reached target Multi-User System\n"), \
             patch.object(vm, "reap", side_effect=reaped) as reap, \
             patch.object(vm, "authenticated_module", return_value=self.stage), \
             patch.object(self.stage, "transfer", side_effect=transfer):
            status = vm.worker("/private/config", vm.digest(raw))
        return status, sends[-1], sessions, reap.call_args_list, guard.call_args_list

    def test_worker_uses_one_original_budget_session_and_all_four_producers(self):
        status, stopped, sessions, reaps, guards = self.worker_case()
        self.assertEqual(status, 0)
        self.assertEqual(len(sessions), 3)
        self.assertTrue(all(item is sessions[0] for item in sessions))
        self.assertEqual([item["phase"] for item in stopped["producers"]], ["guest-info", *self.stage.PHASES])
        self.assertEqual(stopped["producers_reaped"], [True] * 4)
        self.assertEqual([call.args[0].pid for call in reaps], [555, 556, 557, 558, 444])
        self.assertEqual(len(guards), 6)
        self.assertEqual(stopped["staging"]["input_bytes"], 49)
        vm.validate_stage_result(stopped["staging"], sessions[0].plan, self.stage, {"stage_input_limit": 49})

    def test_registration_ack_failure_stops_all_later_transfers(self):
        status, stopped, sessions, reaps, _guards = self.worker_case(acknowledgment_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(stopped["error"], "stage-producer-acknowledgment")
        self.assertEqual(sessions, [])
        self.assertEqual([call.args[0].pid for call in reaps], [555, 444])
        self.assertEqual(stopped["producers_reaped"], [True])

    def test_first_transfer_failure_survives_later_reap_failure_no_retry(self):
        status, stopped, sessions, _reaps, _guards = self.worker_case(transfer_error="stage-reply-mismatch", reap_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(stopped["error"], "stage-reply-mismatch")
        self.assertEqual(len(sessions), 1)
        self.assertEqual(stopped["producers_reaped"], [True, False])
        self.assertIsNone(stopped["staging"])

    def test_outside_retirement_accounts_every_stage_producer_and_actual_reap(self):
        c = {**config(), "phase": "stage-inputs"}
        records = [{"phase": phase, "process": identity(555 + index)}
                   for index, phase in enumerate(("guest-info", *self.stage.PHASES))]
        stopped = {**barrier(), "producers": records, "producers_reaped": [True] * 4, "staging": None}
        inactive = {**unit(), "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "InvocationID": ""}
        def exercise(value):
            with patch.object(vm, "unit_show", side_effect=[unit(), inactive, inactive]), \
                 patch.object(vm, "run", return_value=(0, b"")), patch.object(vm, "boot_id", return_value="boot"), \
                 patch.object(vm, "process_retired", return_value=True) as retired, \
                 patch.object(vm, "empty_cgroup", return_value="removed"), patch.object(vm.time, "sleep"):
                receipt = vm.retire(c, vm.Budget(time.monotonic() + 60, 10), "b" * 32, {"path": "/target"},
                                    identity(), identity(444), value, producers=records)
                return receipt, retired.call_args_list
        receipt, calls = exercise(stopped)
        self.assertEqual(receipt["producers"], records)
        for item in records:
            self.assertEqual(sum(call.args[0] == item["process"] for call in calls), 2)
        for flags in ([True] * 3, [True, True, False, True], [True, True, 1, True]):
            with self.assertRaisesRegex(vm.Refusal, "stage-producer-barrier-unproved"):
                exercise({**stopped, "producers_reaped": flags})
        with self.assertRaisesRegex(vm.Refusal, "stage-producer-barrier-unproved"):
            exercise({**stopped, "producers": records[:-1]})

    def test_parent_rejects_incomplete_extra_or_conformance_labeled_stage_results(self):
        raw, plan = self.plan()
        result = {"state": "stage-replies-observed", "plan_sha256": plan.sha256, "input_bytes": 49, "replies": []}
        for phase, file in zip(self.stage.PHASES, plan.files):
            result["replies"].append({"schema": "kubernetes-lens-owned-guest-stage-reply-v1", "owner": plan.owner,
                "plan_sha256": plan.sha256, "phase": phase, "role": file.role, "bytes": file.size,
                "sha256": file.sha256, "state": "stage-reply-observed", "vm_retirement": "not-established",
                "runtime_conformance": "not-performed"})
        vm.validate_stage_result(result, plan, self.stage, {"stage_input_limit": 49})
        cases = [{**result, "input_bytes": True}, {**result, "replies": result["replies"][:-1]},
                 {**result, "extra": "unknown"}, {**result, "plan_sha256": "0" * 64}]
        changed = deepcopy(result)
        changed["replies"][0]["runtime_conformance"] = "passed"
        cases.append(changed)
        for changed in cases:
            with self.assertRaises(vm.Refusal):
                vm.validate_stage_result(changed, plan, self.stage, {"stage_input_limit": 49})

    def _parent_stage_case(self, *, drift_after=None, drift_kind="source", archive_bytes=21, guest_override=None):
        raw_plan, plan = self.plan()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            image = parent / "input.xz"
            image.write_bytes(b"fake prepared archive")
            c, tools = config(), config()["tools"]
            target = "/sys/fs/cgroup/owned/" + c["unit"]
            args = SimpleNamespace(phase="stage-inputs", deadline_seconds=120, cleanup_seconds=20,
                cpus=2, pids=256, memory_mib=4096, guest_memory_mib=2048, disk_gib=16, ssh_port=22222,
                host_tools=str(parent / "tools.json"), host_tools_sha256="a" * 64,
                image=str(image), output_parent=str(parent))
            server, probe, channel = MagicMock(), MagicMock(), Mock()
            server.accept.return_value = (channel, None)
            observed, guard_budgets = [], []
            drift = [False]
            def archive(_source, directory, _pin, _budget):
                (directory / "image.qcow2").write_bytes(b"private base")
                # The immutable reservation must remain safe if the selected
                # source is replaced/grows after all preliminary metadata.
                replacement = parent / "replacement.xz"
                replacement.write_bytes(b"larger replacement archive bytes")
                replacement.replace(image)
                if drift_after == "preparation":
                    drift[0] = True
                return {"expanded_sha256": vm.digest(b"private base"), "expanded_bytes": 12, "archive_bytes": archive_bytes}
            def source_check(_config, budget):
                guard_budgets.append(budget)
                if drift[0] and drift_kind == "source":
                    raise vm.Refusal("owning-source-drift")
            def tool_check(*_args):
                return {} if drift[0] and drift_kind == "tool" else tools
            def execute(argv, _budget, _directory, **_kwargs):
                observed.append(argv)
                if argv[0] == tools["ssh_keygen"]["path"]:
                    path = Path(argv[-1])
                    path.write_text("PRIVATE TEST KEY")
                    Path(str(path) + ".pub").write_text("ssh-ed25519 AAAA\n")
                    if drift_after == path.name:
                        drift[0] = True
                if drift_after == "show-environment" and argv[-1] == "show-environment":
                    drift[0] = True
                return 0, b""
            events, producers = [], []
            def received(_channel, budget, **_kwargs):
                index = len(events)
                if index == 0:
                    value = {"stage": "barrier", "worker": identity(), "config_sha256": "unused"}
                elif index == 1:
                    value = {"stage": "qemu-started", "qemu": identity(444)}
                elif index < 6:
                    phase = ("guest-info", *self.stage.PHASES)[index - 2]
                    process = identity(555 + index - 2)
                    producers.append({"phase": phase, "process": process})
                    value = {"stage": "stage-producer-started", "index": index - 2, "phase": phase, "ssh": process}
                else:
                    replies = []
                    for phase, file in zip(self.stage.PHASES, plan.files):
                        replies.append(self.stage.reply(vm.encode({"schema": "kubernetes-lens-owned-guest-stage-reply-v1",
                            "owner": plan.owner, "plan_sha256": plan.sha256, "phase": phase, "role": file.role,
                            "bytes": file.size, "sha256": file.sha256, "state": "staged"}) + b"\n", plan, phase, file))
                    value = {**barrier(), "guest": barrier()["guest"] if guest_override is None else guest_override,
                        "original_end": budget.end, "producers": producers,
                        "producers_reaped": [True] * 4, "staging": {"state": "stage-replies-observed",
                            "plan_sha256": plan.sha256, "input_bytes": 49, "replies": replies}}
                events.append(value)
                return value
            fake_view = Mock()
            fake_view.ParentView.return_value.attest.return_value = {"test": "parent-bound-view"}
            fake_view.ParentView.return_value.partial = {"schema": "host-view-partial", "qualification": "incomplete"}
            native = SimpleNamespace(select_profile=Mock(), Refusal=vm.Refusal)
            observed_retirement = ObservedParentRetirement(self, execute)
            send = Mock()
            patches = [
                patch.object(vm, "host_view_module", return_value=fake_view),
                patch.object(vm, "validate_config_args", return_value=parent), patch.object(vm, "admit_tools", side_effect=tool_check),
                patch.object(vm, "check_source_bindings", side_effect=source_check),
                patch.object(vm, "pin_document", return_value=({"release": "44.20260928.3.2"}, "c" * 64)),
                patch.object(vm.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)),
                patch.object(vm, "boot_id", side_effect=observed_retirement.boot_id), patch.object(vm.socket, "socket", side_effect=[server, probe]),
                patch.object(vm, "admit_archive", side_effect=archive), patch.object(vm, "verify_source"),
                patch.object(vm, "run", side_effect=observed_retirement.run), patch.object(vm, "peer_identity", return_value=identity()),
                patch.object(vm, "receive", side_effect=received),
                patch.object(vm, "attest_barrier", side_effect=observed_retirement.attest),
                patch.object(vm, "process_identity", side_effect=observed_retirement.process_identity),
                patch.object(vm, "process_cgroup", side_effect=observed_retirement.process_cgroup),
                patch.object(vm, "unit_show", side_effect=observed_retirement.unit_show),
                patch.object(vm, "send", send),
                patch.object(vm, "RetirementEvidence", side_effect=observed_retirement.evidence),
                patch.object(vm.time, "monotonic", side_effect=lambda: observed_retirement.now),
                patch.object(vm.time, "sleep", side_effect=observed_retirement.sleep),
                patch.object(vm.subprocess, "Popen", side_effect=AssertionError("native process forbidden")),
                patch.object(vm, "authenticated_module", side_effect=lambda name, *_args: self.stage if name == "owned_guest_stage" else native),
                patch.object(self.stage, "admit_inputs", return_value=(raw_plan, plan, {"import": "not-performed",
                    "ledger_sha256": vm.digest(vm.read(vm.ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json", 32 * 1024**2))}))
            ]
            with ExitStack() as stack:
                for context in patches:
                    stack.enter_context(context)
                receipt, status = vm.qualify(args)
            private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
            if private["retirement"] is not None:
                self.assertTrue(private["retirement_evidence"]["complete"], private["retirement_error"])
                trace = vm.retirement_evidence_document((parent / private["retirement_evidence"]["file"]).read_bytes())
                self.assertEqual(vm.validated_retirement_evidence(trace, observed_retirement.config)["retirement"],
                                 private["retirement"])
            return receipt, status, private, observed, send.call_args_list, guard_budgets

    def test_genuine_parent_stage_dispatch_reaches_only_staging_receipt_after_retirement(self):
        receipt, status, private, observed, sends, budgets = self._parent_stage_case(archive_bytes=vm.ARCHIVE_MAX)
        self.assertEqual(status, 0, receipt)
        self.assertEqual(receipt["state"], "stage-inputs-retired")
        self.assertEqual(private["guest_info"], barrier()["guest"])
        self.assertEqual(private["runtime_conformance"], "not-performed")
        self.assertEqual(len(private["retirement"]["producers"]), 4)
        self.assertEqual(len(private["retirement"]["observations"]), 2)
        self.assertEqual(sum(call.args[1].get("stage") == "stage-producer-admitted" for call in sends), 4)
        self.assertNotIn("PRIVATE TEST KEY", vm.encode(private).decode())
        storage = private["staging"]["storage"]
        self.assertEqual(storage["source_vm_archive_reserved_bytes"], vm.ARCHIVE_MAX)
        self.assertEqual(storage["overlay_max"], 16 * 1024**3 - 2 * vm.ARCHIVE_MAX - vm.EXPANDED_MAX - 4 * 1024**2 - 9)
        self.assertTrue(all(budget is budgets[0] for budget in budgets))

    def test_parent_drift_after_preparation_and_between_keys_blocks_next_native_child(self):
        expected_counts = {"preparation": 0, "client_key": 1, "host_key": 2, "stage_key": 3, "show-environment": 3}
        for kind in ("source", "tool"):
            for boundary, expected_keys in expected_counts.items():
                with self.subTest(kind=kind, boundary=boundary):
                    receipt, status, private, observed, _sends, budgets = self._parent_stage_case(drift_after=boundary, drift_kind=kind)
                    self.assertEqual(status, 1)
                    self.assertEqual(receipt["error"], "owning-source-drift" if kind == "source" else "host-tools-drift")
                    self.assertEqual(len([argv for argv in observed if argv[0] == config()["tools"]["ssh_keygen"]["path"]]), expected_keys)
                    self.assertFalse(any("--_worker" in argv for argv in observed))
                    self.assertEqual(any(argv[-1] == "show-environment" for argv in observed), boundary == "show-environment")
                    self.assertIsNone(private["guest_info"])
                    self.assertIsNone(private["retirement"])
                    self.assertTrue(all(budget is budgets[0] for budget in budgets))

    def test_archive_full_reservation_covers_replaced_and_unequal_admitted_source(self):
        for admitted_size in (1, vm.ARCHIVE_MAX):
            _receipt, status, private, _observed, _sends, _budgets = self._parent_stage_case(archive_bytes=admitted_size)
            self.assertEqual(status, 0)
            self.assertEqual(private["staging"]["storage"]["source_vm_archive_reserved_bytes"], vm.ARCHIVE_MAX)
        for admitted_size in (vm.ARCHIVE_MAX + 1, True, 0):
            receipt, status, private, observed, _sends, _budgets = self._parent_stage_case(archive_bytes=admitted_size)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["error"], "stage-storage-reservation-exceeded")
            self.assertEqual(observed, [])
            self.assertIsNone(private["guest_info"])

    def test_controller_does_not_retain_unvalidated_guest_frames(self):
        for value in ({**barrier()["guest"], "rootful": 1}, {**barrier()["guest"], "raw": "protected"}, {}):
            receipt, status, private, _observed, _sends, _budgets = self._parent_stage_case(guest_override=value)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["error"], "guest-result-unproved")
            self.assertIsNone(private["guest_info"])
            self.assertNotIn("protected", vm.encode(private).decode())



class CommandOutcomeControls(unittest.TestCase):
    """Pure pipe/process mocks: no native command or VM is started."""
    EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    HELLO = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def setUp(self):
        vm.CANCELLED = 0

    def expected(self, status=255):
        return {"schema": "kubernetes-lens-command-outcome-v1", "classification": "signal" if status < 0 else "exit",
                "returncode": status,
                "stdout": {"charged_bytes": 3, "charged_sha256": self.ABC, "eof": True},
                "stderr": {"charged_bytes": 5, "charged_sha256": self.HELLO, "eof": True}}

    def run_mock(self, *, status=255, output=vm.OUTPUT_MAX, maximum=vm.META_MAX, fail=None, wait_error=False, stdout_capture=None):
        process, selector, console = Mock(), Mock(), Mock()
        process.pid = 444
        process.returncode = status
        process.poll.return_value = None if wait_error else status
        if wait_error:
            process.wait.side_effect = vm.subprocess.TimeoutExpired("mock", 0)
        streams = {11: process.stdout, 12: process.stderr, 13: console}
        keys = {fd: SimpleNamespace(fd=fd, fileobj=stream) for fd, stream in streams.items()}
        selector.select.side_effect = [[(keys[fd], None)] for fd in (11, 12, 13, 11, 12)]
        reads = [b"abc", b"hello", b"console", b"", b""]
        if fail == "read":
            reads[3] = OSError("secret-raw-error")
        if fail == "close":
            selector.close.side_effect = OSError("close-refused")
        if fail == "cancel":
            def read(_fd, _size):
                block = reads.pop(0)
                vm.CANCELLED = 1
                return block
        else:
            read = Mock(side_effect=reads)
        budget = vm.Budget(time.monotonic() + 60, 10, output=output)
        initial = budget.end, budget.work_end
        outcome = vm.command_outcome()
        error = None
        with patch.object(vm.subprocess, "Popen", return_value=process) as launch, \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "read", side_effect=read), \
             patch.object(vm.os, "killpg") as kill:
            try:
                result = vm.run(["/reviewed/ssh"], budget, "/private", extra_streams=(console,),
                                maximum=maximum, outcome_capture=outcome, stdout_capture=stdout_capture)
            except (vm.Refusal, OSError) as caught:
                result, error = None, str(caught)
        self.assertEqual((budget.end, budget.work_end), initial)
        self.assertEqual(budget.commands_left, 127)
        self.assertEqual(launch.call_count, 1)
        return outcome, result, error, budget, process, kill

    def test_exact_hashes_signed_status_and_extra_console_exclusion(self):
        for status in (0, 17, 255, -9):
            with self.subTest(status=status):
                outcome, result, error, budget, process, _kill = self.run_mock(status=status)
                self.assertEqual(result, (status, b"abc"))
                self.assertIsNone(error)
                self.assertEqual(outcome, self.expected(status))
                self.assertEqual(vm.validated_command_outcome(outcome), self.expected(status))
                self.assertEqual(budget.output_left, vm.OUTPUT_MAX - 15)
                self.assertEqual(process.poll.call_count, 2)
                process.wait.assert_not_called()
                self.assertNotIn(b"hello", vm.encode(outcome))
                self.assertNotIn(b"console", vm.encode(outcome))
                self.assertNotIn("auth", vm.encode(outcome).decode())

    def test_failed_charge_retains_only_previously_charged_prefix(self):
        outcome, _result, error, budget, _process, _kill = self.run_mock(output=4)
        self.assertEqual(error, "output-budget")
        self.assertEqual(outcome["stdout"], {"charged_bytes": 3, "charged_sha256": self.ABC, "eof": False})
        self.assertEqual(outcome["stderr"], {"charged_bytes": 0, "charged_sha256": self.EMPTY, "eof": False})
        self.assertEqual(outcome["returncode"], 255)
        self.assertEqual(outcome["classification"], "incomplete")
        self.assertEqual(budget.output_left, -4)

    def test_failed_stdout_charge_does_not_capture_unfunded_bytes(self):
        capture = Mock()
        outcome, _result, error, budget, _process, _kill = self.run_mock(output=2, stdout_capture=capture)
        self.assertEqual(error, "output-budget")
        capture.assert_not_called()
        self.assertEqual(outcome["stdout"], {"charged_bytes": 0, "charged_sha256": self.EMPTY, "eof": False})
        self.assertEqual(budget.output_left, -1)
        outcome, _result, error, _budget, _process, _kill = self.run_mock(maximum=2, stdout_capture=capture)
        self.assertEqual(error, "command-output-budget")
        capture.assert_called_once_with(b"abc")
        self.assertEqual(outcome["stdout"]["charged_bytes"], 3)

    def test_stdout_limit_error_keeps_charged_bytes_without_claiming_eof(self):
        outcome, _result, error, _budget, _process, _kill = self.run_mock(maximum=2)
        self.assertEqual(error, "command-output-budget")
        self.assertEqual(outcome["stdout"]["charged_sha256"], self.ABC)
        self.assertFalse(outcome["stdout"]["eof"])
        self.assertEqual(outcome["classification"], "incomplete")

    def test_error_cancellation_and_unobserved_retirement_do_not_invent_completion(self):
        for fail, wait_error, expected in (("read", False, "secret-raw-error"),
                                           ("cancel", False, "cancelled"),
                                           ("read", True, "control-child-retirement-unproved"),
                                           ("close", False, "close-refused")):
            with self.subTest(fail=fail, wait_error=wait_error):
                outcome, _result, error, _budget, _process, kill = self.run_mock(fail=fail, wait_error=wait_error)
                self.assertEqual(error, expected)
                self.assertNotIn("secret-raw-error", vm.encode(outcome).decode())
                if wait_error:
                    self.assertIsNone(outcome["returncode"])
                    kill.assert_called_once_with(444, signal.SIGKILL)
                if fail != "close":
                    self.assertEqual(outcome["classification"], "incomplete")
                    self.assertFalse(outcome["stderr"]["eof"])
                vm.CANCELLED = 0

    def test_status_from_existing_retirement_wait_is_retained_as_partial(self):
        process, selector = Mock(), Mock()
        process.pid = 444
        process.poll.return_value = None
        process.wait.return_value = -9
        selector.select.side_effect = OSError("read-refused")
        outcome = vm.command_outcome()
        with patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "killpg"):
            with self.assertRaisesRegex(OSError, "read-refused"):
                vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic()+60, 10), "/private", outcome_capture=outcome)
        self.assertEqual(outcome["returncode"], -9)
        self.assertEqual(outcome["classification"], "incomplete")
        self.assertEqual(process.poll.call_count, 1)
        process.wait.assert_called_once()

    def test_before_start_and_before_poll_failure_leave_status_unavailable(self):
        outcome = vm.command_outcome()
        with patch.object(vm.subprocess, "Popen", side_effect=OSError("not-started")):
            with self.assertRaises(OSError):
                vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic()+60, 10), "/private", outcome_capture=outcome)
        self.assertEqual(outcome, vm.command_outcome())
        process = Mock()
        process.poll.side_effect = OSError("poll-unavailable")
        with patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector"), \
             patch.object(vm.os, "set_blocking"):
            with self.assertRaisesRegex(OSError, "poll-unavailable"):
                vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic()+60, 10), "/private",
                       outcome_capture=outcome, on_start=Mock(side_effect=vm.Refusal("identity-refused")))
        self.assertEqual(outcome, vm.command_outcome())

    def test_strict_closed_validation_and_binding(self):
        good = self.expected()
        changes = [lambda v: v.update(extra="secret"), lambda v: v.update(returncode=True),
                   lambda v: v.update(returncode=256), lambda v: v.update(returncode=-65),
                   lambda v: v.update(classification="authenticated"),
                   lambda v: v["stderr"].update(extra="secret"),
                   lambda v: v["stderr"].update(charged_bytes=True),
                   lambda v: v["stderr"].update(charged_bytes=-1),
                   lambda v: v["stderr"].update(charged_bytes=vm.OUTPUT_MAX),
                   lambda v: v["stderr"].update(charged_sha256="A"*64),
                   lambda v: v["stderr"].update(eof=1),
                   lambda v: v["stdout"].update(charged_bytes=0),
                   lambda v: v["stdout"].update(charged_bytes=vm.META_MAX+1)]
        for mutate in changes:
            with self.subTest(mutate=mutate):
                value = deepcopy(good)
                mutate(value)
                with self.assertRaises(vm.Refusal):
                    vm.validated_command_outcome(value)
        producer = {"phase": "guest-info", "process": identity(555)}
        wrapped = {**producer, "outcome": good}
        admitted = vm.validated_guest_info_command(wrapped, [producer])
        wrapped["outcome"]["stderr"]["charged_bytes"] = 99
        self.assertEqual(admitted["outcome"]["stderr"]["charged_bytes"], 5)
        for value, producers in (({**admitted, "extra": True}, [producer]),
                                 ({**admitted, "process": identity(556)}, [producer]),
                                 (admitted, []), (admitted, [{"phase": "other", "process": identity(555)}]),
                                 ({**admitted, "process": {**identity(555), "pid": True}}, [producer])):
            with self.subTest(value=value, producers=producers), self.assertRaises(vm.Refusal):
                vm.validated_guest_info_command(value, producers)
        self.assertIsNone(vm.validated_guest_info_command(None, []))

    def test_chunked_and_empty_stream_hashes_have_independent_literal_expectations(self):
        for chunks, expected in (([b"a", b"bc"], self.ABC), ([], self.EMPTY)):
            with self.subTest(chunks=chunks):
                process, selector = Mock(), Mock()
                process.returncode = 1
                process.poll.return_value = 1
                stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
                stderr = SimpleNamespace(fd=12, fileobj=process.stderr)
                selector.select.side_effect = [[(stdout, None)]] * (len(chunks)+1) + [[(stderr, None)]]
                outcome = vm.command_outcome()
                with patch.object(vm.subprocess, "Popen", return_value=process), \
                     patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
                     patch.object(vm.os, "set_blocking"), \
                     patch.object(vm.os, "read", side_effect=[*chunks, b"", b""]):
                    result = vm.run(["/reviewed/ssh"], vm.Budget(time.monotonic()+60, 10), "/private", outcome_capture=outcome)
                self.assertEqual(result, (1, b"".join(chunks)))
                self.assertEqual(outcome["stdout"], {"charged_bytes": 3 if chunks else 0,
                    "charged_sha256": expected, "eof": True})
                self.assertEqual(outcome["stderr"], {"charged_bytes": 0, "charged_sha256": self.EMPTY, "eof": True})
                self.assertEqual(outcome["classification"], "exit")
                self.assertEqual(outcome["returncode"], 1)

    def test_original_deadline_failure_preserves_prefix_and_real_retirement_status(self):
        process, selector = Mock(), Mock()
        process.pid = 444
        process.poll.return_value = None
        process.wait.return_value = -9
        clock = [100.0]
        stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
        selector.select.return_value = [(stdout, None)]
        def read(_fd, _size):
            clock[0] = 102.0
            return b"abc"
        budget, outcome = vm.Budget(200.0, 20), vm.command_outcome()
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector), \
             patch.object(vm.os, "set_blocking"), patch.object(vm.os, "read", side_effect=read), \
             patch.object(vm.os, "killpg"):
            with self.assertRaisesRegex(vm.Refusal, "command-deadline-expired"):
                vm.run(["/reviewed/ssh"], budget, "/private", deadline=101.0, outcome_capture=outcome)
        self.assertEqual(outcome["stdout"], {"charged_bytes": 3, "charged_sha256": self.ABC, "eof": False})
        self.assertEqual(outcome["returncode"], -9)
        self.assertEqual(outcome["classification"], "incomplete")
        self.assertEqual((budget.end, budget.work_end), (200.0, 180.0))
        self.assertEqual(process.wait.call_args.kwargs["timeout"], 98.0)

    def test_nonfresh_capture_refuses_before_any_command_credit_or_start(self):
        budget = vm.Budget(time.monotonic()+60, 10)
        with patch.object(vm.subprocess, "Popen") as start, self.assertRaises(vm.Refusal):
            vm.run(["/reviewed/ssh"], budget, "/private", outcome_capture=self.expected(0))
        start.assert_not_called()
        self.assertEqual(budget.commands_left, 128)



class GuestInfoParentOutcomeControls(unittest.TestCase):
    """Exercise actual qualify dispatch with entirely mocked external peers."""
    def setUp(self):
        vm.CANCELLED = 0

    def test_unfunded_explicit_profile_refuses_before_unit_start_without_fallback(self):
        _result, status, _private, _valid = self.parent_case(
            diagnostic_profile=True, output_budget=vm.DIAGNOSTIC_CREDIT_BYTES - 1,
            expected_error="host-view-diagnostic-credit-unavailable")
        self.assertEqual(status, 1)
        self.assertEqual(self.last_unit_start_balances, [])
        self.assertEqual(self.last_diagnostic_lifecycle, [])

    def parent_case(self, diagnostic="valid", *, worker_error=None, retirement_error=None, cleanup_delivery=False,
                    host_view_mismatch=None, diagnostic_profile=False, output_budget=None,
                    expected_error=None, poll_diagnostic=None, poll_v4=False):
        import owned_guest_stage as stage
        fixture = StagePhaseControls()
        fixture.setUp()
        raw_plan, plan = fixture.plan()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            image = parent / "input.xz"
            image.write_bytes(b"private archive")
            tools = config()["tools"]
            target = "/sys/fs/cgroup/owned/" + config()["unit"]
            args = SimpleNamespace(phase="run-rootful-kind", deadline_seconds=120, cleanup_seconds=20,
                cpus=2, pids=256, memory_mib=8192, guest_memory_mib=4096, disk_gib=24, ssh_port=22222,
                host_tools=str(parent / "tools.json"), host_tools_sha256="a"*64,
                image=str(image), output_parent=str(parent))
            if diagnostic_profile:
                args.host_view_diagnostic_profile = vm.DIAGNOSTIC_CREDIT_PROFILE
            server, probe, channel = MagicMock(), MagicMock(), Mock()
            server.accept.return_value = (channel, None)
            lifecycle = []
            optional_frame = b""
            if diagnostic_profile and host_view_mismatch is not None:
                body = vm.encode(host_view_mismatch)
                optional_frame = struct.pack(">I", len(body)) + body
            channel.recv.side_effect = lambda maximum, _flags: (lifecycle.append("drain") or optional_frame[:maximum])
            channel.close.side_effect = lambda: lifecycle.append("close")
            native = SimpleNamespace(select_profile=Mock(), Refusal=vm.Refusal)
            rootful = Mock(EVIDENCE_MAX=256*1024)
            rootful.reservation.return_value = {'native':75,'output':1048576,'utilities':768,
                'utility_work':680,'utility_cleanup':64,'record_guards_prepaid':24}
            rootful.guest_files.return_value = ({}, {"scenarios_sha256": vm.digest(vm.read(
                vm.ROOT / "schemas/capabilities/kubernetes-native-scenarios.json", 4*1024**2))})
            rootful.wire_record.return_value = {"closed": "mock-rootful-result"}
            rootful.durable_wire.return_value = {"retained": "mock-wire"}
            if poll_diagnostic is not None:
                import owned_guest_rootful as actual_rootful
                if poll_v4:
                    from test_owned_guest_rootful import DirectExecDecoderControls
                    _unused, poll_value, _prefix = DirectExecDecoderControls.bundle(self)
                else:
                    from test_owned_guest_rootful import PollDiagnosticDecoderControls
                    _unused, poll_value, _prefix = PollDiagnosticDecoderControls.bundle(self)
                rootful.guest_files.return_value[1].update(_unused['rootful_spec'])
                rootful.wire_record.side_effect = actual_rootful.wire_record
                rootful.durable_wire.side_effect = actual_rootful.durable_wire
            def archive(_source, directory, _pin, _budget):
                (directory / "image.qcow2").write_bytes(b"private base")
                return {"expanded_sha256": vm.digest(b"private base"), "expanded_bytes": 12, "archive_bytes": 15}
            calls = []
            unit_start_balances = []
            captured_configs = []
            source_write = vm.write
            def write_capture(path, data, *args, **kwargs):
                if Path(path).name == "config.json":
                    captured_configs.append(vm.strict_json(data))
                return source_write(path, data, *args, **kwargs)
            def execute(argv, _budget, _directory, **_kwargs):
                calls.append(argv)
                if argv[0] == tools["systemd_run"]["path"]:
                    unit_start_balances.append(_budget.output_left)
                if argv[0] == tools["ssh_keygen"]["path"]:
                    key = Path(argv[-1])
                    key.write_text("PRIVATE TEST KEY")
                    Path(str(key)+".pub").write_text("ssh-ed25519 AAAA\n")
                return 0, b""
            producers, events, interrupted = [], [], []
            valid = {"phase": "guest-info", "process": identity(555),
                     "outcome": CommandOutcomeControls().expected(0)}
            def received(_channel, budget, **_kwargs):
                index = len(events)
                if index == 0:
                    value = {"stage": "barrier", "worker": identity(), "config_sha256": "unused"}
                elif index == 1:
                    value = {"stage": "qemu-started", "qemu": identity(444)}
                elif index < 7:
                    phase = ("guest-info", *stage.PHASES, "rootful-kind")[index-2]
                    record = identity(555+index-2)
                    producers.append({"phase": phase, "process": record})
                    value = {"stage": "stage-producer-started", "index": index-2, "phase": phase, "ssh": record}
                else:
                    if cleanup_delivery and not interrupted:
                        interrupted.append(True)
                        raise vm.Refusal("original-command-interrupted")
                    wire = parent / ("kubernetes-lens-vm-" + "a"*32) / "rootful-wire.json"
                    worker_rootful = rootful.wire_record.return_value
                    if poll_diagnostic is None:
                        wire.write_bytes(b"closed mocked wire")
                    else:
                        c = captured_configs[-1]
                        poll_value.update(owner=c['owner'], plan_sha256=c['stage_plan_sha256'])
                        poll_value['evidence'].update(owner=c['owner'], plan_sha256=c['stage_plan_sha256'],
                            source_spec_sha256=vm.digest(vm.encode(c['rootful_spec'])))
                        wire_raw = vm.encode(poll_value)+b'\n'
                        worker_rootful = actual_rootful.wire_record(wire_raw, c, allow_failure=True)
                        if poll_diagnostic == 'malformed':
                            poll_value['logs']['state'] = 'pg2.g.foreign.S.4096.8.106'
                            wire_raw = vm.encode(poll_value)+b'\n'
                        elif poll_diagnostic == 'summary-mismatch':
                            worker_rootful = deepcopy(worker_rootful)
                            worker_rootful['logs']['state'] = 'pg1.g'
                        wire.write_bytes(wire_raw)
                        self.last_poll_wire = wire_raw
                    value = {**barrier(), "error": worker_error, "original_end": budget.end,
                        "producers": producers, "producers_reaped": [True]*5,
                        "staging": {}, "rootful": worker_rootful,
                        "rootful_input_bytes": 100,
                        "rootful_record_guards": {"prepaid":24,"consumed_purposes":[
                            "guest-info","stage-kind","stage-kubectl","stage-node-oci","rootful-kind"],
                            "comparisons_attempted":None},
                        "rootful_wire": {"bytes": wire.stat().st_size, "sha256": vm.digest(wire.read_bytes()),
                                         "identity": vm.file_id(wire.stat())}}
                    if diagnostic != "missing":
                        selected = deepcopy(valid)
                        if diagnostic == "null":
                            selected = None
                        elif diagnostic == "partial":
                            selected["outcome"]["stderr"]["eof"] = False
                            selected["outcome"]["classification"] = "incomplete"
                        elif diagnostic == "nonzero":
                            selected["outcome"]["returncode"] = 255
                        elif diagnostic == "malformed":
                            selected["outcome"]["secret"] = "raw-secret-must-not-persist"
                        elif diagnostic == "wrong-producer":
                            selected["process"] = identity(556)
                        value["guest_info_command"] = selected
                events.append(value)
                return value
            fake_view = Mock()
            fake_view.PendingDiagnosticReservation = host_view.PendingDiagnosticReservation
            fake_view.ParentView.return_value.attest.return_value = {"test": "view"}
            fake_view.ParentView.return_value.partial = None
            observed_retirement = ObservedParentRetirement(self, execute)
            def retire_result(*args, **kwargs):
                lifecycle.append("retire")
                if retirement_error:
                    raise vm.Refusal(retirement_error)
                self.assertIsNotNone(kwargs.get("evidence"))
                return observed_retirement.actual_retire(*args, **kwargs)
            retire = Mock(side_effect=retire_result)
            overrides = [
                (vm, "validate_config_args", {"return_value": parent}),
                (vm, "admit_tools", {"return_value": tools}), (vm, "check_source_bindings", {}),
                (vm, "pin_document", {"return_value": ({"release": "44.20260928.3.2"}, "c"*64)}),
                (vm.uuid, "uuid4", {"return_value": SimpleNamespace(hex="a"*32)}),
                (vm, "boot_id", {"side_effect": observed_retirement.boot_id}),
                (vm.socket, "socket", {"side_effect": [server, probe]}),
                (vm, "admit_archive", {"side_effect": archive}), (vm, "verify_source", {}),
                (vm, "ignition", {"return_value": {}}), (vm, "run", {"side_effect": observed_retirement.run}),
                (vm, "write", {"side_effect": write_capture}),
                (vm, "peer_identity", {"return_value": identity()}), (vm, "receive", {"side_effect": received}),
                (vm, "attest_barrier", {"side_effect": observed_retirement.attest}),
                (vm, "unit_show", {"side_effect": observed_retirement.unit_show}),
                (vm, "process_identity", {"side_effect": observed_retirement.process_identity}),
                (vm, "process_cgroup", {"side_effect": observed_retirement.process_cgroup}), (vm, "send", {}),
                (vm, "host_view_module", {"return_value": fake_view}),
                (vm, "validate_stage_result", {}), (vm, "retire", {"new": retire}),
                (vm, "RetirementEvidence", {"side_effect": observed_retirement.evidence}),
                (vm.time, "monotonic", {"side_effect": lambda: observed_retirement.now}),
                (vm.time, "sleep", {"side_effect": observed_retirement.sleep}),
                (vm.subprocess, "Popen", {"side_effect": AssertionError("native process forbidden")}),
                (vm, "authenticated_module", {"side_effect": lambda name, *_: stage if name == "owned_guest_stage"
                                               else rootful if name == "owned_guest_rootful" else native}),
                (stage, "admit_inputs", {"return_value": (raw_plan, plan, {"import": "not-performed",
                    "ledger_sha256": vm.digest(vm.read(vm.ROOT / "schemas/capabilities/kubernetes-1.20-1.37.json", 32*1024**2))})})]
            if output_budget is not None:
                budget_class = vm.Budget
                overrides.append((vm, "Budget", {"side_effect": lambda end, cleanup:
                    budget_class(end, cleanup, output=output_budget)}))
            with ExitStack() as stack:
                send_mock = None
                for obj, name, kwargs in overrides:
                    patched = stack.enter_context(patch.object(obj, name, **kwargs))
                    if obj is vm and name == "send":
                        send_mock = patched
                try:
                    result, status = vm.qualify(args)
                except vm.Refusal as caught:
                    if expected_error is None:
                        raise
                    self.assertEqual(str(caught), expected_error)
                    self.last_unit_start_balances = unit_start_balances
                    self.last_diagnostic_lifecycle = lifecycle
                    self.assertEqual(list(parent.glob("*.receipt.json")), [])
                    return None, 1, None, valid
            if expected_error is not None:
                self.last_unit_start_balances = unit_start_balances
                self.last_unit_start_credit = unit_start_balances[0] if unit_start_balances else None
                self.last_config = captured_configs[-1] if captured_configs else None
                self.last_send_calls = send_mock.call_args_list
                private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
                self.last_diagnostic_lifecycle = lifecycle
                self.assertEqual(result["error"], expected_error)
                self.assertEqual(unit_start_balances, [])
                self.assertEqual(retire.call_count, 0)
                return result, status, private, valid
            self.last_unit_start_balances = unit_start_balances
            self.last_unit_start_credit = unit_start_balances[0] if unit_start_balances else None
            self.last_config = captured_configs[-1] if captured_configs else None
            self.last_send_calls = send_mock.call_args_list
            private = vm.strict_json(next(parent.glob("*.receipt.json")).read_bytes())
            self.last_diagnostic_lifecycle = lifecycle
            self.assertEqual(retire.call_count, 1, (private["error"], private["retirement_error"]))
            self.assertNotIn(b"raw-secret-must-not-persist", vm.encode(private))
            self.assertEqual(len(calls) + sum("kill" in argv for argv in observed_retirement.commands),
                             6 if cleanup_delivery else 5)  # Existing controller/cancel commands.
            self.last_retirement_commands = len(observed_retirement.commands)
            self.last_retirement_output = sum(observed_retirement.output_charges)
            if poll_diagnostic is not None:
                descriptor = private['rootful_durable_evidence']
                self.last_poll_durable = None if descriptor is None else (parent/descriptor['name']).read_bytes()
                if descriptor is not None:
                    self.assertEqual((parent/descriptor['name']).stat().st_mode & 0o777, 0o600)
            if private["retirement"] is not None:
                self.assertTrue(private["retirement_evidence"]["complete"], private["retirement_error"])
                trace = vm.retirement_evidence_document((parent / private["retirement_evidence"]["file"]).read_bytes())
                if poll_diagnostic is not None:
                    self.assertEqual(len(trace['actors']), 7)
                    self.assertEqual(len(trace['producer_prefix']), 5)
                self.assertEqual(vm.validated_retirement_evidence(trace, observed_retirement.config)["retirement"],
                                 private["retirement"])
            return result, status, private, valid

    def test_bounded_host_view_mismatch_is_validated_from_prepaid_post_retirement_frame(self):
        detail = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                  "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}
        self.assertEqual(vm.validated_host_view_mismatch(detail), detail)
        result, status, private, _valid = self.parent_case(worker_error="host-view-object-not-equivalent",
            host_view_mismatch=detail, diagnostic_profile=True)
        self.assertEqual(status, 1, result)
        self.assertEqual(private["error"], "host-view-object-not-equivalent")
        self.assertEqual(private["host_view_mismatch"], detail)
        self.assertNotIn("host_view_mismatch", result)
        self.assertEqual(private["retirement"]["state"], "retired")
        self.assertEqual(len(private["retirement"]["observations"]), 2)
        self.assertTrue(private["retirement_evidence"]["complete"])
        self.assertEqual(self.last_diagnostic_lifecycle, ["retire", "drain", "close"])
        self.assertEqual(self.last_unit_start_credit, vm.OUTPUT_MAX - vm.DIAGNOSTIC_CREDIT_BYTES)
        self.assertEqual(self.last_config["host_view_diagnostic_profile"], vm.DIAGNOSTIC_CREDIT_PROFILE)
        self.assertEqual(self.last_config["host_view_diagnostic_credit_bytes"], vm.DIAGNOSTIC_CREDIT_BYTES)
        go = next(call.args[1] for call in self.last_send_calls if call.args[1].get("stage") == "go")
        self.assertEqual(go["config_sha256"], vm.digest(vm.encode(self.last_config)))
        self.assertEqual(set(go), {"stage", "config_sha256", "invocation", "cgroup", "host_view", "host_view_sha256"})
        result, status, private, _valid = self.parent_case(diagnostic="malformed",
            worker_error="host-view-object-not-equivalent", host_view_mismatch=detail, diagnostic_profile=True)
        self.assertEqual(status, 1, result)
        self.assertEqual(private["error"], "host-view-object-not-equivalent")
        self.assertEqual(private["host_view_mismatch"], detail)
        self.assertIsNotNone(private["retirement"])
        self.assertNotIn("raw-secret-must-not-persist", vm.encode(private).decode())

    def test_successful_parent_receipt_keeps_original_shape_without_mismatch_member(self):
        result, status, private, _valid = self.parent_case()
        self.assertEqual(status, 0, result)
        self.assertNotIn("host_view_mismatch", result)
        self.assertNotIn("host_view_mismatch", private)
        self.assertIsNone(vm.diagnostic_credit_profile(self.last_config))

    def test_malformed_or_unbound_worker_mismatch_is_omitted_without_replacing_failure(self):
        variants = (({"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "/usr/bin/qemu",
                      "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]},
                     None, "original-worker-failure"),
                    ({"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                      "differences": [{"field": "identity", "member": "ino", "expected": True, "observed": 2}]},
                     "outside-retirement-unproved", "original-worker-failure"),
                    ({"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "parent-attest", "object": "bin",
                      "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]},
                     None, "host-view-object-not-equivalent"))
        for detail, cleanup_error, worker_error in variants:
            result, status, private, _valid = self.parent_case(worker_error=worker_error,
                retirement_error=cleanup_error, host_view_mismatch=detail, diagnostic_profile=True)
            self.assertEqual(status, 1, result)
            self.assertEqual(private["error"], worker_error)
            self.assertEqual(private["retirement_error"], cleanup_error)
            if cleanup_error is None:
                self.assertIsNotNone(private["retirement"])
            self.assertNotIn("host_view_mismatch", private)
            self.assertNotIn("raw-secret-must-not-persist", vm.encode(private).decode())
            should_drain = cleanup_error is None and worker_error == "host-view-object-not-equivalent"
            expected_order = ["retire", "drain", "close"] if should_drain else ["retire", "close"]
            self.assertEqual(self.last_diagnostic_lifecycle, expected_order)

    def test_parent_attest_and_recheck_failure_details_reach_private_receipt(self):
        for stage, site in (("attest", "parent-attest"), ("recheck", "parent-recheck")):
            detail = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": site, "object": "tool-python",
                      "differences": [{"field": "mode", "expected": 493, "observed": 448}]}
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                fixture = OutsideLifecycleControls()
                fixture.setUp()
                receipt, status, private, _calls, sends = fixture.exercise(
                    Path(directory), view_error="host-view-object-not-equivalent", view_diagnostic=detail,
                    view_failure_at=stage, diagnostic_profile=vm.DIAGNOSTIC_CREDIT_PROFILE)
                self.assertEqual(status, 1)
                self.assertEqual(receipt["error"], "host-view-object-not-equivalent")
                self.assertEqual(private["host_view_mismatch"], detail)
                self.assertFalse(any(call.args[1].get("stage") == "go" for call in sends))

    def test_host_view_mismatch_schema_rejects_shape_order_range_and_privacy_violations(self):
        good = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}
        cases = (
            {**good, "site": ["worker-local"]},
            {**good, "object": "/usr/bin/qemu"},
            {**good, "extra": "secret"},
            {**good, "differences": [{"field": "mystery", "expected": 1, "observed": 2}]},
            {**good, "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2},
                                      {"field": "identity", "member": "ino", "expected": 3, "observed": 4}]},
            {**good, "differences": [{"field": "uid", "expected": 1, "observed": 2},
                                      {"field": "gid", "expected": 1, "observed": 2}]},
            {**good, "differences": ([{"field": "identity", "member": "ctime_ns", "expected": 1, "observed": 2}] * 12)},
            {**good, "differences": [{"field": "identity", "member": "ino", "expected": True, "observed": 2}]},
            {**good, "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2},
                                      {"field": "identity", "member": "dev", "expected": 1, "observed": 2}]},
            {**good, "differences": [{"field": "identity", "member": "ino", "expected": 2**64, "observed": 2}]},
            {**good, "differences": [{"field": "sha256", "expected": "/private/path", "observed": "a"*64}]},
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(vm.Refusal):
                vm.validated_host_view_mismatch(value)
        self.assertLessEqual(len(vm.encode(vm.validated_host_view_mismatch(good))), 2048)

    def test_host_view_mismatch_accepts_all_scalar_enum_and_range_boundaries(self):
        rows = [
            {"field": "gid", "expected": 0, "observed": 2**32 - 1},
            {"field": "identity", "member": "ctime_ns", "expected": -(2**63), "observed": 2**63 - 1},
            {"field": "identity", "member": "dev", "expected": 0, "observed": 2**64 - 1},
            {"field": "identity", "member": "ino", "expected": 0, "observed": 2**64 - 1},
            {"field": "identity", "member": "mtime_ns", "expected": -(2**63), "observed": 2**63 - 1},
            {"field": "identity", "member": "size", "expected": 0, "observed": 2**64 - 1},
            {"field": "mode", "expected": 0, "observed": 0o7777},
            {"field": "sha256", "expected": "0" * 64, "observed": "f" * 64},
            {"field": "type", "expected": "directory", "observed": "regular"},
            {"field": "uid", "expected": 0, "observed": 2**32 - 1},
        ]
        detail = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "parent-recheck", "object": "tool-qemu_img",
                  "differences": rows}
        normalized = vm.validated_host_view_mismatch(detail)
        self.assertEqual(normalized, detail)
        self.assertIsNot(normalized, detail)
        self.assertLessEqual(len(vm.encode(normalized)), 2048)

    def test_observed_completed_zero_is_required_for_actual_rootful_parent_success(self):
        result, status, private, valid = self.parent_case()
        self.assertEqual(status, 0, result)
        self.assertEqual(private["state"], "rootful-kind-smoke-retired")
        self.assertEqual(private["guest_info_command"], valid)
        for diagnostic in ("missing", "null", "partial", "nonzero"):
            with self.subTest(diagnostic=diagnostic):
                result, status, private, _valid = self.parent_case(diagnostic)
                self.assertEqual(status, 1, result)
                self.assertEqual(private["error"], "guest-info-command-success-unproved")
                self.assertEqual(private["state"], "failed-retired")
                self.assertEqual(private["runtime_conformance"], "not-established")

    def test_completed255_is_retained_on_worker_failure_and_retirement_quarantine(self):
        for retirement_error in (None, "outside-retirement-unproved"):
            with self.subTest(retirement_error=retirement_error):
                result, status, private, valid = self.parent_case("nonzero",
                    worker_error="authenticated-guest-check-failed", retirement_error=retirement_error)
                valid["outcome"]["returncode"] = 255
                self.assertEqual(status, 1, result)
                self.assertEqual(private["guest_info_command"], valid)
                self.assertEqual(private["error"], "authenticated-guest-check-failed")
                self.assertEqual(private["retirement_error"], retirement_error)
                self.assertEqual(private["state"], "failed-quarantined" if retirement_error else "failed-retired")

    def test_cleanup_received_barrier_retains_diagnostic_before_quarantine(self):
        result, status, private, valid = self.parent_case("nonzero", cleanup_delivery=True,
            retirement_error="outside-retirement-unproved")
        valid["outcome"]["returncode"] = 255
        self.assertEqual(status, 1, result)
        self.assertEqual(private["guest_info_command"], valid)
        self.assertEqual(private["error"], "original-command-interrupted")
        self.assertEqual(private["retirement_error"], "outside-retirement-unproved")

    def test_malformed_diagnostic_cannot_skip_retirement_or_replace_worker_failure(self):
        for diagnostic in ("malformed", "wrong-producer"):
            for worker_error in (None, "authenticated-guest-check-failed"):
                with self.subTest(diagnostic=diagnostic, worker_error=worker_error):
                    result, status, private, _valid = self.parent_case(diagnostic, worker_error=worker_error)
                    self.assertEqual(status, 1, result)
                    self.assertIsNone(private["guest_info_command"])
                    self.assertIsNotNone(private["retirement"])
                    self.assertIsNone(private["retirement_error"])
                    self.assertEqual(private["error"], worker_error or
                        ("command-outcome-schema" if diagnostic == "malformed" else "guest-info-command-binding"))



class PollDiagnosticParentControls(unittest.TestCase):
    """Real parent validation/publication/retirement, all peers are fixed DATA."""
    parent_case = GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED = 0

    def test_exact_source_stage_and_prepared_catalogue_caps_refuse_next_byte(self):
        import owned_guest_stage as stage
        fixture = RootfulIgnitionRepresentationControls()
        rootful, _stage, stage_files, rootful_files, _spec, receiver = fixture.payloads()
        # Padded DATA tests representation bounds only, never source enrollment.
        exact = receiver + b'\n#' + b'x'*(65536-len(receiver)-2)
        changed = dict(rootful_files); changed[rootful.ROOT+'/receiver'] = (exact, 0o500)
        result = fixture.assemble(stage_files, changed)
        row = next(r for r in result['storage']['files'] if r['path'] == rootful.ROOT+'/receiver')
        self.assertEqual(gzip.decompress(base64.b64decode(row['contents']['source'].removeprefix('data:;base64,'))), exact)
        changed[rootful.ROOT+'/receiver'] = (exact+b'x', 0o500)
        with self.assertRaisesRegex(vm.Refusal, 'rootful-ignition-receiver-contract'):
            fixture.assemble(stage_files, changed)
        base = Path(stage.__file__).with_name('owned_guest_receiver.sh').read_bytes()
        delta = len(stage.rootful_receiver(base))-len(base)
        padded = base+b'\n#'+b'x'*(65536-delta-len(base)-2)
        self.assertEqual(len(stage.rootful_receiver(padded)), 65536)
        with self.assertRaisesRegex(vm.Refusal, 'rootful-stage-generated-budget'):
            stage.rootful_receiver(padded+b'x')
        with tempfile.TemporaryDirectory(prefix='poll-prepared-cap-') as directory:
            parent = Path(directory)
            (parent/'config.json').write_bytes(b'x'*65536)
            (parent/'rootful-wire.json').write_bytes(b'x'*262144)
            reservation = vm.retirement_metadata_catalogue(parent)
            self.assertEqual((reservation['limit'], reservation['reserved']), (4194304, 1376256))
            (parent/'rootful-wire.json').write_bytes(b'x'*262145)
            with self.assertRaisesRegex(vm.Refusal, 'retirement-metadata-catalogue'):
                vm.retirement_metadata_catalogue(parent)

    def test_actual_worker_refuses_valid_and_malformed_v3_without_positive_barrier(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls
        for malformed in (False, True):
            host = RootfulHostControls(); self.addCleanup(host.doCleanups)
            value = host.result()
            value.update(schema=rootful.RESULT_V3, state='failed', source_deployment='not-reached')
            identity = value['logs']['identities']['wrapper']
            token = f'pg2.g.wrapper.S.4096.{identity["pid"]}.{identity["start"]}'
            value['logs'].update(state=token, startup_marker=False)
            if malformed: value['logs']['state'] = token.replace('.4096.', '.4095.')
            with patch.object(host, 'result', return_value=value):
                status, stopped, budgets, sessions, _calls, c = host.worker_case()
            self.assertEqual(status, 1)
            self.assertEqual(stopped['error'], 'rootful-poll-range' if malformed else 'rootful-success-unproved')
            self.assertTrue(stopped['qemu_reaped'])
            self.assertEqual(stopped['producers_reaped'], [True]*5)
            self.assertEqual(len(stopped['producers']), 5)
            self.assertEqual(stopped['original_end'], c['end'])
            self.assertTrue(all(b is budgets[0] for b in budgets))
            self.assertTrue(all(session.budget is budgets[0] for session in sessions))
            self.assertEqual(budgets[0].commands_left, 45)
            self.assertEqual(stopped['rootful_record_guards'], {'prepaid':24,
                'consumed_purposes':['guest-info','stage-kind','stage-kubectl','stage-node-oci','rootful-kind'],
                'comparisons_attempted':None})
            if malformed:
                self.assertIsNone(stopped['rootful'])
            else:
                self.assertEqual(stopped['rootful']['logs']['state'], token)
                self.assertEqual(stopped['rootful']['state'], 'failed')

    def test_v3_failed_private_summary_never_promotes_or_leaks_and_retirement_is_independent(self):
        import owned_guest_rootful as rootful
        observations = []
        for diagnostic in ('valid', 'malformed', 'summary-mismatch'):
            result, status, private, _ = self.parent_case(worker_error='rootful-kind-phase-failed',
                                                       poll_diagnostic=diagnostic)
            self.assertEqual(status, 1)
            self.assertEqual(private['error'], 'rootful-kind-phase-failed')
            self.assertEqual(private['runtime_conformance'], 'not-established')
            self.assertEqual(private['kubernetes_readiness'], 'not-established')
            self.assertEqual(private['retirement']['state'], 'retired')
            self.assertEqual(len(private['retirement']['producers']), 5)
            self.assertEqual([p['phase'] for p in private['retirement']['producers']],
                ['guest-info', 'stage-kind', 'stage-kubectl', 'stage-node-oci', 'rootful-kind'])
            self.assertEqual(len(private['retirement']['observations']), 2)
            self.assertTrue(private['retirement_evidence']['complete'])
            self.assertEqual(private['rootful_record_guards'], {'prepaid':24,
                'consumed_purposes':['guest-info','stage-kind','stage-kubectl','stage-node-oci','rootful-kind'],
                'comparisons_attempted':None})
            self.assertEqual(private['rootful_result']['schema'], rootful.RESULT_V3)
            self.assertNotIn('poll_failure', private['rootful_result'])
            public = vm.encode(result)
            for protected in (b'pg2.', b'pg1.g', b'last_observed_state', b'iterations_completed',
                              b'private-prefix', b'fixed\x00private-prefix\xff', b'logs', b'rootful_result'):
                self.assertNotIn(protected, public)
            if diagnostic == 'valid':
                self.assertIsNone(private['retirement_error'])
                self.assertEqual(self.last_poll_durable, self.last_poll_wire)
                self.assertEqual(private['state'], 'failed-retired')
                detail = rootful.poll_failure(private['rootful_result']['logs'], version=rootful.RESULT_V3,
                                              failure=private['rootful_result'])
                self.assertEqual((detail.reason, detail.role, detail.iterations_completed),
                                 ('iteration-limit', 'wrapper', 4096))
            else:
                self.assertIsNone(self.last_poll_durable)
                self.assertEqual(private['state'], 'failed-quarantined')
                self.assertEqual(private['retirement_error'],
                                 'rootful-poll-code' if diagnostic == 'malformed' else 'rootful-wire-summary')
            observations.append((self.last_retirement_commands, self.last_retirement_output))
        self.assertEqual(observations, [observations[0]]*3)


class GuestInfoWorkerOutcomeControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def worker_case(self, status, guest, *, placement_error=False, settle_error=None,
                    diagnostic_profile=False, helper_load_error=None, helper_mismatch_at=None):
        c = {**config(), "phase": "run-rootful-kind", "start": time.monotonic()-1,
             "end": time.monotonic()+60, "cleanup_seconds": 10, "controller": identity(111),
             "rootful_reservation": {"native": 75, "output": 1048576, "utilities": 768},
             "manifest": "/private/manifest", "manifest_sha256": vm.digest(b"manifest"),
             "input_files": {}}
        c["work_end"] = c["end"]-10
        if diagnostic_profile:
            c.update(host_view_diagnostic_profile=vm.DIAGNOSTIC_CREDIT_PROFILE,
                     host_view_diagnostic_credit_bytes=vm.DIAGNOSTIC_CREDIT_BYTES)
        raw = vm.encode(c)
        channel, qemu, selector = Mock(), Mock(), Mock()
        qemu.pid = 444
        qemu.poll.return_value = None
        target = "/sys/fs/cgroup/"+c["unit"]
        gate = {"stage": "go", "config_sha256": vm.digest(raw), "invocation": "b"*32,
                "cgroup": {"path": target}, "host_view": {}, "host_view_sha256": vm.digest(vm.encode({}))}
        acknowledgment = {"stage": "stage-producer-admitted", "index": 0, "phase": "guest-info", "ssh": identity(555)}
        selector.select.return_value = [(SimpleNamespace(fd=123, fileobj=qemu.stdout), None)]
        rootful = Mock()
        rootful.reserve.return_value = c["rootful_reservation"]
        rootful.ssh_arguments.return_value = [c["tools"]["ssh"]["path"]]
        captures = []
        local_checks = []
        mismatch = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
                    "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}
        helper = Mock()
        def validate_local(*_args):
            local_checks.append(True)
            if helper_mismatch_at == len(local_checks):
                error = vm.Refusal("host-view-object-not-equivalent")
                error.host_view_mismatch = mismatch
                raise error
        helper.validate_local.side_effect = validate_local
        helper.send_optional_diagnostic.return_value = True
        def source_read(path, *_args, **_kwargs):
            if str(path) == "/private/config":
                return raw
            if str(path) == c["manifest"]:
                return b"manifest"
            return raw
        def execute(argv, _budget, _directory, **kwargs):
            if argv[0] != c["tools"]["ssh"]["path"]:
                self.assertNotIn("outcome_capture", kwargs)
                return (0, b'{"format":"qcow2","virtual-size":1024}') if argv[1] == "info" else (0, b"")
            captures.append(kwargs["outcome_capture"])
            self.assertEqual(captures[-1], vm.command_outcome())
            kwargs["on_start"](SimpleNamespace(pid=555))
            captures[-1].update(CommandOutcomeControls().expected(status))
            return status, guest
        with ExitStack() as stack:
            overrides = [(vm, "read", {"side_effect": source_read}),
                (vm.socket, "socket", {"return_value": channel}),
                (vm, "peer_identity", {"return_value": c["controller"]}),
                (vm, "process_identity", {"side_effect": lambda pid: identity(pid)}),
                (vm, "process_cgroup", {"side_effect": lambda pid: "/foreign" if placement_error and pid == 555 else target}),
                (vm, "cgroup_snapshot", {"return_value": {"path": target}}),
                (vm, "send", {}), (vm, "receive", {"side_effect": [gate, acknowledgment]}),
                (vm, "run", {"side_effect": execute}), (vm.subprocess, "Popen", {"return_value": qemu}),
                (vm.selectors, "DefaultSelector", {"return_value": selector}),
                (vm.os, "set_blocking", {}), (vm.os, "read", {"return_value": b"Reached target Multi-User System\n"}),
                (vm, "reap", {"return_value": True}), (vm, "authenticated_module", {"return_value": rootful}),
                (vm, "settle_guest_check", {"side_effect": vm.Refusal(settle_error)} if settle_error else {})]
            if diagnostic_profile:
                overrides.extend([(vm, "check_source_bindings", {}), (vm, "verify_rootful_stage_source", {}),
                    (vm, "host_view_module", {"side_effect": helper_load_error or Mock(return_value=helper)})])
            else:
                overrides.extend([(vm, "verify_source", {}), (vm, "worker_pre_child", {})])
            mocks = {}
            for obj, name, kwargs in overrides:
                mocks[name] = stack.enter_context(patch.object(obj, name, **kwargs))
            stack.enter_context(patch.dict(vm.os.environ, {"INVOCATION_ID": "b"*32}))
            result = vm.worker("/private/config", vm.digest(raw))
        mocks["channel"] = channel
        mocks["helper"] = helper
        mocks["local_checks"] = local_checks
        return result, mocks["send"].call_args.args[1], captures, mocks

    def test_capture_survives_status_and_guest_parse_refusal(self):
        for status, guest, error in ((255, b"not-json", "authenticated-guest-check-failed"),
                                      (0, b"not-json", "invalid-json")):
            with self.subTest(status=status):
                result, stopped, captures, mocks = self.worker_case(status, guest)
                self.assertEqual(result, 1)
                self.assertEqual(stopped["error"], error)
                self.assertEqual(stopped["guest_info_command"], {"phase": "guest-info", "process": identity(555),
                    "outcome": CommandOutcomeControls().expected(status)})
                self.assertIs(stopped["guest_info_command"]["outcome"], captures[0])
                self.assertEqual(stopped["producers_reaped"], [True])
                self.assertEqual(mocks["run"].call_count, 3)
                self.assertEqual(mocks["reap"].call_count, 2)

    def test_identity_bound_diagnostic_survives_placement_refusal_before_ack(self):
        result, stopped, _captures, _mocks = self.worker_case(255, b"", placement_error=True)
        self.assertEqual(result, 1)
        self.assertEqual(stopped["error"], "ssh-placement")
        self.assertEqual(stopped["guest_info_command"], {"phase": "guest-info", "process": identity(555),
                                                       "outcome": vm.command_outcome()})
        self.assertEqual(stopped["producers_reaped"], [True])

    def test_opt_in_helper_load_failure_stays_inside_cleanup_and_sends_bare_barrier(self):
        cases = ((vm.Refusal("host-view-helper-source-drift"), "host-view-helper-source-drift"),
                 (OSError("synthetic helper read failure"), "worker-prerequisite-unavailable"))
        for failure, expected in cases:
            with self.subTest(expected=expected):
                result, stopped, captures, mocks = self.worker_case(0, b"", diagnostic_profile=True,
                                                                    helper_load_error=failure)
                self.assertEqual(result, 1)
                self.assertEqual(stopped["error"], expected)
                self.assertEqual(captures, [])
                self.assertEqual(mocks["receive"].call_count, 1)
                self.assertEqual([call.args[1]["stage"] for call in mocks["send"].call_args_list],
                                 ["barrier", "producer-stopped"])
                self.assertNotIn("host_view_mismatch", stopped)
                self.assertEqual(mocks["reap"].call_count, 1)
                mocks["channel"].close.assert_called_once()
                mocks["helper"].send_optional_diagnostic.assert_not_called()

    def test_helper_reference_precedes_first_and_post_qemu_pre_ssh_comparators(self):
        for mismatch_at in (1, 4):
            with self.subTest(mismatch_at=mismatch_at):
                result, stopped, _captures, mocks = self.worker_case(
                    0, b"", diagnostic_profile=True, helper_mismatch_at=mismatch_at)
                self.assertEqual(result, 1)
                self.assertEqual(stopped["error"], "host-view-object-not-equivalent")
                self.assertEqual(len(mocks["local_checks"]), mismatch_at)
                self.assertEqual(mocks["host_view_module"].call_count, 1)
                mocks["helper"].send_optional_diagnostic.assert_called_once_with(
                    mocks["channel"], DiagnosticCreditControls.DETAIL,
                    vm.DIAGNOSTIC_CREDIT_PROFILE)
                self.assertNotIn("host_view_mismatch", stopped)
                self.assertEqual(mocks["send"].call_args.args[1]["stage"], "producer-stopped")
                self.assertEqual(mocks["channel"].close.call_count, 1)



class GuestInfoStderrPatternControls(unittest.TestCase):
    """Literal-byte matching only; all process/receiver acquisition stays absent."""
    SOURCE = '145ea71ea21376b2f0385320a7799259ebd0c99168c9eec03d1c9144733872f1'
    EXPECTED = {
        None: (25, "8e648fa8c89eb6f12a37533e2ea8764bdcc729391df5098c258538296219e354"),
        "entry": (60, "019cf68157ab8ae0c0355953c3e9c9f54dc6bbf61230759128ed21e9381348cc"),
        "source": (61, "0fd9ab1572f1e6e95d3d4ba78900c4a5a40438453b25d05284a55dcbdf3c6f42"),
        "paths": (60, "3d6ac096bc81a7121a4afbd9d477d602cc7a4fb6a0c928681a5d0541925550cf"),
        "packages": (63, "e1dc204830438ac626ff778dbd0e65ac79f10273e54e693b92e99935e462646f"),
        "exec-closure": (67, "2b290d947a164b44f91e21611d0375aaa04c54d880797f76a47765a94454aa16"),
        "eof": (58, "e9c55235d3916107cb784fb3f296ba006a321be76212e3043173b7b89f68ac34"),
        "fresh-state": (66, "134faedbfa9751175fb8b57e09cabdbbc7023fc0d14ad975aa54293c26c9a721"),
        "pid-limits": (65, "8911191d1bca60e48ebdf323634f10981c0cf78cf375e476d86330ad5c708a57"),
        "namespace": (64, "78d7b35e5eac28bbfa99c70ad250cd51da259278317cfa640943c7aa22fda18d"),
        "mount": (60, "218e5c0637f39f492d6d1a973eab713e6e08c468b5bdccd05d05de31aaaf98a3"),
        "memory": (61, "2ffcebceb8b6d31b41d9fad69fd2cb8b21652ccf9ab7d7179821b7431a37bd1e"),
        "block": (60, "6a20ef468874f776e43ab5ccdbe19fc8dd226de65ae3dc6d7f41be46155d5452"),
        "mapper": (61, "666a92fb4be2b02c89c7878b0145de9590afa0bef88fddef6ea9fd108a079ebf"),
        "filesystem": (65, "cabdc0917721642b740b8616f7407ad48e07dc845c8b5acf98c04bb4a1039cc8"),
        "inventory": (64, "3447254791c0300709e7be3136a873a7bc8aed9826d7aaa2595954d55dd25744"),
        "podman-info": (66, "74cc830e660c923f8fd385b298d02dd88c4af010be77144b4144f8ed44f55d14"),
        "podman-profile": (69, "52b029e5fa532783466cb2833603716a6987b9ae91b97e24e08008462cd78679"),
        "pkg-jq-ver": (65, "4f7ee21a33407f5a22b5e566b9e00120817eb166e3e7a5c9c21b14b81cbf9a3a"),
        "pkg-sd-ver": (65, "d96ed047e7fff32541096b8b8734139f7307e29f38694db6d0a1d94670afdf97"),
        "pkg-kernel": (65, "d20739d40c735c558d72cb139774c54770ba9ac7f0d76a0e4cc832407b588fdb"),
        "rpm-shape": (64, "44908099aae210be9fa718a4064bd091327bad030ac673a6d781600d109ef4a1"),
        "rpm-bash": (63, "ae2f943129b6f4cbca75f36ef51e7d6a9bea16d65ba1beba5237dc45732ea2fb"),
        "rpm-jq": (61, "bf9ff98e27549e71cfb6afdedab3a897bdabaa683ec60fa576cdc36731a13b49"),
        "rpm-coreutils": (68, "a2f2e0d2aa7f07e811e0bd749dfc2bc53fa8d14bc87970d973273d43055d1917"),
        "rpm-systemd": (66, "079a1539f4729fc9550b01a5ec206d3ddc97519d6c8ab5a7ef94fb963fb6359f"),
        "rpm-podman": (65, "9d13201496e5dec9e48af2483658f9be25e3363ac449f9929944f9f204496c9e"),
        "rpm-skopeo": (65, "18509327e8b36cf58fc345905bb4060eb2c7492a749c4db0735b7f00a45e7fd0"),
        "rpm-crun": (63, "4032048a3558e147fb0d49e7e700f3c759b5995c8997fca9bb4897d385efc6ec"),
        "rpm-conmon": (65, "3b8d1cbf9bb2c31088ca212aa42fdb7fa569c7db4d5ad53b7c7a61a941f5881a"),
        "rpm-netavark": (67, "a59848d433090c3cc058c34ab01579a686c0626e86c6847f7746515fbe42e9fd"),
        "rpm-aardvark": (67, "65a41b6500ff15d88c839cf4394ec6284770616c253445449ac20baaf106b2d6"),
        "rpm-util-linux": (69, "a9d8682c49e8be663c239200fda88460314783a22d0b4a7aa3b420c375916570"),
        "rpm-libcap": (65, "9bee5e4cd051edfd3d69620d10965a8976e6d45a527873b2baa8936ed943513f"),
        "pkg-sd-query": (67, "808363753ca8c105b3849cb4545f9a333b54dc9d008f6184b08d34bd13cc45ac"),
        "pkg-sd-q1": (64, "b594df95e761623a544f880e39d6732c19e6093a32c40b307bf39934929f3198"),
        "pkg-sd-q2": (64, "bd034c8c0686c166ad2da482b75bae2f7c93032b7de9e0584b2342e025f51c56"),
        "pkg-sd-q3": (64, "22493410c9a8b49413f26234ada4ac601dd66ee8504c1d4bf4f4b4ae471d07f9"),
        "pkg-sd-q4": (64, "0fdfb0c8bf2700cc78c4946aab5c5a018b0b998d9409a8d8c7827fc738c96137"),
        "pkg-sd-q5": (64, "1a6486e2e6ff1a1ff50a63656e9d6d859c741d03f2a09e39bbe8b1a5723e28ab"),
        "pkg-sd-q6": (64, "6071b8e3ef7f02f0e7eacbc21787f1978ad9180438a62fa42bf06af85df10ed5"),
        "pkg-sd-q7": (64, "150a5a6851c5921cdde6c6a401f8547f2319cb68caa1090a87d080e3286cbf21"),
        "pkg-sd-q8": (64, "33d9fb330ea6ea4cdc170b8e906432652a90377b638eff3c06f1f9ce9a92fbd6"),
        "pkg-sd-q9": (64, "7e5ead50880f6677b7d3d1619d05616725ba6a5077fd4113858f6a56f81f6f31"),
        "pkg-sd-q10": (65, "215a6304af8ef3f2121eaaef6635637fee04443b1aeac53867112697dc74a4e3"),
        "pkg-sd-q11": (65, "d580d26d23ecc691004453b30d2fc6ef61f16f26ac462ecf6f5cabf53348c134"),
        "pkg-sd-q12": (65, "b6c3c3be16214b0cab444cc34821f672ced71d3a809b0f840b5899b51d1588fc"),
        "pkg-sd-q13": (65, "8db28283a6bb3bd37148e6b32129b5cd73105b606daab09fefd121fdd3bdd30b"),
        "pkg-sd-q14": (65, "f9176e34ae1d1b45fa456c41a8eb46ad23bbf99c83f12e2a113b456e6caf0d29"),
        "pkg-sd-q15": (65, "139eaecdd5db935854c2591e37fd040f2d12f70301dd13459ed1f0f95f0fe268"),
        "pkg-sd-q16": (65, "9344e5da3f258e7ed2e2147338ad4f30ba4a8554fc031c345eb771100f8e2d8c"),
        "pkg-sd-q17": (65, "61c239a1caed1753650ce2983db54198bd736eccad978b416a0388fb1a2a6e13"),
        "pkg-sd-q18": (65, "8c588915a330615a5810f8ab5e75d4039989424ffd431e0c7c6c1c5d508ed8bc"),
        "pkg-sd-q19": (65, "65922af0d7e7a89882bbea44d00071ec7ec0aa4e135882d746c3d5942e4d4928"),
        "pkg-sd-q20": (65, "705d4f2765a790cfdc22489e1ba8e0fd143c4171028d73ac46a4211beeb4e8e9"),
        "pkg-sd-q21": (65, "1c672cc3b9369fe961334cd4750bba2bde8006c9eef9e484ac4038862b038cb2"),
        "pkg-sd-q22": (65, "2895281cbf0f8366ee14451198abef2bc2c21438f9778c9e7add4fc535f6b353"),
        "pkg-sd-q23": (65, "36969e3fd84136ff3381a83912eaba792662fcb66a61cb09f20ea9690bcbd3f6"),
        "pkg-sd-q24": (65, "1d7d446094632a0985636eb0a1e48220937f4dff5b38f34ca41d1ae9d67a7344"),
        "pkg-sd-q25": (65, "683b8b1e198b769316608e6881ad17fc2f4edcefb902108f00f63ad2e393c2f5"),
        "pkg-sd-q26": (65, "47a1a71311bddff4334b6c83072bcee8361100bb6d3f4046e4525147376208c7"),
        "pkg-sd-q27": (65, "4df104393d968f6f69547e72af8b9e3963adb81bdba8f8b4c320a99632e89a39"),
        "pkg-sd-q28": (65, "1132303ca2611f5585b96f0d746b5d3483e1a8546da46aaa1014963252d05811"),
        "pkg-sd-q29": (65, "aabd895219b2934eb19c9db551c22376a7b54bffc7be62999dcd2d75cd8a09b7"),
        "pkg-sd-q30": (65, "d8e4f8a857a87b137d05e4aa03a5b06ce740b85ea3857853a5e22c1e6fe530a5"),
        "pkg-sd-q31": (65, "8336377b6569f75be0855e7865a98b1ee7700daae07f0aea0fc435167121b327"),
        "pkg-sd-q32": (65, "c2695836505578409cef5288c8930c71c26fe0c5b14eb89770a33ad4dc99c5eb"),
        "pkg-sd-q33": (65, "4889381f2cd48983fe36ff8eae575f1e0b1570ee0e16038dc823b541fd054ac1"),
        "pkg-sd-q34": (65, "b2ae082e1f710da3802444aa3172772d1ecc34152217e840915bf82689e600b6"),
        "pkg-sd-q35": (65, "916c9ae54c48701dabcdd4a044a8f6e0d8f17e6e5c69a4c4673b2571fc8b374d"),
        "pkg-sd-q36": (65, "efe7df960470ef04fef5d94646d6d46181aa942ac1b583db2962eaa70efec277"),
        "pkg-sd-q37": (65, "0fe6b385be04fdfdcf0ee3901038eeab6fef06e14cbbe0c73541f585d97d6852"),
        "pkg-sd-q38": (65, "1cced4ceb922a33319da6608f4626820d3b031724fd470d1a48d535845c08dc3"),
        "pkg-sd-q39": (65, "f32776f4329cf5e54009b2df6b09d1feec04ccbd30f300f7091382c10e9ee8dd"),
        "pkg-sd-q40": (65, "45815bc513fd6fb1ffdda12bdb0ae00d864037355ac1f836c5d17b112d3d97a7"),
        "pkg-sd-q41": (65, "220d5b1db53ed33a07ed93d267fe523b2ed475986bea4805d46f88a71da00934"),
        "pkg-sd-q42": (65, "33ee625aa088507f7739546899d21d2426720942465e269774344bfd8228dccd"),
        "pkg-sd-q43": (65, "78bdf73b72532768bcae4cce1fd59074f9f2c56d5f6cc7e7c079360ebcf499c2"),
        "pkg-sd-q44": (65, "9a9b867a0e5d132f9fe5699028ad7d43d24c04e026ff378e3a380fe51e5112a2"),
        "pkg-sd-q45": (65, "c4d9a59a9bf1adb0aa0645d493af90857c51acd17643c34db153a597ed385684"),
        "pkg-sd-q46": (65, "3613a2635125bd045cb0564234fe7c1bec7b22a3ebe22362f7fb43b7690e6e70"),
        "pkg-sd-q47": (65, "b75af74c9293c1cb4daa0232e557c195c1e57493636cb109d7fefec0ec9d9c8c"),
        "pkg-sd-q48": (65, "59718bbc9593e5df56308e0baad441496324a483979e24e07dd639c2aea7d87f"),
        "pkg-sd-q49": (65, "ef705445e9d4073bd44e25aa59637246f931b0a7d6efbaf5615c20d3623f6031"),
        "pkg-sd-q50": (65, "51ccf6b1a72727ca007cb4099bb61d3b9d8b70c558ecf6ae4941b5a755d64a04"),
        "pkg-sd-q51": (65, "b3bb2fd684e114179d6a9ad4781b4648e06ad17406d49e0949e05ae242ac2a68"),
        "pkg-sd-q52": (65, "3f5766f77ade444e0679e8128c3de0e0065d6e1e829899cf2674e06d0171c8bb"),
        "pkg-sd-q53": (65, "6711c0801099a12d157cda50b0d7e5c5fc1b64b880b6993cf30e46d759f63bcb"),
        "pkg-sd-q54": (65, "bbb8619d822fdd98bed634ffe3715248d2d755b792c110d204d12c88a63b0aec"),
        "pkg-sd-q55": (65, "7d64a343df5af5b47add49c19d375c659369fb4e6208e877a0e4774815d2f527"),
        "pkg-sd-q56": (65, "c3c895059a93f85c9d524865353a5e05432a2806938da8725d0cfd57b97a55a4"),
        "pkg-sd-q57": (65, "b85439ae1a7cd804b579dc41af49998de461d03d641f43770a2ca174ceb6e698"),
        "pkg-sd-q58": (65, "4d9e48f0da80c3fe651423824949f0b8ec892a9f1eae3d3ddd821831a577d797"),
        "pkg-sd-q59": (65, "c3f76f62dbed3f15271d735dc9fd72ff70101037521252ec769f4f30baaf07f6"),
        "pkg-sd-q60": (65, "f9988ddead390cc1a8cb33e650cd143416442003427fd8d1e427db2b81ec7df6"),
        "pkg-sd-q61": (65, "ef348760bb5295ad3271c5fb46970f688f4cc08fbad11efaa451937068a9e324"),
        "pkg-sd-q62": (65, "7614eaa5f350a4fd6d7f81974f42358483721d397e84957e892ac854b1022523"),
        "pkg-sd-q63": (65, "2f20359f614dce9ffb597547498a981927c19eb25da9e119654632ae0a657293"),
        "pkg-sd-q64": (65, "89fb2e1092e7c00271646a5d7ff784f47ea436ad19898b021f044ff6f8842076"),
        "pkg-sd-q65": (65, "52607176c5d24e80704dcb3b01025bd809014a6a29aa5abe27ba86df69025ce1"),
        "pkg-sd-q66": (65, "b68a818c0e83d68e5a92298d4184d4285613e3bc427b5feb8a4d7e7763db742a"),
        "pkg-sd-q67": (65, "f01aebdf5bd363961d0230f76dc4a1f4b5482fa47cd0f46d1fffcc4a854fdd4a"),
        "pkg-sd-q68": (65, "d9130f2e861a00c66c26e223519dbb64782d4aa3c9936b8c7eac920e7947ade8"),
        "pkg-sd-q69": (65, "26a9b07faf0129fcebf22f33c2a090b52977f8d5cbb9b36c120bb85cffdead60"),
        "pkg-sd-q70": (65, "a3c0d0ab55bb0e08692c8a2956c1a887bbf105862068812b0d481e2139b4ae33"),
        "pkg-sd-q71": (65, "750d60104de85729f9185a6aaaf8ff67eccd3d59c8ed0c045c099ba634095623"),
        "pkg-sd-q72": (65, "18b48417236a6e868f998e2a8a5320dfbb0b61594174d65b8b590f0ba3d2102c"),
        "pkg-sd-q73": (65, "b1eec0b879b07282f67d1c255ef23a669651bdba58498a7280ad64315a4425c1"),
        "pkg-sd-q74": (65, "ef260c0d214ed35e9da0dbc39ae3b52b6aedb7483b907fceae3af134f9a6af54"),
        "pkg-sd-q75": (65, "441168341ca1fd3b4c604dc0c97be21644f53dba9117aa8e931baccd8722fb86"),
        "pkg-sd-q76": (65, "14c1d578e6701d8d1e5e53b0fdf5e9084be0f1208bd414724ec7ac29f82e2b7c"),
        "pkg-sd-q77": (65, "a602aca5ddb615b8acb2043d2fd2d4f0d52296baafa7913b0016fef26e6fe1ce"),
        "pkg-sd-q78": (65, "43573818f253ceea013bffa2cb6571c35374068088d94273c68331b7e428d203"),
        "pkg-sd-q79": (65, "907829cd62f1719fca9dc92371a972b9a46452fdbfb627f4f962b9227c0821e1"),
        "pkg-sd-q80": (65, "f7af1603c4b04a38871b20adb392406ad5c24389aa0fc81df187ea8bf7f643dd"),
        "pkg-sd-q81": (65, "836f0710cded43523e928db50240b6196080cf3aa7f063742e3056631c79fb0d"),
        "pkg-sd-q82": (65, "b2097829b41eb471c4ba57c0df5c32960b15ab0c30954a9822b28f1f3d76f19c"),
        "pkg-sd-q83": (65, "621e7b4aa3e0fe155019f7c7bb1b8fefbb684a43e6d6d14dac9a3691ec801303"),
        "pkg-sd-q84": (65, "5b983db06af210c73f1746fde111424e597052c8308d7a7d24cfdecedb5ec35f"),
        "pkg-sd-q85": (65, "4e17b897927c8a585f7ca8aa178731ace5052b0ab9fd3f9db4da20eff10a484d"),
        "pkg-sd-q86": (65, "29b78ed204394a689d237902f8c266b0dfc24d0ad1814ff75e5767ec2d736d04"),
        "pkg-sd-q87": (65, "127283260eb4f375adf5b35b019adc0dbd800e5f10dbf44671d7001a6263fcf1"),
        "pkg-sd-q88": (65, "25ef113d1bde8238ca01148fefd228c029b29d673a660024d195835a35726db2"),
        "pkg-sd-q89": (65, "412e36effc78cdd8832814138c0c1b5524cade9602f0bde7166c63109d5163e0"),
        "pkg-sd-q90": (65, "e0787610bf94ea5d72f246075cb713a1c5b5a294ead049b2e0639e07a191fd31"),
        "pkg-sd-q91": (65, "8b8ff1a750333a5bc070c7c39b5b3a1ce47832a7b3088ade319c4730412fecab"),
        "pkg-sd-q92": (65, "5897041ea8d455b3237cf405c1d84c7053e84e8a0bb72cd92e10b6f23cfe8126"),
        "pkg-sd-q93": (65, "73eb3b38119bca0611401935d16c230f93496f2740cabbe9e0f67709a430cb68"),
        "pkg-sd-q94": (65, "75e15d6a7429180c6b23d4adeeb98febd2e1c33baab69085db0cf6cb09e066c7"),
        "pkg-sd-q95": (65, "a3fed8f5d5294c8bd33cb97002c6a2906859128d43c072e206e2758e87504543"),
        "pkg-sd-q96": (65, "0315ec0a8d5595c69dcf542c73540e8bcb8727dc6f0ec275dbb26d678dd667ed"),
        "pkg-sd-q97": (65, "517479cfb787edf4dd3044dbb6e344ccdffe462c738502c2d56dc22eb4600868"),
        "pkg-sd-q98": (65, "3b163fbbf1fe792f2bdf1981e28a856bcee366217c19abf6256e98dd94c54469"),
        "pkg-sd-q99": (65, "a1cd36494419a30b4a64caa2a1188bdefb2c121ea7c5febf9d4d88fb19e3fc2f"),
        "pkg-sd-q100": (66, "5a8833a67545c581fafb68fc006366b610130122b7503a593449503325350d7b"),
        "pkg-sd-q101": (66, "0ae82244db736fd0ff8e91c2ee1a6bbbf26796a5b62f0cb9348b7cce15c374dc"),
        "pkg-sd-q102": (66, "75057a671052c97e11cc8c9347af31b3c7daafb9f2571c8f5c6738b5c4008886"),
        "pkg-sd-q103": (66, "661b02fc3ac41c2caea945e0bc21ad57ead6e411ad769e8b3b8f5ece74d09ac7"),
        "pkg-sd-q104": (66, "5e3481fec1c55afdd16c454c36af27d136aa161942127c494c8489b186058944"),
        "pkg-sd-q105": (66, "af07854172170b3eb82ade16861f6a5cf9956e981db7ad5d0baa6ce1ac4022c8"),
        "pkg-sd-q106": (66, "9cd06aca95c6a2c7a0f3c93cdca9db2b1df10fb313c49037f1582b8a4a46156a"),
        "pkg-sd-q107": (66, "90af1714f13ce4d9fd2449d0e89c4e48e9e186ab4dbb0985754307f5579d90ed"),
        "pkg-sd-q108": (66, "feca651ab1f915926fcba4a5dabd5638a5a75a7be3640f79d3400047536c7d27"),
        "pkg-sd-q109": (66, "d61b6784fb8ec9bab9a7c7be1e9dd903c09af89a621e1851fca518246913144f"),
        "pkg-sd-q110": (66, "d310fce4be59375d13a3aa40150900a0388ea1d7f28c7ac463732a9941418740"),
        "pkg-sd-q111": (66, "ef3b57baee59c532430f898620221e9ff2622eeece4a7ecf3e869288c9586b6f"),
        "pkg-sd-q112": (66, "0474c421eb1f344ce75d62ae1f613215def3d2bb1ddabf65c97aa206eb7fdf63"),
        "pkg-sd-q113": (66, "613e87f56762cc231ae2710652e9c1d23831891aec8ef04fd243ac157748e3dc"),
        "pkg-sd-q114": (66, "d3160f52dd89813413665574f1aa3b2a5b754e363e5c4eb814f2a05f63dd8b00"),
        "pkg-sd-q115": (66, "833e19dfcf9127044b5d5add6d7f0c69094347f31d5e4eabd84663a43cccdc0e"),
        "pkg-sd-q116": (66, "ce99cfdba43bb7d2b96763cc2b295b33a85c20881b1f059747b3921964e1d4d1"),
        "pkg-sd-q117": (66, "c5754f87f851260ac896c177dd041fe3cce643bab1f25495f5dc444a36dae082"),
        "pkg-sd-q118": (66, "e6c08aeb84dafbb8e85bb82e14aac983efbf2a431b4cc8cda6058f56e69303a6"),
        "pkg-sd-q119": (66, "919fdb85ec9fc2a47c0abb0b9f65ebf276b392340b170c83435c0c7734d7aada"),
        "pkg-sd-q120": (66, "e5c35e7567d84dc50f0f1bc31cffbb6dbb8d4c6ef17c873bd1e781aaa725b9c9"),
        "pkg-sd-q121": (66, "5e96ae57107df22783e8adf4f79acdcd55ac1449c534c42fd1045dd2e2de84a8"),
        "pkg-sd-q122": (66, "f81bbe2fb60c75841a36db11a47745d78ef39fb4b7cf0ad883a403b1fe8e28e5"),
        "pkg-sd-q123": (66, "09e787da51647cb2165137d084345088103801484cb8c7e4adc4d9bf26a134c5"),
        "pkg-sd-q124": (66, "06ff58463a5782f90a38cb797cb4301d69890e90acab948134b85cec79d403f3"),
        "pkg-sd-q125": (66, "5f886da8c7f9b1bb0b89b2e2d6d1c1495fe24485e4cfa6a5513c72b379804176"),
        "pkg-sd-q126": (66, "664e83ae39c01db620f9aedf0596aef3f4d76d193cfbc436975be260a17224a9"),
        "pkg-sd-q127": (66, "102a5be400cfa5a0f4b30e2689149139198b2fcd49ffeb05a34e8cf80595a27f"),
        "pkg-sd-q128": (66, "15db7c72517b3212d65ada76cca78a79fa2ca04fe011fa1870de306be809ff07"),
        "pkg-sd-q129": (66, "54e9b1e48ab8aee2d85684dfa230f067361ed653879e6973602946fcf1de378b"),
        "pkg-sd-q130": (66, "f2da6c169970a86ba2093448df311ff63d94a574efebca90f5d4fda27e2aa71c"),
        "pkg-sd-q131": (66, "49af94215214e3764976c00c9f0dccbb85f20b897a7cecf18a291032d24a7131"),
        "pkg-sd-q132": (66, "a5034046716a9b31e763ca3dd6037695e9738a771a3b9aee2ef55760fa6bda08"),
        "pkg-sd-q133": (66, "0f45a9ee13e6bf20c048c1705d2b8eba5d06dc74f5f21c4ab7f4df0b406df804"),
        "pkg-sd-q134": (66, "b605f5a6f4fcad6eefb2b1c32ac8d83fbe4ef8a868bff2f2aae1226f817e8211"),
        "pkg-sd-q135": (66, "27256c04af921b008ff68c74c31c611999b044c44f6c056f130aff478958be8f"),
        "pkg-sd-q136": (66, "6edcb302de40ef45f8297e2fe70cad6eeda3e06bab5d9ff23cfc6582a8c75dc6"),
        "pkg-sd-q137": (66, "ee703376382e4ef8a9174fa8d2e80f611abb0962b0fae9dca447ad2ebd4c4759"),
        "pkg-sd-q138": (66, "4463128d464984c94f8bc5150eea80f3576551149f3d6f95c3e1fa5307c1f0d5"),
        "pkg-sd-q139": (66, "46b2b193b0c0837419a5ed512fa55969a6a0e50b8f3b63c302d49b868400cefe"),
        "pkg-sd-q140": (66, "9a021c24e60bd02f5decb6e2fd5c011319d7217ad8eebecb74a9e0a22d1bc221"),
        "pkg-sd-q141": (66, "af4244372dd20f109fd60f04b727458cd0dd538ef9f58ccee940a42c30056252"),
        "pkg-sd-q142": (66, "0dc0f09bcf693cbe7d535dcf785ec56132402f61f089348a2371c29582ff4501"),
        "pkg-sd-q143": (66, "70a8e5e5626b64dc0df25c3842d89fbe67aff827b6a536068d904b464f403dbf"),
        "pkg-sd-q144": (66, "01633645efdd2a6b9a781775e031aab55bcd1182c2aa1c0c809643b87d222a4c"),
        "pkg-sd-q145": (66, "4da39241f0b2b9f49ee0c9eaf1398b3ecdb05c73c6fcaeaa71409c6b63ae2c34"),
        "pkg-sd-q146": (66, "105df18c1e8290fbd9ebb7688208d475addcd6be2d8e9a3335d8fb27c9d1386b"),
        "pkg-sd-q147": (66, "c0ac1fae42aa115ff4243073ea53af46950518d815da7e69732b136c9a5c5f26"),
        "pkg-sd-q148": (66, "b3eb69dbc25b7737cfb35caa3b6312464c5932587a71d17294ad5684321d3912"),
        "pkg-sd-q149": (66, "c629022bf6d6d9b60f62d2c42041d0b2e5f33446e91b32474d93392e6499a1b8"),
        "pkg-sd-q150": (66, "5d6b263e1f0f6844f917529f85728fe65440b346917e255abec754385c31bbb1"),
        "pkg-sd-q151": (66, "8df3fd615ff3824c0deafc859a4bfbd4525fad1b333759a8a0ef4d2def1bac4d"),
        "pkg-sd-q152": (66, "382ca35129f71ba33f9c5da858f40d1246bcc18f71baded0d060327386f35bb8"),
        "pkg-sd-q153": (66, "c380b790834206d25650c8925907b4c2c3f1101278d42c0e1ee137e3fb2444e4"),
        "pkg-sd-q154": (66, "42ef71babf87b30bd281c5e6ce60178bb7b059eea8afa2d68b87921af13585f2"),
        "pkg-sd-q155": (66, "ba1478a7d3d196742296e10a8e39d8b159f0fafaa83f5fc56819fee6f2e9dc51"),
        "pkg-sd-q156": (66, "dea9c1bb123e0bbc662e0e311ffc13c0fda802218a0b429489ac14b7ce96d6fa"),
        "pkg-sd-q157": (66, "69f74dddd0ef3515787e464030f52be476d973181725c6266823dd02de5d1655"),
        "pkg-sd-q158": (66, "6271dcac48b50cbbe337d1193ea22fa31226702883673c66edcab2b4df1d50eb"),
        "pkg-sd-q159": (66, "1202930cd737d3dbd36a5a4e30119a214a4c2b317ddc5030bca49a38e57c90c5"),
        "pkg-sd-q160": (66, "0a4b8e2344a8a3497708fa4c825410478fc3daa9c752f661eff17be1de70eb9f"),
        "pkg-sd-q161": (66, "33e790d8c0beaddd5e8bc8dd5f14ad618bd8f22a77ac451e5119023000e87789"),
        "pkg-sd-q162": (66, "fe1477888e91884cf99e3f297621e00dd873bc8e48000d43364dfa46a6e3136c"),
        "pkg-sd-q163": (66, "72110b2f085809b4a8184895ce5337645f8c2248d46e481ad783857337d62dab"),
        "pkg-sd-q164": (66, "ed5c984ee9a16f1bed7450452b97625e6032aeea10655f71b6e7ccc4696f3284"),
        "pkg-sd-q165": (66, "59416faa6910f823f69387d139e8f1e2ccf403bfe9eba9f6355b04928114e77d"),
        "pkg-sd-q166": (66, "c91986bc11e95cd2da45dc9bb5b09f948ec6108a398f3596b2de1b2117a3e595"),
        "pkg-sd-q167": (66, "74ce86bde7aa29329efc5bfeaf19f632cee8a6961f746ce8f70950e76e370833"),
        "pkg-sd-q168": (66, "9709519b5d0dc51c83d2c5319cd0fd6efd9d6845ab2e8e16b007384c019c0acd"),
        "pkg-sd-q169": (66, "aaf723394997c3d7d9dd319cfd22d15fb6b7a9c3ea1fa8853b77029c8d9adb50"),
        "pkg-sd-q170": (66, "70614ab43efb7683882c3a7a5648f304659b4d17ccce5083dbfb5e908426a146"),
        "pkg-sd-q171": (66, "2c5f23cb8243e51cd13564de459988db9998f7d306ead8cd6e3770b0ed0082a9"),
        "pkg-sd-q172": (66, "c9ddfa5f6133bb753fb37af2c1d1861049fb9b8dfe56a3e432cd56b599d44531"),
        "pkg-sd-q173": (66, "292bf2a329673a7e613c3769cda8ad946b4095d36dd49fa915a97bb481f75fec"),
        "pkg-sd-q174": (66, "f99133d0436b14c0c2ef71e7f74a89d8c004cb9f2db4e04bc977357a986012b4"),
        "pkg-sd-q175": (66, "48262113aadecc110c95943d03018f0320a8afac5b73405b03b3cb75f1eb2e52"),
        "pkg-sd-q176": (66, "7b92064d6eedf6eba58e5f9f29709405c7c169c559c12b6637dd4af6d37c2e7c"),
        "pkg-sd-q177": (66, "ccf9166942f58a7e0f79cda18aea9b555c93e93c0a6bd37fd0b6a3d10aed6165"),
        "pkg-sd-q178": (66, "cf7b6e43dafa1af2f53ac508d5c6e0505d07c57db0b90f0a7ed3d51cbb00b84d"),
        "pkg-sd-q179": (66, "9003c5fef51bac5af91dd0bb15e2bfda8817afdfbf39d3fc08bd4ba861c256b4"),
        "pkg-sd-q180": (66, "f796f4e40dbc6e840053b98c24aa4d78e378d3afb68ba9a5c9a88b2968a60e6e"),
        "pkg-sd-q181": (66, "b63537b75f7dcd41f0cd2f8c576292c6520c61dac496d1cdb882759da51347e3"),
        "pkg-sd-q182": (66, "728c78fb0357583bdc0f5d6118c2fe88a22836ec371eede6e2e04474aaec1928"),
        "pkg-sd-q183": (66, "57ac5cccd87d8e3cad8397831b450f2920971c8305ecc8fa56d764cf1abb437b"),
        "pkg-sd-q184": (66, "5052354d65f37992e3248ba22e47a378f20055a900e905333aaa3353446de68d"),
        "pkg-sd-q185": (66, "7a0900de601e8a884d3dc94b1c50ac7ae90ff18caf274711b0a7b89fac6ff5e7"),
        "pkg-sd-q186": (66, "28b3cf105a47c4feb8ea9b320134d2657b2c98ef4d193aad82493d2028bb3c3d"),
        "pkg-sd-q187": (66, "331bfe051529439351e8c1535258dca071f4f07779f68f4da4f34f1d899404bc"),
        "pkg-sd-q188": (66, "43b8c1954657262e8385d2e2b23e6b8c14ea4b6969cfe35f32cbf0868c935742"),
        "pkg-sd-q189": (66, "76f47c4ac653d70b28ab84530593866db17eb0e1cd5176a25d534eac5432221b"),
        "pkg-sd-q190": (66, "c8f33780c957324b091518956740247abe5bdfcdab2efc77242e68b2da92788a"),
        "pkg-sd-q191": (66, "d3b9385b439932230ebf97af3341257ac4678efa52d383292e66e37d559bd926"),
        "pkg-sd-q192": (66, "93414d59884658700a10d127dc09bc0bb1cfc667df5904f29e2a9ae9740548e5"),
        "pkg-sd-q193": (66, "e0f272661cccc29a128a40254b4bdf339fb3ebb2a5175b09c7eca0a112478267"),
        "pkg-sd-q194": (66, "6bf52a1eaa6d127948d47869f97942d64b5188aa6fc3bba2719e411999deb216"),
        "pkg-sd-q195": (66, "e357fc53112489399cde0ba9e41cd90dde00d919404fcc2c4ac8bd0a9f497501"),
        "pkg-sd-q196": (66, "d778251d41e503e3fcd4170b0fb83e644e7913f8fb1ed967a664610cb257b61a"),
        "pkg-sd-q197": (66, "b31b071806649defb801be8266454b336d5837fc1656bbaa63953c31ef56fe28"),
        "pkg-sd-q198": (66, "075bba4841ae814f0e4502c1dc3717945b7c603bc233b1da2a5b485758804846"),
        "pkg-sd-q199": (66, "ef51e6f292fcdeebab8a827d85a72e8656535463acd62195b1173cc03de7a4f7"),
        "pkg-sd-q200": (66, "ab4a9748837ddb7d88d0ca3b6b4cdb0ef7b69a03a72313e00decdebb64ff24d4"),
        "pkg-sd-q201": (66, "8c9a3d6a787f215e140be07df37b2b8b8161c314f41cb3d34b3e70d454dbb76a"),
        "pkg-sd-q202": (66, "3ae1b1b6758db5075fc6b7e3c1aedad37b90539f6dafcbce0ad3f772af33a61d"),
        "pkg-sd-q203": (66, "ee766514b45db2d352e5fa3bc41e8990c1f904af2e323d9084580ed1051ec091"),
        "pkg-sd-q204": (66, "fd1c345dbe9522dd83e21e07e72d79993affb0911447520c2f2d5e2bd208d57e"),
        "pkg-sd-q205": (66, "853f611754742c7632fd1b4cd224835405ca4daab7e000d9b8072b5a44e48f15"),
        "pkg-sd-q206": (66, "a83aa46a520f090c9dec7855a0942c5863ee6b147c12143cdb7dd87b340f170d"),
        "pkg-sd-q207": (66, "e64a9d8835cbef0951b5f7d0e791cb2d716f3c3290dab0198e63d8dac3a2c3dc"),
        "pkg-sd-q208": (66, "bd9350979211edc0c535bea6922deec311d899c69b32c5f0ad2dac863fccdc64"),
        "pkg-sd-q209": (66, "f6d200d816756afee20f302e264fb95af9fee38b3ebe553dd1d2a38954abbdb9"),
        "pkg-sd-q210": (66, "33b3d4dd8ef4035de28e6b0a6d78d47028a41fbb1446f027254de0d263a6dae5"),
        "pkg-sd-q211": (66, "daac161158e9c2c28eee401c9a87624d39da357dda7e2f2e6432d09c1a931857"),
        "pkg-sd-q212": (66, "3a233bd110cdddb5859e759b6bea2840c5d263b312be41e77b139b6b6065ab4a"),
        "pkg-sd-q213": (66, "3dedc23948be8f9f1748d4ec4aa6d086afddd05fd93ea8e205882f7cf859bab7"),
        "pkg-sd-q214": (66, "2c9a51c31920dfd2eb6532bd5160c1b907bd67fc7a6360d7236428a5d4fec8da"),
        "pkg-sd-q215": (66, "f2ad422becd94702c4f89aa998273c18b7c36544a22a2ad0019448fc7ccbdbb1"),
        "pkg-sd-q216": (66, "2edbde79ca7b8e33dd03553110e1232539613e5ca3622993d8f0d0985ba5cecd"),
        "pkg-sd-q217": (66, "89b8ba1af7146aad3d1703fb08cdbedddb2669431c970bda7bb4548aa09ea0b1"),
        "pkg-sd-q218": (66, "1f4bedf43dfc2baef469a9fba5f9043949e0f787873d88bc1d55f1530fb418e9"),
        "pkg-sd-q219": (66, "d9488badc8a03a41f554dfae6bc9b98f6d0ec5cb737b1f694b70d14b24f34b11"),
        "pkg-sd-q220": (66, "8c867069efc62f172f96a1ee7746d29ad5efddbc3f08de21993b0ec056974376"),
        "pkg-sd-q221": (66, "19fe54147aa488b4d6ce3b026c384c34954c4a3da5c8679a5c685bf203c77771"),
        "pkg-sd-q222": (66, "3effb7542c72ceb36b25c2675e0d297962766e100280964ad09f532fe8ec71ac"),
        "pkg-sd-q223": (66, "347ff168ae60cb404d4b1dd3d6e48dc51304eb579cb7bd1e7c9ea63cf2e5dee0"),
        "pkg-sd-q224": (66, "fdc32ee283c84c93ceb3017f8f4d84f1285c764b75a16e71a79b6859f95b39bb"),
        "pkg-sd-q225": (66, "6a6f9b0fffa9ac623501f5ab813176ddffa582a8bcf08bacc20a7c8f75e57b1e"),
        "pkg-sd-q226": (66, "1fbd7f0ea34444913a2ce074a705eabaa6a851470f3dc141747e8763332d75ca"),
        "pkg-sd-q227": (66, "ffc422606fefb3c3fadb048a207046b5dcd7867dec1f3492583bb350985b18b9"),
        "pkg-sd-q228": (66, "d677f8ae6d45efc190410bc3e13d0f8472bfcb2a7eb6e002857956248a0d844f"),
        "pkg-sd-q229": (66, "00adaeb5ddeb1c358e6e02ba938df48ac387cf3671428e07e28fc628a141ea5f"),
        "pkg-sd-q230": (66, "3b8da221194ae0e50b261e87739e8129d1bd1145d5b6fa67059c2331c7840e0c"),
        "pkg-sd-q231": (66, "e1dafdef9267e8bb681a9757b0019b8a7251bf2ba5f52e511caa54abc0c9c8e6"),
        "pkg-sd-q232": (66, "15dfdc9175a58373415d99c003c4a519f194354fd85c1189c27ed15ba03e5026"),
        "pkg-sd-q233": (66, "f9aca852dd6857b43ca40a70855898e710e51befa49ced3b5fe051e5583c341f"),
        "pkg-sd-q234": (66, "65d7acc6f05fc6e3aaea07edd6cc5083ee5181384c5c94fbf7d7186382eb86b0"),
        "pkg-sd-q235": (66, "56a26e1d0cfab9a3c7f6a7532dc91b1efee504e5a397016473bf2e6581ba5a63"),
        "pkg-sd-q236": (66, "937e84617651f11623cab67de6f6133b9651a779ed5f13919baa48589482c199"),
        "pkg-sd-q237": (66, "7fa5ccd24ba9735f1e38dfa1f302806e1276983ccc9985a037ff85884e5af8e1"),
        "pkg-sd-q238": (66, "45060a178392a5e939c7ad523185802a8ed5c72453ce92a78d9ad69e53bb51d3"),
        "pkg-sd-q239": (66, "3e046a99061d35103ac6e6c36456ae424c22bd94d5d2b2cbf0aa1952e192784c"),
        "pkg-sd-q240": (66, "7532ece06b9748cdf96aaf7052c99b3f4f81db149ac6b6e29e35cc4942be4c01"),
        "pkg-sd-q241": (66, "5a21aaa828b3b7729db2fc4e49be71866d5ed754c1a7483d7e1a28d88460a232"),
        "pkg-sd-q242": (66, "0cd53e7d1d8043854db7b3881532b39c9fc9bb6fcdf73b4d4c3c0771dff1b6ae"),
        "pkg-sd-q243": (66, "b77751364ae837d5b56354e115cd86dde425accad6ba654e49cf972951353d5d"),
        "pkg-sd-q244": (66, "3ae0e38592ca47bc21d25d1298ff271fe2082b64cd4c94075e6016f8b8e97236"),
        "pkg-sd-q245": (66, "4c5248b33b43fd112bf7f92d56562e6226f0639cf07b5400761ae377fea48484"),
        "pkg-sd-q246": (66, "56d94debfb1260205f77d102ef9384125706b1f0cca56f7ebaec255ab8d9d70c"),
        "pkg-sd-q247": (66, "1eb121b2cdd060a42a8ef540156a9a7d1acd350a605130e12ee2b2a5aecec6fd"),
        "pkg-sd-q248": (66, "c35c2b49a5403190ba4830d73c4c00c1d91ca45da5e8f6b3d93cd29eb727efd1"),
        "pkg-sd-q249": (66, "95da21af0189cd33a61d47c8b73adf585832444ba3fb06ebadd6eae672a760ba"),
        "pkg-sd-q250": (66, "b722892dbfaaf71bcbcf4ffb8a863a045009446899cf77157da384335587677e"),
        "pkg-sd-q251": (66, "e59e049c5a02704279412779d343475a2072a52fcda5cc88fb241be1af1c3921"),
        "pkg-sd-q252": (66, "0cd3b220b886377c19dafa7c223db9b6971e6c97bda6261becbd73c7b916ff6e"),
        "pkg-sd-q253": (66, "2133a828d0436cd459744a2b1e99a0e7fe6c5779952110adeffd2c23d24c6c36"),
        "pkg-sd-q254": (66, "232e998debcf3c371efb2fa2980f71e97fd99c8144fa1e81ab58f5138948e6d6"),
        "pkg-sd-q255": (66, "f53502c06788bba43e290eea7c12a88f5685677004cb8180e3f33b23a0fbbfe8"),
        "pid-max": (62, "ed7dd548fe0a427d533aa5a29d356d5e16f0d032b8ed92fb36a0ef8497c0699f"),
        "nr-open-form": (67, "9373669b25591775d765b3c9ef02c77f07eb21822c51a6bb181e66f679b49570"),
        "nr-open-range": (68, "65a7e29b6697188a8da63fdc0f3e655a786f915e77d7564b6bd0bce207a84488"),
        "mount-both": (65, "a1a6465be9ba0e68eb04c46d5c1df3c48dfaecec8e946a0d92c71e51fbdb2c9c"),
        "mount-proc": (65, "8a3ccd933078010605579af4cf1b5573210a78a2ec96750a731cd40e98a48b5d"),
        "mount-root": (65, "95966c9b4d45756da13347a8a6ccd0d8d982162a8bf4eb21d3b84d0efce62806"),
        "inv-pid-range": (68, "c0df55c53e9ec11bfbfdf303046636d12f5132451c40258e438b120a1b43f587"),
        "inv-proc-task": (68, "572b0336c99cab8d5d548884c81185731237e5e57c16ac8ade56c45c54700ed7"),
        "inv-proc-read": (68, "8a0df6b6456b64e654d24d9e34cb0b5c15e330d6b24b8eff8992f5915ef99039"),
        "inv-proc-pid": (67, "e34cc656b3cac6738579ef10f0b12855e2fdc5dc71d21928f8af40b61b6c4164"),
        "inv-proc-form": (68, "7350a5ef84389c2690736f4e39ab99e170f93c35b4ac3655f8f230b3f4c26fe1"),
        "inv-task-empty": (69, "cb993014c1a216faf5dd509660b7258a6ac2be1a35f36c18e8b96e51880eae0a"),
        "inv-tid-count": (68, "d3b3bb96396cfa368c12630c966a83736e316cbabc44343dc844534984086489"),
        "inv-task-read": (68, "33e594fe97f64caf2732dc71ac4a693ce146f4b11979b9ca3bcdfa183fde6911"),
        "inv-task-tid": (67, "1b243974896c009a84aff3fd3850be1cfd093716e67af0022ba8f65fd0a6d6fb"),
        "inv-task-form": (68, "8c6984cc4a856563529a36fabd9fa5b52e1e0a5302b5612d48fa05b84e5aab55"),
        "inv-nf-form": (66, "02d06defa097d42c0f27d212242b6a6bee5260e2194bfa3f873e339e0c9b069e"),
        "inv-nf-range": (67, "77eac6aeaecf3fffe764ef83389c1a582d6ff2987375fa5cef3c6c7c0226bf8a"),
        "inv-fd-access": (68, "81cf868c966e0b98099e80a47d4a13d75845fc033d35dfb3ffb04ff6e88f353f"),
        "inv-fd-form": (66, "620a20c3e0f4c91b9d85606835ac06cb7cfd80a910bebfc6ac04b1eb9cbbbd70"),
        "inv-fd-range": (67, "8e1c2b928ac4eb027e7449e3f28e7163b75b7573c5f057f57aca2c8310ea81b5"),
        "inv-snap-size": (68, "3d1f9e08209b30e5089529213e9ca6199af2bc4c5f49080fde7f8d0264482b9c"),
        "inv-empty": (64, "370750f0c30ea1873248433e8cd77b09dfeb31210824daa4653e0e44776faeef"),
        "inv-drift": (64, "6a8dbc09f114ad9fd61a9ed1ea34e015e38641d9f7e3c71fb120905361ed5a9d"),
    }

    def command(self, code="entry", *, raw=None, status=255):
        if raw is None:
            count, sha = self.EXPECTED[code]
        else:
            count, sha = len(raw), hashlib.sha256(raw).hexdigest()
        return {"phase": "guest-info", "process": identity(555), "outcome": {
            "schema": "kubernetes-lens-command-outcome-v1", "classification": "signal" if status < 0 else "exit",
            "returncode": status,
            "stdout": {"charged_bytes": 0, "charged_sha256": CommandOutcomeControls.EMPTY, "eof": True},
            "stderr": {"charged_bytes": count, "charged_sha256": sha, "eof": True}}}

    def expected(self, classification, code=None, source=SOURCE):
        return {"schema": "kubernetes-lens-guest-info-stderr-pattern-v1", "source_sha256": source,
                "classification": classification, "code": code}

    def test_frozen_source_and_all_literal_patterns_have_independent_expected_hashes(self):
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, self.SOURCE)
        self.assertEqual(hashlib.sha256(Path(__file__).with_name("owned_guest_rootful.sh").read_bytes()).hexdigest(), self.SOURCE)
        self.assertEqual(len(self.EXPECTED), 314)
        for code, pair in self.EXPECTED.items():
            with self.subTest(code=code):
                raw = b"rootful-receiver-refused\n"
                if code is not None:
                    raw += ("rootful-prerequisite-code-v1:"+code+"\n").encode("ascii")
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), pair)
                with patch.object(vm, "read", side_effect=AssertionError("no raw/file read")), \
                     patch.object(vm.subprocess, "Popen", side_effect=AssertionError("no command")):
                    result = vm.guest_info_stderr_pattern(self.command(code), self.SOURCE)
                self.assertEqual(result, self.expected("legacy-refusal-bytes" if code is None else "prerequisite-code-bytes", code))
                self.assertNotIn(raw, vm.encode(result))

    def test_stale_v12_receiver_hash_cannot_admit_any_registered_pattern(self):
        stale = "ba1710d3710ecaa9c81082fb544c465400a933d57c025169cc3ef076d214647b"
        self.assertNotEqual(stale, self.SOURCE)
        for code in self.EXPECTED:
            with self.subTest(code=code):
                command = self.command(code)
                self.assertEqual(vm.guest_info_stderr_pattern(command, stale),
                    self.expected("not-established", source=stale))
                matched = self.expected("legacy-refusal-bytes" if code is None else "prerequisite-code-bytes", code, stale)
                with self.assertRaises(vm.Refusal):
                    vm.validated_guest_info_stderr_pattern(matched)

    def test_observed_exit_status_is_independent_of_literal_byte_pattern(self):
        for status in (0, 1, 255, -9):
            with self.subTest(status=status):
                command = self.command(status=status)
                before = deepcopy(command)
                result = vm.guest_info_stderr_pattern(command, self.SOURCE)
                self.assertEqual(result, self.expected("prerequisite-code-bytes", "entry"))
                self.assertEqual(command, before)
                self.assertEqual(command["outcome"]["returncode"], status)
                self.assertNotIn("auth", vm.encode(result).decode())

    def test_unknown_source_and_partial_evidence_remain_not_established(self):
        for source in (None, "a"*64, "invalid", True):
            with self.subTest(source=source):
                result = vm.guest_info_stderr_pattern(self.command(), source)
                self.assertEqual(result, self.expected("not-established", source=source if type(source) is str and len(source)==64 else None))
        self.assertEqual(vm.guest_info_stderr_pattern(None, self.SOURCE), self.expected("not-established"))
        for stream in ("stdout", "stderr", "status"):
            command = self.command()
            if stream == "status":
                command["outcome"]["returncode"] = None
            else:
                command["outcome"][stream]["eof"] = False
            command["outcome"]["classification"] = "incomplete"
            with self.subTest(stream=stream):
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.SOURCE), self.expected("not-established"))

    def test_unknown_extra_truncated_repeated_empty_and_secret_streams_are_unrecognized(self):
        generic = b"rootful-receiver-refused\n"
        frame = b"rootful-prerequisite-code-v1:entry\n"
        raws = (b"", generic[:-1], generic+frame[:-1], generic+frame+b"x", generic+frame+frame,
                generic+b"rootful-prerequisite-code-v1:\n", generic+b"rootful-prerequisite-code-v1:unknown\n",
                generic+b"rootful-prerequisite-code-v1:entry\r\n", b"raw-secret-must-never-be-retained")
        for raw in raws:
            with self.subTest(raw=raw):
                result = vm.guest_info_stderr_pattern(self.command(raw=raw), self.SOURCE)
                self.assertEqual(result, self.expected("unrecognized"))
                self.assertNotIn(b"raw-secret", vm.encode(result))
        for stream, changes in (("stderr", {"charged_bytes": 61}),
                                 ("stderr", {"charged_sha256": "a"*64}),
                                 ("stdout", {"charged_bytes": 3, "charged_sha256": CommandOutcomeControls.ABC})):
            command = self.command()
            command["outcome"][stream].update(changes)
            with self.subTest(stream=stream, changes=changes):
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.SOURCE), self.expected("unrecognized"))

    def test_strict_pattern_schema_rejects_unknown_fields_codes_and_claims(self):
        good = self.expected("prerequisite-code-bytes", "entry")
        changes = ({"extra": "raw-secret"}, {"schema": "other"}, {"source_sha256": True},
                   {"source_sha256": "a"*64}, {"classification": "authenticated"},
                   {"classification": "receiver-executed"}, {"classification": True},
                   {"code": ""}, {"code": "unknown"}, {"code": None}, {"code": True},
                   {"classification": "not-established"}, {"classification": "legacy-refusal-bytes"})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(vm.Refusal):
                vm.validated_guest_info_stderr_pattern({**good, **change})
        for key in good:
            changed = dict(good)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(vm.Refusal):
                vm.validated_guest_info_stderr_pattern(changed)
        copied = vm.validated_guest_info_stderr_pattern(good)
        good["code"] = "paths"
        self.assertEqual(copied["code"], "entry")

    def test_actual_parent_retains_source_bound_pattern_on_worker_failure_and_quarantine(self):
        for retirement_error in (None, "outside-retirement-unproved"):
            with self.subTest(retirement_error=retirement_error):
                outcome = self.command()["outcome"]
                fixture = GuestInfoParentOutcomeControls()
                fixture.setUp()
                with patch.object(CommandOutcomeControls, "expected", return_value=outcome):
                    result, status, private, _valid = fixture.parent_case("nonzero",
                        worker_error="authenticated-guest-check-failed", retirement_error=retirement_error)
                self.assertEqual(status, 1, result)
                self.assertEqual(private["guest_info_stderr_pattern"], self.expected("prerequisite-code-bytes", "entry"))
                self.assertEqual(private["guest_info_command"]["outcome"]["returncode"], 255)
                self.assertEqual(private["error"], "authenticated-guest-check-failed")
                self.assertEqual(private["retirement_error"], retirement_error)
                self.assertEqual(private["control_plane"]["commands_remaining"] + fixture.last_retirement_commands, 128)
                self.assertEqual(private["control_plane"]["output_bytes_remaining"] + fixture.last_retirement_output, 2097152)

    def test_malformed_worker_diagnostic_is_not_established_and_still_retires(self):
        fixture = GuestInfoParentOutcomeControls()
        fixture.setUp()
        result, status, private, _valid = fixture.parent_case("malformed", worker_error="original-worker-failure")
        self.assertEqual(status, 1, result)
        self.assertEqual(private["guest_info_stderr_pattern"], self.expected("not-established"))
        self.assertEqual(private["error"], "original-worker-failure")
        self.assertIsNotNone(private["retirement"])



class PidProfilePatternControls(unittest.TestCase):
    CODES = ('pid-max', 'nr-open-form', 'nr-open-range')
    V13_SOURCE = "da0ded0fb32e1d47feedebcda5d065ef008cd166c86ec82046667f3831b11835"

    def test_new_three_fixed_transcripts_have_exact_sizes_and_keep_outer_status(self):
        fixture = GuestInfoStderrPatternControls()
        for code, frame_size, whole_size in zip(self.CODES, (37, 42, 43), (62, 67, 68)):
            with self.subTest(code=code):
                raw = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
                self.assertEqual((len(raw)-25, len(raw)), (frame_size, whole_size))
                self.assertEqual(fixture.EXPECTED[code], (whole_size, hashlib.sha256(raw).hexdigest()))
                command = fixture.command(code, status=1)
                self.assertEqual(vm.guest_info_stderr_pattern(command, fixture.SOURCE),
                    fixture.expected('prerequisite-code-bytes', code))
                self.assertEqual(command['outcome']['returncode'], 1)
                self.assertLessEqual(frame_size, 44)
                self.assertLessEqual(whole_size, 69)

    def test_new_patterns_refuse_stale_source_nonempty_stdout_partial_and_changed_whole_bytes(self):
        fixture = GuestInfoStderrPatternControls()
        for code in self.CODES:
            with self.subTest(code=code):
                command = fixture.command(code, status=1)
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.V13_SOURCE),
                    fixture.expected('not-established', source=self.V13_SOURCE))
                with self.assertRaises(vm.Refusal):
                    vm.validated_guest_info_stderr_pattern(fixture.expected('prerequisite-code-bytes', code, self.V13_SOURCE))
                for stream in ('stdout', 'stderr'):
                    changed = deepcopy(command); changed['outcome'][stream]['eof'] = False
                    changed['outcome']['classification'] = 'incomplete'
                    self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('not-established'))
                changed = deepcopy(command)
                changed['outcome']['stdout'].update(charged_bytes=3, charged_sha256=CommandOutcomeControls.ABC)
                self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('unrecognized'))
                for mutation in ({'charged_bytes': 61}, {'charged_sha256': 'a'*64}):
                    changed = deepcopy(command); changed['outcome']['stderr'].update(mutation)
                    self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('unrecognized'))
                raw = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
                old = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pid-limits\n'
                for malformed in (raw+raw, raw+old, raw[:-1], b'private-prefix'+raw, raw+b'private-tail',
                                  raw.replace(code.encode(), code.encode()+b'x')):
                    result = vm.guest_info_stderr_pattern(fixture.command(raw=malformed, status=1), fixture.SOURCE)
                    self.assertEqual(result, fixture.expected('unrecognized'))
                    self.assertNotIn(b'private', vm.encode(result))


class FinePackagePatternControls(unittest.TestCase):
    CODES = ('pkg-jq-ver', 'pkg-sd-ver', 'pkg-sd-query', 'pkg-kernel', 'rpm-shape', 'rpm-bash', 'rpm-jq',
             'rpm-coreutils', 'rpm-systemd', 'rpm-podman', 'rpm-skopeo', 'rpm-crun', 'rpm-conmon',
             'rpm-netavark', 'rpm-aardvark', 'rpm-util-linux', 'rpm-libcap')

    def setUp(self):
        vm.CANCELLED = 0
        self.fixture = GuestInfoStderrPatternControls()

    def test_all_fine_patterns_remain_literal_bytes_with_source_status_and_closed_code_checks(self):
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        self.assertEqual(set(vm.PREREQUISITE_STDERR_PATTERNS.values()), set(self.fixture.EXPECTED))
        for code in self.CODES:
            with self.subTest(code=code):
                raw = ('rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code+'\n').encode('ascii')
                pair = self.fixture.EXPECTED[code]
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), pair)
                command = self.fixture.command(code)
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.fixture.SOURCE),
                                 self.fixture.expected('prerequisite-code-bytes', code))
                self.assertEqual(command['outcome']['returncode'], 255)
                self.assertEqual(vm.guest_info_stderr_pattern(command, 'a'*64),
                                 self.fixture.expected('not-established', source='a'*64))
                self.assertEqual(vm.guest_info_stderr_pattern(self.fixture.command(raw=raw+b'extra'), self.fixture.SOURCE),
                                 self.fixture.expected('unrecognized'))
        with self.assertRaises(vm.Refusal):
            vm.validated_guest_info_stderr_pattern(self.fixture.expected('prerequisite-code-bytes', 'rpm-unknown-private'))

    def test_chunked_fine_frame_requires_genuine_eof_and_observed_status_without_more_budget(self):
        raw = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:rpm-util-linux\n'
        for ending in ('eof', 'missing-eof', 'extra'):
            with self.subTest(ending=ending):
                process, selector = Mock(), Mock()
                process.returncode = 1
                process.poll.return_value = 1
                stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
                stderr = SimpleNamespace(fd=12, fileobj=process.stderr)
                chunks = [raw[:5], raw[5:25], raw[25:]]
                if ending == 'extra':
                    chunks.append(b'private-extra')
                reads = [b'', *chunks, OSError('unobserved-eof') if ending == 'missing-eof' else b'']
                selector.select.side_effect = [[(stdout, None)]] + [[(stderr, None)]]*(len(reads)-1)
                outcome = vm.command_outcome()
                budget = vm.Budget(time.monotonic()+60, 10)
                before = budget.end, budget.work_end
                with patch.object(vm.subprocess, 'Popen', return_value=process), \
                     patch.object(vm.selectors, 'DefaultSelector', return_value=selector), \
                     patch.object(vm.os, 'set_blocking'), patch.object(vm.os, 'read', side_effect=reads):
                    if ending == 'missing-eof':
                        with self.assertRaisesRegex(OSError, 'unobserved-eof'):
                            vm.run(['/reviewed/ssh'], budget, '/private', outcome_capture=outcome)
                    else:
                        self.assertEqual(vm.run(['/reviewed/ssh'], budget, '/private', outcome_capture=outcome), (1, b''))
                command = {'phase': 'guest-info', 'process': identity(555), 'outcome': outcome}
                classification = 'not-established' if ending == 'missing-eof' else 'unrecognized' if ending == 'extra' else 'prerequisite-code-bytes'
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.fixture.SOURCE),
                    self.fixture.expected(classification, 'rpm-util-linux' if ending == 'eof' else None))
                self.assertEqual((budget.end, budget.work_end), before)
                self.assertEqual(budget.commands_left, 127)
                self.assertEqual(budget.output_left, 2097152-len(raw)-(13 if ending == 'extra' else 0))
                self.assertNotIn(b'private-extra', vm.encode(outcome))

    def test_actual_parent_keeps_fine_code_during_worker_failure_and_quarantine(self):
        for retirement_error in (None, 'outside-retirement-unproved'):
            with self.subTest(retirement_error=retirement_error):
                outcome = self.fixture.command('pkg-jq-ver', status=1)['outcome']
                parent = GuestInfoParentOutcomeControls()
                parent.setUp()
                with patch.object(CommandOutcomeControls, 'expected', return_value=outcome):
                    result, status, private, _valid = parent.parent_case('valid',
                        worker_error='authenticated-guest-check-failed', retirement_error=retirement_error)
                self.assertEqual(status, 1, result)
                self.assertEqual(private['guest_info_stderr_pattern'],
                    self.fixture.expected('prerequisite-code-bytes', 'pkg-jq-ver'))
                self.assertEqual(private['guest_info_command']['outcome']['returncode'], 1)
                self.assertEqual(private['error'], 'authenticated-guest-check-failed')
                self.assertEqual(private['retirement_error'], retirement_error)



class SystemdQueryPatternControls(unittest.TestCase):
    RAW = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-query\n'
    SHA = '808363753ca8c105b3849cb4545f9a333b54dc9d008f6184b08d34bd13cc45ac'

    def test_new_exact_literal_pattern_requires_complete_empty_stdout_and_enrolled_source(self):
        fixture = GuestInfoStderrPatternControls()
        self.assertEqual(len(self.RAW), 67)
        self.assertEqual(len(self.RAW)-25, 42)
        self.assertEqual(hashlib.sha256(self.RAW).hexdigest(), self.SHA)
        expected = fixture.expected('prerequisite-code-bytes', 'pkg-sd-query')
        command = fixture.command('pkg-sd-query', status=1)
        self.assertEqual(vm.guest_info_stderr_pattern(command, fixture.SOURCE), expected)
        self.assertEqual(command['outcome']['stderr']['charged_sha256'], self.SHA)
        for changes in ({'charged_bytes': 66}, {'charged_sha256': 'a'*64}):
            changed = deepcopy(command)
            changed['outcome']['stderr'].update(changes)
            self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('unrecognized'))
        changed = deepcopy(command)
        changed['outcome']['stdout'].update(charged_bytes=3, charged_sha256=CommandOutcomeControls.ABC)
        self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('unrecognized'))
        for stream in ('stdout', 'stderr'):
            changed = deepcopy(command)
            changed['outcome'][stream]['eof'] = False
            changed['outcome']['classification'] = 'incomplete'
            self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('not-established'))
        changed = deepcopy(command)
        changed['outcome'].update(returncode=None, classification='incomplete')
        self.assertEqual(vm.guest_info_stderr_pattern(changed, fixture.SOURCE), fixture.expected('not-established'))
        self.assertEqual(vm.guest_info_stderr_pattern(command, 'a'*64), fixture.expected('not-established', source='a'*64))
        for raw in (self.RAW[:-1], self.RAW+b'private-extra'):
            self.assertEqual(vm.guest_info_stderr_pattern(fixture.command(raw=raw), fixture.SOURCE), fixture.expected('unrecognized'))
        self.assertNotIn(self.RAW, vm.encode(expected))

    def test_chunked_existing_command_capture_preserves_status_budget_and_real_eof_requirement(self):
        fixture = GuestInfoStderrPatternControls()
        for complete in (True, False):
            with self.subTest(complete=complete):
                process, selector = Mock(), Mock()
                process.returncode = 1
                process.poll.return_value = 1
                stdout = SimpleNamespace(fd=11, fileobj=process.stdout)
                stderr = SimpleNamespace(fd=12, fileobj=process.stderr)
                selector.select.side_effect = [[(stdout, None)]]+[[((stderr), None)]]*4
                reads = [b'', self.RAW[:25], self.RAW[25:40], self.RAW[40:], b'' if complete else OSError('no-real-eof')]
                outcome = vm.command_outcome()
                budget = vm.Budget(time.monotonic()+60, 10)
                initial = budget.end, budget.work_end
                with patch.object(vm.subprocess, 'Popen', return_value=process), \
                     patch.object(vm.selectors, 'DefaultSelector', return_value=selector), \
                     patch.object(vm.os, 'set_blocking'), patch.object(vm.os, 'read', side_effect=reads):
                    if complete:
                        self.assertEqual(vm.run(['/reviewed/ssh'], budget, '/private', outcome_capture=outcome), (1, b''))
                    else:
                        with self.assertRaisesRegex(OSError, 'no-real-eof'):
                            vm.run(['/reviewed/ssh'], budget, '/private', outcome_capture=outcome)
                self.assertEqual(outcome['returncode'], 1)
                self.assertEqual(outcome['stderr'], {'charged_bytes': 67, 'charged_sha256': self.SHA, 'eof': complete})
                command = {'phase': 'guest-info', 'process': identity(555), 'outcome': outcome}
                self.assertEqual(vm.guest_info_stderr_pattern(command, fixture.SOURCE),
                    fixture.expected('prerequisite-code-bytes', 'pkg-sd-query') if complete else fixture.expected('not-established'))
                self.assertEqual((budget.end, budget.work_end), initial)
                self.assertEqual(budget.commands_left, 127)
                self.assertEqual(budget.output_left, 2097152-67)

    def test_parent_retains_new_literal_pattern_on_failure_and_quarantine_without_reclassifying_status(self):
        fixture = GuestInfoStderrPatternControls()
        for retirement_error in (None, 'outside-retirement-unproved'):
            with self.subTest(retirement_error=retirement_error):
                parent = GuestInfoParentOutcomeControls()
                parent.setUp()
                with patch.object(CommandOutcomeControls, 'expected', return_value=fixture.command('pkg-sd-query', status=1)['outcome']):
                    result, status, private, _valid = parent.parent_case('valid',
                        worker_error='authenticated-guest-check-failed', retirement_error=retirement_error)
                self.assertEqual(status, 1, result)
                self.assertEqual(private['guest_info_command']['outcome']['returncode'], 1)
                self.assertEqual(private['guest_info_stderr_pattern'], fixture.expected('prerequisite-code-bytes', 'pkg-sd-query'))
                self.assertEqual(private['error'], 'authenticated-guest-check-failed')
                self.assertEqual(private['retirement_error'], retirement_error)
                self.assertEqual(private['runtime_conformance'], 'not-established')



class SystemdNumericStatusPatternControls(unittest.TestCase):
    def test_all255_status_patterns_are_closed_unique_and_bound_to_exact_source(self):
        fixture = GuestInfoStderrPatternControls()
        seen = set()
        for status in range(1, 256):
            with self.subTest(status=status):
                code = 'pkg-sd-q'+str(status)
                raw = ('rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code+'\n').encode('ascii')
                pair = len(raw), hashlib.sha256(raw).hexdigest()
                self.assertNotIn(pair, seen)
                seen.add(pair)
                self.assertEqual(fixture.EXPECTED[code], pair)
                command = fixture.command(code, status=1)
                result = vm.guest_info_stderr_pattern(command, fixture.SOURCE)
                self.assertEqual(result, fixture.expected('prerequisite-code-bytes', code))
                self.assertEqual(command['outcome']['returncode'], 1)
                self.assertEqual(set(result), {'schema', 'source_sha256', 'classification', 'code'})
                self.assertLessEqual(len(raw), 66)
        self.assertEqual(len(seen), 255)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        self.assertEqual(len(set(vm.PREREQUISITE_STDERR_PATTERNS.values())), 314)
        for suffix in ('0', '01', '+1', '-1', '256', '1 ', '١', '1x'):
            code = 'pkg-sd-q'+suffix
            with self.assertRaises(vm.Refusal):
                vm.validated_guest_info_stderr_pattern(fixture.expected('prerequisite-code-bytes', code))
            raw = ('rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code+'\n').encode('utf-8')
            self.assertEqual(vm.guest_info_stderr_pattern(fixture.command(raw=raw), fixture.SOURCE), fixture.expected('unrecognized'))

    def test_duplicate_mixed_nested_truncated_embedded_and_conflicting_transcripts_are_unrecognized(self):
        fixture = GuestInfoStderrPatternControls()
        raw = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q255\n'
        other = b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q1\n'
        for transcript in (raw+raw, raw+other, raw[:-1], b'private-prefix'+raw, raw+b'private-tail',
                           b'rootful-receiver-refused\n'+raw, raw.replace(b'q255', b'q0255')):
            with self.subTest(transcript=transcript):
                result = vm.guest_info_stderr_pattern(fixture.command(raw=transcript, status=1), fixture.SOURCE)
                self.assertEqual(result, fixture.expected('unrecognized'))
                self.assertNotIn(b'private', vm.encode(result))
        command = fixture.command('pkg-sd-q255', status=1)
        for change in ({'charged_bytes': 65}, {'charged_sha256': 'a'*64}):
            modified = deepcopy(command)
            modified['outcome']['stderr'].update(change)
            self.assertEqual(vm.guest_info_stderr_pattern(modified, fixture.SOURCE), fixture.expected('unrecognized'))
        modified = deepcopy(command)
        modified['outcome']['stdout'].update(charged_bytes=3, charged_sha256=CommandOutcomeControls.ABC)
        self.assertEqual(vm.guest_info_stderr_pattern(modified, fixture.SOURCE), fixture.expected('unrecognized'))
        for stream in ('stdout', 'stderr'):
            modified = deepcopy(command)
            modified['outcome'][stream]['eof'] = False
            modified['outcome']['classification'] = 'incomplete'
            self.assertEqual(vm.guest_info_stderr_pattern(modified, fixture.SOURCE), fixture.expected('not-established'))
        self.assertEqual(vm.guest_info_stderr_pattern(command, 'a'*64), fixture.expected('not-established', source='a'*64))

    def test_encoded255_does_not_rewrite_observed_ssh1_or_claim_a_systemd_status(self):
        fixture = GuestInfoStderrPatternControls()
        for retirement_error in (None, 'outside-retirement-unproved'):
            with self.subTest(retirement_error=retirement_error):
                parent = GuestInfoParentOutcomeControls()
                parent.setUp()
                with patch.object(CommandOutcomeControls, 'expected', return_value=fixture.command('pkg-sd-q255', status=1)['outcome']):
                    result, status, private, _valid = parent.parent_case('valid',
                        worker_error='authenticated-guest-check-failed', retirement_error=retirement_error)
                self.assertEqual(status, 1, result)
                self.assertEqual(private['guest_info_command']['outcome']['returncode'], 1)
                self.assertEqual(private['guest_info_stderr_pattern'], fixture.expected('prerequisite-code-bytes', 'pkg-sd-q255'))
                self.assertNotIn('systemd_status', private['guest_info_stderr_pattern'])
                self.assertEqual(private['retirement_error'], retirement_error)
                self.assertEqual(private['runtime_conformance'], 'not-established')


class InventoryPatternControls(unittest.TestCase):
    CODES=('inv-pid-range','inv-proc-task','inv-proc-read','inv-proc-pid','inv-proc-form',
           'inv-task-empty','inv-tid-count','inv-task-read','inv-task-tid','inv-task-form',
           'inv-nf-form','inv-nf-range','inv-fd-access','inv-fd-form','inv-fd-range',
           'inv-snap-size','inv-empty','inv-drift')
    V15_SOURCE='913c6b053c11d80e067b6dd4591cd81073d158a19e2a5cdc5eb7372b86565439'

    def test_actual_closed_emitter_and_controller_agree_on_all18_without_acquisition(self):
        from test_owned_guest_rootful import BashProtocolControls,INVENTORY_CODES
        self.assertEqual(self.CODES,INVENTORY_CODES)
        fixture=GuestInfoStderrPatternControls()
        for code in self.CODES:
            with self.subTest(code=code):
                control=BashProtocolControls();control.setUp();self.addCleanup(control.doCleanups)
                result=control.child(control.initial_selection()+'\nprivate_value=never-expose-this\nfail '+code+'\n').finish()
                self.assertEqual((result.returncode,result.stdout),(1,b''))
                raw=b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
                self.assertEqual(result.stderr,raw)
                self.assertLessEqual(len(raw)-25,44);self.assertLessEqual(len(raw),69)
                command=fixture.command(code,raw=result.stderr,status=result.returncode)
                with patch.object(vm,'read',side_effect=AssertionError('no raw read')), \
                     patch.object(vm.subprocess,'Popen',side_effect=AssertionError('no acquisition')):
                    matched=vm.guest_info_stderr_pattern(command,fixture.SOURCE)
                self.assertEqual(matched,fixture.expected('prerequisite-code-bytes',code))
                self.assertNotIn(b'never-expose-this',vm.encode(matched))

    def test_all314_patterns_reject_stale_v15_source_and_legacy_inventory_is_retained(self):
        fixture=GuestInfoStderrPatternControls()
        self.assertEqual(len(fixture.EXPECTED),314)
        for code in fixture.EXPECTED:
            command=fixture.command(code,status=1)
            self.assertEqual(vm.guest_info_stderr_pattern(command,self.V15_SOURCE),fixture.expected('not-established',source=self.V15_SOURCE))
            with self.assertRaises(vm.Refusal):
                vm.validated_guest_info_stderr_pattern(fixture.expected(
                    'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes',code,self.V15_SOURCE))
        self.assertEqual(vm.guest_info_stderr_pattern(fixture.command('inventory',status=1),fixture.SOURCE),
            fixture.expected('prerequisite-code-bytes','inventory'))

    def test_each_new_pattern_requires_whole_stream_exact_hash_count_empty_stdout_and_eof(self):
        fixture=GuestInfoStderrPatternControls()
        for code in self.CODES:
            raw=b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
            for malformed in (raw[:-1],raw+b'x',raw+raw,raw.replace(b'\n',b'\r\n'),
                              b'prefix'+raw,raw+b'protected-private-suffix',raw[:-1]+b'\x00\n'):
                self.assertEqual(vm.guest_info_stderr_pattern(fixture.command(code,raw=malformed,status=1),fixture.SOURCE),fixture.expected('unrecognized'))
            for stream,change in (('stderr',{'charged_bytes':len(raw)-1}),
                                  ('stderr',{'charged_sha256':'0'*64}),
                                  ('stdout',{'charged_bytes':3,'charged_sha256':CommandOutcomeControls.ABC})):
                command=fixture.command(code,status=1);command['outcome'][stream].update(change)
                self.assertEqual(vm.guest_info_stderr_pattern(command,fixture.SOURCE),fixture.expected('unrecognized'))
            for stream in ('stdout','stderr'):
                command=fixture.command(code,status=1);command['outcome'][stream]['eof']=False
                command['outcome']['classification']='incomplete'
                self.assertEqual(vm.guest_info_stderr_pattern(command,fixture.SOURCE),fixture.expected('not-established'))
            command=fixture.command(code,status=1);command['outcome'].update(classification='incomplete',returncode=None)
            self.assertEqual(vm.guest_info_stderr_pattern(command,fixture.SOURCE),fixture.expected('not-established'))

    def test_byte_pattern_never_relabels_the_independently_observed_status_or_claims_cause(self):
        fixture=GuestInfoStderrPatternControls()
        for code in self.CODES:
            for status in (0,1,255,-9):
                command=fixture.command(code,status=status);before=deepcopy(command)
                matched=vm.guest_info_stderr_pattern(command,fixture.SOURCE)
                self.assertEqual(matched,fixture.expected('prerequisite-code-bytes',code))
                self.assertEqual(command,before)
                self.assertEqual(set(matched),{'schema','source_sha256','classification','code'})


class HardNofileV2EnrollmentControls(unittest.TestCase):
    V16_SOURCE = 'd5d77a0298248e1de780e20f334fff42a4bf639358d605f61959bbf0f196a343'

    def test_controller_only_change_is_new_receiver_enrollment_and_all314_patterns_remain(self):
        source = before_boot_settling(before_host_view_diagnostics(_historical_diagnostic_source()))
        self.assertEqual(source.count(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256), 1)
        normalized = source.replace(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256, self.V16_SOURCE)
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(),
                         '3130e50fe0ff1d1f6588038b8243d5ed74852598bf1f6fd21dafca04ff1b3187')
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        self.assertEqual(len(set(vm.PREREQUISITE_STDERR_PATTERNS.values())), 314)
        receiver = Path(vm.__file__).with_name('owned_guest_rootful.sh').read_bytes()
        self.assertEqual(hashlib.sha256(receiver).hexdigest(), vm.PREREQUISITE_RECEIVER_SHA256)

    def test_failed_v16_source_cannot_authenticate_any_v17_pattern_or_replay_evidence(self):
        fixture = GuestInfoStderrPatternControls()
        self.assertNotEqual(fixture.SOURCE, self.V16_SOURCE)
        for code in fixture.EXPECTED:
            with self.subTest(code=code):
                command = fixture.command(code, status=1)
                with patch.object(vm, 'read', side_effect=AssertionError('no acquisition')), \
                     patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no process')):
                    matched = vm.guest_info_stderr_pattern(command, self.V16_SOURCE)
                self.assertEqual(matched, fixture.expected('not-established', source=self.V16_SOURCE))
                with self.assertRaises(vm.Refusal):
                    vm.validated_guest_info_stderr_pattern(fixture.expected(
                        'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes', code, self.V16_SOURCE))


class PrivatePrefixReceiverEnrollmentControls(unittest.TestCase):
    V18_SOURCE = '9120732254d5e5f3ba41b342d7a785daef74f69d30a68efe6c726d03d4c33f04'
    HISTORICAL_SOURCE = '744d3673eb1a44419e91e9c34614b8225c71b05937c7b1476add1e2a4931444f'
    CURRENT_SOURCE = '145ea71ea21376b2f0385320a7799259ebd0c99168c9eec03d1c9144733872f1'
    PRE_PACING_V3_SOURCE = 'e744849dab1741da10fdb70f4d420da2f94f33450dc4626a90a27dfc06da3b5b'
    V20_CONTROLLER_SHA256 = '9a231fceccd46b90131518083d5651f0061878fe5538e40919d3d67b14deec13'

    def test_all314_current_literals_match_and_stale_v18_never_authenticates(self):
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, self.CURRENT_SOURCE)
        fixture = GuestInfoStderrPatternControls()
        self.assertEqual(fixture.SOURCE, self.CURRENT_SOURCE)
        self.assertEqual(len(fixture.EXPECTED), 314)
        self.assertEqual(vm.PREREQUISITE_STDERR_PATTERNS,
                         {tuple(record): code for code, record in fixture.EXPECTED.items()})
        with patch.object(vm, 'read', side_effect=AssertionError('no raw acquisition')), \
             patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no native acquisition')):
            for code in fixture.EXPECTED:
                command = fixture.command(code, status=1)
                classification = 'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes'
                self.assertEqual(vm.guest_info_stderr_pattern(command, fixture.SOURCE),
                                 fixture.expected(classification, code))
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.V18_SOURCE),
                                 fixture.expected('not-established', source=self.V18_SOURCE))
                with self.assertRaises(vm.Refusal):
                    vm.validated_guest_info_stderr_pattern(fixture.expected(classification, code, self.V18_SOURCE))

    def test_pre_pacing_v3_source_stays_refused_and_exact_inverse_preserves_history(self):
        from test_owned_guest_rootful import receiver_before_capture_size, receiver_before_node_wait, receiver_before_ready_reason, receiver_before_i_atoms, receiver_before_k_stage, receiver_before_poll_pacing
        receiver = Path(vm.__file__).with_name('owned_guest_rootful.sh').read_bytes()
        self.assertEqual(hashlib.sha256(receiver).hexdigest(), self.CURRENT_SOURCE)
        # Current receiver and historical diagnostic-only v3 are explicit domains.
        # Project the exact outer pacing delta before any earlier historical seam.
        historical_v3 = receiver_before_poll_pacing(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(receiver.decode('utf-8')))))))
        self.assertEqual((len(historical_v3.encode()), hashlib.sha256(historical_v3.encode()).hexdigest()),
                         (65431, self.PRE_PACING_V3_SOURCE))
        self.assertNotEqual(self.PRE_PACING_V3_SOURCE, self.CURRENT_SOURCE)
        fixture = GuestInfoStderrPatternControls()
        with patch.object(vm, 'read', side_effect=AssertionError('no raw acquisition')), \
             patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no native acquisition')):
            for code in fixture.EXPECTED:
                with self.subTest(code=code):
                    command = fixture.command(code, status=1)
                    self.assertEqual(vm.guest_info_stderr_pattern(command, self.PRE_PACING_V3_SOURCE),
                                     fixture.expected('not-established', source=self.PRE_PACING_V3_SOURCE))
                    classification = 'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes'
                    with self.assertRaises(vm.Refusal):
                        vm.validated_guest_info_stderr_pattern(fixture.expected(
                            classification, code, self.PRE_PACING_V3_SOURCE))

    def test_only_current_enrollment_changes_and_pattern_or_guard_mutation_fails_identity(self):
        source = before_boot_settling(before_host_view_diagnostics(_historical_diagnostic_source()))
        self.assertEqual(source.count(self.HISTORICAL_SOURCE), 1)
        normalized = source.replace(self.HISTORICAL_SOURCE, self.V18_SOURCE)
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(), self.V20_CONTROLLER_SHA256)
        receiver = Path(vm.__file__).with_name('owned_guest_rootful.sh').read_bytes()
        self.assertEqual(hashlib.sha256(receiver).hexdigest(), self.CURRENT_SOURCE)
        changes = [('source != PREREQUISITE_RECEIVER_SHA256', 'False'),
                   ('classification == "not-established" or source == PREREQUISITE_RECEIVER_SHA256', 'True'),
                   ('"rpm-util-linux"', '"rpm-util-unknown"')]
        for old, new in changes:
            self.assertIn(old, source)
            modified = source.replace(old, new, 1).replace(self.HISTORICAL_SOURCE, self.V18_SOURCE)
            self.assertNotEqual(hashlib.sha256(modified.encode()).hexdigest(), self.V20_CONTROLLER_SHA256)


class NodeMonochromeEnrollmentControls(unittest.TestCase):
    V22_SOURCE = 'b323efa06dbafdd4958ac593c9fe7081e97535e87963f8508149b2ab2d8b9647'
    V22_CONTROLLER = 'a5fd5ffd2fd14b9d3e662dd45f43e71b2717e462527d49efe9587ebc87bf8aa6'

    def test_only_derived_receiver_enrollment_changes_not_any_historical_pattern(self):
        source = before_host_view_diagnostics(_historical_diagnostic_source())
        self.assertEqual(source.count(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256), 1)
        normalized = source.replace(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256, self.V22_SOURCE)
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(), self.V22_CONTROLLER)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        self.assertEqual(hashlib.sha256(Path(vm.__file__).with_name('owned_guest_rootful.sh').read_bytes()).hexdigest(),
                         vm.PREREQUISITE_RECEIVER_SHA256)

    def test_consumed_v22_source_is_not_reenrolled_by_unchanged_diagnostic_bytes(self):
        fixture = GuestInfoStderrPatternControls()
        self.assertNotEqual(fixture.SOURCE, self.V22_SOURCE)
        with patch.object(vm, 'read', side_effect=AssertionError('no acquisition')), \
             patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no native process')):
            for code in fixture.EXPECTED:
                command = fixture.command(code, status=1)
                self.assertEqual(vm.guest_info_stderr_pattern(command, self.V22_SOURCE),
                                 fixture.expected('not-established', source=self.V22_SOURCE))


class RootfulBootSettlingControls(unittest.TestCase):
    def setUp(self):
        vm.CANCELLED = 0

    def tearDown(self):
        vm.CANCELLED = 0

    def exercise(self, *, output=1024 * 1024, select_action=None, read=b"boot\n", exited=None,
                 end=180.0):
        clock = [100.0]
        qemu, selector = Mock(), Mock()
        qemu.poll.return_value = exited
        keys = [SimpleNamespace(fd=11), SimpleNamespace(fd=12)]
        budget = vm.Budget(end, 10, output=output, commands=17)

        def selected(wait):
            clock[0] += wait
            if select_action:
                return select_action(clock)
            return [(key, None) for key in keys]

        selector.select.side_effect = selected
        with patch.object(vm.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(vm.os, "read", return_value=read) as reading, \
             patch.object(vm.subprocess, "Popen", side_effect=AssertionError("no child")), \
             patch.object(vm, "run", side_effect=AssertionError("no command")):
            try:
                vm.settle_guest_check(qemu, selector, budget)
            except (vm.Refusal, OSError) as error:
                return error, clock[0], budget, selector, reading
        return None, clock[0], budget, selector, reading

    def test_one_fixed_interval_drains_and_charges_both_streams_without_commands(self):
        error, now, budget, selector, reading = self.exercise()
        self.assertIsNone(error)
        self.assertAlmostEqual(now, 130.0)
        self.assertGreater(selector.select.call_count, 0)
        self.assertLessEqual(selector.select.call_count, 301)
        self.assertEqual(reading.call_count, selector.select.call_count * 2)
        self.assertEqual({call.args for call in reading.call_args_list}, {(11, 65536), (12, 65536)})
        self.assertEqual(budget.output_left, 1024 * 1024 - 5 * reading.call_count)
        self.assertEqual((budget.end, budget.work_end, budget.commands_left), (180.0, 170.0, 17))

    def test_repeated_boot_markers_never_extend_the_fixed_interval(self):
        error, now, _budget, _selector, _reading = self.exercise(read=b"Startup finished in\n")
        self.assertIsNone(error)
        self.assertAlmostEqual(now, 130.0)

    def test_insufficient_original_work_time_refuses_without_drain_or_deadline_change(self):
        error, now, budget, selector, reading = self.exercise(end=140.0)
        self.assertEqual(str(error), "guest-settle-original-deadline")
        self.assertEqual((now, budget.end, budget.work_end), (100.0, 140.0, 130.0))
        selector.select.assert_not_called()
        reading.assert_not_called()

    def test_cancellation_and_original_deadline_expiry_stop_the_interval(self):
        def cancel(_clock):
            vm.CANCELLED = 1
            return []

        def expire(clock):
            clock[0] = 170.0
            return []

        for action, expected in ((cancel, "cancelled"), (expire, "original-deadline-expired")):
            vm.CANCELLED = 0
            error, _now, budget, selector, _reading = self.exercise(select_action=action)
            self.assertEqual(str(error), expected)
            self.assertEqual(selector.select.call_count, 1)
            self.assertEqual((budget.end, budget.work_end), (180.0, 170.0))

    def test_qemu_exit_eof_and_output_exhaustion_prevent_a_successful_interval(self):
        cases = [({"exited": 0}, "qemu-exited-before-guest-check"),
                 ({"read": b""}, "qemu-console-closed"), ({"output": 0}, "output-budget")]
        for kwargs, expected in cases:
            with self.subTest(expected=expected):
                error, _now, _budget, _selector, _reading = self.exercise(**kwargs)
                self.assertEqual(str(error), expected)

    def test_worker_settles_once_before_its_only_authenticated_check(self):
        result, stopped, captures, mocks = GuestInfoWorkerOutcomeControls().worker_case(255, b"")
        self.assertEqual(result, 1)
        self.assertEqual(stopped["error"], "authenticated-guest-check-failed")
        mocks["settle_guest_check"].assert_called_once()
        self.assertEqual(len(captures), 1)
        self.assertEqual(mocks["run"].call_count, 3)
        self.assertEqual(mocks["reap"].call_count, 2)

    def test_settle_failure_never_starts_guest_check_and_still_reaps_qemu(self):
        result, stopped, captures, mocks = GuestInfoWorkerOutcomeControls().worker_case(
            0, b"", settle_error="guest-settle-original-deadline")
        self.assertEqual(result, 1)
        self.assertEqual(stopped["error"], "guest-settle-original-deadline")
        self.assertEqual(captures, [])
        self.assertEqual(stopped["producers"], [])
        self.assertEqual(mocks["run"].call_count, 2)
        mocks["settle_guest_check"].assert_called_once()
        mocks["reap"].assert_called_once()

    def test_exact_source_inverse_rejects_helper_or_call_mutation(self):
        source = Path(vm.__file__).read_text()
        for mutated in (source.replace("+ 30\n", "+ 31\n", 1),
                        source.replace("            settle_guest_check(qemu, selector, budget)\n", "", 1)):
            with self.assertRaises(AssertionError):
                before_boot_settling(mutated)

    def test_worker_sends_validated_local_diagnostic_after_bare_barrier_only_with_credit_profile(self):
        authority = {"identity": [1, 2, 3, 4, 5], "type": 32768, "mode": 0o755,
                     "uid": 0, "gid": 0, "sha256": "a" * 64}
        observed = {**authority, "identity": [1, 99, 3, 4, 5], "uid": 65534, "gid": 65534}
        with self.assertRaises(vm.Refusal) as raised:
            host_view.compare_object(authority, observed, uid_map=[[1000, 1000, 1]],
                gid_map=[[1000, 1000, 1]], overflow_uid=65534, overflow_gid=65534,
                site="worker-local", object_name="tool-qemu")
        detail = raised.exception.host_view_mismatch
        self.assertEqual(str(raised.exception), "host-view-object-not-equivalent")
        self.assertEqual(raised.exception.args, ("host-view-object-not-equivalent",))
        self.assertEqual(detail, {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local",
            "object": "tool-qemu", "differences": [{"field": "identity", "member": "ino",
            "expected": 2, "observed": 99}]})
        fixture = WorkerControls()
        fixture.setUp()
        _baseline_result, baseline = fixture._worker_ssh_case(0, b"", guard_error_at=1, reap_error=True)
        baseline_budget = fixture.last_worker_budget
        result, stopped = fixture._worker_ssh_case(0, b"", guard_error_at=1, view_mismatch=detail,
            reap_error=True, diagnostic_profile=True)
        self.assertEqual(fixture.last_worker_budget, baseline_budget)
        self.assertEqual(baseline["error"], "host-view-local-drift")
        self.assertEqual(result, 1)
        self.assertEqual(stopped["error"], "host-view-object-not-equivalent")
        self.assertNotIn("host_view_mismatch", stopped)
        self.assertEqual(vm.strict_json(fixture.last_optional_frame[4:]), detail)
        self.assertLessEqual(len(fixture.last_optional_frame), vm.DIAGNOSTIC_FRAME_BYTES)
        self.assertEqual(fixture.last_send_events[-2:], [("mandatory", "producer-stopped"),
                         ("optional", fixture.last_optional_frame)])
        self.assertIsNone(stopped["qemu"])
        self.assertEqual(host_view.object_alias("/usr/bin/qemu", config()["tools"]), "tool-qemu")
        cap_expected = {**authority, "capabilities_sha256": "b" * 64}
        cap_observed = {**authority, "capabilities_sha256": "c" * 64}
        with self.assertRaises(vm.Refusal) as cap_error:
            host_view.compare_object(cap_expected, cap_observed, site="worker-local", object_name="tool-qemu")
        self.assertEqual(cap_error.exception.args, ("host-view-object-not-equivalent",))
        self.assertFalse(hasattr(cap_error.exception, "host_view_mismatch"))


class DiagnosticCreditControls(unittest.TestCase):
    DETAIL = {"schema": vm.HOST_VIEW_MISMATCH_SCHEMA, "site": "worker-local", "object": "bin",
              "differences": [{"field": "identity", "member": "ino", "expected": 1, "observed": 2}]}

    def reservation(self, *, budget=None, channel=None):
        budget = budget or vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES)
        channel = channel or Mock()
        reservation = host_view.PendingDiagnosticReservation(budget, "a" * 64)
        reservation.bind_authenticated(budget, channel, identity(), "a" * 64)
        reservation.activate(budget, channel, "a" * 64)
        return budget, channel, reservation

    class ModeAwareChannel:
        def __init__(self, raw=b"", *, fail_mode=False):
            self.timeout = None
            self.blocking = True
            self.fail_mode = fail_mode
            self.incoming = bytearray(raw)
            self.timeout_calls = []
            self.mode_calls = []
            self.mandatory = []
            self.optional_sends = []
            self.optional_reads = []

        def settimeout(self, value):
            self.timeout = value
            self.timeout_calls.append(value)

        def setblocking(self, value):
            self.mode_calls.append(value)
            if self.fail_mode:
                raise OSError("synthetic-mode-change-failure")
            self.blocking = value
            if not value:
                self.timeout = None

        def sendall(self, frame):
            if self.timeout is None or self.timeout <= 0:
                raise AssertionError("mandatory framing must retain positive timeout")
            self.mandatory.append(frame)

        def send(self, frame, flags):
            if self.blocking or self.timeout is not None:
                raise AssertionError("optional send requires explicit nonblocking mode")
            self.optional_sends.append((frame, flags))
            return len(frame)

        def recv(self, maximum, flags=0):
            if flags == 0:
                if self.timeout is None or self.timeout <= 0:
                    raise AssertionError("mandatory framing must retain positive timeout")
                raw = bytes(self.incoming[:maximum])
                del self.incoming[:maximum]
                return raw
            if self.blocking or self.timeout is not None:
                raise AssertionError("optional read requires explicit nonblocking mode")
            self.optional_reads.append((maximum, flags))
            raw = bytes(self.incoming[:maximum])
            del self.incoming[:maximum]
            return raw

    def test_optional_worker_send_switches_inherited_positive_timeout_to_nonblocking_once(self):
        channel = self.ModeAwareChannel()
        budget = vm.Budget(time.monotonic() + 60, 10)
        vm.send(channel, {"stage": "producer-stopped"}, budget, cleanup=True)
        self.assertGreater(channel.timeout, 0)
        self.assertTrue(host_view.send_optional_diagnostic(channel, self.DETAIL,
                                                           vm.DIAGNOSTIC_CREDIT_PROFILE))
        self.assertEqual(channel.mode_calls, [False])
        self.assertEqual(len(channel.mandatory), 1)
        self.assertEqual(len(channel.optional_sends), 1)
        self.assertEqual(channel.optional_sends[0][1], socket.MSG_DONTWAIT)
        self.assertEqual(len(channel.timeout_calls), 1)
        self.assertGreater(channel.timeout_calls[0], 0)

    def test_worker_mode_change_failure_omits_without_optional_retry_or_mandatory_io(self):
        channel = self.ModeAwareChannel(fail_mode=True)
        budget = vm.Budget(time.monotonic() + 60, 10)
        vm.send(channel, {"stage": "producer-stopped"}, budget, cleanup=True)
        self.assertFalse(host_view.send_optional_diagnostic(channel, self.DETAIL,
                                                            vm.DIAGNOSTIC_CREDIT_PROFILE))
        self.assertEqual(channel.mode_calls, [False])
        self.assertEqual(channel.optional_sends, [])
        self.assertEqual(len(channel.mandatory), 1)

    def test_optional_controller_read_switches_timeout_to_nonblocking_and_mode_failure_is_terminal(self):
        budget = vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES + 1024)
        mandatory = vm.encode({"stage": "producer-stopped"})
        optional = struct.pack(">I", len(vm.encode(self.DETAIL))) + vm.encode(self.DETAIL)
        channel = self.ModeAwareChannel(struct.pack(">I", len(mandatory)) + mandatory + optional)
        self.assertEqual(vm.receive(channel, budget, cleanup=True), {"stage": "producer-stopped"})
        self.assertGreater(channel.timeout, 0)
        reservation = host_view.PendingDiagnosticReservation(budget, "b" * 64)
        reservation.bind_authenticated(budget, channel, identity(), "b" * 64)
        reservation.activate(budget, channel, "b" * 64)
        self.assertEqual(reservation.drain_once(budget, channel), self.DETAIL)
        self.assertEqual(channel.mode_calls, [False])
        self.assertEqual(channel.optional_reads, [(vm.DIAGNOSTIC_CREDIT_BYTES, socket.MSG_DONTWAIT)])
        self.assertEqual(reservation.observed_bytes, 4 + len(vm.encode(self.DETAIL)))

        budget = vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES + 1024)
        channel = self.ModeAwareChannel(struct.pack(">I", len(mandatory)) + mandatory + optional, fail_mode=True)
        self.assertEqual(vm.receive(channel, budget, cleanup=True), {"stage": "producer-stopped"})
        self.assertGreater(channel.timeout, 0)
        reservation = host_view.PendingDiagnosticReservation(budget, "b" * 64)
        reservation.bind_authenticated(budget, channel, identity(), "b" * 64)
        reservation.activate(budget, channel, "b" * 64)
        self.assertIsNone(reservation.drain_once(budget, channel))
        self.assertEqual(reservation.state, "omitted-absent")
        self.assertEqual(channel.mode_calls, [False])
        self.assertEqual(channel.optional_reads, [])

    def test_credit_predebits_exactly_once_and_binding_is_single_use(self):
        too_small = vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES - 1)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-unavailable"):
            host_view.PendingDiagnosticReservation(too_small, "a" * 64)
        self.assertEqual(too_small.output_left, vm.DIAGNOSTIC_CREDIT_BYTES - 1)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-already-claimed"):
            host_view.PendingDiagnosticReservation(too_small, "a" * 64)
        self.assertEqual(too_small.output_left, vm.DIAGNOSTIC_CREDIT_BYTES - 1)

        budget = vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES)
        reservation = host_view.PendingDiagnosticReservation(budget, "a" * 64)
        self.assertEqual(reservation.state, "pending")
        self.assertEqual(budget.output_left, 0)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-already-claimed"):
            host_view.PendingDiagnosticReservation(budget, "a" * 64)
        self.assertEqual(budget.output_left, 0)
        channel = Mock()
        wrong_budget = vm.Budget(time.monotonic() + 60, 10)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-channel-binding"):
            reservation.bind_authenticated(wrong_budget, channel, identity(), "a" * 64)
        self.assertEqual(reservation.state, "finalized-unbound")
        self.assertEqual(budget.output_left, 0)
        with self.assertRaises(vm.Refusal):
            reservation.bind_authenticated(budget, channel, identity(), "a" * 64)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-state"):
            reservation.activate(budget, channel, "a" * 64)
        self.assertEqual(reservation.state, "finalized-unbound")

        budget, channel, reservation = self.reservation()
        with self.assertRaises(vm.Refusal):
            reservation.bind_authenticated(budget, channel, identity(), "a" * 64)
        self.assertEqual(reservation.state, "finalized-unused")
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-state"):
            reservation.activate(budget, channel, "a" * 64)
        self.assertEqual(reservation.state, "finalized-unused")
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-drain-state"):
            reservation.drain_once(budget, Mock())
        self.assertEqual(reservation.state, "finalized-unused")
        self.assertEqual(budget.output_left, 0)

        budget = vm.Budget(time.monotonic() + 60, 10, output=vm.DIAGNOSTIC_CREDIT_BYTES)
        channel = Mock()
        reservation = host_view.PendingDiagnosticReservation(budget, "c" * 64)
        reservation.bind_authenticated(budget, channel, identity(), "c" * 64)
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-channel-binding"):
            reservation.bind_authenticated(budget, channel, identity(), "c" * 64)
        self.assertEqual(reservation.state, "finalized-unbound")
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-state"):
            reservation.activate(budget, channel, "c" * 64)
        self.assertEqual(reservation.state, "finalized-unbound")

        budget, channel, reservation = self.reservation()
        with self.assertRaisesRegex(vm.Refusal, "host-view-diagnostic-credit-state"):
            reservation.activate(budget, channel, "a" * 64)
        self.assertEqual(reservation.state, "finalized-unused")

    def test_profile_is_closed_and_legacy_config_has_no_grant(self):
        self.assertIsNone(vm.diagnostic_credit_profile({}))
        valid = {"host_view_diagnostic_profile": vm.DIAGNOSTIC_CREDIT_PROFILE,
                 "host_view_diagnostic_credit_bytes": vm.DIAGNOSTIC_CREDIT_BYTES}
        self.assertEqual(vm.diagnostic_credit_profile(valid), vm.DIAGNOSTIC_CREDIT_PROFILE)
        for value in ({"host_view_diagnostic_profile": vm.DIAGNOSTIC_CREDIT_PROFILE},
                      {**valid, "host_view_diagnostic_credit_bytes": True},
                      {**valid, "host_view_diagnostic_credit_bytes": vm.DIAGNOSTIC_FRAME_BYTES},
                      {**valid, "host_view_diagnostic_profile": "automatic"}):
            with self.subTest(value=value), self.assertRaises(vm.Refusal):
                vm.diagnostic_credit_profile(value)

    def test_attested_channel_binding_occurs_after_existing_authentication(self):
        events = []
        budget, channel = vm.Budget(time.monotonic() + 60, 10), Mock()
        reservation = host_view.PendingDiagnosticReservation(budget, "b" * 64)
        with patch.object(vm, "attest_barrier", side_effect=lambda *_: (events.append("authenticated") or
                ("b" * 32, {"path": "/target"}))):
            vm.attest_barrier_and_bind(unit(), {"stage": "barrier"}, identity(), config(), "b" * 64,
                reservation=reservation, budget=budget, channel=channel)
        self.assertEqual(events, ["authenticated"])
        self.assertEqual(reservation.state, "bound")
        self.assertIs(reservation.channel, channel)
        reservation.activate(budget, channel, "b" * 64)
        reservation.finalize()
        self.assertEqual(reservation.state, "finalized-unused")

    def test_maximum_frame_fits_and_one_trailing_sentinel_omits_without_second_read(self):
        body = vm.encode(self.DETAIL)
        body += b" " * (vm.DIAGNOSTIC_BODY_BYTES - len(body))
        self.assertEqual(len(body), vm.DIAGNOSTIC_BODY_BYTES)
        frame = struct.pack(">I", len(body)) + body
        self.assertEqual(len(frame), vm.DIAGNOSTIC_FRAME_BYTES)

        budget, channel, reservation = self.reservation()
        channel.recv.return_value = frame
        with patch.object(budget, "charge", wraps=budget.charge) as charge:
            retained = reservation.drain_once(budget, channel)
        self.assertEqual(retained, self.DETAIL)
        self.assertEqual(reservation.state, "retained")
        self.assertEqual(reservation.observed_bytes, vm.DIAGNOSTIC_FRAME_BYTES)
        self.assertEqual(budget.output_left, 0)
        charge.assert_not_called()
        channel.recv.assert_called_once_with(vm.DIAGNOSTIC_CREDIT_BYTES, socket.MSG_DONTWAIT)

        budget, channel, reservation = self.reservation()
        channel.recv.return_value = frame + b"!"
        self.assertIsNone(reservation.drain_once(budget, channel))
        self.assertEqual(reservation.state, "omitted-trailing")
        self.assertEqual(reservation.observed_bytes, vm.DIAGNOSTIC_CREDIT_BYTES)
        channel.recv.assert_called_once_with(vm.DIAGNOSTIC_CREDIT_BYTES, socket.MSG_DONTWAIT)
        self.assertEqual(budget.output_left, 0)

    def test_missing_partial_invalid_wrong_site_overcap_and_long_trailing_are_one_read_omissions(self):
        invalid = {**self.DETAIL, "extra": "private"}
        wrong_site = {**self.DETAIL, "site": "parent-attest"}
        frames = (
            (b"", "omitted-absent"),
            (b"\x00\x00", "omitted-partial"),
            (struct.pack(">I", 5) + b"{}", "omitted-partial"),
            (struct.pack(">I", len(vm.encode(invalid))) + vm.encode(invalid), "omitted-invalid"),
            (struct.pack(">I", len(vm.encode(wrong_site))) + vm.encode(wrong_site), "omitted-site"),
            (struct.pack(">I", vm.DIAGNOSTIC_BODY_BYTES + 1), "omitted-over-cap"),
        )
        for raw, state in frames:
            with self.subTest(state=state, raw_length=len(raw)):
                budget, channel, reservation = self.reservation()
                channel.recv.return_value = raw
                self.assertIsNone(reservation.drain_once(budget, channel))
                self.assertEqual(reservation.state, state)
                channel.recv.assert_called_once_with(vm.DIAGNOSTIC_CREDIT_BYTES, socket.MSG_DONTWAIT)
                self.assertEqual(budget.output_left, 0)
        budget, channel, reservation = self.reservation()
        body = vm.encode(self.DETAIL)
        raw = struct.pack(">I", len(body)) + body + b"x" * (vm.DIAGNOSTIC_CREDIT_BYTES + 10)
        channel.recv.side_effect = lambda maximum, _flags: raw[:maximum]
        self.assertIsNone(reservation.drain_once(budget, channel))
        self.assertEqual(reservation.state, "omitted-trailing")
        self.assertEqual(reservation.observed_bytes, vm.DIAGNOSTIC_CREDIT_BYTES)
        channel.recv.assert_called_once_with(vm.DIAGNOSTIC_CREDIT_BYTES, socket.MSG_DONTWAIT)
        self.assertEqual(budget.output_left, 0)



class HistoricalDiagnosticInverseControls(unittest.TestCase):
    """Durable actual-helper controls; no process, socket or clock observation."""
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        for name in ('subprocess.Popen', 'subprocess.run', 'os.fork', 'os.execv', 'os.execve',
                     'os.system', 'socket.socket', 'time.time', 'time.monotonic',
                     'time.perf_counter', 'time.sleep'):
            guards.enter_context(patch(name, side_effect=AssertionError('forbidden inverse control effect: ' + name)))

    def test_exact_actual_fold_matches_independent_target_and_keeps_raw_behavior(self):
        source = _historical_diagnostic_source()
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                         'b857fb2f20d98483466ab252c0580b9bcfab0d81d4b7c3a47d8748326d8ab682')
        view = before_host_view_diagnostics(source)
        self.assertEqual((len(view.encode()), hashlib.sha256(view.encode()).hexdigest()),
                         (131127, '4ede9ab56d7c850fc8c80f6bbdbf9b70992c532a073b46b1d3df7a655957344a'))
        self.assertEqual(source.count(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256), 1)
        self.assertEqual(view.count(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256), 1)
        self.assertEqual(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256,
                         '744d3673eb1a44419e91e9c34614b8225c71b05937c7b1476add1e2a4931444f')
        self.assertNotEqual(vm.PREREQUISITE_RECEIVER_SHA256,
                            _HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256)
        self.assertIn('def diagnostic_credit_profile(config):', source)
        self.assertNotIn('def diagnostic_credit_profile(config):', view)
        self.assertTrue(hasattr(vm, 'diagnostic_credit_profile'))
        self.assertEqual(vm.worker.__code__.co_filename, vm.__file__)

    def test_unknown_folded_and_nondiagnostic_heads_refuse_before_actual_core(self):
        source = _historical_diagnostic_source()
        folded = before_host_view_diagnostics(source)
        mutations = [folded, '# unknown head\n' + source,
            source.replace('source != PREREQUISITE_RECEIVER_SHA256', 'False', 1),
            source.replace('"rpm-util-linux"', '"rpm-util-unknown"', 1),
            source.replace('def ssh_arguments(config):', 'def ssh_arguments(config, extra=None):', 1),
            source.replace(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256, '0' * 64, 1)]
        for changed in mutations:
            self.assertNotEqual(changed, source)
            with patch(__name__ + '._apply_host_view_diagnostic_hunk',
                       side_effect=AssertionError('core forbidden for unknown head')) as core:
                with self.assertRaisesRegex(AssertionError, '^unknown actual diagnostic source$'):
                    before_host_view_diagnostics(changed)
                core.assert_not_called()

    def test_actual_core_rejects_current_and_historical_payload_digest_drift(self):
        identity, current, historical, current_sha, historical_sha = _HOST_VIEW_DIAGNOSTIC_HUNKS[0]
        rows = [(identity, current + 'changed', historical, current_sha, historical_sha),
                (identity, current, historical + 'changed', current_sha, historical_sha),
                (identity, current, historical, '0' * 64, historical_sha),
                (identity, current, historical, current_sha, '0' * 64)]
        for row in rows:
            with self.assertRaisesRegex(AssertionError, '^diagnostic hunk literal integrity: D01$'):
                _apply_host_view_diagnostic_hunk(current, *row)

    def test_actual_core_rejects_missing_and_duplicate_context(self):
        row = _HOST_VIEW_DIAGNOSTIC_HUNKS[0]
        for changed in (row[1][1:], row[1] + row[1]):
            with self.assertRaisesRegex(AssertionError, '^diagnostic hunk occurrence: D01$'):
                _apply_host_view_diagnostic_hunk(changed, *row)

    def test_actual_core_rejects_diagnostic_helper_and_call_mutation(self):
        source = _historical_diagnostic_source()
        for index, old, new in [(1, 'def validated_host_view_mismatch(value):',
                                'def validated_host_view_mismatch(other):'),
                               (12, 'diagnostic_helper.send_optional_diagnostic(channel, host_view_mismatch, diagnostic_profile)',
                                'diagnostic_helper.send_optional_diagnostic(channel, host_view_mismatch, other_profile)')]:
            self.assertIn(old, source)
            row = _HOST_VIEW_DIAGNOSTIC_HUNKS[index]
            changed = source.replace(old, new, 1)
            with self.assertRaisesRegex(AssertionError, '^diagnostic hunk occurrence: ' + row[0] + '$'):
                _apply_host_view_diagnostic_hunk(changed, *row)

    def test_actual_outer_final_target_guard_rejects_corrupted_last_core_result(self):
        source = _historical_diagnostic_source()
        actual_core = _apply_host_view_diagnostic_hunk
        corruptions = [lambda text: text + '\n# independent injected final corruption\n',
            lambda text: text.replace('source != PREREQUISITE_RECEIVER_SHA256', 'False', 1),
            lambda text: text.replace('"rpm-util-linux"', '"rpm-util-unknown"', 1),
            lambda text: text.replace(_HISTORICAL_DIAGNOSTIC_RECEIVER_SHA256, '0' * 64, 1)]
        for corrupt in corruptions:
            def last_result(text, *row):
                result = actual_core(text, *row)
                if row[0] == 'D23':
                    changed = corrupt(result)
                    self.assertNotEqual(changed, result)
                    return changed
                return result
            with patch(__name__ + '._apply_host_view_diagnostic_hunk', side_effect=last_result) as core:
                with self.assertRaisesRegex(AssertionError, '^independent historical target mismatch$'):
                    before_host_view_diagnostics(source)
                self.assertEqual(core.call_count, 23)


    def test_historical_fixture_missing_refuses_without_source_fallback(self):
        with tempfile.TemporaryDirectory(prefix="kl-diagnostic-history-missing-") as directory:
            missing = Path(directory) / "absent.source"
            actual_open = Path.open
            def only_fixture(target, *args, **kwargs):
                self.assertEqual(target, missing)
                return actual_open(target, *args, **kwargs)
            with patch.object(Path, "open", autospec=True, side_effect=only_fixture) as opened, \
                    patch.object(Path, "read_text", side_effect=AssertionError("source fallback forbidden")), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("source fallback forbidden")):
                with self.assertRaisesRegex(AssertionError, "^historical diagnostic fixture unavailable$"):
                    _historical_diagnostic_source(path=missing)
                opened.assert_called_once_with(missing, "rb")

    def test_historical_fixture_corruption_refuses_without_source_fallback(self):
        original = _historical_diagnostic_source().encode("utf-8")
        mutations = [bytes([original[0] ^ 1]) + original[1:], original[:-1],
                     original + b"!", b"\xff" + original[1:]]
        with tempfile.TemporaryDirectory(prefix="kl-diagnostic-history-corrupt-") as directory:
            changed = Path(directory) / "changed.source"
            actual_open = Path.open
            def only_fixture(target, *args, **kwargs):
                self.assertEqual(target, changed)
                return actual_open(target, *args, **kwargs)
            for data in mutations:
                changed.write_bytes(data)
                with patch.object(Path, "open", autospec=True, side_effect=only_fixture) as opened, \
                        patch.object(Path, "read_text", side_effect=AssertionError("source fallback forbidden")), \
                        patch.object(Path, "read_bytes", side_effect=AssertionError("source fallback forbidden")):
                    with self.assertRaisesRegex(AssertionError, "^historical diagnostic fixture integrity$"):
                        _historical_diagnostic_source(path=changed)
                    opened.assert_called_once_with(changed, "rb")

    def test_historical_fixture_read_has_one_fixed_plus_one_bound(self):
        original = _historical_diagnostic_source().encode("utf-8")
        source_file = MagicMock()
        source_file.__enter__.return_value = source_file
        source_file.read.return_value = original
        with patch.object(Path, "open", autospec=True, return_value=source_file) as opened:
            self.assertEqual(_historical_diagnostic_source(), original.decode("utf-8"))
            opened.assert_called_once_with(_HISTORICAL_DIAGNOSTIC_SOURCE_PATH, "rb")
        source_file.read.assert_called_once_with(140694)

    def test_actual_new_runtime_source_refuses_old_reader_before_core(self):
        current_source = Path(vm.__file__).read_text()
        self.assertNotEqual((len(current_source.encode()), hashlib.sha256(current_source.encode()).hexdigest()),
                            (140693, 'b857fb2f20d98483466ab252c0580b9bcfab0d81d4b7c3a47d8748326d8ab682'))
        with patch(__name__ + '._apply_host_view_diagnostic_hunk',
                   side_effect=AssertionError('core forbidden for current runtime source')) as core:
            with self.assertRaisesRegex(AssertionError, '^unknown actual diagnostic source$'):
                before_host_view_diagnostics(current_source)
            core.assert_not_called()


class RetirementEvidenceControls(unittest.TestCase):
    """One real observer over fixed raw DATA; no native manager/kernel queries."""
    def setUp(self):
        from types import SimpleNamespace
        self.storage = tempfile.TemporaryDirectory(prefix="kl-retirement-evidence-test-")
        self.addCleanup(self.storage.cleanup)
        self.parent = Path(self.storage.name)
        self.c = {**config(), "boot": "11111111-1111-1111-1111-111111111111",
                  "source": {str(Path(vm.__file__).resolve()): vm.digest(Path(vm.__file__).read_bytes())}}
        self.lease = self.parent / ("kubernetes-lens-vm-" + self.c["owner"])
        self.lease.mkdir(mode=0o700)
        self.c["directory"] = str(self.lease)
        self.now = 200.0
        self.stopped = False
        self.commands = []
        self.command_outputs = []
        self.manager_attempts = 0
        self.unloaded_after_stop = False
        self.hold_active = False
        self.kernel_override = None
        self.actual_run = vm.run
        self.reads = []
        self.typed_raw = empty_stop_properties()
        self.removed = False
        self.kernel_values = {
            "/proc/sys/kernel/random/boot_id": (self.c["boot"] + "\n").encode(),
        }
        self.cg = "/sys/fs/cgroup/owned/" + self.c["unit"]
        for name, value in (("cpu.max", b"100000 100000\n"), ("memory.max", str(self.c["memory_bytes"]).encode() + b"\n"),
                            ("pids.max", b"256\n"), ("memory.swap.max", b"0\n"),
                            ("cgroup.events", b"populated 0\nfrozen 0\n"), ("cgroup.procs", b"")):
            self.kernel_values[self.cg + "/" + name] = value
        self.info = SimpleNamespace(st_mode=vm.stat.S_IFDIR | 0o700, st_uid=os.getuid(), st_gid=os.getgid(),
            st_dev=7, st_ino=23, st_nlink=1, st_size=0, st_atime_ns=0, st_mtime_ns=0, st_ctime_ns=0)
        owner = self
        class Kernel:
            def read(self, path):
                owner.reads.append(("read", str(path)))
                if owner.kernel_override is not None:
                    result = owner.kernel_override(str(path))
                    if result is not NotImplemented:return result
                if str(path) not in owner.kernel_values:
                    raise FileNotFoundError(2, "fixture absent", str(path))
                return owner.kernel_values[str(path)]
            def canonical(self, path):
                owner.reads.append(("canonical", str(path)))
                if owner.removed:
                    raise FileNotFoundError(2, "fixture absent", str(path))
                return Path(path)
            def stat(self, path):
                owner.reads.append(("stat", str(path)))
                return owner.info
            def exists(self, path):
                owner.reads.append(("exists", str(path)))
                return not owner.removed
        self.kernel = Kernel()
        self.enterContext(patch.object(vm.time, "monotonic", side_effect=lambda: self.now))
        self.enterContext(patch.object(vm.time, "sleep", side_effect=self.sleep))
        self.enterContext(patch.object(vm, "run", side_effect=self.manager))
        self.enterContext(patch.object(vm.subprocess, "Popen", side_effect=AssertionError("native process forbidden")))
        self.budget = vm.Budget(self.c["end"], self.c["cleanup_seconds"])
        vm.CANCELLED = 0
        self.snapshot = {"path": self.cg, "device": 7, "inode": 23, "cpu_max": "100000 100000",
                         "memory_max": self.c["memory_bytes"], "pids_max": 256, "swap_max": 0}

    def sleep(self, seconds):
        self.assertGreaterEqual(seconds, 0)
        self.now += seconds

    def manager(self, argv, budget, directory, **kwargs):
        self.manager_attempts += 1
        self.assertTrue(kwargs["manager"])
        self.assertLessEqual(kwargs["deadline"], min(self.now + 5.0, self.c["end"]))
        budget.commands_left -= 1
        vm.require(budget.commands_left >= 0, "command-budget")
        self.commands.append(list(argv))
        if "stop" in argv:
            self.stopped = True
            raw = b""
        elif argv[0] == self.c["tools"]["busctl"]["path"]:
            raw = self.typed_raw
        else:
            row = unit()
            if self.stopped and not self.hold_active:
                row.update(ActiveState="inactive", SubState="dead", MainPID="0", InvocationID="")
                if self.unloaded_after_stop:
                    row.update(LoadState="not-found", ControlGroup="", ExecMainStartTimestampMonotonic=str(100000000 + self.manager_attempts))
            raw = simple_unit_text(row)
        self.command_outputs.append(raw)
        outcome = kwargs.get("outcome_capture")
        if outcome is not None:
            outcome.update(classification="exit", returncode=0)
            for name, value in (("stdout", raw), ("stderr", b"")):
                outcome[name].update(charged_bytes=len(value), charged_sha256=vm.digest(value), eof=True)
        try:
            budget.charge(len(raw))
        finally:
            if kwargs.get("stdout_capture") is not None and raw:
                kwargs["stdout_capture"](raw)
        self.now += 0.001
        return 0, raw

    def observe(self, *, worker=True, qemu=True, producers=None, barrier_override=None):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        stopped = barrier() if barrier_override is None else barrier_override
        result = vm.retire(self.c, self.budget, "b" * 32, self.snapshot,
            identity() if worker else None, identity(444) if qemu else None,
            stopped, producers=producers, evidence=evidence)
        return result, evidence

    def test_same_read_raw_and_parsed_two_point_evidence_is_private_and_bounded(self):
        result, evidence = self.observe()
        self.assertIsNone(evidence.error)
        self.assertTrue(evidence.complete)
        self.assertEqual(result["state"], "retired")
        raw = evidence.path.read_bytes()
        document = vm.validated_retirement_evidence(vm.strict_json(raw), self.c)
        self.assertEqual(vm.stat.S_IMODE(evidence.path.stat().st_mode), 0o600)
        self.assertLessEqual(len(raw), 32768)
        self.assertEqual(len(document["frames"]), 2)
        self.assertGreaterEqual(result["observations"][1]["at"] - result["observations"][0]["at"], 0.100)
        self.assertEqual(len(self.commands), 10)
        self.assertEqual(sum(argv[0] == self.c["tools"]["busctl"]["path"] for argv in self.commands), 3)
        self.assertEqual(sum(path.endswith("/stat") for kind, path in self.reads if kind == "read"), 4)
        self.assertEqual(self.budget.commands_left, 118)
        self.assertEqual(self.c["end"], 700.0)
        self.assertEqual(self.budget.end, 700.0)
        self.assertEqual(document["collection_end"], 250.0)

    def test_nonempty_typed_stop_keeps_raw_partial_without_stopping_foreign_policy(self):
        self.typed_raw = vm.encode({"type": "a(sasbttttuii)", "data": [["/unexpected"]]}) + b"\n" + empty_stop_properties().splitlines()[0] + b"\n"
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "unit-stop-command-present"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        typed = document["initial"]["reads"][-1]
        self.assertEqual(base64.b64decode(typed["stdout_b64"]), self.typed_raw)
        self.assertFalse(evidence.complete)
        self.assertFalse(self.stopped)
        self.assertTrue(self.lease.exists())

    def test_unknown_metadata_refuses_before_any_manager_effect(self):
        (self.lease / "unregistered.metadata").write_bytes(b"unknown")
        with self.assertRaisesRegex(vm.Refusal, "retirement-metadata-catalogue"):
            vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.reads, [])


    def test_original_shared_output_is_debited_once_for_each_actual_read(self):
        _result, evidence = self.observe()
        command_bytes = sum(len(value) for value in self.command_outputs)
        kernel_bytes = sum(len(self.kernel_values[path]) for kind, path in self.reads
                           if kind == "read" and path in self.kernel_values)
        primitive_bytes = sum(len(vm.encode(self.cg)) for kind, _path in self.reads if kind == "canonical")
        primitive_bytes += sum(len(vm.encode(vars(self.info))) for kind, _path in self.reads if kind == "stat")
        self.assertEqual(self.budget.output_left, 2 * 1024**2 - command_bytes - kernel_bytes - primitive_bytes)
        self.assertTrue(evidence.complete)
        self.assertEqual(vm.DIAGNOSTIC_CREDIT_BYTES, 2053)

    def test_raw_and_parsed_tampering_each_refuse_without_any_source_resample(self):
        _result, evidence = self.observe()
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        before_reads, before_commands = len(self.reads), len(self.commands)
        for mutation in ("boot-raw", "boot-parsed", "owner", "source", "end", "cleanup", "spacing",
                         "manager-raw", "typed-raw", "manager-argv", "cgroup-inode", "cgroup-limit",
                         "cgroup-path", "cgroup-populated", "process-pid"):
            forged = deepcopy(document)
            frame = forged["frames"][-1]
            boot = next(event for event in frame["reads"] if event["kind"] == "boot")
            manager = next(event for event in frame["reads"] if event["kind"] == "manager")
            if mutation == "boot-raw":boot["raw_b64"] = base64.b64encode(b"wrong\n").decode()
            elif mutation == "boot-parsed":boot["parsed"] = "22222222-2222-2222-2222-222222222222"
            elif mutation == "owner":forged["owner"] = "c" * 32
            elif mutation == "source":forged["source"][str(Path(vm.__file__).resolve())] = "0" * 64
            elif mutation == "end":forged["original_end"] += 1
            elif mutation == "cleanup":forged["original_cleanup_seconds"] += 1
            elif mutation == "spacing":forged["frames"][-1]["at"] = forged["frames"][0]["at"] + 0.099
            elif mutation == "manager-raw":manager["stdout_b64"] = base64.b64encode(b"Id=foreign\n").decode()
            elif mutation == "typed-raw":
                typed = next(event for event in frame["reads"] if event["kind"] == "manager" and event["site"] == "typed-stop")
                typed["parsed"] = {"ExecStop": {"type": "as", "data": []}}
            elif mutation == "manager-argv":manager["argv"][0] = "/unregistered/systemctl"
            elif mutation == "cgroup-inode":
                event = next(event for event in frame["reads"] if event["kind"] == "cgroup-stat")
                event["raw_value"]["st_ino"] += 1
                event["parsed"]["st_ino"] += 1
            elif mutation == "cgroup-limit":
                event = next(event for event in frame["reads"] if event["kind"] == "cgroup-number" and event["path"].endswith("memory.max"))
                raw = b"1\n";event.update(raw_b64=base64.b64encode(raw).decode(), observed_bytes=len(raw), observed_sha256=vm.digest(raw), parsed=1)
            elif mutation == "cgroup-path":
                next(event for event in frame["reads"] if event["kind"] == "cgroup-events")["path"] = "/foreign/cgroup.events"
            elif mutation == "cgroup-populated":
                event = next(event for event in frame["reads"] if event["kind"] == "cgroup-events")
                raw = b"populated 1\nfrozen 0\n";event.update(raw_b64=base64.b64encode(raw).decode(), observed_bytes=len(raw), observed_sha256=vm.digest(raw), parsed={"populated":"1", "frozen":"0"})
            else:
                index = frame["processes"][0]["read"]
                frame["reads"][index]["pid"] += 1
            with self.subTest(mutation=mutation), self.assertRaises((vm.Refusal, ValueError, KeyError)):
                vm.validated_retirement_evidence(forged, self.c)
        self.assertEqual((len(self.reads), len(self.commands)), (before_reads, before_commands))

    def test_initial_policy_typed_proof_cannot_be_omitted_in_raw_readback(self):
        _result, evidence = self.observe()
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        document["initial"]["reads"] = [event for event in document["initial"]["reads"]
                                        if not(event["kind"] == "manager" and event["site"] == "typed-stop")]
        with self.assertRaisesRegex(vm.Refusal, "retirement-evidence-initial-policy"):
            vm.validated_retirement_evidence(document, self.c)

    def test_cgroup_removal_and_missing_actor_prefix_need_no_late_identity_queries(self):
        self.removed = True
        stopped = {**barrier(), "qemu": None}
        result, evidence = self.observe(worker=False, qemu=False, barrier_override=stopped)
        self.assertTrue(evidence.complete)
        self.assertEqual(result["worker"], None)
        self.assertEqual(result["qemu"], None)
        document = vm.validated_retirement_evidence(vm.retirement_evidence_document(evidence.path.read_bytes()), self.c)
        self.assertEqual(document["actors"], [])
        self.assertEqual([frame["cgroup"] for frame in document["frames"]], ["removed", "removed"])
        self.assertFalse(any(path.startswith("/proc/") and path.endswith("/stat") for _kind, path in self.reads))
        self.assertEqual(sum(kind == "exists" for kind, _path in self.reads), 2)

    def test_every_actual_zero_to_five_producer_prefix_is_retained_without_fabricated_actors(self):
        phases = ("guest-info", "stage-kind", "stage-kubectl", "stage-node-oci", "rootful-kind")
        original_parent = self.parent
        for count in range(6):
            with self.subTest(prefix=count):
                self.parent = original_parent / str(count);self.parent.mkdir(mode=0o700)
                self.lease = self.parent / ("kubernetes-lens-vm-" + self.c["owner"]);self.lease.mkdir(mode=0o700)
                self.c.update(directory=str(self.lease), phase="run-rootful-kind", rootful_input_reserved=4096)
                self.budget = vm.Budget(700.0, 50)
                self.stopped = False
                records = [{"phase": phase, "process": identity(551 + index)} for index, phase in enumerate(phases[:count])]
                stopped = {**barrier(), "producers": deepcopy(records), "producers_reaped": [True] * count,
                    "staging": None, "rootful": None, "rootful_input_bytes": 0, "rootful_wire": None,
                    "rootful_record_guards": {"prepaid": 24, "consumed_purposes": list(phases[:count]), "comparisons_attempted": None}}
                _result, evidence = self.observe(producers=records, barrier_override=stopped)
                self.assertTrue(evidence.complete, evidence.error)
                document = vm.validated_retirement_evidence(vm.retirement_evidence_document(evidence.path.read_bytes()), self.c)
                self.assertEqual(document["producer_prefix"], records)
                self.assertEqual(document["actors"], [identity(), identity(444), *(item["process"] for item in records)])
                self.assertTrue(all(len(frame["processes"]) == count + 2 for frame in document["frames"]))

    def test_pid_reuse_and_boot_drift_each_keep_partial_and_quarantine(self):
        for mutation in ("pid", "boot"):
            with self.subTest(mutation=mutation):
                self.stopped = False
                if mutation == "pid":
                    tail = ["S", "1", "321", "321", *(["0"] * 15), "999"]
                    self.kernel_values["/proc/321/stat"] = ("321 (fixture) " + " ".join(tail) + "\n").encode()
                    expected = "retirement-pid-reused"
                else:
                    self.kernel_values.pop("/proc/321/stat", None)
                    self.kernel_values["/proc/sys/kernel/random/boot_id"] = b"22222222-2222-2222-2222-222222222222\n"
                    expected = "retirement-host-boot-drift"
                parent = self.parent / mutation;parent.mkdir(mode=0o700)
                lease = parent / ("kubernetes-lens-vm-" + self.c["owner"]);lease.mkdir(mode=0o700)
                self.c["directory"] = str(lease)
                evidence = vm.RetirementEvidence(parent, self.c, self.budget, kernel=self.kernel)
                with self.assertRaisesRegex(vm.Refusal, expected):
                    vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
                self.assertFalse(evidence.complete)
                document = vm.retirement_evidence_document(evidence.path.read_bytes())
                self.assertTrue(document["frames"][-1]["reads"])
                self.assertTrue(lease.exists())

    def test_descendant_population_refuses_even_with_empty_direct_membership(self):
        self.kernel_values[self.cg + "/cgroup.events"] = b"populated 1\nfrozen 0\n"
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "retirement-cgroup-populated"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertFalse(evidence.complete)
        frame = vm.retirement_evidence_document(evidence.path.read_bytes())["frames"][-1]
        self.assertEqual(self.kernel_values[self.cg + "/cgroup.procs"], b"")
        self.assertFalse(any(event["kind"] == "cgroup-procs" for event in frame["reads"]))
        self.assertEqual(next(event for event in frame["reads"] if event["kind"] == "cgroup-events")["parsed"]["populated"], "1")

    def test_original_end_cannot_shrink_the_accepted_spacing_or_be_renewed(self):
        self.now = 699.94
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "retirement-collection-end"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertFalse(evidence.complete)
        self.assertEqual(self.budget.end, 700.0)
        self.assertEqual(evidence.collection_end, 700.0)
        self.assertEqual(len(evidence.document["frames"]), 1)
        self.assertAlmostEqual(self.now, 699.947)

    def test_cancellation_cleanup_uses_original_fuel_and_does_not_become_native_success(self):
        vm.CANCELLED = signal.SIGINT
        result, evidence = self.observe()
        self.assertTrue(evidence.complete)
        private = {"state":"forged-positive", "error":None, "retirement_error":None, "retirement":result}
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "cancelled")
        self.assertEqual(public["state"], "failed-retired")
        self.assertFalse(self.lease.exists())
        self.assertEqual(self.budget.end, 700.0)

    def test_atomic_capture_failure_preserves_prior_partial_and_still_runs_same_safe_stop(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        previous = evidence.path.read_bytes()
        with patch.object(evidence, "_persist", side_effect=OSError("injected storage failure")):
            result = vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertEqual(result["state"], "retired")
        self.assertTrue(self.stopped)
        self.assertEqual(len(self.commands), 10)
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)
        self.assertEqual(evidence.path.read_bytes(), previous)
        self.assertTrue(self.lease.exists())

    def test_trace_saturation_is_sticky_unknown_and_does_not_grant_new_output_credit(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        old_output = self.budget.output_left
        with patch.object(evidence, "encoded", side_effect=vm.Refusal("retirement-trace-budget")):
            result = vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertEqual(result["state"], "retired")
        self.assertFalse(evidence.complete)
        self.assertFalse(evidence.descriptor()["complete"])
        self.assertLess(self.budget.output_left, old_output)
        self.assertLessEqual(evidence.path.stat().st_size, 32768)
        self.assertEqual(self.budget.commands_left, 118)

    def test_non_none_physical_data_cannot_bypass_incomplete_evidence_or_delete_lease(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        private = {"state":"vm-qualified-retired", "error":"first-native-error", "retirement_error":None,
                   "retirement":{"state":"retired"}}
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
            private["retirement"], evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "retirement-evidence-incomplete")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertTrue(self.lease.exists())

    def test_complete_raw_and_final_receipt_precede_rmtree_and_publication(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        real_rmtree = vm._retirement_remove_lease
        observed = []
        def remove(path, *args, **kwargs):
            pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
            final = pending.with_name(pending.name.removesuffix(".pending"))
            self.assertTrue(pending.exists())
            self.assertFalse(final.exists())
            receipt = vm.strict_json(pending.read_bytes())
            raw = evidence.path.read_bytes()
            document = vm.validated_retirement_evidence(vm.strict_json(raw), self.c)
            self.assertEqual(document["final_receipt"]["projection_sha256"],
                             vm.digest(vm.encode({k:v for k,v in receipt.items() if k != "retirement_evidence"})))
            self.assertEqual(receipt["retirement_evidence"]["sha256"], vm.digest(raw))
            observed.append("durable-before-remove")
            return real_rmtree(path, *args, **kwargs)
        with patch.object(vm, "_retirement_remove_lease", side_effect=remove):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
                result, evidence, True)
        self.assertEqual(observed, ["durable-before-remove"])
        self.assertEqual(status, 0)
        self.assertEqual(public["state"], "vm-qualified-retired")
        self.assertFalse(self.lease.exists())
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        self.assertEqual(vm.digest(final.read_bytes()), public["receipt_sha256"])
        self.assertEqual(set(public["retirement_evidence"]), {"file","bytes","sha256","complete"})
        self.assertNotIn("raw_b64", repr(public))

    def test_receipt_persistence_failure_preserves_first_native_error_and_quarantines(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        with patch.object(vm, "stage_retirement_receipt", side_effect=OSError("fixture disk failure")):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
                result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-persistence-unproved")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertIsNone(public["receipt_sha256"])
        self.assertTrue(self.lease.exists())
        self.assertFalse(evidence.complete)
        self.assertEqual(vm.retirement_evidence_document(evidence.path.read_bytes())["final_receipt"]["native_error"], "first-native-error")

    def test_lease_deletion_noop_cannot_publish_positive_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        with patch.object(vm, "_retirement_remove_lease", return_value=None):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
                result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["retirement_error"], "private-artifact-retirement-unproved")
        self.assertTrue(self.lease.exists())

    def test_metadata_and_exclusive_temporary_reservation_are_not_new_allowances(self):
        catalogue = vm.retirement_metadata_catalogue(self.lease)
        self.assertEqual(catalogue["limit"], 4 * 1024**2)
        self.assertEqual(catalogue["trace_and_one_temporary"], 65536)
        self.assertLessEqual(catalogue["reserved"], catalogue["limit"])
        (self.lease / "config.json").write_bytes(b"x" * 65537)
        with self.assertRaisesRegex(vm.Refusal, "retirement-metadata-catalogue"):
            vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        self.assertFalse(self.commands)

    def test_existing_foreign_temporary_is_preserved_and_refuses_before_start(self):
        path = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".retirement.json.tmp")
        path.write_bytes(b"prior")
        with self.assertRaisesRegex(vm.Refusal, "retirement-metadata-already-exists"):
            vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        self.assertEqual(path.read_bytes(), b"prior")
        self.assertFalse(self.commands)


    def test_more_than_forty_one_cheap_polls_keep_varied_reads_and_bounded_reachable_ring(self):
        self.unloaded_after_stop = True
        busy = []
        def varying(path):
            if path != "/proc/321/stat":return NotImplemented
            if len(busy) < 42:
                tail = ["S", "1", "321", "321", *(["0"] * 15), "123"]
                raw = ("321 (fixture poll" + str(len(busy) + 1) + ") " + " ".join(tail) + "\n").encode()
                busy.append(raw)
                return raw
            raise FileNotFoundError(2, "fixture absent", path)
        self.kernel_override = varying
        result, evidence = self.observe(qemu=False, barrier_override={**barrier(), "qemu":None})
        self.assertTrue(evidence.complete, evidence.error)
        document = vm.validated_retirement_evidence(vm.strict_json(evidence.path.read_bytes()), self.c)
        self.assertEqual([frame["poll"] for frame in document["frames"]], [43, 44])
        self.assertEqual(len(self.commands), 48)
        self.assertEqual(self.budget.commands_left, 80)
        self.assertEqual(len(busy), 42)
        self.assertEqual(len(set(busy)), 42)
        self.assertLessEqual(evidence.path.stat().st_size, 32768)
        encoded = evidence.path.read_text()
        self.assertFalse(any(base64.b64encode(raw).decode() in encoded for raw in busy))
        self.assertEqual(document["actors"], [identity()])
        self.assertEqual(len(document["frames"]), 2)
        self.assertGreaterEqual(result["observations"][1]["at"] - result["observations"][0]["at"], 0.100)

    def test_loaded_polls_exhaust_same_global_one_hundred_twenty_eight_before_extra_effect(self):
        self.hold_active = True
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "command-budget"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertEqual(len(self.commands), 128)
        self.assertEqual(self.manager_attempts, 129)
        self.assertEqual(self.budget.commands_left, -1)
        self.assertEqual(self.budget.end, 700.0)
        self.assertFalse(evidence.complete)
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        self.assertEqual(document["frames"][-1]["poll"], 42)
        self.assertEqual(len(document["frames"]), 2)
        self.assertFalse(document["frames"][-1]["reads"][-1]["raw_complete"])
        self.assertEqual(document["frames"][-1]["reads"][-1]["outcome"]["classification"], "incomplete")

    def test_actual_run_predebit_and_manager_limit_precede_injected_start_boundary(self):
        exhausted = vm.Budget(700.0, 50, commands=0)
        with self.assertRaisesRegex(vm.Refusal, "command-budget"):
            self.actual_run(["/must-not-start"], exhausted, self.lease, cleanup=True, manager=True)
        self.assertEqual(exhausted.commands_left, -1)
        vm.subprocess.Popen.assert_not_called()
        captured = []
        with patch.object(vm, "child_limits", side_effect=lambda seconds, _size: captured.append(seconds)), \
             patch.object(vm.subprocess, "Popen", side_effect=vm.Refusal("injected-start-boundary")):
            budget = vm.Budget(700.0, 50)
            with self.assertRaisesRegex(vm.Refusal, "injected-start-boundary"):
                self.actual_run(["/must-not-start"], budget, self.lease, cleanup=True, manager=True)
        self.assertEqual(captured, [5.0])
        self.assertEqual(budget.commands_left, 127)

    def test_replacement_budget_and_mutated_source_scope_refuse_before_manager_effect(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "retirement-original-budget"):
            vm.retire(self.c, vm.Budget(700.0, 50), "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        changed = {**self.c, "boot":"22222222-2222-2222-2222-222222222222"}
        with self.assertRaisesRegex(vm.Refusal, "retirement-original-scope"):
            vm.retire(changed, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.reads, [])

    def test_record_snapshots_cannot_be_changed_by_later_caller_mutation(self):
        result, evidence = self.observe()
        original = deepcopy(evidence.document["retirement"])
        result["worker"]["start"] = 999
        self.assertEqual(evidence.document["retirement"], original)
        self.assertEqual(evidence.document["actors"][0], identity())
        private = {"state":"positive", "error":None, "retirement_error":None, "retirement":result}
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
                                                  result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["retirement_error"], "retirement-evidence-receipt-binding")
        self.assertTrue(self.lease.exists())

    def test_reference_codec_refuses_unknown_wrongtype_forward_chain_cycle_and_duplicate_keys(self):
        _result, evidence = self.observe()
        raw = evidence.path.read_bytes()
        wire = vm.strict_json(raw)
        self.assertTrue(wire["_retained_values"])
        first = next(iter(wire["_retained_values"]))
        for name, reference in (("unknown", "0" * 64), ("out-of-range", -1), ("wrongtype", [])):
            forged = deepcopy(wire)
            forged["frames"][0]["unit"] = {"$retained":reference}
            with self.subTest(reference=name), self.assertRaises(vm.Refusal):
                vm.retirement_evidence_document(vm.encode(forged))
        forged = {key:value for key,value in wire.items() if key != "_retained_values"}
        forged["_retained_values"] = wire["_retained_values"]
        with self.assertRaisesRegex(vm.Refusal, "retirement-retained-forward"):
            vm.retirement_evidence_document(json.dumps(forged, separators=(",", ":")).encode())
        for name, value in (("chain", {"$retained":first}), ("cycle", {"$retained":"f" * 64})):
            forged = deepcopy(wire)
            forged["_retained_values"][vm.digest(vm.encode(value))] = value
            with self.subTest(reference=name), self.assertRaisesRegex(vm.Refusal, "retirement-retained-value"):
                vm.retirement_evidence_document(vm.encode(forged))
        duplicate = b'{"_retained_values":{},"owner":"one","owner":"two"}'
        with self.assertRaises(vm.Refusal):vm.retirement_evidence_document(duplicate)
        duplicate = b'{"_retained_values":{"' + first.encode() + b'":' + vm.encode(wire["_retained_values"][first]) + b',"' + first.encode() + b'":null}}'
        with self.assertRaises(vm.Refusal):vm.retirement_evidence_document(duplicate)
        decoded = vm.retirement_evidence_document(raw)
        self.assertIsNot(decoded["frames"][0]["unit"], decoded["frames"][1]["unit"])

    def test_reference_entry_expansion_and_depth_bounds_preflight_before_materialization(self):
        entries = {vm.digest(vm.encode(str(index))):str(index) for index in range(129)}
        raw = vm.encode({"_retained_values":entries, "values":[]})
        parser = vm.strict_json
        with patch.object(vm, "strict_json", wraps=parser) as parsed:
            with self.assertRaisesRegex(vm.Refusal, "retirement-retained-table"):
                vm.retirement_evidence_document(raw)
            self.assertEqual(parsed.call_count, 1)
        value = "x" * 2048;key = vm.digest(vm.encode(value))
        raw = vm.encode({"_retained_values":{key:value}, "values":[{"$retained":key} for _ in range(200)]})
        self.assertLess(len(raw), 32768)
        with patch.object(vm, "strict_json", wraps=parser) as parsed:
            with self.assertRaisesRegex(vm.Refusal, "retirement-logical-trace-budget"):
                vm.retirement_evidence_document(raw)
            self.assertEqual(parsed.call_count, 1)
        value = []
        for _ in range(65):value = [value]
        key = vm.digest(vm.encode(value))
        raw = vm.encode({"_retained_values":{key:value}, "value":{"$retained":key}})
        with self.assertRaisesRegex(vm.Refusal, "retirement-trace-depth"):
            vm.retirement_evidence_document(raw)

    def test_partial_manager_loss_keeps_same_read_bytes_and_never_retries_for_free(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        original = self.manager
        partial = b'{"type":"a(sasbttttuii)","data":['
        def losing(argv, budget, directory, **kwargs):
            if self.stopped and argv[0] == self.c["tools"]["busctl"]["path"]:
                budget.commands_left -= 1;vm.require(budget.commands_left >= 0, "command-budget")
                self.commands.append(list(argv))
                budget.charge(len(partial))
                outcome = kwargs["outcome_capture"]
                outcome["stdout"].update(charged_bytes=len(partial), charged_sha256=vm.digest(partial))
                kwargs["stdout_capture"](partial)
                raise OSError("injected source-read loss")
            return original(argv, budget, directory, **kwargs)
        with patch.object(vm, "run", side_effect=losing), self.assertRaises(OSError):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        event = document["frames"][-1]["reads"][-1]
        self.assertEqual(base64.b64decode(event["stdout_b64"]), partial)
        self.assertIsNone(event["parsed"])
        self.assertFalse(event["raw_complete"])
        self.assertFalse(event["outcome"]["stdout"]["eof"])
        self.assertEqual(len(self.commands), 6)
        self.assertEqual(self.budget.commands_left, 122)
        self.assertFalse(evidence.complete)

    def test_partial_cgroup_disappearance_is_not_complete_bound_group_removal(self):
        self.kernel_values.pop(self.cg + "/cgroup.events")
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "retirement-partial-cgroup-disappearance"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        self.assertEqual(document["frames"][-1]["reads"][-1]["kind"], "cgroup-exists")
        self.assertIs(document["frames"][-1]["reads"][-1]["parsed"], True)
        self.assertFalse(evidence.complete)

    def test_late_cancellation_at_publication_never_promotes_native_success(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        real_link = vm.os.link
        first = [True]
        def cancel_link(*args, **kwargs):
            value = real_link(*args, **kwargs)
            if first[0]:
                first[0] = False;vm.CANCELLED = signal.SIGTERM
            return value
        with patch.object(vm.os, "link", side_effect=cancel_link):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease,
                                                      result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "cancelled")
        self.assertEqual(public["state"], "failed-retired")
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        self.assertEqual(vm.strict_json(final.read_bytes())["error"], "cancelled")


    def test_exact_schema_and_json_types_refuse_before_retained_materialization(self):
        _result, evidence = self.observe()
        original = vm.retirement_evidence_document(evidence.path.read_bytes())
        def bad_poll(doc):doc["frames"][0]["poll"] = True
        def bad_swap(doc):
            event = next(row for row in doc["frames"][0]["reads"] if row["kind"] == "cgroup-number" and row["parsed"] == 0)
            event["parsed"] = False
        def bad_status(doc):doc["frames"][0]["reads"][0]["status"] = "pending"
        def extra_root(doc):doc["unexpected"] = {"evidence": doc["frames"][0]["unit"]}
        def extra_event(doc):doc["frames"][0]["reads"][1]["unexpected"] = doc["cgroup"]
        def extra_outcome(doc):doc["frames"][0]["reads"][1]["outcome"]["unexpected"] = False
        def wrong_stream(doc):doc["frames"][0]["reads"][1]["outcome"]["stdout"]["eof"] = 1
        def wrong_result(doc):doc["retirement"]["worker"]["pid"] = True
        for mutate in (bad_poll, bad_swap, bad_status, extra_root, extra_event, extra_outcome, wrong_stream, wrong_result):
            forged = deepcopy(original);mutate(forged)
            raw = vm.encode(vm._retirement_pack(forged))
            parser = vm.strict_json
            with self.subTest(mutation=mutate.__name__), patch.object(vm, "strict_json", wraps=parser) as parsed:
                with self.assertRaises(vm.Refusal):vm.retirement_evidence_document(raw)
                self.assertEqual(parsed.call_count, 1, "schema must reject before retained-value clone")

    def test_each_read_stays_in_its_own_window_and_observations_match_frames(self):
        _result, evidence = self.observe()
        original = vm.retirement_evidence_document(evidence.path.read_bytes())
        for mutation in ("copied-manager", "kernel-before-frame", "initial-after-window", "observation-time", "observation-state"):
            forged = deepcopy(original)
            first, last = forged["frames"]
            if mutation == "copied-manager":last["reads"][1] = deepcopy(first["reads"][1])
            elif mutation == "kernel-before-frame":last["reads"][0]["started"] = last["started"] - 0.001
            elif mutation == "initial-after-window":forged["initial"]["reads"][-1]["finished"] = last["at"]
            elif mutation == "observation-time":forged["retirement"]["observations"][-1]["at"] += 0.001
            else:forged["retirement"]["observations"][-1]["cgroup"] = "removed"
            with self.subTest(mutation=mutation), self.assertRaises(vm.Refusal):
                vm.validated_retirement_evidence(forged, self.c)

    def test_actor_scope_cannot_be_reduced_independently_of_actual_retirement_result(self):
        _result, evidence = self.observe()
        original = vm.retirement_evidence_document(evidence.path.read_bytes())
        forged = deepcopy(original)
        forged["actors"] = []
        for frame in forged["frames"]:
            frame["processes"] = []
            frame["reads"] = [event for event in frame["reads"] if event["kind"] != "process"]
        with self.assertRaisesRegex(vm.Refusal, "retirement-evidence-result-scope"):
            vm.validated_retirement_evidence(forged, self.c)
        forged = deepcopy(original);forged["retirement"]["unexpected"] = None
        with self.assertRaisesRegex(vm.Refusal, "retirement-evidence-schema-map"):
            vm.validated_retirement_evidence(forged, self.c)

    def test_kernel_read_crossing_original_local_end_cannot_gain_later_reads_or_completion(self):
        def late(path):
            if path == "/proc/sys/kernel/random/boot_id":
                self.now = self.budget.retirement_end
                return self.kernel_values[path]
            return NotImplemented
        self.kernel_override = late
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        with self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
            vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertFalse(evidence.complete)
        self.assertEqual(len(self.commands), 4)
        self.assertEqual(self.reads, [("read", "/proc/sys/kernel/random/boot_id")])
        self.assertLess(self.budget.output_left, vm.OUTPUT_MAX - sum(map(len, self.command_outputs)))
        self.assertTrue(self.lease.exists())

    def test_expired_local_end_blocks_private_staging_without_renewing_original_budget(self):
        result, evidence = self.observe()
        original_end = self.budget.end
        self.now = self.budget.retirement_end
        private = {"state":"pending", "error": "first-native-error", "retirement_error": None, "retirement":result}
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(self.budget.end, original_end)
        self.assertTrue(self.lease.exists())

    def test_cleanup_crossing_local_end_leaves_only_non_authorizing_prepared_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error": None, "retirement_error": None, "retirement":result}
        real_remove = vm._retirement_remove_lease
        def late(path, *args, **kwargs):
            real_remove(path, *args, **kwargs);self.now = self.budget.retirement_end
        with patch.object(vm, "_retirement_remove_lease", side_effect=late):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        self.assertFalse((self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")).exists())
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")

    def test_prepared_private_success_requires_matching_public_commit_and_exit_zero(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error": None, "retirement_error": None, "retirement":result}
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 0)
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        durable = vm.strict_json(final.read_bytes())
        self.assertEqual(durable["publication"], {"schema": "kubernetes-lens-retirement-publication-v1", "state":"prepared",
            "requires":["matching-public-commit-acknowledgement", "cli-exit-zero"]})
        self.assertEqual(public["publication_commit"], {"schema":"kubernetes-lens-retirement-publication-v1", "state":"committed",
            "owner":self.c["owner"], "receipt_sha256":vm.digest(final.read_bytes()),
            "retirement_evidence_sha256":vm.digest(evidence.path.read_bytes())})

    def test_publication_io_faults_quarantine_and_roll_back_only_owned_names(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error": None, "retirement":result}
        original_link = vm.os.link
        linked = [False]
        def link(*args, **kwargs):
            original_link(*args, **kwargs);linked[0] = True
        original_sync = vm.sync_retirement_parent
        def fail_after_link(parent, **kwargs):
            if linked[0]:raise OSError("injected parent sync failure")
            return original_sync(parent, **kwargs)
        with patch.object(vm.os, "link", side_effect=link), patch.object(vm, "sync_retirement_parent", side_effect=fail_after_link):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertFalse((self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")).exists())
        self.assertTrue((self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")).exists())

    def test_pending_unlink_fault_cannot_leave_authorizing_final_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error": None, "retirement":result}
        original_unlink = Path.unlink
        def fail_pending(path, *args, **kwargs):
            if path.name.endswith(".receipt.json.pending"):raise OSError("injected unlink failure")
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, "unlink", new=fail_pending):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        self.assertFalse((self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")).exists())

    def test_foreign_final_replacement_is_preserved_and_has_no_acknowledgement(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error": None, "retirement":result}
        original_link = vm.os.link
        foreign = b"foreign replacement"
        def replaced(pending, final, **kwargs):
            original_link(pending, final, **kwargs)
            final.unlink();final.write_bytes(foreign)
        with patch.object(vm.os, "link", side_effect=replaced):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertNotIn("publication_commit", public)
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        self.assertEqual(final.read_bytes(), foreign)

    def test_main_public_stdout_uses_same_local_end_and_rechecks_after_publication(self):
        arguments = ["--phase", "qualify-vm", "--image", "image", "--host-tools", "tools", "--host-tools-sha256", "0" * 64,
            "--output-parent", str(self.parent), "--cpus", "1", "--memory-mib", "512", "--guest-memory-mib", "256",
            "--pids", "256", "--disk-gib", "2", "--deadline-seconds", "500", "--cleanup-seconds", "50", "--ssh-port", "2222"]
        def qualify(args, **kwargs):
            args._retirement_budget = self.budget
            self.budget.retirement_end = 205.0
            return {"state":"vm-qualified-retired", "publication_commit":{"state":"committed"}}, 0
        def publish(receipt, end):
            self.assertEqual(end, 205.0)
            self.now = 205.0
            return True
        with patch.object(vm, "qualify", side_effect=qualify), patch.object(vm, "publish_receipt", side_effect=publish), \
             patch.object(vm.resource, "setrlimit"), patch.object(vm.os, "umask"), patch.object(vm.signal, "signal"):
            self.assertEqual(vm.main(arguments), 1)


    def test_final_sample_fsync_crossing_local_end_never_marks_complete(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        original_fsync = vm.os.fsync
        crossed = [False]
        def late(fd):
            original_fsync(fd)
            if (evidence.document["frames"] and evidence.document["frames"][-1]["poll"] == 2
                    and evidence.document["frames"][-1]["accepted"] and not crossed[0]):
                crossed[0] = True;self.now = self.budget.retirement_end
        with patch.object(vm.os, "fsync", side_effect=late):
            result = vm.retire(self.c, self.budget, "b" * 32, self.snapshot, identity(), identity(444), barrier(), evidence=evidence)
        self.assertEqual(result["state"], "retired")
        self.assertTrue(crossed[0])
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)
        self.assertLessEqual(evidence.path.stat().st_size, 32768)
        self.assertNotEqual(vm.retirement_evidence_document(evidence.path.read_bytes())["state"], "complete")
        self.assertTrue(self.lease.exists())

    def test_receipt_seal_crossing_local_end_preserves_lease_and_first_native_error(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        original_fsync = vm.os.fsync
        crossed = [False]
        def late(fd):
            original_fsync(fd)
            if evidence.document["final_receipt"] is not None and not crossed[0]:
                crossed[0] = True;self.now = self.budget.retirement_end
        with patch.object(vm.os, "fsync", side_effect=late):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertTrue(crossed[0])
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertTrue(self.lease.exists())

    def test_link_crossing_local_end_rolls_back_and_keeps_prepared_pending(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        original_link = vm.os.link
        def late(*args, **kwargs):
            original_link(*args, **kwargs);self.now = self.budget.retirement_end
        with patch.object(vm.os, "link", side_effect=late):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        self.assertTrue(final.exists())
        pending = final.with_name(final.name + ".pending")
        self.assertEqual(final.read_bytes(), pending.read_bytes())
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unavailable")
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")

    def test_failed_rollback_is_explicit_quarantine_with_prepared_non_authorizing_bytes(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        original_link, original_unlink, original_sync = vm.os.link, Path.unlink, vm.sync_retirement_parent
        linked = [False]
        def link(*args, **kwargs):
            original_link(*args, **kwargs);linked[0] = True
        def no_sync(parent, **kwargs):
            if linked[0]:raise OSError("injected post-link sync failure")
            return original_sync(parent, **kwargs)
        def no_rollback(path, *args, **kwargs):
            if path.name.endswith(".receipt.json"):raise OSError("injected rollback unlink failure")
            return original_unlink(path, *args, **kwargs)
        with patch.object(vm.os, "link", side_effect=link), patch.object(vm, "sync_retirement_parent", side_effect=no_sync), \
             patch.object(Path, "unlink", new=no_rollback):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unproved")
        self.assertNotIn("publication_commit", public)
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")

    def test_preexisting_foreign_final_name_is_never_unlinked_or_overwritten(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        final.write_bytes(b"preexisting foreign receipt")
        public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), b"preexisting foreign receipt")


    def test_pending_read_crossing_local_end_refuses_before_link_effect(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        original_read = vm._retirement_read
        def late(path, *args, **kwargs):
            raw = original_read(path, *args, **kwargs)
            if str(path).endswith(".receipt.json.pending") and not self.lease.exists():
                self.now = self.budget.retirement_end
            return raw
        with patch.object(vm, "_retirement_read", side_effect=late), patch.object(vm.os, "link", side_effect=AssertionError("late link forbidden")) as link:
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        link.assert_not_called()
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")


    def test_second_parent_fsync_fault_preserves_sole_exact_full_prepared_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result,
                   "full_diagnostic_payload":{"source":"native fixed raw DATA", "nested":["retain every field", {"counter":7}]}}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        original_sync, original_unlink = vm.sync_retirement_parent, Path.unlink
        captured = []
        final_unlinks = []
        def fail_second_sync(parent, **kwargs):
            if final.exists() and not pending.exists():
                captured.append(final.read_bytes())
                raise OSError("injected second parent fsync failure after pending unlink")
            return original_sync(parent, **kwargs)
        def record_unlink(path, *args, **kwargs):
            if path == final:final_unlinks.append(path)
            return original_unlink(path, *args, **kwargs)
        with patch.object(vm, "sync_retirement_parent", side_effect=fail_second_sync), patch.object(Path, "unlink", new=record_unlink):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertTrue(captured)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-prepared-only")
        self.assertNotIn("publication_commit", public)
        self.assertIsNone(public["receipt_sha256"])
        self.assertEqual(final_unlinks, [])
        self.assertEqual(final.read_bytes(), captured[0])
        durable = vm.strict_json(final.read_bytes())
        self.assertEqual(durable["full_diagnostic_payload"], private["full_diagnostic_payload"])
        self.assertEqual(durable["publication"]["state"], "prepared")
        self.assertEqual(durable["publication"]["requires"], ["matching-public-commit-acknowledgement", "cli-exit-zero"])
        self.assertFalse(pending.exists())
        self.assertFalse(self.lease.exists())
        self.assertEqual(vm.stat.S_IMODE(final.stat().st_mode), 0o600)

    def test_after_pending_unlink_expiry_preserves_exact_last_copy_without_new_write(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        original_sync, original_replace, original_link, original_unlink = vm.sync_retirement_parent, vm.os.replace, vm.os.link, Path.unlink
        captured = []
        def expire_second_sync(parent, **kwargs):
            value = original_sync(parent, **kwargs)
            if final.exists() and not pending.exists():
                captured.append(final.read_bytes());self.now = self.budget.retirement_end
            return value
        def no_late_replace(*args, **kwargs):
            self.assertLess(self.now, self.budget.retirement_end)
            return original_replace(*args, **kwargs)
        def no_late_link(*args, **kwargs):
            self.assertLess(self.now, self.budget.retirement_end)
            return original_link(*args, **kwargs)
        def no_late_unlink(path, *args, **kwargs):
            self.assertLess(self.now, self.budget.retirement_end)
            return original_unlink(path, *args, **kwargs)
        with patch.object(vm, "sync_retirement_parent", side_effect=expire_second_sync), \
             patch.object(vm.os, "replace", side_effect=no_late_replace), patch.object(vm.os, "link", side_effect=no_late_link), \
             patch.object(Path, "unlink", new=no_late_unlink):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(len(captured), 1)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unavailable")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), captured[0])
        self.assertFalse(pending.exists())
        self.assertEqual(vm.retirement_evidence_document(evidence.path.read_bytes())["state"], "complete")
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")

    def test_after_pending_unlink_cancellation_quarantines_and_keeps_last_prepared_copy(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        original_sync = vm.sync_retirement_parent
        captured = []
        def cancel_second_sync(parent, **kwargs):
            value = original_sync(parent, **kwargs)
            if final.exists() and not pending.exists():
                captured.append(final.read_bytes());vm.CANCELLED = signal.SIGTERM
            return value
        with patch.object(vm, "sync_retirement_parent", side_effect=cancel_second_sync):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertTrue(captured)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "cancelled")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-prepared-only")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), captured[0])
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")
        self.assertFalse(pending.exists())

    def test_foreign_pending_after_unlink_cannot_authorize_deleting_owned_last_copy(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        original_sync = vm.sync_retirement_parent
        captured = []
        foreign = b"foreign pending receipt; do not change"
        def foreign_second_sync(parent, **kwargs):
            if final.exists() and not pending.exists():
                captured.append(final.read_bytes());pending.write_bytes(foreign)
                raise OSError("injected second parent fsync fault and foreign pending")
            return original_sync(parent, **kwargs)
        with patch.object(vm, "sync_retirement_parent", side_effect=foreign_second_sync):
            public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(len(captured), 1)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unproved")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), captured[0])
        self.assertEqual(pending.read_bytes(), foreign)
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")


    def deadline_io_guards(self):
        """Reject every later filesystem observation/mutation; FD close must run."""
        guards = ExitStack()
        events, closes = [], []
        late_attempts = []
        guards.callback(lambda: self.assertEqual(late_attempts, [], "late filesystem attempts, including caught failures"))
        for owner, name in ((Path, "stat"), (Path, "exists"), (Path, "is_symlink"), (Path, "unlink"),
                            (vm.os, "stat"), (vm.os, "lstat"), (vm.os, "open"), (vm.os, "fstat"),
                            (vm.os, "read"), (vm.os, "write"), (vm.os, "fsync"), (vm.os, "replace"), (vm.os, "link"),
                            (vm.os, "scandir"), (vm.os, "unlink"), (vm.os, "rmdir")):
            actual = getattr(owner, name)
            def guarded(*args, _name=name, _actual=actual, **kwargs):
                if self.now >= self.budget.retirement_end:
                    late_attempts.append(_name)
                self.assertLess(self.now, self.budget.retirement_end, "late filesystem I/O: " + _name)
                events.append(_name)
                return _actual(*args, **kwargs)
            guards.enter_context(patch.object(owner, name, new=guarded))
        actual_close = vm.os.close
        def close(fd):
            closes.append(fd)
            return actual_close(fd)
        guards.enter_context(patch.object(vm.os, "close", new=close))
        return guards, events, closes

    def test_bounded_reader_expiry_between_canonical_open_fstat_and_read_stops_next_io(self):
        path = self.parent / "bounded-read.json"
        path.write_bytes(b"exact bounded private DATA")
        for boundary in ("canonical", "open", "fstat", "read"):
            self.now = 200.0;self.budget.retirement_end = 201.0
            guards, events, closes = self.deadline_io_guards()
            with self.subTest(boundary=boundary), guards:
                owner, name = (Path, "is_symlink") if boundary == "canonical" else (vm.os, boundary)
                actual = getattr(owner, name)
                def late(*args, **kwargs):
                    value = actual(*args, **kwargs)
                    self.now = self.budget.retirement_end
                    return value
                with patch.object(owner, name, new=late), self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                    vm._retirement_read(path, self.budget)
                self.assertEqual(len(closes), 0 if boundary == "canonical" else 1)
                self.assertNotIn("write", events)
            self.assertEqual(path.read_bytes(), b"exact bounded private DATA")

    def test_parent_sync_expiry_after_open_or_fsync_closes_fd_without_more_io(self):
        for boundary in ("open", "fsync"):
            self.now = 200.0;self.budget.retirement_end = 201.0
            guards, events, closes = self.deadline_io_guards()
            with self.subTest(boundary=boundary), guards:
                actual = getattr(vm.os, boundary)
                def late(*args, **kwargs):
                    value = actual(*args, **kwargs);self.now = self.budget.retirement_end;return value
                with patch.object(vm.os, boundary, new=late), self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                    vm.sync_retirement_parent(self.parent, budget=self.budget)
                self.assertEqual(len(closes), 1)
                self.assertEqual(events.count("fsync"), 0 if boundary == "open" else 1)

    def test_persist_fsync_expiry_preserves_temporary_and_prior_trace_without_late_discovery(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        prior = evidence.path.read_bytes()
        evidence.document["initial"]["finished"] = self.now
        self.budget.retirement_end = self.now + 1
        guards, _events, closes = self.deadline_io_guards()
        with guards:
            actual = vm.os.fsync
            def late(fd):
                value = actual(fd);self.now = self.budget.retirement_end;return value
            with patch.object(vm.os, "fsync", new=late):
                evidence.sync()
            self.assertEqual(len(closes), 1)
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)
        self.assertEqual(evidence.path.read_bytes(), prior)
        self.assertEqual(evidence.last_raw, prior)
        self.assertTrue(evidence.temporary.exists())
        self.assertNotEqual(evidence.temporary.read_bytes(), prior)
        self.assertLessEqual(evidence.temporary.stat().st_size, vm.RETIREMENT_TRACE_MAX)

    def test_funded_failed_persist_never_unlinks_foreign_temporary_replacement(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        prior = evidence.path.read_bytes()
        self.budget.retirement_end = self.now + 1
        actual_write, actual_unlink = vm.os.write, Path.unlink
        foreign = b"foreign temporary replacement"
        unlinks = []
        replaced = [False]
        def replace_then_fail(fd, raw):
            if not replaced[0]:
                actual_write(fd, raw)
                actual_unlink(evidence.temporary)
                evidence.temporary.write_bytes(foreign)
                replaced[0] = True
                raise OSError("injected write failure and foreign replacement")
            return actual_write(fd, raw)
        def record_unlink(path, *args, **kwargs):
            unlinks.append(path);return actual_unlink(path, *args, **kwargs)
        with patch.object(vm.os, "write", new=replace_then_fail), patch.object(Path, "unlink", new=record_unlink):
            evidence.sync()
        self.assertEqual(unlinks, [])
        self.assertEqual(evidence.path.read_bytes(), prior)
        self.assertEqual(evidence.temporary.read_bytes(), foreign)
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)

    def test_link_expiry_skips_all_rollback_reads_and_keeps_both_exact_prepared_names(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual = vm.os.link
            def late(*args, **kwargs):
                value = actual(*args, **kwargs);self.now = self.budget.retirement_end;return value
            with patch.object(vm.os, "link", new=late):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), pending.read_bytes())
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")

    def test_stage_identity_stat_expiry_prevents_receipt_read_or_restat(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual = Path.stat
            def late(path, *args, **kwargs):
                value = actual(path, *args, **kwargs)
                if path == pending:self.now = self.budget.retirement_end
                return value
            with patch.object(Path, "stat", new=late):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        self.assertTrue(self.lease.exists())
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")

    def test_rmtree_expiry_prevents_even_directory_exists_and_later_caller_io(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        actual_remove = vm._retirement_remove_lease
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            def late(path, *args, **kwargs):
                actual_remove(path, *args, **kwargs);self.now = self.budget.retirement_end
            with patch.object(vm, "_retirement_remove_lease", side_effect=late):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")

    def test_failed_deletion_pending_stat_expiry_prevents_caller_unlink(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        deletion = [False]
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual = Path.stat
            def late(path, *args, **kwargs):
                value = actual(path, *args, **kwargs)
                if deletion[0] and path == pending:self.now = self.budget.retirement_end
                return value
            def no_remove(_path, *_args, **_kwargs):deletion[0] = True
            with patch.object(Path, "stat", new=late), patch.object(vm, "_retirement_remove_lease", side_effect=no_remove):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertNotIn("publication_commit", public)
        self.assertTrue(self.lease.exists())
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")


    def test_bounded_writer_expiry_after_open_write_or_fsync_only_closes_fd(self):
        for boundary in ("open", "write", "fsync"):
            path = self.parent / ("bounded-write-" + boundary + ".json")
            self.now = 200.0;self.budget.retirement_end = 201.0
            guards, events, closes = self.deadline_io_guards()
            with self.subTest(boundary=boundary), guards:
                actual = getattr(vm.os, boundary)
                def late(*args, **kwargs):
                    value = actual(*args, **kwargs);self.now = self.budget.retirement_end;return value
                with patch.object(vm.os, boundary, new=late), self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                    vm._retirement_write(path, b"bounded exact bytes", self.budget)
                self.assertEqual(len(closes), 1)
                self.assertNotIn("unlink", events)
            self.assertEqual(path.read_bytes(), b"" if boundary == "open" else b"bounded exact bytes")

    def test_post_unlink_expiry_skips_read_only_rollback_and_preserves_exact_sole_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        original_sync = vm.sync_retirement_parent
        captured = []
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            def late(parent, **kwargs):
                value = original_sync(parent, **kwargs)
                if final.exists() and not pending.exists():
                    captured.append(final.read_bytes());self.now = self.budget.retirement_end
                return value
            with patch.object(vm, "sync_retirement_parent", side_effect=late):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(len(captured), 1)
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unavailable")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), captured[0])
        self.assertFalse(pending.exists())

    def test_rollback_exists_expiry_cannot_authorize_owned_read_or_unlink(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        final = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json")
        pending = final.with_name(final.name + ".pending")
        rollback = [False]
        original_sync = vm.sync_retirement_parent
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual_exists = Path.exists
            def fail_sync(parent, **kwargs):
                if final.exists():
                    rollback[0] = True
                    raise OSError("injected funded post-link sync failure")
                return original_sync(parent, **kwargs)
            def late_exists(path):
                value = actual_exists(path)
                if rollback[0] and path == pending:self.now = self.budget.retirement_end
                return value
            with patch.object(vm, "sync_retirement_parent", side_effect=fail_sync), patch.object(Path, "exists", new=late_exists):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertTrue(rollback[0])
        self.assertEqual(status, 1)
        self.assertEqual(public["error"], "first-native-error")
        self.assertEqual(public["retirement_error"], "private-receipt-publication-rollback-unavailable")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(final.read_bytes(), pending.read_bytes())

    def test_persist_ownership_stat_expiry_prevents_open_and_temp_creation(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        prior = evidence.path.read_bytes()
        self.budget.retirement_end = self.now + 1
        guards, events, _closes = self.deadline_io_guards()
        with guards:
            actual_stat = Path.stat
            def late(path, *args, **kwargs):
                value = actual_stat(path, *args, **kwargs)
                if path == evidence.path:self.now = self.budget.retirement_end
                return value
            with patch.object(Path, "stat", new=late):evidence.sync()
            self.assertNotIn("open", events)
        self.assertEqual(evidence.path.read_bytes(), prior)
        self.assertFalse(evidence.temporary.exists())
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)

    def test_persist_replace_returning_late_stops_restat_parent_sync_and_cleanup_discovery(self):
        evidence = vm.RetirementEvidence(self.parent, self.c, self.budget, kernel=self.kernel)
        evidence.document["initial"]["finished"] = self.now
        self.budget.retirement_end = self.now + 1
        guards, _events, closes = self.deadline_io_guards()
        with guards:
            actual_replace = vm.os.replace
            def late(*args, **kwargs):
                value = actual_replace(*args, **kwargs);self.now = self.budget.retirement_end;return value
            with patch.object(vm.os, "replace", new=late):evidence.sync()
            self.assertEqual(len(closes), 1)
        self.assertFalse(evidence.complete)
        self.assertIsNotNone(evidence.error)
        self.assertFalse(evidence.temporary.exists())
        document = vm.retirement_evidence_document(evidence.path.read_bytes())
        self.assertEqual(document["state"], "incomplete")
        self.assertLessEqual(evidence.path.stat().st_size, vm.RETIREMENT_TRACE_MAX)


    def rewrite_receipt_fixture(self):
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        final = pending.with_name(pending.name.removesuffix(".pending"))
        marker = {"schema":"kubernetes-lens-retirement-publication-v1", "state":"prepared",
                  "requires":["matching-public-commit-acknowledgement", "cli-exit-zero"]}
        old = {"state":"vm-qualified-retired", "error":"first-native-error", "retirement_error":None,
               "publication":marker, "full_payload":{"exact":"old private DATA"}}
        revised = {**old, "state":"failed-quarantined", "retirement_error":"private-artifact-retirement-unproved",
                   "full_payload":{"exact":"revised private DATA"}}
        identity, raw = vm.stage_retirement_receipt(pending, old, self.budget)
        return pending, final, identity, raw, revised

    def test_atomic_rewrite_expiry_preserves_old_or_revised_full_prepared_copy_without_late_io(self):
        self.budget.retirement_end = self.now + 1
        for boundary in ("staged-fsync", "new-proof", "old-proof", "before-replace", "after-replace", "readback"):
            self.now = 200.0;self.budget.retirement_end = 201.0
            pending, final, identity, old_raw, revised = self.rewrite_receipt_fixture()
            new_raw = vm.encode(revised)
            guards, _events, _closes = self.deadline_io_guards()
            with self.subTest(boundary=boundary), guards:
                actual_stat, actual_replace, actual_sync, actual_io = Path.stat, vm.os.replace, vm.sync_retirement_parent, vm._retirement_io
                actual_stage = vm.stage_retirement_receipt
                staged = [False]
                replaced = [False]
                new_stats, old_stats = [0], [0]
                def late_stat(path, *args, **kwargs):
                    info = actual_stat(path, *args, **kwargs)
                    if path == final and staged[0]:
                        new_stats[0] += 1
                        if boundary == "new-proof" and new_stats[0] == 1:self.now = self.budget.retirement_end
                    if boundary == "readback" and path == pending and replaced[0]:self.now = self.budget.retirement_end
                    if path == pending and staged[0]:
                        old_stats[0] += 1
                        if boundary == "old-proof" and old_stats[0] == 1:self.now = self.budget.retirement_end
                    return info
                def stage(*args, **kwargs):
                    result = actual_stage(*args, **kwargs);staged[0] = True;return result
                def late_sync(parent, **kwargs):
                    value = actual_sync(parent, **kwargs)
                    if boundary == "staged-fsync" and final.exists():self.now = self.budget.retirement_end
                    return value
                def late_replace(*args, **kwargs):
                    value = actual_replace(*args, **kwargs)
                    replaced[0] = True
                    if boundary == "after-replace":self.now = self.budget.retirement_end
                    return value
                def late_io(budget, operation, *args, **kwargs):
                    if boundary == "before-replace" and operation is vm.os.replace:self.now = self.budget.retirement_end
                    return actual_io(budget, operation, *args, **kwargs)
                with patch.object(Path, "stat", new=late_stat), patch.object(vm, "sync_retirement_parent", side_effect=late_sync), \
                     patch.object(vm.os, "replace", new=late_replace), patch.object(vm, "_retirement_io", new=late_io), \
                     patch.object(vm, "stage_retirement_receipt", side_effect=stage), \
                     self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                    vm.rewrite_staged_retirement_receipt(pending, final, identity, old_raw, revised, self.budget)
            copies = [path.read_bytes() for path in (pending, final) if path.exists()]
            self.assertTrue(any(raw in (old_raw, new_raw) for raw in copies))
            self.assertTrue(all(vm.strict_json(raw)["publication"]["state"] == "prepared" for raw in copies))
            if boundary in ("after-replace", "readback"):self.assertEqual(copies, [new_raw])
            else:self.assertIn(old_raw, copies)
            for path in (pending, final):path.unlink(missing_ok=True)

    def test_atomic_rewrite_failure_and_foreign_final_preserve_exact_old_pending(self):
        self.budget.retirement_end = self.now + 1
        pending, final, identity, old_raw, revised = self.rewrite_receipt_fixture()
        foreign = b"foreign existing final; never overwrite"
        final.write_bytes(foreign)
        with self.assertRaises(FileExistsError):
            vm.rewrite_staged_retirement_receipt(pending, final, identity, old_raw, revised, self.budget)
        self.assertEqual(pending.read_bytes(), old_raw)
        self.assertEqual(final.read_bytes(), foreign)
        final.unlink()
        actual_sync = vm.sync_retirement_parent
        def failed_sync(parent, **kwargs):
            if final.exists():raise OSError("injected revised-receipt fsync failure")
            return actual_sync(parent, **kwargs)
        with patch.object(vm, "sync_retirement_parent", side_effect=failed_sync), self.assertRaises(OSError):
            vm.rewrite_staged_retirement_receipt(pending, final, identity, old_raw, revised, self.budget)
        self.assertEqual(pending.read_bytes(), old_raw)
        self.assertEqual(final.read_bytes(), vm.encode(revised))

    def test_atomic_rewrite_foreign_pending_drift_prevents_replace_and_keeps_revised_copy(self):
        self.budget.retirement_end = self.now + 1
        pending, final, identity, old_raw, revised = self.rewrite_receipt_fixture()
        foreign = b"foreign pending changed during revised staging"
        actual_stage = vm.stage_retirement_receipt
        def replace_pending(path, *args, **kwargs):
            result = actual_stage(path, *args, **kwargs)
            if path == final:
                pending.unlink();pending.write_bytes(foreign)
            return result
        with patch.object(vm, "stage_retirement_receipt", side_effect=replace_pending), \
             patch.object(vm.os, "replace", side_effect=AssertionError("foreign pending overwrite forbidden")) as replace, \
             self.assertRaisesRegex(vm.Refusal, "private-receipt-rewrite-drift"):
            vm.rewrite_staged_retirement_receipt(pending, final, identity, old_raw, revised, self.budget)
        replace.assert_not_called()
        self.assertEqual(pending.read_bytes(), foreign)
        self.assertEqual(final.read_bytes(), vm.encode(revised))

    def test_caller_failed_deletion_rewrite_expiry_retains_exact_full_old_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        final = pending.with_name(pending.name.removesuffix(".pending"))
        actual_stage = vm.stage_retirement_receipt
        old = []
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            def late_stage(path, *args, **kwargs):
                result = actual_stage(path, *args, **kwargs)
                if path == pending:old.append(pending.read_bytes())
                if path == final:self.now = self.budget.retirement_end
                return result
            with patch.object(vm, "_retirement_remove_lease", return_value=None), patch.object(vm, "stage_retirement_receipt", side_effect=late_stage):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(pending.read_bytes(), old[0])
        self.assertEqual(vm.strict_json(final.read_bytes())["publication"]["state"], "prepared")

    def test_caller_cancel_rewrite_late_atomic_replace_preserves_full_failed_receipt(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":None, "retirement_error":None, "retirement":result}
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        final = pending.with_name(pending.name.removesuffix(".pending"))
        actual_link, actual_replace = vm.os.link, vm.os.replace
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            cancelled = [False]
            def cancel_link(*args, **kwargs):
                value = actual_link(*args, **kwargs)
                if not cancelled[0]:cancelled[0] = True;vm.CANCELLED = signal.SIGTERM
                return value
            def late_replace(source, target):
                value = actual_replace(source, target)
                if source == final and target == pending:self.now = self.budget.retirement_end
                return value
            with patch.object(vm.os, "link", new=cancel_link), patch.object(vm.os, "replace", new=late_replace):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "cancelled")
        self.assertNotIn("publication_commit", public)
        durable = vm.strict_json(pending.read_bytes())
        self.assertEqual(durable["error"], "cancelled")
        self.assertEqual(durable["publication"]["state"], "prepared")
        self.assertFalse(final.exists())


    def test_atomic_rewrite_new_identity_drift_during_old_proof_preserves_foreign_and_old_names(self):
        self.budget.retirement_end = self.now + 1
        pending, final, identity, old_raw, revised = self.rewrite_receipt_fixture()
        actual_read = vm._retirement_read
        foreign = b"foreign replacement after first new-file proof"
        drifted = [False]
        def replace_new_during_old(path, *args, **kwargs):
            raw = actual_read(path, *args, **kwargs)
            if path == pending and not drifted[0]:
                final.unlink();final.write_bytes(foreign);drifted[0] = True
            return raw
        with patch.object(vm, "_retirement_read", side_effect=replace_new_during_old), \
             patch.object(vm.os, "replace", side_effect=AssertionError("foreign replacement mutation forbidden")) as replace, \
             self.assertRaisesRegex(vm.Refusal, "private-receipt-rewrite-drift"):
            vm.rewrite_staged_retirement_receipt(pending, final, identity, old_raw, revised, self.budget)
        replace.assert_not_called()
        self.assertTrue(drifted[0])
        self.assertEqual(pending.read_bytes(), old_raw)
        self.assertEqual(final.read_bytes(), foreign)

    def test_caller_cancel_rewrite_stat_expiry_prevents_read_unlink_or_restage(self):
        result, evidence = self.observe()
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result}
        pending = self.parent / ("kubernetes-lens-vm-" + self.c["owner"] + ".receipt.json.pending")
        final = pending.with_name(pending.name.removesuffix(".pending"))
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual_stat = Path.stat
            cancelled = [False]
            def cancel(*args, **kwargs):
                cancelled[0] = True;vm.CANCELLED = signal.SIGTERM
                raise vm.Refusal("cancelled")
            def late(path, *args, **kwargs):
                value = actual_stat(path, *args, **kwargs)
                if cancelled[0] and path == pending:self.now = self.budget.retirement_end
                return value
            with patch.object(vm, "publish_staged_retirement_receipt", side_effect=cancel), patch.object(Path, "stat", new=late):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertTrue(cancelled[0])
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(vm.strict_json(pending.read_bytes())["publication"]["state"], "prepared")
        self.assertFalse(final.exists())


    def cleanup_fixture(self, names=("config.json", "ignition.json")):
        for name in names:(self.lease / name).write_bytes(("private " + name).encode())
        self.budget.retirement_end = self.now + 1

    def test_flat_cleanup_full_source_catalogue_uses_original_bounds_and_no_recursion(self):
        names = list(vm._retirement_metadata_reservation()["lease_files"])
        names += ["image.qcow2", "image.qcow2.xz", "overlay.qcow2"]
        self.cleanup_fixture(names)
        # Inject only socket stat DATA; no socket/service/runtime is created.
        (self.lease / "control.sock").write_bytes(b"")
        actual_stat = vm.os.stat
        def socket_stat(path, *args, **kwargs):
            info = actual_stat(path, *args, **kwargs)
            if path == "control.sock":
                return SimpleNamespace(**{**vm._retirement_stat(info), "st_mode":vm.stat.S_IFSOCK | 0o600})
            return info
        guards, events, closes = self.deadline_io_guards()
        with guards, patch.object(vm.os, "stat", new=socket_stat):
            vm._retirement_remove_lease(self.lease, self.c, self.budget)
        self.assertFalse(self.lease.exists())
        self.assertEqual(events.count("unlink"), len(names) + 1)
        self.assertEqual(events.count("rmdir"), 1)
        self.assertEqual(len(closes), 2)
        self.assertEqual(vm.ARCHIVE_MAX, 2 * 1024**3)
        self.assertEqual(vm.EXPANDED_MAX, 4 * 1024**3)
        self.assertEqual(vm._retirement_metadata_reservation()["limit"], 4 * 1024**2)

    def test_flat_cleanup_preserves_unknown_symlink_subdirectory_hardlink_and_foreign_owner(self):
        for case in ("unknown", "symlink", "subdirectory", "hardlink", "foreign-owner", "oversized"):
            parent = self.parent / case;parent.mkdir(mode=0o700)
            lease = parent / self.lease.name;lease.mkdir(mode=0o700)
            outside = parent / "foreign.txt";outside.write_bytes(b"exact foreign DATA")
            (lease / "ignition.json").write_bytes(b"retained known DATA")
            if case == "unknown":(lease / "unexpected.txt").write_bytes(b"unknown DATA")
            elif case == "symlink":(lease / "config.json").symlink_to(outside)
            elif case == "subdirectory":
                (lease / "config.json").mkdir();(lease / "config.json" / "nested").write_bytes(b"nested DATA")
            elif case == "hardlink":vm.os.link(outside, lease / "config.json")
            else:(lease / "config.json").write_bytes(b"unadmitted DATA")
            config_case = {**self.c, "directory":str(lease)}
            self.budget.retirement_end = self.now + 1
            actual_stat = vm.os.stat
            def foreign_stat(path, *args, **kwargs):
                info = actual_stat(path, *args, **kwargs)
                if path == "config.json" and case in ("foreign-owner", "oversized"):
                    changes = {"st_uid":os.getuid() + 1} if case == "foreign-owner" else {"st_size":vm.META_MAX + 1}
                    return SimpleNamespace(**{**vm._retirement_stat(info), **changes})
                return info
            guards, events, _closes = self.deadline_io_guards()
            with self.subTest(case=case), guards, patch.object(vm.os, "stat", new=foreign_stat), self.assertRaises(vm.Refusal):
                vm._retirement_remove_lease(lease, config_case, self.budget)
            self.assertNotIn("unlink", events)
            self.assertNotIn("rmdir", events)
            self.assertEqual(outside.read_bytes(), b"exact foreign DATA")
            self.assertEqual((lease / "ignition.json").read_bytes(), b"retained known DATA")
            if case == "unknown":self.assertEqual((lease / "unexpected.txt").read_bytes(), b"unknown DATA")
            if case == "subdirectory":self.assertEqual((lease / "config.json" / "nested").read_bytes(), b"nested DATA")
            if case == "symlink":self.assertTrue((lease / "config.json").is_symlink())

    def test_flat_cleanup_expiry_at_scandir_acquisition_iteration_stat_unlink_and_rmdir_stops_next_io(self):
        for boundary in ("scandir", "next", "stat", "unlink", "rmdir"):
            self.now = 200.0;self.budget.retirement_end = 201.0
            for name in ("config.json", "ignition.json"):(self.lease / name).write_bytes(("exact " + name).encode())
            guards, _events, closes = self.deadline_io_guards()
            closed = []
            with self.subTest(boundary=boundary), guards:
                actual_scan, actual_stat = vm.os.scandir, vm.os.stat
                actual_unlink, actual_rmdir = vm.os.unlink, vm.os.rmdir
                class Scanner:
                    def __init__(scan_self, actual):scan_self.actual = actual
                    def __iter__(scan_self):return scan_self
                    def __next__(scan_self):
                        value = next(scan_self.actual)
                        if boundary == "next":self.now = self.budget.retirement_end
                        return value
                    def close(scan_self):closed.append(True);scan_self.actual.close()
                def scan(*args, **kwargs):
                    result = Scanner(actual_scan(*args, **kwargs))
                    if boundary == "scandir":self.now = self.budget.retirement_end
                    return result
                def late_stat(path, *args, **kwargs):
                    value = actual_stat(path, *args, **kwargs)
                    if boundary == "stat" and path == "config.json":self.now = self.budget.retirement_end
                    return value
                def late_unlink(*args, **kwargs):
                    value = actual_unlink(*args, **kwargs)
                    if boundary == "unlink":self.now = self.budget.retirement_end
                    return value
                def late_rmdir(*args, **kwargs):
                    value = actual_rmdir(*args, **kwargs)
                    if boundary == "rmdir":self.now = self.budget.retirement_end
                    return value
                with patch.object(vm.os, "scandir", new=scan), patch.object(vm.os, "stat", new=late_stat), \
                     patch.object(vm.os, "unlink", new=late_unlink), patch.object(vm.os, "rmdir", new=late_rmdir), \
                     self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                    vm._retirement_remove_lease(self.lease, self.c, self.budget)
            self.assertEqual(closed, [True])
            self.assertEqual(len(closes), 2)
            if boundary == "rmdir":self.assertFalse(self.lease.exists())
            else:
                self.assertTrue(self.lease.exists())
                self.assertEqual((self.lease / "ignition.json").read_bytes(), b"exact ignition.json")
                if boundary != "unlink":self.assertEqual((self.lease / "config.json").read_bytes(), b"exact config.json")
            # Test fixture cleanup is outside the guarded production operation.
            for name in ("config.json", "ignition.json"):(self.lease / name).unlink(missing_ok=True)

    def test_flat_cleanup_delete_proof_expiry_prevents_unlink_and_preserves_all_leaf_bytes(self):
        self.cleanup_fixture()
        actual_stat = vm.os.stat
        calls = [0]
        guards, events, _closes = self.deadline_io_guards()
        with guards:
            def late(path, *args, **kwargs):
                info = actual_stat(path, *args, **kwargs)
                if path == "config.json":
                    calls[0] += 1
                    if calls[0] == 2:self.now = self.budget.retirement_end
                return info
            with patch.object(vm.os, "stat", new=late), self.assertRaisesRegex(vm.Refusal, "original-deadline-expired"):
                vm._retirement_remove_lease(self.lease, self.c, self.budget)
        self.assertEqual(calls[0], 2)
        self.assertNotIn("unlink", events)
        self.assertEqual((self.lease / "config.json").read_bytes(), b"private config.json")
        self.assertEqual((self.lease / "ignition.json").read_bytes(), b"private ignition.json")

    def test_flat_cleanup_observed_leaf_replacement_is_not_unlinked(self):
        self.cleanup_fixture()
        actual_stat, external_unlink = vm.os.stat, vm.os.unlink
        calls = [0]
        guards, events, _closes = self.deadline_io_guards()
        with guards:
            def drift(path, *args, **kwargs):
                if path == "config.json":
                    calls[0] += 1
                    if calls[0] == 2:
                        external_unlink(self.lease / "config.json")
                        (self.lease / "config.json").write_bytes(b"foreign replacement DATA")
                return actual_stat(path, *args, **kwargs)
            with patch.object(vm.os, "stat", new=drift), self.assertRaisesRegex(vm.Refusal, "private-artifact-leaf-drift"):
                vm._retirement_remove_lease(self.lease, self.c, self.budget)
        self.assertNotIn("unlink", events)  # External fixture mutation bypasses the production-I/O log.
        self.assertEqual((self.lease / "config.json").read_bytes(), b"foreign replacement DATA")
        self.assertEqual((self.lease / "ignition.json").read_bytes(), b"private ignition.json")

    def test_flat_cleanup_directory_name_replacement_never_redirects_held_fd_deletion(self):
        self.cleanup_fixture()
        original_info = self.lease.stat()
        moved = self.parent / "held-original-lease"
        actual_fstat = vm.os.fstat
        replaced = [False]
        guards, events, _closes = self.deadline_io_guards()
        with guards:
            def swap(fd):
                info = actual_fstat(fd)
                if info.st_ino == original_info.st_ino and info.st_dev == original_info.st_dev and not replaced[0]:
                    self.lease.rename(moved);self.lease.mkdir(mode=0o700)
                    (self.lease / "config.json").write_bytes(b"foreign directory DATA")
                    replaced[0] = True
                return info
            with patch.object(vm.os, "fstat", new=swap), self.assertRaisesRegex(vm.Refusal, "private-artifact-lease-drift"):
                vm._retirement_remove_lease(self.lease, self.c, self.budget)
        self.assertTrue(replaced[0])
        self.assertNotIn("unlink", events)
        self.assertNotIn("rmdir", events)
        self.assertEqual((moved / "config.json").read_bytes(), b"private config.json")
        self.assertEqual((self.lease / "config.json").read_bytes(), b"foreign directory DATA")

    def test_flat_cleanup_inside_leaf_expiry_keeps_full_staged_diagnostic_receipt(self):
        result, evidence = self.observe()
        (self.lease / "config.json").write_bytes(b"owned private config DATA")
        (self.lease / "ignition.json").write_bytes(b"remaining private DATA")
        private = {"state":"pending", "error":"first-native-error", "retirement_error":None, "retirement":result,
                   "full_payload":{"native":"exact private diagnostic DATA"}}
        pending = self.parent / (self.lease.name + ".receipt.json.pending")
        final = pending.with_name(pending.name.removesuffix(".pending"))
        actual_stage = vm.stage_retirement_receipt
        saved = []
        guards, _events, _closes = self.deadline_io_guards()
        with guards:
            actual_unlink = vm.os.unlink
            def capture(path, *args, **kwargs):
                result = actual_stage(path, *args, **kwargs)
                if path == pending:saved.append(pending.read_bytes())
                return result
            def late_unlink(*args, **kwargs):
                value = actual_unlink(*args, **kwargs);self.now = self.budget.retirement_end;return value
            with patch.object(vm, "stage_retirement_receipt", side_effect=capture), patch.object(vm.os, "unlink", new=late_unlink):
                public, status = vm.finish_qualify_receipt(private, self.c, self.budget, self.parent, self.lease, result, evidence, True)
        self.assertEqual(status, 1)
        self.assertEqual(public["state"], "failed-quarantined")
        self.assertEqual(public["error"], "first-native-error")
        self.assertNotIn("publication_commit", public)
        self.assertEqual(pending.read_bytes(), saved[0])
        self.assertEqual(vm.strict_json(pending.read_bytes())["full_payload"], private["full_payload"])
        self.assertFalse(final.exists())
        self.assertTrue(self.lease.exists())
        self.assertEqual((self.lease / "ignition.json").read_bytes(), b"remaining private DATA")


    def test_flat_cleanup_preserves_new_unknown_leftover_after_admitted_leaf_deletion(self):
        self.cleanup_fixture(("config.json",))
        unknown = self.lease / "late-unknown.txt"
        actual_unlink = vm.os.unlink
        guards, events, _closes = self.deadline_io_guards()
        with guards:
            def new_leftover(*args, **kwargs):
                value = actual_unlink(*args, **kwargs)
                unknown.write_bytes(b"exact late unknown DATA")
                return value
            with patch.object(vm.os, "unlink", new=new_leftover), self.assertRaises(OSError):
                vm._retirement_remove_lease(self.lease, self.c, self.budget)
        self.assertEqual(events.count("rmdir"), 1)
        self.assertEqual(unknown.read_bytes(), b"exact late unknown DATA")
        self.assertFalse((self.lease / "config.json").exists())
        self.assertTrue(self.lease.exists())

    def test_flat_cleanup_uses_exact_existing_disk_and_rootful_byte_ceilings(self):
        limits = {"image.qcow2":vm.EXPANDED_MAX, "image.qcow2.xz":vm.ARCHIVE_MAX,
                  "overlay.qcow2":self.c["overlay_max"], "rootful-wire.json":256 * 1024}
        for name, maximum in limits.items():
            parent = self.parent / ("over-" + name.replace(".", "-"));parent.mkdir(mode=0o700)
            lease = parent / self.lease.name;lease.mkdir(mode=0o700)
            (lease / name).write_bytes(b"small backing fixture")
            self.budget.retirement_end = self.now + 1
            actual_stat = vm.os.stat
            def over_limit(path, *args, **kwargs):
                info = actual_stat(path, *args, **kwargs)
                if path == name:return SimpleNamespace(**{**vm._retirement_stat(info), "st_size":maximum + 1})
                return info
            guards, events, _closes = self.deadline_io_guards()
            with self.subTest(name=name), guards, patch.object(vm.os, "stat", new=over_limit), \
                 self.assertRaisesRegex(vm.Refusal, "private-artifact-leaf-owner-type-budget"):
                vm._retirement_remove_lease(lease, {**self.c, "directory":str(lease)}, self.budget)
            self.assertNotIn("unlink", events)
            self.assertNotIn("rmdir", events)
            self.assertEqual((lease / name).read_bytes(), b"small backing fixture")


class CommandUnwindControls(unittest.TestCase):
    """Every acquired pipe is unwound even when another cleanup step fails."""

    def tearDown(self):
        vm.CANCELLED = 0

    def unwind(self, *, acquire_error=None, selector_error=None, wait_timeout=False,
               close_failure=None, poll_error=None):
        vm.CANCELLED = 0
        process, selector = Mock(), Mock()
        process.pid = 444
        process.stdin.closed = False
        events = []

        def close(name):
            events.append(name)
            if close_failure is not None and close_failure[0] == name:
                raise close_failure[1]

        for name in ("stdin", "stdout", "stderr"):
            getattr(process, name).close.side_effect = lambda name=name: close(name)

        def close_selector():
            events.append("selector")
            if selector_error is not None:
                raise selector_error

        selector.close.side_effect = close_selector
        process.poll.side_effect = poll_error
        process.poll.return_value = None

        def wait(**_kwargs):
            events.append("wait")
            if wait_timeout:
                raise vm.subprocess.TimeoutExpired("mock", 0)
            return -9

        process.wait.side_effect = wait
        budget = vm.Budget(time.monotonic() + 60, 10)
        original_ends = budget.end, budget.work_end
        outcome = vm.command_outcome()
        error = None
        with patch.object(vm.subprocess, "Popen", return_value=process), \
             patch.object(vm.selectors, "DefaultSelector", return_value=selector, side_effect=acquire_error), \
             patch.object(vm.os, "killpg", side_effect=lambda *_args: events.append("kill")):
            try:
                vm.run(["/reviewed/ssh"], budget, "/private", outcome_capture=outcome,
                       on_start=Mock(side_effect=vm.Refusal("initial-refusal")))
            except BaseException as caught:
                error = caught
        self.assertIsNotNone(error)
        self.assertEqual((budget.end, budget.work_end), original_ends)
        self.assertEqual(budget.commands_left, 127)
        self.assertEqual(budget.output_left, vm.OUTPUT_MAX)
        self.assertEqual(outcome["classification"], "incomplete")
        self.assertFalse(outcome["stdout"]["eof"])
        self.assertFalse(outcome["stderr"]["eof"])
        return error, events, outcome, process

    def test_selector_acquisition_failure_still_reaps_and_closes_all_pipes(self):
        failure = OSError("selector-acquire")
        error, events, outcome, _process = self.unwind(acquire_error=failure)
        self.assertIs(error, failure)
        self.assertEqual(events, ["kill", "wait", "stdin", "stdout", "stderr"])
        self.assertEqual(outcome["returncode"], -9)

    def test_unproved_retirement_still_closes_all_pipes(self):
        error, events, outcome, _process = self.unwind(wait_timeout=True)
        self.assertIsInstance(error, vm.Refusal)
        self.assertEqual(str(error), "control-child-retirement-unproved")
        self.assertEqual(events, ["selector", "kill", "wait", "stdin", "stdout", "stderr"])
        self.assertIsNone(outcome["returncode"])

    def test_selector_close_failure_still_reaps_and_closes_all_pipes(self):
        for failure in (OSError("selector-close"), KeyboardInterrupt()):
            with self.subTest(kind=type(failure).__name__):
                error, events, outcome, _process = self.unwind(selector_error=failure)
                self.assertIs(error, failure)
                self.assertEqual(events, ["selector", "kill", "wait", "stdin", "stdout", "stderr"])
                self.assertEqual(outcome["returncode"], -9)

    def test_each_pipe_close_failure_still_attempts_every_pipe(self):
        for name in ("stdin", "stdout", "stderr"):
            for failure in (OSError("pipe-close"), KeyboardInterrupt()):
                with self.subTest(stream=name, kind=type(failure).__name__):
                    error, events, outcome, _process = self.unwind(close_failure=(name, failure))
                    self.assertIs(error, failure)
                    self.assertEqual(events, ["selector", "kill", "wait", "stdin", "stdout", "stderr"])
                    self.assertEqual(outcome["returncode"], -9)

    def test_first_cleanup_failure_survives_later_retirement_and_close_failures(self):
        first = OSError("first-cleanup")
        error, events, outcome, _process = self.unwind(
            selector_error=first, wait_timeout=True, close_failure=("stdin", OSError("later-close")))
        self.assertIs(error, first)
        self.assertEqual(events, ["selector", "kill", "wait", "stdin", "stdout", "stderr"])
        self.assertIsNone(outcome["returncode"])

    def test_unavailable_poll_still_closes_all_pipes_without_inventing_status(self):
        failure = OSError("poll-unavailable")
        error, events, outcome, process = self.unwind(poll_error=failure)
        self.assertIs(error, failure)
        self.assertEqual(events, ["selector", "stdin", "stdout", "stderr"])
        self.assertIsNone(outcome["returncode"])
        process.wait.assert_not_called()


class DirectExecParentControls(unittest.TestCase):
    """Explicit v4 peers through the real worker/parent, without a runtime."""
    parent_case = GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED = 0

    def test_v4_worker_failure_keeps_shared_budget_and_all_owned_producer_reaps(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls
        for malformed in (False, True):
            host = RootfulHostControls(); self.addCleanup(host.doCleanups)
            value = host.result()
            value.update(schema=rootful.RESULT_V4, state='failed', source_deployment='not-reached')
            value['logs']['identities'] = {role: {'pid': 23+i, 'start': 1}
                for i, role in enumerate(('native', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee'))}
            value['logs'].update(state='pg2.g.native.S.4095.23.1' if malformed else 'pg2.g.native.S.4096.23.1',
                                 startup_marker=False, wrapper_observed_child_wait_status=None)
            with patch.object(host, 'result', return_value=value):
                status, stopped, budgets, sessions, _calls, c = host.worker_case()
            self.assertEqual(status, 1)
            self.assertEqual(stopped['error'], 'rootful-poll-range' if malformed else 'rootful-success-unproved')
            self.assertTrue(stopped['qemu_reaped'])
            self.assertEqual(stopped['producers_reaped'], [True]*5)
            self.assertEqual(stopped['original_end'], c['end'])
            self.assertTrue(all(b is budgets[0] for b in budgets))
            self.assertTrue(all(session.budget is budgets[0] for session in sessions))
            self.assertEqual(budgets[0].commands_left, 45)
            if not malformed:
                self.assertEqual(stopped['rootful']['schema'], rootful.RESULT_V4)
                self.assertIsNone(stopped['rootful']['logs']['wrapper_observed_child_wait_status'])

    def test_v4_parent_durability_quarantine_and_private_redaction_are_independent(self):
        import owned_guest_rootful as rootful
        observations = []
        for diagnostic in ('valid', 'malformed', 'summary-mismatch'):
            result, status, private, _valid = self.parent_case(worker_error='rootful-kind-phase-failed',
                poll_diagnostic=diagnostic, poll_v4=True)
            self.assertEqual(status, 1)
            self.assertEqual(private['rootful_result']['schema'], rootful.RESULT_V4)
            self.assertEqual(private['runtime_conformance'], 'not-established')
            self.assertEqual(private['kubernetes_readiness'], 'not-established')
            self.assertEqual(len(private['retirement']['producers']), 5)
            self.assertEqual(len(private['retirement']['observations']), 2)
            self.assertTrue(private['retirement_evidence']['complete'])
            for protected in (b'pg2.', b'logs', b'rootful_result', b'private-prefix'):
                self.assertNotIn(protected, vm.encode(result))
            if diagnostic == 'valid':
                self.assertEqual(self.last_poll_durable, self.last_poll_wire)
                self.assertEqual(private['state'], 'failed-retired')
                detail = rootful.poll_failure(private['rootful_result']['logs'], version=rootful.RESULT_V4,
                    failure=private['rootful_result'])
                self.assertEqual((detail.role, detail.iterations_completed), ('native', 4096))
            else:
                self.assertIsNone(self.last_poll_durable)
                self.assertEqual(private['state'], 'failed-quarantined')
                self.assertEqual(private['retirement_error'],
                    'rootful-poll-code' if diagnostic == 'malformed' else 'rootful-wire-summary')
            observations.append((self.last_retirement_commands, self.last_retirement_output))
        self.assertEqual(observations, [observations[0]]*3)




class PostlogParentControls(unittest.TestCase):
    """Explicit v5 through existing mocked worker and real parent/private wire."""
    parent_case = GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED = 0

    def test_v5_worker_keeps_failure_delete_status_and_original_shared_budget(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls, PostlogDecoderControls
        for delete in (0,19):
            host=RootfulHostControls(); self.addCleanup(host.doCleanups)
            value=host.result()
            _config,wire,_raw=PostlogDecoderControls.bundle(self,'pl1.n')
            value.update(schema=rootful.RESULT_V5,postlog_failure='pl1.n',state='failed',
                         source_deployment='not-reached',kind_delete_status=delete,logs=wire['logs'])
            with patch.object(host,'result',return_value=value):
                status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
            self.assertEqual(status,1)
            self.assertEqual(stopped['error'],'rootful-kind-phase-failed' if delete else 'rootful-success-unproved')
            self.assertEqual(stopped['rootful']['postlog_failure'],'pl1.n')
            self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
            self.assertTrue(stopped['qemu_reaped'])
            self.assertEqual(stopped['producers_reaped'],[True]*5)
            self.assertEqual(stopped['original_end'],c['end'])
            self.assertTrue(all(b is budgets[0] for b in budgets))
            self.assertTrue(all(session.budget is budgets[0] for session in sessions))
            self.assertEqual(budgets[0].commands_left,45)

    def test_v5_parent_private_durability_redaction_and_retirement_stay_independent(self):
        from test_owned_guest_rootful import DirectExecDecoderControls, PostlogDecoderControls
        observations=[]
        for diagnostic in ('valid','malformed','summary-mismatch'):
            bundle=PostlogDecoderControls.bundle(self,'pl1.e')
            with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',
                    poll_diagnostic=diagnostic,poll_v4=True)
            self.assertEqual(status,1)
            self.assertEqual(private['runtime_conformance'],'not-established')
            self.assertEqual(private['kubernetes_readiness'],'not-established')
            self.assertEqual(len(private['retirement']['producers']),5)
            self.assertEqual(len(private['retirement']['observations']),2)
            self.assertTrue(private['retirement_evidence']['complete'])
            for protected in (b'pl1.',b'postlog_failure',b'logs',b'rootful_result'):
                self.assertNotIn(protected,vm.encode(result))
            if diagnostic=='valid':
                self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                self.assertEqual(private['state'],'failed-retired')
                self.assertEqual(private['rootful_result']['postlog_failure'],'pl1.e')
            else:
                self.assertIsNone(self.last_poll_durable)
                self.assertEqual(private['state'],'failed-quarantined')
            observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*3)


class NativeStatusParentControls(unittest.TestCase):
    """V6 status-only private results use existing real worker/parent projection."""
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_v6_worker_keeps_obtained_statuses_delete_failure_and_shared_budgets(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,NativeStatusDecoderControls
        for form in ((None,None,None,None),(None,0,0,0),(7,7,0,0),(125,0,1,0)):
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_raw=NativeStatusDecoderControls.bundle(self,form)
                value.update(schema=rootful.RESULT_V6,postlog_failure='pl1.n',postlog_native=wire['postlog_native'],
                             state='failed',source_deployment='not-reached',kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
                self.assertEqual(status,1)
                self.assertEqual(stopped['error'],'rootful-kind-phase-failed' if delete else 'rootful-success-unproved')
                self.assertEqual(stopped['rootful']['postlog_native'],wire['postlog_native'])
                self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
                self.assertTrue(stopped['qemu_reaped'])
                self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertEqual(stopped['original_end'],c['end'])
                self.assertTrue(all(b is budgets[0] for b in budgets))
                self.assertTrue(all(session.budget is budgets[0] for session in sessions))
                self.assertEqual(budgets[0].commands_left,45)

    def test_v6_parent_private_durability_redaction_and_retirement_are_independent(self):
        from test_owned_guest_rootful import DirectExecDecoderControls,NativeStatusDecoderControls
        observations=[]
        for form in ((None,None,None,None),(None,0,0,0),(7,7,0,0),(125,0,1,0)):
            for diagnostic in ('valid','malformed','summary-mismatch'):
                bundle=NativeStatusDecoderControls.bundle(self,form)
                with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',
                        poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1)
                self.assertEqual(private['runtime_conformance'],'not-established')
                self.assertEqual(private['kubernetes_readiness'],'not-established')
                self.assertEqual(len(private['retirement']['producers']),5)
                self.assertEqual(len(private['retirement']['observations']),2)
                self.assertTrue(private['retirement_evidence']['complete'])
                for protected in (b'postlog_native',b'command_status',b'capture_status',b'pl1.n',b'rootful_result'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                    self.assertEqual(private['state'],'failed-retired')
                    self.assertEqual(private['rootful_result']['postlog_native'],bundle[1]['postlog_native'])
                else:
                    self.assertIsNone(self.last_poll_durable)
                    self.assertEqual(private['state'],'failed-quarantined')
                observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*len(observations))


class ResourceReasonParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_v7_worker_reason_delete_failure_and_original_budget_are_independent(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,ResourceReasonDecoderControls
        for reason in ('pid-max','unlabelled','inv-task-empty'):
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_raw=ResourceReasonDecoderControls.bundle(self,reason)
                value.update(schema=rootful.RESULT_V7,postlog_failure='pl1.r',postlog_native=None,postlog_reason=reason,
                             state='failed',source_deployment='not-reached',kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
                self.assertEqual(status,1)
                self.assertEqual(stopped['error'],'rootful-kind-phase-failed' if delete else 'rootful-success-unproved')
                self.assertEqual(stopped['rootful']['postlog_reason'],reason)
                self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
                self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
                self.assertTrue(all(b is budgets[0] for b in budgets))
                self.assertTrue(all(session.budget is budgets[0] for session in sessions))

    def test_v7_parent_reason_private_durability_public_redaction_and_exact_summary_tamper(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,ResourceReasonDecoderControls
        observations=[]
        for reason in ('pid-max','unlabelled','inv-task-empty'):
            for diagnostic in ('valid','malformed','summary-mismatch'):
                bundle=ResourceReasonDecoderControls.bundle(self,reason)
                with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',
                        poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1);self.assertEqual(private['runtime_conformance'],'not-established')
                self.assertEqual(private['kubernetes_readiness'],'not-established');self.assertTrue(private['retirement_evidence']['complete'])
                self.assertEqual(len(private['retirement']['producers']),5);self.assertEqual(len(private['retirement']['observations']),2)
                for protected in (b'postlog_reason',reason.encode(),b'pl1.r',b'rootful_result'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire);self.assertEqual(private['state'],'failed-retired')
                    self.assertEqual(private['rootful_result']['postlog_reason'],reason)
                else:
                    self.assertIsNone(self.last_poll_durable);self.assertEqual(private['state'],'failed-quarantined')
                observations.append((self.last_retirement_commands,self.last_retirement_output))
        # Change only a valid new-field value in the worker summary, retaining the real wire.
        bundle=ResourceReasonDecoderControls.bundle(self,'pid-max');decode=rootful.wire_record;calls=[]
        def changed_once(raw,config,**kwargs):
            checked=decode(raw,config,**kwargs);calls.append(True)
            if len(calls)==1:
                checked=deepcopy(checked);checked['postlog_reason']='memory'
            return checked
        with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle),patch.object(rootful,'wire_record',side_effect=changed_once):
            result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic='valid',poll_v4=True)
        self.assertEqual((status,private['state'],private['retirement_error']),(1,'failed-quarantined','rootful-wire-summary'))
        self.assertIsNone(self.last_poll_durable)
        for protected in (b'postlog_reason',b'pid-max',b'memory',b'pl1.r'):
            self.assertNotIn(protected,vm.encode(result))
        observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*len(observations))


class CompactInspectParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_compact_v7_private_body_keeps_outer_failure_retirement_and_public_redaction(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import CompactInspectControls,DirectExecDecoderControls
        observations=[]
        for diagnostic in ('valid','malformed','summary-mismatch'):
            bundle=CompactInspectControls.bundle(self)
            with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',
                    poll_diagnostic=diagnostic,poll_v4=True)
            self.assertEqual(status,1);self.assertEqual(private['runtime_conformance'],'not-established')
            self.assertEqual(private['kubernetes_readiness'],'not-established')
            self.assertEqual(private['rootful_result']['schema'],rootful.RESULT_V7)
            self.assertEqual(len(private['retirement']['producers']),5)
            self.assertEqual(len(private['retirement']['observations']),2)
            self.assertTrue(private['retirement_evidence']['complete'])
            for protected in (b'SYNTHETIC_ONLY',b'private-placeholder',b'SyntheticProtectedExtension',b'node-inspect',b'rootful_result'):
                self.assertNotIn(protected,vm.encode(result))
            if diagnostic=='valid':
                self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                self.assertEqual(private['state'],'failed-retired')
                self.assertEqual(private['rootful_result']['state'],'source-deployment-positive')
            else:
                self.assertIsNone(self.last_poll_durable)
                self.assertEqual(private['state'],'failed-quarantined')
            observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*3)

class PostnodeParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_v8_worker_seven_codes_and_real_delete_failure_keep_one_original_budget(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,PostnodeDecoderControls
        for code in sorted(rootful.POSTNODE_FAILURES):
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_rows=PostnodeDecoderControls.bundle(self,code)
                value.update(schema=rootful.RESULT_V8,postlog_failure=code,postlog_native=None,postlog_reason=None,
                             state='failed',source_deployment='not-reached',kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
                self.assertEqual(status,1)
                self.assertEqual(stopped['error'],'rootful-kind-phase-failed' if delete else 'rootful-success-unproved')
                self.assertEqual(stopped['rootful']['postlog_failure'],code)
                self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
                self.assertIsNone(stopped['rootful']['postlog_native']);self.assertIsNone(stopped['rootful']['postlog_reason'])
                self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
                self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))

    def test_v8_parent_private_durability_public_redaction_and_summary_tamper(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,PostnodeDecoderControls
        observations=[]
        for code in sorted(rootful.POSTNODE_FAILURES):
            for diagnostic in ('valid','malformed','summary-mismatch'):
                bundle=PostnodeDecoderControls.bundle(self,code);bundle[1]['kind_delete_status']=19
                with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',
                        poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1);self.assertEqual(private['runtime_conformance'],'not-established')
                self.assertEqual(private['kubernetes_readiness'],'not-established')
                self.assertTrue(private['retirement_evidence']['complete'])
                self.assertEqual(len(private['retirement']['producers']),5);self.assertEqual(len(private['retirement']['observations']),2)
                for protected in (b'postlog_failure',code.encode(),b'rootful_result',b'node-inspect',
                                  b'SYNTHETIC_ONLY',b'private-placeholder',b'SyntheticProtectedExtension'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire);self.assertEqual(private['state'],'failed-retired')
                    self.assertEqual(private['rootful_result']['schema'],rootful.RESULT_V8)
                    self.assertEqual(private['rootful_result']['postlog_failure'],code)
                    self.assertEqual(private['rootful_result']['kind_delete_status'],19)
                else:
                    self.assertIsNone(self.last_poll_durable);self.assertEqual(private['state'],'failed-quarantined')
                observations.append((self.last_retirement_commands,self.last_retirement_output))
        bundle=PostnodeDecoderControls.bundle(self,'pl2.a');decode=rootful.wire_record;calls=[]
        def changed_once(raw,config,**kwargs):
            checked=decode(raw,config,**kwargs);calls.append(True)
            if len(calls)==1:
                checked=deepcopy(checked);checked['postlog_failure']='pl2.k'
            return checked
        with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle),patch.object(rootful,'wire_record',side_effect=changed_once):
            result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic='valid',poll_v4=True)
        self.assertEqual((status,private['state'],private['retirement_error']),(1,'failed-quarantined','rootful-wire-summary'))
        self.assertIsNone(self.last_poll_durable)
        for protected in (b'postlog_failure',b'pl2.a',b'pl2.k',b'SYNTHETIC_ONLY'):
            self.assertNotIn(protected,vm.encode(result))
        observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*len(observations))



class KStageParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_v9_worker_closed_groups_native_forms_and_delete_failure_share_original_budget(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,KStageDecoderControls
        for stage in 'abcdefghijklmn':
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_rows=KStageDecoderControls.bundle(self,stage)
                value.update(schema=rootful.RESULT_V9,postlog_failure='pl2.k',postlog_reason=wire['postlog_reason'],
                             postlog_native=wire['postlog_native'],state='failed',source_deployment='not-reached',
                             kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
                self.assertEqual(status,1)
                self.assertEqual(stopped['rootful']['postlog_reason'],'k1.'+stage)
                self.assertEqual(stopped['rootful']['postlog_native'],wire['postlog_native'])
                self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
                self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
                self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))

    def test_v9_parent_private_equality_double_decode_and_public_redaction(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,KStageDecoderControls
        observations=[]
        for stage in 'abcdefghijklmn':
            for diagnostic in ('valid','malformed','summary-mismatch'):
                bundle=KStageDecoderControls.bundle(self,stage);bundle[1]['kind_delete_status']=19
                with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1)
                self.assertEqual((private['runtime_conformance'],private['kubernetes_readiness']),('not-established','not-established'))
                self.assertTrue(private['retirement_evidence']['complete'])
                for protected in (b'postlog_reason',b'postlog_native',b'k1.',b'pl2.k',b'rootful_result',b'node-inspect',b'SYNTHETIC_ONLY'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                    self.assertEqual(private['state'],'failed-retired')
                    self.assertEqual(private['rootful_result']['schema'],rootful.RESULT_V9)
                    self.assertEqual(private['rootful_result']['postlog_reason'],'k1.'+stage)
                else:
                    self.assertIsNone(self.last_poll_durable);self.assertEqual(private['state'],'failed-quarantined')
                observations.append((self.last_retirement_commands,self.last_retirement_output))
        bundle=KStageDecoderControls.bundle(self,'b');decode=rootful.wire_record;calls=[]
        def changed_once(raw,config,**kwargs):
            checked=decode(raw,config,**kwargs);calls.append(True)
            if len(calls)==1:
                checked=deepcopy(checked);checked['postlog_reason']='k1.d'
            return checked
        with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle),patch.object(rootful,'wire_record',side_effect=changed_once):
            result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic='valid',poll_v4=True)
        self.assertEqual((status,private['state'],private['retirement_error']),(1,'failed-quarantined','rootful-wire-summary'))
        self.assertIsNone(self.last_poll_durable)
        for protected in (b'postlog_reason',b'k1.b',b'k1.d',b'SYNTHETIC_ONLY'):
            self.assertNotIn(protected,vm.encode(result))
        observations.append((self.last_retirement_commands,self.last_retirement_output))
        self.assertEqual(observations,[observations[0]]*len(observations))



class ReadinessAtomParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_worker_tokens_delete_failure_and_original_shared_budget(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,ReadinessAtomDecoderControls
        for reason in ('k2.i.1.p','k2.i.2.r','k2.i.2.e.5'):
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_rows=ReadinessAtomDecoderControls.bundle(self,reason)
                value.update(schema=rootful.RESULT_V10,postlog_failure='pl2.k',postlog_reason=reason,postlog_native=None,
                             state='failed',source_deployment='not-reached',kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete)
                self.assertEqual(status,1);self.assertEqual(stopped['rootful']['postlog_reason'],reason)
                self.assertEqual(stopped['rootful']['kind_delete_status'],delete)
                self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
                self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))

    def test_parent_private_revalidation_durability_and_public_redaction(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,ReadinessAtomDecoderControls
        bundle=ReadinessAtomDecoderControls.bundle(self,'k2.i.2.v');bundle[1]['kind_delete_status']=19
        for diagnostic in ('valid','summary-mismatch'):
            with patch.object(DirectExecDecoderControls,'bundle',return_value=deepcopy(bundle)):
                result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic=diagnostic,poll_v4=True)
            self.assertEqual(status,1)
            self.assertEqual((private['runtime_conformance'],private['kubernetes_readiness']),('not-established','not-established'))
            self.assertTrue(private['retirement_evidence']['complete'])
            for protected in (b'k2.i.',b'postlog_reason',b'postlog_native',b'rootful_result',b'node-inspect',b'SYNTHETIC_ONLY'):
                self.assertNotIn(protected,vm.encode(result))
            if diagnostic=='valid':
                self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                self.assertEqual(private['rootful_result']['schema'],rootful.RESULT_V10)
                self.assertEqual(private['rootful_result']['postlog_reason'],'k2.i.2.v')
            else:self.assertIsNone(self.last_poll_durable)


class ReadyReasonParentControls(unittest.TestCase):
    parent_case=GuestInfoParentOutcomeControls.parent_case
    def setUp(self):
        vm.CANCELLED=0

    def test_new_private_codes_revalidate_durably_and_public_output_is_redacted(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,ReadyReasonDecoderControls
        for code in (68,69):
            bundle=ReadyReasonDecoderControls.bundle(self,'k3.i.2.x.'+str(code))
            bundle[1]['kind_delete_status']=19
            for diagnostic in ('valid','summary-mismatch'):
                with patch.object(DirectExecDecoderControls,'bundle',return_value=deepcopy(bundle)):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1)
                self.assertTrue(private['retirement_evidence']['complete'])
                self.assertEqual((private['runtime_conformance'],private['kubernetes_readiness']),('not-established','not-established'))
                for protected in (b'k3.i.',b'NetworkPluginNotReady',b'postlog_reason',b'rootful_result',b'node-inspect',b'SYNTHETIC_ONLY'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                    self.assertEqual((private['rootful_result']['schema'],private['rootful_result']['postlog_reason']),
                                     (rootful.RESULT_V11,'k3.i.2.x.'+str(code)))
                else:self.assertIsNone(self.last_poll_durable)

    def test_worker_new_schema_preserves_original_shared_budget_and_reaping(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,ReadyReasonDecoderControls
        host=RootfulHostControls();self.addCleanup(host.doCleanups)
        value=host.result();_config,wire,_rows=ReadyReasonDecoderControls.bundle(self,'k3.i.2.x.69')
        value.update(schema=rootful.RESULT_V11,postlog_failure='pl2.k',postlog_reason='k3.i.2.x.69',postlog_native=None,
                     state='failed',source_deployment='not-reached',kind_delete_status=19,logs=wire['logs'])
        with patch.object(host,'result',return_value=value):
            status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=19)
        self.assertEqual((status,stopped['rootful']['postlog_reason'],stopped['rootful']['kind_delete_status']),
                         (1,'k3.i.2.x.69',19))
        self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
        self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
        self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))


class NodeWaitParentControls(unittest.TestCase):
    """V12 fake worker/parent custody; no runtime or actual VM parent."""
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_v12_worker_preserves_shared_budget_reaping_and_cleanup_failure(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,NodeWaitDecoderControls
        for reason in ('k4.o','k4.i.2.x.69'):
            for delete in (0,19):
                host=RootfulHostControls();self.addCleanup(host.doCleanups)
                value=host.result();_config,wire,_rows=NodeWaitDecoderControls.bundle(self,reason)
                value.update(schema=rootful.RESULT_V12,postlog_failure='pl2.k',postlog_reason=reason,
                             postlog_native=wire['postlog_native'],state='failed',source_deployment='not-reached',
                             kind_delete_status=delete,logs=wire['logs'])
                with patch.object(host,'result',return_value=value):
                    status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=delete,spec_schema='kubernetes-lens-owned-rootful-v12')
                self.assertEqual((status,stopped['rootful']['schema'],stopped['rootful']['postlog_reason'],stopped['rootful']['kind_delete_status']),
                                 (1,rootful.RESULT_V12,reason,delete))
                self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
                self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
                self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))

    def test_v12_parent_revalidates_private_wire_and_keeps_public_redaction(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import DirectExecDecoderControls,NodeWaitDecoderControls
        for reason in ('k4.o','k4.i.1.x.69'):
            bundle=NodeWaitDecoderControls.bundle(self,reason);bundle[1]['kind_delete_status']=19
            for diagnostic in ('valid','summary-mismatch'):
                with patch.object(DirectExecDecoderControls,'bundle',return_value=deepcopy(bundle)):
                    result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic=diagnostic,poll_v4=True)
                self.assertEqual(status,1);self.assertTrue(private['retirement_evidence']['complete'])
                self.assertEqual((private['runtime_conformance'],private['kubernetes_readiness']),('not-established','not-established'))
                for protected in (b'k4.',b'postlog_reason',b'postlog_native',b'NetworkPluginNotReady',b'rootful_result',b'node-inspect',b'SYNTHETIC_ONLY'):
                    self.assertNotIn(protected,vm.encode(result))
                if diagnostic=='valid':
                    self.assertEqual(self.last_poll_durable,self.last_poll_wire)
                    self.assertEqual((private['rootful_result']['schema'],private['rootful_result']['postlog_reason']),
                                     (rootful.RESULT_V12,reason))
                else:self.assertIsNone(self.last_poll_durable)


class CaptureSizeRawStatusParentControls(unittest.TestCase):
    """Inert mock worker/parent raw-status passthrough; no VM or native tool."""
    parent_case=GuestInfoParentOutcomeControls.parent_case

    def setUp(self):
        vm.CANCELLED=0

    def test_worker_and_parent_keep_raw_capture23_without_new_semantic_field(self):
        import owned_guest_rootful as rootful
        from test_owned_guest_rootful import RootfulHostControls,NodeWaitDecoderControls,DirectExecDecoderControls
        for stdout,stderr in ((23,0),(0,23)):
            snapshot=dict(return_status=125,command_status=0,stdout_capture_status=stdout,stderr_capture_status=stderr)
            bundle=NodeWaitDecoderControls.bundle(self,'k4.m');bundle[1]['postlog_native']=snapshot
            host=RootfulHostControls();self.addCleanup(host.doCleanups)
            value=host.result();value.update(schema=rootful.RESULT_V12,postlog_failure='pl2.k',postlog_reason='k4.m',
                postlog_native=snapshot,state='failed',source_deployment='not-reached',kind_delete_status=19,logs=bundle[1]['logs'])
            with patch.object(host,'result',return_value=value):
                status,stopped,budgets,sessions,_calls,c=host.worker_case(delete_status=19,spec_schema='kubernetes-lens-owned-rootful-v12')
            self.assertEqual((status,stopped['rootful']['postlog_native']),(1,snapshot))
            self.assertEqual(stopped['original_end'],c['end']);self.assertEqual(budgets[0].commands_left,45)
            self.assertTrue(stopped['qemu_reaped']);self.assertEqual(stopped['producers_reaped'],[True]*5)
            self.assertTrue(all(b is budgets[0] for b in budgets));self.assertTrue(all(s.budget is budgets[0] for s in sessions))
            bundle[1]['kind_delete_status']=19
            with patch.object(DirectExecDecoderControls,'bundle',return_value=deepcopy(bundle)):
                result,status,private,_valid=self.parent_case(worker_error='rootful-kind-phase-failed',poll_diagnostic='valid',poll_v4=True)
            self.assertEqual((status,private['rootful_result']['postlog_native']),(1,snapshot))
            self.assertEqual(self.last_poll_durable,self.last_poll_wire)
            self.assertEqual((private['runtime_conformance'],private['kubernetes_readiness']),('not-established','not-established'))
            for protected in (b'postlog_native',b'k4.m',b'over-cap',b'rootful_result',b'PRIVATE_NODE_METADATA'):
                self.assertNotIn(protected,vm.encode(result))


class CompactRootEnrollmentControls(unittest.TestCase):
    def test_new_source_enrolls_all_original_patterns_and_old_capture_source_stays_stale(self):
        from test_owned_guest_rootful import CAPTURE_SIZE_SOURCE, FROZEN_CAPTURE_SIZE_SOURCE
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, CAPTURE_SIZE_SOURCE)
        self.assertEqual(GuestInfoStderrPatternControls.SOURCE, CAPTURE_SIZE_SOURCE)
        self.assertEqual(PrivatePrefixReceiverEnrollmentControls.CURRENT_SOURCE, CAPTURE_SIZE_SOURCE)
        fixture = GuestInfoStderrPatternControls()
        self.assertEqual(len(fixture.EXPECTED), 314)
        with patch.object(vm, 'read', side_effect=AssertionError('no acquisition')), \
             patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no native')):
            for code in fixture.EXPECTED:
                command = fixture.command(code, status=1)
                classification = 'legacy-refusal-bytes' if code is None else 'prerequisite-code-bytes'
                self.assertEqual(vm.guest_info_stderr_pattern(command, CAPTURE_SIZE_SOURCE),
                                 fixture.expected(classification, code))
                self.assertEqual(vm.guest_info_stderr_pattern(command, FROZEN_CAPTURE_SIZE_SOURCE),
                                 fixture.expected('not-established', source=FROZEN_CAPTURE_SIZE_SOURCE))




class LiveEnvelopeV13SourcePlumbingControls(unittest.TestCase):
    """Current metadata/closed wire plumbing; no outer lifecycle change."""
    def setUp(self):
        vm.CANCELLED=0

    def test_current_metadata_admission_precedes_guest_files_and_fixed_qemu_ram_is_unchanged(self):
        import owned_guest_rootful as rootful
        source=Path(vm.__file__).read_text()
        self.assertLess(source.index('rootful.admit_live_resource_profile(config)'),
                        source.index('rootful_files, spec = rootful.guest_files'))
        for name in (rootful.LIVE_FACTS_NAME,rootful.LIVE_SCHEMA_NAME):
            self.assertIn('"'+name+'"',source)
        args=['qemu','-no-user-config','-nodefaults','-display','none','-monitor','none',
              '-serial','stdio','-machine','q35,accel=kvm','-cpu','host','-smp','2','-m','4096']
        argv=vm.qemu_arguments({'directory':'/private','tools':{'qemu':{'path':'qemu'}},
            'cpus':2,'guest_memory_mib':4096,'owner':'a'*32,'port':22222,'phase':'run-rootful-kind'})
        self.assertEqual(argv[:len(args)],args)
        for argument in ('-object','-device','-qmp'):
            self.assertNotIn(argument,argv)
        self.assertNotIn('slots=',' '.join(argv));self.assertNotIn('maxmem=',' '.join(argv))

    def test_v13_private_wire_does_not_promote_failure_or_retirement_and_stays_publicly_redacted(self):
        from test_owned_guest_rootful import DirectExecDecoderControls,LiveEnvelopeV13FactsAndDecoderControls
        bundle=LiveEnvelopeV13FactsAndDecoderControls.bundle(self)
        with patch.object(DirectExecDecoderControls,'bundle',return_value=bundle):
            result,status,private,_valid=GuestInfoParentOutcomeControls.parent_case(
                self,worker_error='rootful-kind-phase-failed',poll_diagnostic='valid',poll_v4=True)
        self.assertEqual(status,1)
        self.assertEqual(private['runtime_conformance'],'not-established')
        self.assertEqual(private['rootful_result']['schema'],'kubernetes-lens-owned-rootful-result-v13')
        self.assertTrue(private['retirement_evidence']['complete'])
        for protected in (b'owned-vm-live-v1',b'resource_profile',b'resource_facts_sha256',b'SYNTHETIC_ONLY'):
            self.assertNotIn(protected,vm.encode(result))



if __name__ == "__main__":
    unittest.main()
