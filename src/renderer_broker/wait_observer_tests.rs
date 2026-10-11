//! Source-derived fixed expectations; no native tools, process launch, runtime or authority.
use super::*;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn selected() -> Selection {
    Selection {
        profile: PROFILE.into(),
        tool_sha256: TOOL_SHA.into(),
    }
}
fn observed() -> Result<super::super::journal::Record> {
    let mut record = route::cleanup_contract_tests::intent()?;
    record.observer = Some(Observation {
        selection: selected(),
        request_sha256: [1; 32],
        helper_sha256: [2; 32],
        evidence: PathBuf::from(format!("/root/journal/archive/{}.json", record.ownership.nonce)),
        origin: None,
        proof: None,
    });
    Ok(record)
}
fn complete_trace(status: &str) -> Vec<u8> {
    format!("strace: Process 21 attached\nwait4(-1, NULL, 0, NULL) = 22\nwait4(23, 0x7fff1, WNOHANG, NULL) = 0\nwait4(23, {status}, WNOHANG, NULL) = 23\n+++ exited with 0 +++\n").into_bytes()
}
#[test]
fn literal_exit_wait_and_readiness_are_distinct_from_natural_supervisor_status() -> TestResult {
    let mut stream = Stream::default();
    stream.feed(
        b"strace: Process 21 attached\nwait4(23, 0x7fff1, WNOHANG, NULL) = 0\n",
        10,
    )?;
    assert!(stream.retirement(Status::Exit(0)).is_err());
    stream.bind(21, 23)?;
    stream.feed(
        b"wait4(23, [{WIFEXITED(s) && WEXITSTATUS(s) == 7}], WNOHANG, NULL) = 23\n+++ exited with 0 +++\n",
        20,
    )?;
    stream.complete()?;
    assert_eq!(stream.retirement(Status::Exit(7))?, (20, 20));
    assert!(stream.retirement(Status::Exit(0)).is_err());
    Ok(())
}
#[test]
fn exact_signal_core_and_realtime_spellings_use_authenticated_stock_source() -> TestResult {
    // Official7.2 commit195ac8dd... src/signal.c105-119 and generic/signalent.h40.
    for (name, number) in [("SIGTERM", 15), ("SIGRTMIN", 32), ("SIGRT_1", 33), ("SIGRT_32", 64)] {
        let status = format!("[{{WIFSIGNALED(s) && WTERMSIG(s) == {name} && WCOREDUMP(s)}}]");
        assert_eq!(
            event(format!("wait4(23, {status}, WNOHANG, NULL) = 23").as_bytes())?,
            Event::Consumed(23, Status::Signal { number, core: true })
        );
        assert_eq!(
            event(format!("+++ killed by {name} (core dumped) +++").as_bytes())?,
            Event::Terminal(Status::Signal { number, core: true })
        );
    }
    for name in [
        "SIGRT_0",
        "SIGRT_33",
        "SIGRTMAX",
        "SIGRTMIN+1",
        "SIGRT_01",
        "SIGRT_032",
        "SIGIOT",
        "SIGCLD",
        "SIGPOLL",
    ] {
        assert!(signal(name).is_err());
    }
    let mut stream = Stream::default();
    stream.feed(
        &complete_trace("[{WIFSIGNALED(s) && WTERMSIG(s) == SIGABRT && WCOREDUMP(s)}]"),
        12,
    )?;
    stream.child = Some(23);
    stream.complete()?;
    assert!(stream.retirement(Status::Signal { number: 6, core: false }).is_err());
    assert!(stream.retirement(Status::Signal { number: 6, core: true }).is_ok());
    Ok(())
}
#[test]
fn startup_zero_poll_and_auxiliary_never_authorize_consuming_reap() -> TestResult {
    assert_eq!(event(b"wait4(-1, NULL, 0, NULL) = 20")?, Event::Startup(20));
    assert_eq!(event(b"wait4(23, 0x1, WNOHANG, NULL)      = 0")?, Event::Zero(23));
    assert_eq!(
        event(b"--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=23, si_status=0} ---")?,
        Event::Auxiliary
    );
    let mut stream = Stream::default();
    stream.feed(b"strace: Process 21 attached\nwait4(-1, NULL, 0, NULL) = 20\nwait4(23, 0x1, WNOHANG, NULL) = 0\n+++ exited with 0 +++\n",12)?;
    stream.child = Some(23);
    stream.complete()?;
    assert!(stream.retirement(Status::Exit(0)).is_err());
    Ok(())
}
#[test]
fn refused_wait_grammar_is_closed_and_never_returns_positive_reap() {
    for raw in [
        "waitid(P_PID, 23, {}, WEXITED) = 0",
        "wait4(23, NULL, WNOHANG, NULL) = 0",
        "wait4(23, 0x0, WNOHANG, NULL) = 0",
        "wait4(23, 0xA, WNOHANG, NULL) = 0",
        "wait4(23, 0x1, WNOHANG|WNOWAIT, NULL) = 0",
        "wait4(23, 0x1, WNOHANG, {}) = 0",
        "wait4(23, 0x1, WNOHANG, NULL) = -1 ECHILD (No child processes)",
        "wait4(23, 0x1, WNOHANG, NULL <unfinished ...>",
        "<... wait4 resumed> ) = 23",
        "123 wait4(23, 0x1, WNOHANG, NULL) = 0",
        "wait4(023, 0x1, WNOHANG, NULL) = 0",
        "wait4(23, [{WIFEXITED(s) && WEXITSTATUS(s) == 256}], WNOHANG, NULL) = 23",
        "wait4(23, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG, NULL) = 24",
        "wait4(23, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOWAIT, NULL) = 23",
    ] {
        assert!(event(raw.as_bytes()).is_err(), "grammar unexpectedly admitted");
    }
}
#[test]
fn wrong_attach_child_partial_duplicate_and_forced_tail_fail_closed() -> TestResult {
    let ready = b"strace: Process 21 attached\nwait4(23, 0x1, WNOHANG, NULL) = 0\n";
    let mut stream = Stream::default();
    stream.feed(ready, 1)?;
    assert!(stream.bind(22, 23).is_err());
    assert!(stream.bind(21, 24).is_err());
    let mut stream = Stream::default();
    stream.feed(ready, 1)?;
    stream.bind(21, 23)?;
    assert!(
        stream
            .feed(
                b"wait4(24, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG, NULL) = 24\n",
                2
            )
            .is_err()
    );
    assert!(stream.complete().is_err());
    for suffix in [
        b"+++ exited with 0 +++".as_slice(),
        b"+++ exited with 0 +++\n+++ exited with 0 +++\n".as_slice(),
        b"+++ exited with 0 +++\n--- SIGTERM {si_signo=SIGTERM} ---\n".as_slice(),
    ] {
        let mut stream = Stream::default();
        let base = complete_trace("[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]");
        let marker = base.windows(3).position(|w| w == b"+++").ok_or("test-marker")?;
        let fed = stream.feed(&[&base[..marker], suffix].concat(), 3);
        assert!(fed.is_err() || stream.complete().is_err());
    }
    Ok(())
}
#[test]
fn inclusive_record_and_trace_limits_do_not_admit_overflow_or_truncated_success() -> TestResult {
    let mut stream = Stream::default();
    assert!(stream.feed(&vec![b'x'; RECORD_LIMIT + 1], 1).is_err());
    assert!(stream.complete().is_err());
    let mut stream = Stream {
        bytes: TRACE_LIMIT,
        ..Stream::default()
    };
    assert!(stream.feed(b"x", 1).is_err());
    let mut stream = Stream::default();
    stream.feed(b"strace: Process 21 attached\n", 1)?;
    assert!(stream.complete().is_err());
    Ok(())
}
#[test]
fn each_ack_fragment_requires_exact_original_sender_and_complete_newline() -> TestResult {
    let expected = Sender {
        pid: 21,
        uid: 60_000,
        gid: 60_000,
    };
    let mut ack = Ack::default();
    ack.feed(b"{\"nonce\":", &[expected], expected, false, 1)?;
    assert!(ack.complete_ns.is_none());
    ack.feed(b"\"private\"}\n", &[expected], expected, false, 2)?;
    ack.end()?;
    assert_eq!(ack.bytes, b"{\"nonce\":\"private\"}\n");
    assert_eq!(ack.complete_ns, Some(2));
    for credentials in [
        vec![],
        vec![expected, expected],
        vec![Sender { pid: 22, ..expected }],
        vec![Sender { uid: 0, ..expected }],
        vec![Sender { gid: 0, ..expected }],
    ] {
        assert!(Ack::default().feed(b"x\n", &credentials, expected, false, 1).is_err());
    }
    assert!(Ack::default().feed(b"x\n", &[expected], expected, true, 1).is_err());
    assert!(Ack::default().feed(b"x\ny", &[expected], expected, false, 1).is_err());
    assert!(ack.feed(b"extra", &[expected], expected, false, 3).is_err());
    assert!(Ack::default().end().is_err());
    Ok(())
}
#[test]
fn ack_body_limit_reserves_only_one_final_newline() -> TestResult {
    let sender = Sender {
        pid: 21,
        uid: 1,
        gid: 1,
    };
    let mut ack = Ack::default();
    ack.feed(&vec![b'x'; RECORD_LIMIT], &[sender], sender, false, 1)?;
    ack.feed(b"\n", &[sender], sender, false, 2)?;
    assert_eq!(ack.bytes.len(), ACK_LIMIT);
    assert!(
        Ack::default()
            .feed(&vec![b'x'; ACK_LIMIT], &[sender], sender, false, 1)
            .is_err()
    );
    assert!(
        Ack::default()
            .feed(&vec![b'x'; ACK_LIMIT + 1], &[sender], sender, false, 1)
            .is_err()
    );
    Ok(())
}
#[test]
fn root_config_and_exec_arguments_are_finite_and_default_is_absent() -> TestResult {
    assert_eq!(selected().validate()?, sha_argument(TOOL_SHA)?);
    for value in ["", &"0".repeat(64), &"a".repeat(63), &"a".repeat(65), &"A".repeat(64)] {
        assert!(sha_argument(value).is_err());
    }
    assert!(
        Selection {
            profile: "trace-plugin".into(),
            tool_sha256: TOOL_SHA.into()
        }
        .validate()
        .is_err()
    );
    assert!(
        Selection {
            profile: PROFILE.into(),
            tool_sha256: "1".repeat(64)
        }
        .validate()
        .is_err()
    );
    assert!(
        serde_json::from_str::<Selection>(&format!(
            "{{\"profile\":\"{PROFILE}\",\"tool_sha256\":\"{TOOL_SHA}\",\"pid\":23}}"
        ))
        .is_err()
    );
    let vector = exec_vector(&[
        "journal".into(),
        "nonce".into(),
        "stage".into(),
        "100".into(),
        "200".into(),
    ]);
    assert_eq!(
        &vector[..12],
        [
            "/usr/bin/strace",
            "-D",
            "--trace=wait4",
            "--signal=all",
            "--interruptible=2",
            "--decode-pids=none",
            "--quiet=none",
            "--color=never",
            "--const-print-style=abbrev",
            "--",
            "/proc/self/fd/3",
            "observed-supervisor"
        ]
    );
    Ok(())
}
#[test]
fn archive_metadata_caps_types_and_names_require_no_evidence_body_reads() -> TestResult {
    let regular = Object {
        dev: 1,
        ino: 2,
        mode: 0o100_600,
        uid: 0,
        gid: 0,
        nlink: 1,
    };
    let fifo = Object {
        mode: 0o010_600,
        ..regular.clone()
    };
    archive_child("trace.bin", &regular, TRACE_LIMIT as u64)?;
    archive_child("ack.bin", &regular, ACK_LIMIT as u64)?;
    archive_child("record.json", &regular, 32_768)?;
    archive_child("trace.fifo", &fifo, 0)?;
    for (name, size) in [
        ("trace.bin", TRACE_LIMIT as u64 + 1),
        ("ack.bin", ACK_LIMIT as u64 + 1),
        ("origin.json", 65_537),
        ("retirement.json", 65_537),
        ("record.json", 32_769),
        ("unknown", 0),
        ("../record.json", 0),
    ] {
        assert!(archive_child(name, &regular, size).is_err());
    }
    for changed in [
        Object {
            mode: 0o120_600,
            ..regular.clone()
        },
        Object {
            mode: 0o040_600,
            ..regular.clone()
        },
        Object {
            nlink: 2,
            ..regular.clone()
        },
        Object {
            mode: 0o100_644,
            ..regular.clone()
        },
        Object {
            uid: 1,
            ..regular.clone()
        },
        Object {
            gid: 1,
            ..regular.clone()
        },
    ] {
        assert!(archive_child("trace.bin", &changed, 0).is_err());
    }
    assert!(archive_child("trace.fifo", &regular, 0).is_err());
    Ok(())
}
#[test]
fn active_reservation_counts_once_inside_the_unchanged_archive_cap() -> TestResult {
    super::super::journal::admit_inventory(15, 255)?;
    //255 finalized entries plus one active reserved observed directory occupies all256.
    assert!(super::super::journal::admit_inventory(15, 255 + 1).is_err());
    assert!(super::super::journal::admit_inventory(16, 0).is_err());
    Ok(())
}
#[test]
fn observed_initial_origin_is_durable_and_cannot_downgrade_or_rebind_pending() -> TestResult {
    let live = observed()?;
    super::super::journal::pending_binding(&live, &live)?;
    let mut missing = live.clone();
    missing.observer = None;
    assert!(super::super::journal::pending_binding(&live, &missing).is_err());
    for changed in ["wire", "tool", "profile", "helper", "path"] {
        let mut candidate = live.clone();
        let observer = candidate.observer.as_mut().ok_or("test-observer")?;
        match changed {
            "wire" => observer.request_sha256 = [9; 32],
            "tool" => observer.selection.tool_sha256 = "1".repeat(64),
            "profile" => observer.selection.profile = "unknown".into(),
            "helper" => observer.helper_sha256 = [3; 32],
            _ => observer.evidence = PathBuf::from(format!("/other/archive/{}.json", live.ownership.nonce)),
        }
        assert!(super::super::journal::pending_binding(&live, &candidate).is_err());
    }
    assert!(super::super::journal::pending_candidate(&live, &vec![b'x'; 32_769]).is_err());
    Ok(())
}
#[test]
fn mixed_archive_forms_and_all_missing_proof_prefixes_never_retire_observed() -> TestResult {
    let observed = observed()?;
    let unobserved = route::cleanup_contract_tests::intent()?;
    archive_form(&unobserved, false, true)?;
    archive_form(&observed, true, false)?;
    assert!(archive_form(&unobserved, true, true).is_err());
    assert!(archive_form(&observed, false, true).is_err());
    assert!(archive_form(&observed, true, true).is_err());
    assert!(super::super::journal::pending_candidate(&observed, b"{\"schema\":1").is_err());
    assert!(format!("{:?}", observed.observer).contains("<private>"));
    Ok(())
}

#[test]
fn actual_recvmsg_fragments_authenticate_credentials_and_natural_eof() -> TestResult {
    let (mut sender, receiver) = UnixStream::pair()?;
    net::sockopt::set_socket_passcred(&receiver, true)?;
    let expected = Sender {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
    };
    let mut ack = Ack::default();
    assert!(receive_ack_chunk(&receiver)?.is_none());
    for (bytes, ns) in [(b"{\"child\":".as_slice(), 10), (b"23}\n".as_slice(), 20)] {
        sender.write_all(bytes)?;
        let chunk = receive_ack_chunk(&receiver)?.ok_or("test-missing-chunk")?;
        assert_eq!(chunk.credentials, [expected]);
        assert!(!chunk.invalid);
        ack.feed(&chunk.bytes, &chunk.credentials, expected, chunk.invalid, ns)?;
    }
    assert_eq!(ack.complete_ns, Some(20));
    sender.shutdown(std::net::Shutdown::Write)?;
    let eof = receive_ack_chunk(&receiver)?.ok_or("test-missing-eof")?;
    assert!(eof.bytes.is_empty() && eof.credentials.is_empty() && !eof.invalid);
    ack.end()?;
    assert!(ack.eof);
    Ok(())
}
#[test]
fn actual_recvmsg_missing_or_wrong_credentials_cannot_contribute_ack() -> TestResult {
    let expected = Sender {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
    };
    let (mut sender, receiver) = UnixStream::pair()?;
    sender.write_all(b"{}\n")?;
    let chunk = receive_ack_chunk(&receiver)?.ok_or("test-missing-chunk")?;
    assert!(chunk.credentials.is_empty());
    assert!(
        Ack::default()
            .feed(&chunk.bytes, &chunk.credentials, expected, chunk.invalid, 10)
            .is_err()
    );
    let (mut sender, receiver) = UnixStream::pair()?;
    net::sockopt::set_socket_passcred(&receiver, true)?;
    sender.write_all(b"{}\n")?;
    let chunk = receive_ack_chunk(&receiver)?.ok_or("test-missing-chunk")?;
    let wrong = Sender {
        pid: expected.pid + 1,
        ..expected
    };
    assert!(
        Ack::default()
            .feed(&chunk.bytes, &chunk.credentials, wrong, chunk.invalid, 10)
            .is_err()
    );
    Ok(())
}
#[test]
fn fifo_quantum_yields_under_continuous_data_or_repeated_interrupts() -> TestResult {
    struct Infinite {
        reads: usize,
        interrupted: bool,
    }
    impl Read for Infinite {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.interrupted {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            bytes.fill(b'a');
            Ok(bytes.len())
        }
    }
    for interrupted in [false, true] {
        let mut reader = Infinite { reads: 0, interrupted };
        let mut consumed = 0;
        assert!(!drain_fifo(&mut reader, |bytes| {
            consumed += bytes.len();
            Ok(())
        })?);
        assert_eq!(reader.reads, 16);
        assert_eq!(consumed, if interrupted { 0 } else { 65_536 });
    }
    let mut empty = std::io::Cursor::new(Vec::<u8>::new());
    assert!(drain_fifo(&mut empty, |_| Err("test-unexpected-consumption"))?);
    Ok(())
}
fn origin_for(record: &super::super::journal::Record) -> TestResultOrigin {
    let object = Object {
        dev: 1,
        ino: 2,
        mode: 0o100_600,
        uid: 0,
        gid: 0,
        nlink: 1,
    };
    let observation = record.observer.as_ref().ok_or("test-observer")?;
    Ok(Origin {
        request_sha256: observation.request_sha256,
        nonce: record.ownership.nonce.clone(),
        boot: record.boot.clone(),
        execution_ns: record.execution_ns,
        total_ns: record.total_end_ns()?,
        work_invocation: "1".repeat(32),
        supervisor: Identity { pid: 21, start: 4 },
        bwrap: Identity { pid: 23, start: 5 },
        tracer: Identity { pid: 24, start: 6 },
        controller: Identity {
            pid: record.controller_pid,
            start: record.controller_start,
        },
        uid: 2000,
        gid: 2000,
        readiness_complete_ns: 1,
        helper_sha256: observation.helper_sha256,
        tool_sha256: selected().validate()?,
        pid_namespace: (1, 2),
        user_namespace: (1, INITIAL_USER_INODE),
        fifo: Object {
            mode: 0o010_600,
            ..object.clone()
        },
        trace: object.clone(),
        ack: object,
    })
}
type TestResultOrigin = std::result::Result<Origin, Box<dyn std::error::Error>>;
#[test]
fn origin_and_retirement_can_append_once_then_never_change_or_disappear() -> TestResult {
    let initial = observed()?;
    let mut ready = initial.clone();
    ready.uid = Some(2000);
    ready.observer.as_mut().ok_or("test-observer")?.origin = Some(origin_for(&initial)?);
    super::super::journal::pending_binding(&initial, &ready)?;
    assert!(super::super::journal::pending_binding(&ready, &initial).is_err());
    let mut altered = ready.clone();
    altered
        .observer
        .as_mut()
        .and_then(|o| o.origin.as_mut())
        .ok_or("test-origin")?
        .pid_namespace = (1, 3);
    assert!(super::super::journal::pending_binding(&ready, &altered).is_err());
    let mut sealed = ready.clone();
    sealed.observer.as_mut().ok_or("test-observer")?.proof = Some(Proof {
        origin_sha256: [3; 32],
        trace_sha256: [4; 32],
        ack_sha256: [5; 32],
        trace_bytes: 100,
        ack_bytes: 10,
        ack_complete_ns: 2,
        consuming_wait_complete_ns: 3,
        terminal_complete_ns: 4,
        retired_ns: 5,
        natural_eof: true,
        tracer_dead: true,
        zero_writers: true,
    });
    super::super::journal::pending_binding(&ready, &sealed)?;
    assert!(super::super::journal::pending_binding(&sealed, &ready).is_err());
    let mut changed = sealed.clone();
    changed
        .observer
        .as_mut()
        .and_then(|o| o.proof.as_mut())
        .ok_or("test-proof")?
        .trace_sha256 = [9; 32];
    assert!(super::super::journal::pending_binding(&sealed, &changed).is_err());
    archive_form(&sealed, true, true)?;
    Ok(())
}

#[test]
fn actual_recvmsg_extra_rights_cannot_fit_credential_only_capacity() -> TestResult {
    use std::{io::IoSlice, os::fd::AsFd};
    let (sender, receiver) = UnixStream::pair()?;
    net::sockopt::set_socket_passcred(&receiver, true)?;
    let file = File::open("/dev/null")?;
    let rights = [file.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
    assert!(ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)));
    assert_eq!(
        net::sendmsg(
            &sender,
            &[IoSlice::new(b"{}\n")],
            &mut ancillary,
            net::SendFlags::empty()
        )?,
        3
    );
    let chunk = receive_ack_chunk(&receiver)?.ok_or("test-missing-chunk")?;
    assert!(chunk.invalid);
    let expected = Sender {
        pid: std::process::id(),
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
    };
    assert!(
        Ack::default()
            .feed(&chunk.bytes, &chunk.credentials, expected, chunk.invalid, 10)
            .is_err()
    );
    Ok(())
}

#[test]
fn initial_namespace_source_predicate_rejects_maps_labels_and_forged_links() -> TestResult {
    let proc = i128::from(rustix::fs::PROC_SUPER_MAGIC);
    namespace_fact(NSFS_MAGIC, proc, 4_026_531_837, b"user:[4026531837]")?;
    for (magic, pm, ino, link) in [
        (0, proc, 4_026_531_837, b"user:[4026531837]".as_slice()),
        (NSFS_MAGIC, 0, 4_026_531_837, b"user:[4026531837]".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_840, b"user:[4026531837]".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_837, b"mnt:[4026531837]".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_837, b"user:[4026531837]\n".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_837, b"user:[402653183".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_837, b"/proc/1/ns/user".as_slice()),
        (NSFS_MAGIC, proc, 4_026_531_837, b"0 0 4294967295".as_slice()),
    ] {
        assert!(namespace_fact(magic, pm, ino, link).is_err());
    }
    // Ordinary files cannot become a namespace witness even with a matching caller label.
    assert!(initial_namespace(&File::open("/dev/null")?).is_err());
    Ok(())
}
