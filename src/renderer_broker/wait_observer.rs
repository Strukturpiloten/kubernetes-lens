//! Finite root-selected stock-strace evidence. Raw bytes remain private; disappearance is not reap.
use super::{Result, audit, authority, route};
use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

pub(super) const PROFILE: &str = "strace-7.2-supervisor-wait-v1";
const TOOL: &str = "/usr/bin/strace";
const TOOL_SHA: &str = "508698af314d3fad6bed553d0dcb59e5002732339ea205ebcce1c617dd368b92";
const TRACE_LIMIT: usize = 4 * 1024 * 1024;
const RECORD_LIMIT: usize = 65_536;
const ACK_LIMIT: usize = 65_537;
const PUMP_CHUNKS: usize = 16;
const INITIAL_USER_INODE: u64 = 4_026_531_837;
const NSFS_MAGIC: i128 = 0x6e73_6673;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub profile: String,
    pub tool_sha256: String,
}
impl Selection {
    pub fn validate(&self) -> Result<[u8; 32]> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
            || self.profile != PROFILE
            || self.tool_sha256 != TOOL_SHA
        {
            return Err("observer-profile");
        }
        sha_argument(&self.tool_sha256)
    }
}
pub(super) fn sha_argument(raw: &str) -> Result<[u8; 32]> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("observer-sha-argument");
    }
    let mut out = [0; 32];
    for (i, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        let value = std::str::from_utf8(pair).map_err(|_| "observer-sha-argument")?;
        out[i] = u8::from_str_radix(value, 16).map_err(|_| "observer-sha-argument")?;
    }
    if out == [0; 32] {
        return Err("observer-sha-argument");
    }
    Ok(out)
}
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 15)]),
            ]
        })
        .collect()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub pid: u32,
    pub start: u64,
}
impl Identity {
    fn of(pid: &authority::HeldPid) -> Self {
        Self {
            pid: pid.pid,
            start: pid.start,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Object {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}
impl Object {
    fn of(file: &File) -> Result<Self> {
        Self::metadata(&file.metadata().map_err(|_| "observer-object-stat")?)
    }
    fn metadata(m: &fs::Metadata) -> Result<Self> {
        if m.uid() != 0 || m.gid() != 0 || m.nlink() != 1 || m.mode() & 0o777 != 0o600 {
            return Err("observer-object-owner");
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            nlink: m.nlink(),
        })
    }
    fn matches(&self, path: &Path, file: &File) -> Result<()> {
        if &Self::of(file)? != self
            || &Self::metadata(&fs::symlink_metadata(path).map_err(|_| "observer-object-path")?)? != self
        {
            return Err("observer-object-changed");
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Origin {
    pub request_sha256: [u8; 32],
    pub nonce: String,
    pub boot: String,
    pub execution_ns: u64,
    pub total_ns: u64,
    pub work_invocation: String,
    pub supervisor: Identity,
    pub bwrap: Identity,
    pub tracer: Identity,
    pub controller: Identity,
    pub uid: u32,
    pub gid: u32,
    pub readiness_complete_ns: u64,
    pub helper_sha256: [u8; 32],
    pub tool_sha256: [u8; 32],
    pid_namespace: (u64, u64),
    user_namespace: (u64, u64),
    fifo: Object,
    trace: Object,
    ack: Object,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    pub origin_sha256: [u8; 32],
    pub trace_sha256: [u8; 32],
    pub ack_sha256: [u8; 32],
    pub trace_bytes: usize,
    pub ack_bytes: usize,
    pub ack_complete_ns: u64,
    pub consuming_wait_complete_ns: u64,
    pub terminal_complete_ns: u64,
    pub retired_ns: u64,
    pub natural_eof: bool,
    pub tracer_dead: bool,
    pub zero_writers: bool,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub selection: Selection,
    pub request_sha256: [u8; 32],
    pub helper_sha256: [u8; 32],
    pub evidence: PathBuf,
    pub origin: Option<Origin>,
    pub proof: Option<Proof>,
}
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Observation(<private>)")
    }
}
impl Observation {
    pub fn validate(&self, nonce: &str) -> Result<()> {
        self.selection.validate()?;
        if self.request_sha256 == [0; 32]
            || self.helper_sha256 == [0; 32]
            || !self.evidence.is_absolute()
            || self.evidence.file_name().and_then(|s| s.to_str()) != Some(format!("{nonce}.json").as_str())
            || self
                .evidence
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                != Some("archive")
        {
            return Err("observer-journal-binding");
        }
        if let Some(origin) = &self.origin {
            if origin.nonce != nonce
                || origin.request_sha256 != self.request_sha256
                || origin.helper_sha256 != self.helper_sha256
                || origin.tool_sha256 != self.selection.validate()?
                || origin.uid == 0
                || origin.gid != origin.uid
                || origin.pid_namespace.0 == 0
                || origin.pid_namespace.1 == 0
                || origin.user_namespace.0 == 0
                || origin.user_namespace.1 != INITIAL_USER_INODE
                || origin.work_invocation.len() != 32
                || !origin
                    .work_invocation
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || [&origin.supervisor, &origin.bwrap, &origin.tracer, &origin.controller]
                    .iter()
                    .any(|i| i.pid <= 1 || i.start == 0)
            {
                return Err("observer-origin-scalar-binding");
            }
            archive_child("trace.fifo", &origin.fifo, 0)?;
            archive_child("trace.bin", &origin.trace, 0)?;
            archive_child("ack.bin", &origin.ack, 0)?;
        }
        if let Some(p) = &self.proof {
            if self.origin.is_none()
                || [p.origin_sha256, p.trace_sha256, p.ack_sha256].contains(&[0; 32])
                || !p.natural_eof
                || !p.tracer_dead
                || !p.zero_writers
                || p.trace_bytes == 0
                || p.trace_bytes > TRACE_LIMIT
                || p.ack_bytes == 0
                || p.ack_bytes > ACK_LIMIT
                || p.ack_complete_ns == 0
                || p.consuming_wait_complete_ns == 0
                || p.terminal_complete_ns == 0
            {
                return Err("observer-proof-incomplete");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    Exit(u8),
    Signal { number: u8, core: bool },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Attach(u32),
    Startup(u32),
    Zero(u32),
    Consumed(u32, Status),
    Auxiliary,
    Terminal(Status),
}
fn decimal(raw: &str, max: u32) -> Result<u32> {
    if raw.is_empty() || (raw.len() > 1 && raw.starts_with('0')) || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("observer-decimal");
    }
    raw.parse::<u32>().ok().filter(|n| *n <= max).ok_or("observer-decimal")
}
fn pid(raw: &str) -> Result<u32> {
    decimal(raw, i32::MAX as u32).and_then(|n| if n > 0 { Ok(n) } else { Err("observer-pid") })
}
fn signal(raw: &str) -> Result<u8> {
    const NAMES: [&str; 31] = [
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    if let Some(i) = NAMES.iter().position(|n| *n == raw) {
        return u8::try_from(i + 1).map_err(|_| "observer-signal");
    }
    if raw == "SIGRTMIN" {
        return Ok(32);
    }
    if let Some(offset) = raw.strip_prefix("SIGRT_") {
        let n = decimal(offset, 32)?;
        if n > 0 {
            return u8::try_from(n + 32).map_err(|_| "observer-signal");
        }
    }
    Err("observer-signal")
}
fn status(raw: &str) -> Result<Status> {
    if let Some(code) = raw
        .strip_prefix("[{WIFEXITED(s) && WEXITSTATUS(s) == ")
        .and_then(|s| s.strip_suffix("}]"))
    {
        return Ok(Status::Exit(
            u8::try_from(decimal(code, 255)?).map_err(|_| "observer-exit")?,
        ));
    }
    if let Some(sig) = raw
        .strip_prefix("[{WIFSIGNALED(s) && WTERMSIG(s) == ")
        .and_then(|s| s.strip_suffix("}]"))
    {
        let (sig, core) = sig.strip_suffix(" && WCOREDUMP(s)").map_or((sig, false), |s| (s, true));
        return Ok(Status::Signal {
            number: signal(sig)?,
            core,
        });
    }
    Err("observer-status")
}
fn event(raw: &[u8]) -> Result<Event> {
    if raw.is_empty() || raw.len() > RECORD_LIMIT || !raw.iter().all(|b| (0x20..=0x7e).contains(b) || *b == b'\t') {
        return Err("observer-record");
    }
    let s = std::str::from_utf8(raw).map_err(|_| "observer-record")?;
    if let Some(p) = s
        .strip_prefix("strace: Process ")
        .and_then(|s| s.strip_suffix(" attached"))
    {
        return Ok(Event::Attach(pid(p)?));
    }
    if let Some(n) = s.strip_prefix("+++ exited with ").and_then(|s| s.strip_suffix(" +++")) {
        return Ok(Event::Terminal(Status::Exit(
            u8::try_from(decimal(n, 255)?).map_err(|_| "observer-exit")?,
        )));
    }
    if let Some(n) = s.strip_prefix("+++ killed by ").and_then(|s| s.strip_suffix(" +++")) {
        let (n, core) = n.strip_suffix(" (core dumped)").map_or((n, false), |s| (s, true));
        return Ok(Event::Terminal(Status::Signal {
            number: signal(n)?,
            core,
        }));
    }
    if let Some(aux) = s.strip_prefix("--- ").and_then(|s| s.strip_suffix(" ---")) {
        let (sig, info) = aux.split_once(' ').ok_or("observer-siginfo")?;
        signal(sig)?;
        if !info.starts_with('{') || !info.ends_with('}') {
            return Err("observer-siginfo");
        }
        let mut depth = 0i32;
        for (i, b) in info.bytes().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => (),
            }
            if depth < 0 || (depth == 0 && i + 1 != info.len()) {
                return Err("observer-siginfo");
            }
        }
        if depth != 0 {
            return Err("observer-siginfo");
        }
        return Ok(Event::Auxiliary);
    }
    let (call, result) = s.rsplit_once("= ").ok_or("observer-wait-separator")?;
    if !call.ends_with([' ', '\t']) {
        return Err("observer-wait-separator");
    }
    let call = call.trim_end_matches([' ', '\t']);
    let args = call
        .strip_prefix("wait4(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or("observer-wait-grammar")?;
    let (selector, rest) = args.split_once(", ").ok_or("observer-wait-grammar")?;
    if selector == "-1" && rest == "NULL, 0, NULL" {
        return Ok(Event::Startup(pid(result)?));
    }
    let child = pid(selector)?;
    let value = rest.strip_suffix(", WNOHANG, NULL").ok_or("observer-wait-flags")?;
    if let Some(pointer) = value.strip_prefix("0x") {
        if pointer.is_empty()
            || pointer.len() > 16
            || !pointer
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || u64::from_str_radix(pointer, 16).ok().is_none_or(|n| n == 0)
            || result != "0"
        {
            return Err("observer-zero-wait");
        }
        return Ok(Event::Zero(child));
    }
    if pid(result)? != child {
        return Err("observer-wait-return");
    }
    Ok(Event::Consumed(child, status(value)?))
}

#[derive(Default)]
struct Stream {
    tail: Vec<u8>,
    bytes: usize,
    attached: Option<u32>,
    child: Option<u32>,
    consumed: Option<(Status, u64)>,
    terminal: Option<(Status, u64)>,
    zero: Option<u32>,
    failed: bool,
    eof: bool,
}
impl Stream {
    fn feed(&mut self, chunk: &[u8], received_ns: u64) -> Result<()> {
        if self.failed || self.eof || self.bytes.checked_add(chunk.len()).is_none_or(|n| n > TRACE_LIMIT) {
            self.failed = true;
            return Err("observer-stream-budget-or-closed");
        }
        self.bytes += chunk.len();
        for &b in chunk {
            if b == b'\n' {
                let line = std::mem::take(&mut self.tail);
                if let Err(e) = self.record(&line, received_ns) {
                    self.failed = true;
                    return Err(e);
                }
            } else {
                self.tail.push(b);
                if self.tail.len() > RECORD_LIMIT {
                    self.failed = true;
                    return Err("observer-record-budget");
                }
            }
        }
        Ok(())
    }
    fn record(&mut self, line: &[u8], ns: u64) -> Result<()> {
        if self.terminal.is_some() {
            return Err("observer-trailing-terminal");
        }
        match event(line)? {
            Event::Attach(p) if self.attached.is_none() => self.attached = Some(p),
            Event::Attach(_) => return Err("observer-duplicate-attach"),
            Event::Startup(_) if self.zero.is_none() && self.consumed.is_none() => (),
            Event::Startup(_) => return Err("observer-late-startup"),
            Event::Zero(p) if self.attached.is_some() && self.consumed.is_none() => {
                if self.zero.is_some_and(|old| old != p) || self.child.is_some_and(|old| old != p) {
                    return Err("observer-zero-child");
                }
                self.zero = Some(p);
            }
            Event::Zero(_) => return Err("observer-zero-order"),
            Event::Consumed(p, s) if self.attached.is_some() && self.zero == Some(p) && self.consumed.is_none() => {
                self.consumed = Some((s, ns));
            }
            Event::Consumed(_, _) => return Err("observer-consuming-order"),
            Event::Auxiliary => (),
            Event::Terminal(s) if self.attached.is_some() => self.terminal = Some((s, ns)),
            Event::Terminal(_) => return Err("observer-terminal-order"),
        }
        Ok(())
    }
    fn bind(&mut self, supervisor: u32, child: u32) -> Result<()> {
        if self.failed
            || self.attached != Some(supervisor)
            || self.zero != Some(child)
            || self.consumed.is_some()
            || self.terminal.is_some()
        {
            return Err("observer-not-ready");
        }
        self.child = Some(child);
        Ok(())
    }
    fn complete(&mut self) -> Result<()> {
        if self.failed || !self.tail.is_empty() || self.terminal.is_none() {
            self.failed = true;
            return Err("observer-incomplete-stream");
        }
        self.eof = true;
        Ok(())
    }
    fn retirement(&self, native: Status) -> Result<(u64, u64)> {
        if self.failed
            || !self.eof
            || self.child.is_none()
            || self.consumed.map(|x| x.0) != Some(native)
            || self.terminal != self.terminal.filter(|x| x.0 == Status::Exit(0))
        {
            return Err("observer-natural-retirement-unproved");
        }
        Ok((
            self.consumed.ok_or("observer-no-consuming-wait")?.1,
            self.terminal.ok_or("observer-no-terminal")?.1,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sender {
    pid: u32,
    uid: u32,
    gid: u32,
}
#[derive(Default)]
struct Ack {
    bytes: Vec<u8>,
    complete_ns: Option<u64>,
    eof: bool,
}
impl Ack {
    fn feed(&mut self, bytes: &[u8], credentials: &[Sender], expected: Sender, truncated: bool, ns: u64) -> Result<()> {
        if truncated
            || credentials != [expected]
            || self.complete_ns.is_some()
            || self.eof
            || bytes.is_empty()
            || self.bytes.len().checked_add(bytes.len()).is_none_or(|n| n > ACK_LIMIT)
        {
            return Err("observer-ack-chunk");
        }
        if bytes
            .iter()
            .position(|b| *b == b'\n')
            .is_some_and(|i| i + 1 != bytes.len())
        {
            return Err("observer-ack-trailing");
        }
        self.bytes.extend_from_slice(bytes);
        if bytes.last() == Some(&b'\n') {
            self.complete_ns = Some(ns);
        } else if self.bytes.len() > RECORD_LIMIT {
            return Err("observer-ack-body-budget");
        }
        Ok(())
    }
    fn end(&mut self) -> Result<()> {
        if self.complete_ns.is_none() {
            return Err("observer-ack-partial");
        }
        self.eof = true;
        Ok(())
    }
}

// Only the owning controller/tracer threads pump. This is not a collector thread or plugin.
pub(super) type Handle = Arc<Mutex<Capture>>;
thread_local! {static ACTIVE:RefCell<Option<Handle>>=const {RefCell::new(None)};}
pub(super) struct PumpGuard(Option<Handle>);
pub(super) fn set_active(handle: Option<Handle>) {
    ACTIVE.with(|s| {
        s.replace(handle);
    });
}
pub(super) fn install(handle: Option<Handle>) -> PumpGuard {
    PumpGuard(ACTIVE.with(|s| s.replace(handle)))
}
impl Drop for PumpGuard {
    fn drop(&mut self) {
        ACTIVE.with(|s| {
            s.replace(self.0.take());
        });
    }
}
pub(super) fn pump() -> Result<()> {
    let handle = ACTIVE.with(|s| s.borrow().clone());
    if let Some(handle) = handle {
        handle.lock().map_err(|_| "observer-pump-lock")?.pump()?;
    }
    Ok(())
}

pub(super) struct Capture {
    directory: PathBuf,
    fifo: File,
    fifo_object: Object,
    trace: File,
    trace_object: Object,
    ack_file: File,
    ack_object: Object,
    stream: Stream,
    ack: Ack,
    trace_hash: Sha256,
    origin: Option<Origin>,
    origin_sha: Option<[u8; 32]>,
    tracer: Option<authority::HeldPid>,
    namespaces: Vec<File>,
    initial_user_namespace: File,
    user_namespaces: Vec<File>,
    failed: Option<&'static str>,
    sealed: bool,
}
#[derive(Clone, Copy)]
pub(super) struct Readiness<'a> {
    pub supervisor: &'a authority::HeldPid,
    pub bwrap: &'a authority::HeldPid,
    pub gate: &'a authority::HeldPid,
    pub uid: u32,
    pub work: &'a str,
    pub cgroup: &'a Path,
    pub d: &'a route::Descriptor,
}
impl Capture {
    pub fn create(observation: &Observation) -> Result<Handle> {
        let initial_user_namespace = File::open("/proc/self/ns/user").map_err(|_| "observer-initial-user-namespace")?;
        initial_namespace(&initial_user_namespace)?;
        let directory = &observation.evidence;
        route::root_ancestry(directory.parent().ok_or("observer-parent")?)?;
        fs::create_dir(directory).map_err(|_| "observer-evidence-create")?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|_| "observer-evidence-mode")?;
        route::root_ancestry(directory)?;
        nix::unistd::mkfifo(
            &directory.join("trace.fifo"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| "observer-fifo-create")?;
        let fifo = OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(directory.join("trace.fifo"))
            .map_err(|_| "observer-fifo-open")?;
        if !fifo.metadata().map_err(|_| "observer-fifo-stat")?.file_type().is_fifo() {
            return Err("observer-fifo-kind");
        }
        let trace = private_new(&directory.join("trace.bin"))?;
        let ack_file = private_new(&directory.join("ack.bin"))?;
        let result = Self {
            directory: directory.clone(),
            fifo_object: Object::of(&fifo)?,
            trace_object: Object::of(&trace)?,
            ack_object: Object::of(&ack_file)?,
            fifo,
            trace,
            ack_file,
            stream: Stream::default(),
            ack: Ack::default(),
            trace_hash: Sha256::new(),
            origin: None,
            origin_sha: None,
            tracer: None,
            namespaces: Vec::new(),
            initial_user_namespace,
            user_namespaces: Vec::new(),
            failed: None,
            sealed: false,
        };
        Ok(Arc::new(Mutex::new(result)))
    }
    fn pump(&mut self) -> Result<()> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.sealed {
            return Ok(());
        }
        let result = self.pump_inner();
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }
    fn pump_inner(&mut self) -> Result<()> {
        self.fifo_object
            .matches(&self.directory.join("trace.fifo"), &self.fifo)?;
        self.trace_object
            .matches(&self.directory.join("trace.bin"), &self.trace)?;
        let eof = drain_fifo(&mut self.fifo, |bytes| {
            if self
                .stream
                .bytes
                .checked_add(bytes.len())
                .is_none_or(|n| n > TRACE_LIMIT)
            {
                return Err("observer-trace-overflow");
            }
            self.trace.write_all(bytes).map_err(|_| "observer-trace-write")?;
            self.trace_hash.update(bytes);
            self.stream.feed(bytes, route::monotonic_ns()?)
        })?;
        if eof && self.stream.attached.is_some() {
            self.stream.complete()?;
        }
        Ok(())
    }
    pub fn ready(&mut self, readiness: Readiness<'_>) -> Result<()> {
        let Readiness {
            supervisor,
            bwrap,
            gate,
            uid,
            work,
            cgroup,
            d,
        } = readiness;
        let _paused = install(None);
        self.pump()?;
        if self.origin.is_some() {
            return self.recheck(supervisor, bwrap, uid, cgroup, d);
        }
        self.stream.bind(supervisor.pid, bwrap.pid)?;
        let status = audit::status(supervisor.pid)?;
        let tracer_pid = status
            .get("TracerPid")
            .and_then(|s| s.parse().ok())
            .ok_or("observer-tracer-pid")?;
        let tracer = authority::HeldPid::open(tracer_pid)?;
        for held in [supervisor, bwrap, &tracer] {
            held.verify()?;
            audit::credentials(held.pid, uid)?;
            audit::single_thread(held.pid)?;
        }
        capability_free(supervisor.pid, uid)?;
        capability_free(tracer.pid, uid)?;
        let user_namespace = initial_namespace(&self.initial_user_namespace)?;
        for p in [std::process::id(), supervisor.pid, tracer.pid] {
            let held = File::open(format!("/proc/{p}/ns/user")).map_err(|_| "observer-user-namespace-held")?;
            if initial_namespace(&held)? != user_namespace {
                return Err("observer-user-namespace-readiness");
            }
            self.user_namespaces.push(held);
        }
        let mut image = File::open(format!("/proc/{}/exe", tracer.pid)).map_err(|_| "observer-tracer-image")?;
        if authority::digest_file_checked(&mut image, route::instant(d.execution_ns)?, &mut || self.pump())?
            != d.observer.as_ref().ok_or("observer-selection")?.validate()?
        {
            return Err("observer-tracer-image");
        }
        let pid_namespace = namespace(std::process::id(), "pid")?;
        for p in [std::process::id(), supervisor.pid, bwrap.pid, tracer.pid] {
            let ns = File::open(format!("/proc/{p}/ns/pid")).map_err(|_| "observer-pid-namespace")?;
            let m = ns.metadata().map_err(|_| "observer-pid-namespace")?;
            if (m.dev(), m.ino()) != pid_namespace {
                return Err("observer-pid-namespace");
            }
            self.namespaces.push(ns);
        }
        if authority::Object::path(&PathBuf::from(format!("/proc/{}/fd/2", tracer.pid)))?
            != authority::Object::of(&self.fifo)?
        {
            return Err("observer-tracer-fifo");
        }
        if authority::bounded(&PathBuf::from(format!("/proc/{}/cgroup", tracer.pid)), 4096)?
            != authority::bounded(&PathBuf::from(format!("/proc/{}/cgroup", supervisor.pid)), 4096)?
        {
            return Err("observer-tracer-cgroup");
        }
        audit::census(
            uid,
            &[supervisor.pid, bwrap.pid, gate.pid, tracer.pid],
            route::instant(d.execution_ns)?,
        )?;
        let controller = authority::HeldPid::open(std::process::id())?;
        let origin = Origin {
            request_sha256: d.request_sha256.ok_or("observer-request-origin")?,
            nonce: d.nonce.clone(),
            boot: d.boot.clone(),
            execution_ns: d.execution_ns,
            total_ns: d.header.total_end_ns().map_err(|_| "observer-total")?,
            work_invocation: work.into(),
            supervisor: Identity::of(supervisor),
            bwrap: Identity::of(bwrap),
            tracer: Identity::of(&tracer),
            controller: Identity::of(&controller),
            uid,
            gid: uid,
            readiness_complete_ns: route::monotonic_ns()?,
            helper_sha256: d.helper_sha,
            tool_sha256: d.observer.as_ref().ok_or("observer-selection")?.validate()?,
            pid_namespace,
            user_namespace,
            fifo: self.fifo_object.clone(),
            trace: self.trace_object.clone(),
            ack: self.ack_object.clone(),
        };
        self.origin_sha = Some(private_json(&self.directory.join("origin.json"), &origin)?);
        self.origin = Some(origin);
        self.tracer = Some(tracer);
        self.recheck(supervisor, bwrap, uid, cgroup, d)
    }
    fn recheck(
        &self,
        supervisor: &authority::HeldPid,
        bwrap: &authority::HeldPid,
        uid: u32,
        cgroup: &Path,
        d: &route::Descriptor,
    ) -> Result<()> {
        let origin = self.origin.as_ref().ok_or("observer-origin")?;
        let tracer = self.tracer.as_ref().ok_or("observer-tracer")?;
        if origin.supervisor != Identity::of(supervisor)
            || origin.bwrap != Identity::of(bwrap)
            || origin.request_sha256 != d.request_sha256.ok_or("observer-request-origin")?
            || origin.uid != uid
        {
            return Err("observer-origin-changed");
        }
        tracer.verify()?;
        supervisor.verify()?;
        bwrap.verify()?;
        if audit::status(supervisor.pid)?
            .get("TracerPid")
            .and_then(|s| s.parse::<u32>().ok())
            != Some(tracer.pid)
        {
            return Err("observer-attach-lost");
        }
        if authority::bounded(&PathBuf::from(format!("/proc/{}/cgroup", tracer.pid)), 4096)?
            != format!(
                "0::{}\n",
                cgroup
                    .strip_prefix("/sys/fs/cgroup")
                    .map_err(|_| "observer-cgroup")?
                    .display()
            )
            .as_bytes()
        {
            return Err("observer-cgroup-changed");
        }
        for (i, p) in [std::process::id(), supervisor.pid, bwrap.pid, tracer.pid]
            .into_iter()
            .enumerate()
        {
            let held = self
                .namespaces
                .get(i)
                .ok_or("observer-namespace-held")?
                .metadata()
                .map_err(|_| "observer-namespace-held")?;
            if (held.dev(), held.ino()) != origin.pid_namespace || namespace(p, "pid")? != origin.pid_namespace {
                return Err("observer-namespace-changed");
            }
        }
        if initial_namespace(&self.initial_user_namespace)? != origin.user_namespace {
            return Err("observer-initial-witness-changed");
        }
        for (i, p) in [std::process::id(), supervisor.pid, tracer.pid].into_iter().enumerate() {
            let retained = self.user_namespaces.get(i).ok_or("observer-user-namespace-held")?;
            let actual = File::open(format!("/proc/{p}/ns/user")).map_err(|_| "observer-user-namespace-held")?;
            if initial_namespace(retained)? != origin.user_namespace
                || initial_namespace(&actual)? != origin.user_namespace
            {
                return Err("observer-user-namespace-changed");
            }
        }
        Ok(())
    }
    pub fn receive_ack(&mut self, socket: &UnixStream) -> Result<Option<Vec<u8>>> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.receive_ack_inner(socket);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }
    fn receive_ack_inner(&mut self, socket: &UnixStream) -> Result<Option<Vec<u8>>> {
        let origin = self.origin.as_ref().ok_or("observer-ack-origin")?;
        let expected = Sender {
            pid: origin.supervisor.pid,
            uid: origin.uid,
            gid: origin.gid,
        };
        let Some(chunk) = receive_ack_chunk(socket)? else {
            return Ok(None);
        };
        if chunk.bytes.is_empty() {
            if chunk.invalid || !chunk.credentials.is_empty() {
                return Err("observer-ack-eof-ancillary");
            }
            self.ack.end()?;
            return Ok(None);
        }
        self.ack.feed(
            &chunk.bytes,
            &chunk.credentials,
            expected,
            chunk.invalid,
            route::monotonic_ns()?,
        )?;
        self.ack_object
            .matches(&self.directory.join("ack.bin"), &self.ack_file)?;
        self.ack_file
            .write_all(&chunk.bytes)
            .map_err(|_| "observer-ack-write")?;
        if self.ack.complete_ns.is_some() {
            return Ok(Some(self.ack.bytes.clone()));
        }
        Ok(None)
    }
    pub fn abandon(&mut self) {
        self.failed = Some("observer-forced-or-incomplete-retirement");
    }
    pub fn origin(&self) -> Result<Origin> {
        self.origin.clone().ok_or("observer-origin-missing")
    }
    pub fn retirement_ready(&mut self) -> Result<bool> {
        let _paused = install(None);
        self.pump()?;
        Ok(self.stream.eof && self.ack.eof && self.tracer.as_ref().is_some_and(|t| t.gone().is_ok()))
    }
    pub fn retire(&mut self, native: Status, cleanup: Instant) -> Result<Proof> {
        let _paused = install(None);
        self.pump()?;
        if Instant::now() >= cleanup || !self.ack.eof || self.failed.is_some() {
            return Err("observer-retirement-deadline-or-ack");
        }
        let (wait_ns, terminal_ns) = self.stream.retirement(native)?;
        let tracer = self.tracer.as_ref().ok_or("observer-tracer")?;
        tracer.gone()?;
        let origin = self.origin.as_ref().ok_or("observer-origin")?;
        if route::monotonic_ns()? > origin.total_ns {
            return Err("observer-original-total-expired");
        }
        audit::census(origin.uid, &[], cleanup)?;
        self.fifo_object
            .matches(&self.directory.join("trace.fifo"), &self.fifo)?;
        self.trace_object
            .matches(&self.directory.join("trace.bin"), &self.trace)?;
        self.ack_object
            .matches(&self.directory.join("ack.bin"), &self.ack_file)?;
        self.trace.sync_all().map_err(|_| "observer-trace-sync")?;
        self.ack_file.sync_all().map_err(|_| "observer-ack-sync")?;
        let proof = Proof {
            origin_sha256: self.origin_sha.ok_or("observer-origin-hash")?,
            trace_sha256: self.trace_hash.clone().finalize().into(),
            ack_sha256: Sha256::digest(&self.ack.bytes).into(),
            trace_bytes: self.stream.bytes,
            ack_bytes: self.ack.bytes.len(),
            ack_complete_ns: self.ack.complete_ns.ok_or("observer-ack-incomplete")?,
            consuming_wait_complete_ns: wait_ns,
            terminal_complete_ns: terminal_ns,
            retired_ns: route::monotonic_ns()?,
            natural_eof: true,
            tracer_dead: true,
            zero_writers: true,
        };
        private_json(&self.directory.join("retirement.json"), &proof)?;
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| "observer-directory-sync")?;
        if Instant::now() >= cleanup {
            return Err("observer-retirement-expired");
        }
        self.sealed = true;
        Ok(proof)
    }
}
fn private_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|_| "observer-private-create")
}
fn private_json<T: Serialize>(path: &Path, value: &T) -> Result<[u8; 32]> {
    let bytes = serde_json::to_vec(value).map_err(|_| "observer-origin-encode")?;
    if bytes.len() > RECORD_LIMIT {
        return Err("observer-origin-budget");
    }
    let mut file = private_new(path)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "observer-origin-write")?;
    Ok(Sha256::digest(&bytes).into())
}
/// One bounded quantum keeps manager, deadline, cancellation and output work runnable.
fn drain_fifo(reader: &mut impl Read, mut consume: impl FnMut(&[u8]) -> Result<()>) -> Result<bool> {
    for _ in 0..PUMP_CHUNKS {
        let mut bytes = [0; 4096];
        match reader.read(&mut bytes) {
            Ok(0) => return Ok(true),
            Ok(n) => consume(&bytes[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => return Err("observer-fifo-read"),
        }
    }
    Ok(false)
}
struct AckChunk {
    bytes: Vec<u8>,
    credentials: Vec<Sender>,
    invalid: bool,
}
/// The sole actual recvmsg path; each returned nonempty chunk must carry original credentials.
fn receive_ack_chunk(socket: &UnixStream) -> Result<Option<AckChunk>> {
    // SO_PASSCRED emits a zero-PID credential sentinel at EOF. Do not ask rustix's
    // nonzero typed UCred decoder to construct it. The sole owning reader peeks
    // without ancillary; buffered bytes remain until the credential-bearing recvmsg.
    let mut probe = [0; 1];
    match net::recv(socket, &mut probe[..], net::RecvFlags::DONTWAIT | net::RecvFlags::PEEK) {
        Ok((0, _)) => {
            return Ok(Some(AckChunk {
                bytes: Vec::new(),
                credentials: Vec::new(),
                invalid: false,
            }));
        }
        Ok(_) => (),
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(None),
        Err(_) => return Err("observer-ack-peek"),
    }
    let mut bytes = [0; 4096];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = match net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        net::RecvFlags::DONTWAIT | net::RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(m) => m,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(None),
        Err(_) => return Err("observer-ack-read"),
    };
    if received.bytes == 0 {
        // A second reader would violate ownership. Do not decode/drop a potential
        // zero-PID sentinel. Stream rights require a data byte, so none arrive at EOF.
        std::mem::forget(ancillary);
        return Err("observer-ack-reader-race");
    }
    let mut credentials = Vec::new();
    let mut invalid = received
        .flags
        .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC);
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmCredentials(c) => credentials.push(Sender {
                pid: c.pid.as_raw_nonzero().get().unsigned_abs(),
                uid: c.uid.as_raw(),
                gid: c.gid.as_raw(),
            }),
            _ => invalid = true,
        }
    }
    Ok(Some(AckChunk {
        bytes: bytes[..received.bytes].to_vec(),
        credentials,
        invalid,
    }))
}
/// Authenticated nsfs name and reserved inode give the safe equivalent of initial `CLONE_NEWUSER`.
fn initial_namespace(fd: &impl AsFd) -> Result<(u64, u64)> {
    let before = rustix::fs::fstat(fd).map_err(|_| "observer-user-namespace-stat")?;
    let magic = i128::from(
        rustix::fs::fstatfs(fd)
            .map_err(|_| "observer-user-namespace-filesystem")?
            .f_type,
    );
    let proc = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_DIRECTORY.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open("/proc/self/fd")
        .map_err(|_| "observer-proc-fd-directory")?;
    let proc_magic = i128::from(
        rustix::fs::fstatfs(&proc)
            .map_err(|_| "observer-proc-fd-filesystem")?
            .f_type,
    );
    let link = rustix::fs::readlinkat(&proc, fd.as_fd().as_raw_fd().to_string(), Vec::new())
        .map_err(|_| "observer-user-namespace-type")?;
    namespace_fact(magic, proc_magic, before.st_ino, link.as_bytes())?;
    let after = rustix::fs::fstat(fd).map_err(|_| "observer-user-namespace-restat")?;
    if before.st_dev == 0
        || before.st_mode & 0o170_000 != 0o100_000
        || (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode)
    {
        return Err("observer-user-namespace-reused");
    }
    Ok((before.st_dev, before.st_ino))
}
fn namespace_fact(magic: i128, proc_magic: i128, inode: u64, link: &[u8]) -> Result<()> {
    if magic != NSFS_MAGIC
        || proc_magic != i128::from(rustix::fs::PROC_SUPER_MAGIC)
        || inode != INITIAL_USER_INODE
        || link != b"user:[4026531837]"
    {
        return Err("observer-initial-user-namespace-type");
    }
    Ok(())
}
fn consume_initial_stdin() -> Result<()> {
    let own = File::open("/proc/self/ns/user").map_err(|_| "observer-self-user-namespace")?;
    let expected = initial_namespace(&own)?;
    if initial_namespace(&std::io::stdin())? != expected {
        return Err("observer-stdin-user-namespace");
    }
    let null = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open("/dev/null")
        .map_err(|_| "observer-stdin-null")?;
    let held = null.metadata().map_err(|_| "observer-stdin-null")?;
    if !held.file_type().is_char_device()
        || held.rdev() != nix::sys::stat::makedev(1, 3)
        || held.uid() != 0
        || held.gid() != 0
    {
        return Err("observer-stdin-null-device");
    }
    nix::unistd::dup2_stdin(&null).map_err(|_| "observer-stdin-reset")?;
    let actual = rustix::fs::fstat(std::io::stdin()).map_err(|_| "observer-stdin-reset")?;
    if (actual.st_dev, actual.st_ino, actual.st_rdev) != (held.dev(), held.ino(), held.rdev()) {
        return Err("observer-stdin-reset");
    }
    Ok(())
}
fn namespace(pid: u32, kind: &str) -> Result<(u64, u64)> {
    let file = File::open(format!("/proc/{pid}/ns/{kind}")).map_err(|_| "observer-namespace")?;
    let m = file.metadata().map_err(|_| "observer-namespace")?;
    Ok((m.dev(), m.ino()))
}
fn capability_free(pid: u32, uid: u32) -> Result<()> {
    audit::credentials(pid, uid)?;
    audit::single_thread(pid)?;
    let s = audit::status(pid)?;
    for k in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if s.get(k).and_then(|s| u64::from_str_radix(s, 16).ok()) != Some(0) {
            return Err("observer-capabilities");
        }
    }
    if s.get("NoNewPrivs").map(String::as_str) != Some("1") {
        return Err("observer-user-namespace-or-nnp");
    }
    let ns = File::open(format!("/proc/{pid}/ns/user")).map_err(|_| "observer-user-namespace")?;
    initial_namespace(&ns)?;
    Ok(())
}

pub(super) fn launch(args: &[String]) -> Result<()> {
    let nonce = args.get(3).ok_or("observer-arguments")?;
    super::journal::Ownership::new(nonce, 0)?;
    let execution = decimal_end(args.get(5).ok_or("observer-arguments")?)?;
    let total = decimal_end(args.get(6).ok_or("observer-arguments")?)?;
    if execution
        .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
        .is_none_or(|n| n > total)
    {
        return Err("observer-original-ends");
    }
    let helper_sha = sha_argument(args.get(7).ok_or("observer-arguments")?)?;
    let tool_sha = sha_argument(args.get(8).ok_or("observer-arguments")?)?;
    if hex(&tool_sha) != TOOL_SHA {
        return Err("observer-tool-profile");
    }
    let end = route::instant(execution)?;
    let uid = nix::unistd::getuid().as_raw();
    if uid == 0 {
        return Err("observer-leased-uid");
    }
    capability_free(std::process::id(), uid)?;
    consume_initial_stdin()?;
    inherited_descriptors()?;
    let mut helper = File::open("/proc/self/exe").map_err(|_| "observer-helper-image")?;
    let image = helper.metadata().map_err(|_| "observer-helper-image")?;
    if !image.is_file() || image.uid() != 0 || image.gid() != 0 || image.mode() & 0o6_022 != 0 {
        return Err("observer-helper-owner");
    }
    let mut tool = route::root_regular(Path::new(TOOL))?;
    if helper.as_raw_fd() != 3 || tool.as_raw_fd() != 4 {
        return Err("observer-fixed-descriptors");
    }
    if authority::digest_file(&mut helper, end)? != helper_sha || authority::digest_file(&mut tool, end)? != tool_sha {
        return Err("observer-launch-image");
    }
    rustix::io::fcntl_setfd(&helper, rustix::io::FdFlags::empty()).map_err(|_| "observer-helper-inherit")?;
    rustix::io::fcntl_setfd(&tool, rustix::io::FdFlags::CLOEXEC).map_err(|_| "observer-tool-cloexec")?;
    if route::monotonic_ns()? >= execution {
        return Err("observer-launch-deadline");
    }
    let vector = exec_vector(&args[2..7]);
    let tool_arguments = vector
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(|_| "observer-exec-argument"))
        .collect::<Result<Vec<_>>>()?;
    let env = [
        CString::new("LANG=C").map_err(|_| "observer-environment")?,
        CString::new("LC_ALL=C").map_err(|_| "observer-environment")?,
    ];
    nix::unistd::fexecve(&tool, &tool_arguments, &env).map_err(|_| "observer-tool-exec")?;
    Ok(())
}
fn decimal_end(raw: &str) -> Result<u64> {
    if raw.is_empty() || raw.starts_with('0') || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("observer-end-argument");
    }
    raw.parse().map_err(|_| "observer-end-argument")
}
fn exec_vector(arguments: &[String]) -> Vec<String> {
    let mut argv = [
        TOOL,
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
        "observed-supervisor",
    ]
    .map(str::to_string)
    .to_vec();
    argv.extend_from_slice(arguments);
    argv
}
fn inherited_descriptors() -> Result<()> {
    let mut scanner = 0;
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| "observer-inherited-fds")? {
        let entry = entry.map_err(|_| "observer-inherited-fds")?;
        let number = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("observer-inherited-fds")?;
        if number > 2 {
            if fs::read_link(entry.path())
                .map_err(|_| "observer-inherited-fds")?
                .as_os_str()
                != std::ffi::OsStr::new(&format!("/proc/{}/fd", std::process::id()))
            {
                return Err("observer-inherited-descriptor");
            }
            scanner += 1;
        }
    }
    if scanner != 1 {
        return Err("observer-fd-scanner");
    }
    let error = fs::metadata("/proc/self/fd/2").map_err(|_| "observer-stderr")?;
    if !error.file_type().is_fifo()
        || error.uid() != 0
        || error.gid() != 0
        || error.nlink() != 1
        || error.mode() & 0o777 != 0o600
    {
        return Err("observer-stderr-origin");
    }
    Ok(())
}
pub(super) fn supervisor(args: &[String]) -> Result<()> {
    let uid = nix::unistd::getuid().as_raw();
    if uid == 0 {
        return Err("observer-leased-uid");
    }
    capability_free(std::process::id(), uid)?;
    nix::unistd::close(3).map_err(|_| "observer-helper-descriptor-close")?;
    let null = File::open("/dev/null").map_err(|_| "observer-supervisor-stderr")?;
    nix::unistd::dup2_stderr(&null).map_err(|_| "observer-supervisor-stderr")?;
    drop(null);
    route::supervisor_mode(
        args.get(3).ok_or("observer-arguments")?,
        Path::new(args.get(4).ok_or("observer-arguments")?),
        decimal_end(args.get(5).ok_or("observer-arguments")?)?,
        decimal_end(args.get(6).ok_or("observer-arguments")?)?,
        true,
    )
}

/// Authenticates finite root evidence without turning recovery into a new observer admission.
pub(super) fn authenticate_archive(record: &super::journal::Record, end: Instant, published: bool) -> Result<()> {
    let Some(observation) = &record.observer else {
        return Err("observer-archive-selection");
    };
    observation.validate(&record.ownership.nonce)?;
    route::root_ancestry(&observation.evidence)?;
    let directory = authenticate_archive_metadata(record, end, published)?;
    let Some(proof) = &observation.proof else {
        return Ok(());
    };
    let mut origin_file = open_child(&directory, "origin.json")?;
    let origin_bytes = authority::read_file(&mut origin_file, RECORD_LIMIT)?;
    if <[u8; 32]>::from(Sha256::digest(&origin_bytes)) != proof.origin_sha256 {
        return Err("observer-origin-hash-changed");
    }
    let origin: Origin = serde_json::from_slice(&origin_bytes).map_err(|_| "observer-origin-schema")?;
    if observation.origin.as_ref() != Some(&origin)
        || origin.nonce != record.ownership.nonce
        || origin.boot != record.boot
        || origin.execution_ns != record.execution_ns
        || origin.total_ns != record.total_end_ns()?
        || origin.request_sha256 != observation.request_sha256
        || origin.helper_sha256 != observation.helper_sha256
        || origin.tool_sha256 != observation.selection.validate()?
        || Some(origin.uid) != record.uid
        || origin.gid != origin.uid
        || origin.controller.pid != record.controller_pid
        || origin.controller.start != record.controller_start
        || origin.supervisor.pid <= 1
        || origin.bwrap.pid <= 1
        || origin.tracer.pid <= 1
        || origin.supervisor.pid == origin.tracer.pid
        || origin.supervisor.pid == origin.bwrap.pid
        || origin.tracer.pid == origin.bwrap.pid
        || origin.work_invocation.len() != 32
        || !origin
            .work_invocation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("observer-archive-origin-binding");
    }
    if proof.retired_ns > origin.total_ns
        || proof.retired_ns == 0
        || [
            proof.ack_complete_ns,
            proof.consuming_wait_complete_ns,
            proof.terminal_complete_ns,
        ]
        .iter()
        .any(|ns| *ns == 0 || *ns > proof.retired_ns)
        || proof.consuming_wait_complete_ns > proof.terminal_complete_ns
    {
        return Err("observer-archive-clock-binding");
    }
    let mut retirement = open_child(&directory, "retirement.json")?;
    let retained: Proof = serde_json::from_slice(&authority::read_file(&mut retirement, RECORD_LIMIT)?)
        .map_err(|_| "observer-retirement-schema")?;
    if &retained != proof {
        return Err("observer-retirement-changed");
    }
    let native = archived_ack(&directory, &origin, proof)?;
    archived_trace(&directory, &origin, proof, native, end)?;
    let fifo = fs::symlink_metadata(observation.evidence.join("trace.fifo")).map_err(|_| "observer-fifo-stat")?;
    if Object::metadata(&fifo)? != origin.fifo || !fifo.file_type().is_fifo() {
        return Err("observer-fifo-object-binding");
    }
    let root = directory.metadata().map_err(|_| "observer-directory-restat")?;
    let after = fs::symlink_metadata(&observation.evidence).map_err(|_| "observer-directory-restat")?;
    if (after.dev(), after.ino(), after.mode(), after.uid(), after.gid())
        != (root.dev(), root.ino(), root.mode(), root.uid(), root.gid())
        || Instant::now() >= end
    {
        return Err("observer-directory-changed");
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAck {
    nonce: String,
    bwrap: u32,
    code: Option<u8>,
    signal: Option<u8>,
    core: bool,
}
fn archived_ack(directory: &File, origin: &Origin, proof: &Proof) -> Result<Status> {
    let mut ack = open_child(directory, "ack.bin")?;
    let ack_object = Object::of(&ack)?;
    let raw = authority::read_file(&mut ack, ACK_LIMIT)?;
    if ack_object != origin.ack
        || raw.len() != proof.ack_bytes
        || <[u8; 32]>::from(Sha256::digest(&raw)) != proof.ack_sha256
        || raw.last() != Some(&b'\n')
        || raw[..raw.len().saturating_sub(1)].contains(&b'\n')
    {
        return Err("observer-archive-ack-binding");
    }
    let native: RawAck = serde_json::from_slice(&raw[..raw.len() - 1]).map_err(|_| "observer-archive-ack-schema")?;
    if native.nonce != origin.nonce || native.bwrap != origin.bwrap.pid {
        return Err("observer-archive-ack-origin");
    }
    let native = match (native.code, native.signal, native.core) {
        (Some(c), None, false) => Status::Exit(c),
        (None, Some(n), core) if (1..=64).contains(&n) => Status::Signal { number: n, core },
        _ => return Err("observer-archive-ack-status"),
    };
    Ok(native)
}
fn archived_trace(directory: &File, origin: &Origin, proof: &Proof, native: Status, end: Instant) -> Result<()> {
    let mut trace = open_child(directory, "trace.bin")?;
    if Object::of(&trace)? != origin.trace
        || trace.metadata().map_err(|_| "observer-trace-stat")?.len()
            != u64::try_from(proof.trace_bytes).map_err(|_| "observer-trace-size")?
    {
        return Err("observer-trace-object-binding");
    }
    let mut stream = Stream::default();
    let mut hash = Sha256::new();
    loop {
        pump()?;
        if Instant::now() >= end {
            return Err("observer-archive-deadline");
        }
        let mut chunk = [0; 4096];
        let n = trace.read(&mut chunk).map_err(|_| "observer-trace-read")?;
        if n == 0 {
            break;
        }
        hash.update(&chunk[..n]);
        stream.feed(&chunk[..n], proof.retired_ns)?;
    }
    if <[u8; 32]>::from(hash.finalize()) != proof.trace_sha256
        || stream.bytes != proof.trace_bytes
        || stream.attached != Some(origin.supervisor.pid)
        || stream.zero != Some(origin.bwrap.pid)
    {
        return Err("observer-trace-hash-or-identity");
    }
    stream.child = Some(origin.bwrap.pid);
    stream.complete()?;
    stream.retirement(native)?;
    Ok(())
}
fn open_child(directory: &File, name: &str) -> Result<File> {
    let fd = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "observer-archive-open")?;
    let file = File::from(fd);
    let m = file.metadata().map_err(|_| "observer-archive-stat")?;
    Object::metadata(&m)?;
    if !m.is_file() {
        return Err("observer-archive-type");
    }
    Ok(file)
}

/// Cold reconciliation reads no evidence bodies: fixed names, types, objects and original caps only.
pub(super) fn authenticate_archive_metadata(
    record: &super::journal::Record,
    end: Instant,
    published: bool,
) -> Result<File> {
    let observation = record.observer.as_ref().ok_or("observer-archive-selection")?;
    observation.validate(&record.ownership.nonce)?;
    route::root_ancestry(&observation.evidence)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_DIRECTORY.bits())
        .open(&observation.evidence)
        .map_err(|_| "observer-archive-directory")?;
    let root = directory.metadata().map_err(|_| "observer-archive-directory")?;
    if !root.is_dir() || root.uid() != 0 || root.gid() != 0 || root.mode() & 0o777 != 0o700 {
        return Err("observer-archive-directory-owner");
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in
        fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(|_| "observer-archive-inventory")?
    {
        pump()?;
        if Instant::now() >= end {
            return Err("observer-archive-deadline");
        }
        let entry = entry.map_err(|_| "observer-archive-inventory")?;
        let name = entry.file_name().into_string().map_err(|_| "observer-archive-name")?;
        let m = fs::symlink_metadata(entry.path()).map_err(|_| "observer-archive-child-stat")?;
        let object = Object::metadata(&m)?;
        archive_child(&name, &object, m.len())?;
        if let Some(origin) = &observation.origin {
            let bound = match name.as_str() {
                "trace.fifo" => Some(&origin.fifo),
                "trace.bin" => Some(&origin.trace),
                "ack.bin" => Some(&origin.ack),
                _ => None,
            };
            if bound.is_some_and(|bound| bound != &object) {
                return Err("observer-archive-object-binding");
            }
        }
        if !seen.insert(name) || seen.len() > 6 {
            return Err("observer-archive-child-count");
        }
    }
    if published && (seen.len() != 6 || observation.proof.is_none()) {
        return Err("observer-archive-proof-missing");
    }
    if observation.proof.is_some()
        && ["trace.fifo", "trace.bin", "ack.bin", "origin.json", "retirement.json"]
            .iter()
            .any(|name| !seen.contains(*name))
    {
        return Err("observer-archive-incomplete");
    }
    validate_record_binding(record)?;
    let after = fs::symlink_metadata(&observation.evidence).map_err(|_| "observer-directory-restat")?;
    if (after.dev(), after.ino(), after.mode(), after.uid(), after.gid())
        != (root.dev(), root.ino(), root.mode(), root.uid(), root.gid())
    {
        return Err("observer-directory-changed");
    }
    Ok(directory)
}

/// Shared admission and cold-recovery scalar checks; never reads evidence bodies.
pub(super) fn validate_record_binding(record: &super::journal::Record) -> Result<()> {
    let observation = record.observer.as_ref().ok_or("observer-record-selection")?;
    if let Some(origin) = &observation.origin {
        if origin.nonce != record.ownership.nonce
            || origin.boot != record.boot
            || origin.execution_ns != record.execution_ns
            || origin.total_ns != record.total_end_ns()?
            || origin.request_sha256 != observation.request_sha256
            || origin.helper_sha256 != observation.helper_sha256
            || origin.tool_sha256 != observation.selection.validate()?
            || Some(origin.uid) != record.uid
            || origin.gid != origin.uid
            || origin.controller.pid != record.controller_pid
            || origin.controller.start != record.controller_start
            || origin.readiness_complete_ns == 0
            || origin.readiness_complete_ns > record.execution_ns
        {
            return Err("observer-archive-origin-binding");
        }
    }
    if let Some(proof) = &observation.proof {
        if proof.retired_ns == 0
            || proof.retired_ns > record.total_end_ns()?
            || [
                proof.ack_complete_ns,
                proof.consuming_wait_complete_ns,
                proof.terminal_complete_ns,
            ]
            .iter()
            .any(|ns| *ns == 0 || *ns > proof.retired_ns)
        {
            return Err("observer-archive-clock-binding");
        }
    }
    if let (Some(origin), Some(proof)) = (&observation.origin, &observation.proof) {
        if proof.consuming_wait_complete_ns > proof.terminal_complete_ns
            || [
                proof.ack_complete_ns,
                proof.consuming_wait_complete_ns,
                proof.terminal_complete_ns,
            ]
            .iter()
            .any(|ns| *ns < origin.readiness_complete_ns)
        {
            return Err("observer-record-clock-order");
        }
    }
    Ok(())
}
fn archive_child(name: &str, object: &Object, size: u64) -> Result<()> {
    let (kind, cap) = match name {
        "trace.fifo" => (0o010_000, 0),
        "trace.bin" => (0o100_000, TRACE_LIMIT as u64),
        "ack.bin" => (0o100_000, ACK_LIMIT as u64),
        "origin.json" | "retirement.json" => (0o100_000, RECORD_LIMIT as u64),
        "record.json" => (0o100_000, 32_768),
        _ => return Err("observer-archive-child"),
    };
    if object.uid != 0
        || object.gid != 0
        || object.nlink != 1
        || object.mode & 0o777 != 0o600
        || object.mode & 0o170_000 != kind
        || size > cap
    {
        return Err("observer-archive-child-type-or-budget");
    }
    Ok(())
}
/// Directory form cannot downgrade to a legacy unobserved archive, or vice versa.
pub(super) fn archive_form(record: &super::journal::Record, directory: bool, published: bool) -> Result<()> {
    record.validate()?;
    if record.observer.is_some() != directory
        || published && directory && record.observer.as_ref().is_none_or(|o| o.proof.is_none())
    {
        return Err("observer-archive-kind-or-proof");
    }
    Ok(())
}
#[cfg(test)]
#[path = "wait_observer_tests.rs"]
mod tests;
