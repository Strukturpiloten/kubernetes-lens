//! Nonce-owned controller and fixed helper roles for the explicit system broker.
use super::super::PackagedChart;
use super::broker_protocol::RequestHeader;
use super::bubblewrap_probe::{GatePlan, LaunchSpec};
use super::{
    Result, audit,
    authority::{self, HeldPid, RootOutput},
    bubblewrap_probe::{self, RootPermit},
    journal::{Journal, Ownership, Record},
    manager::SystemManager,
    tracer::{self, Observer},
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub fn monotonic_ns() -> Result<u64> {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_err(|_| "clock")?;
    let seconds = u64::try_from(t.tv_sec()).map_err(|_| "clock-negative")?;
    let nanos = u64::try_from(t.tv_nsec()).map_err(|_| "clock-negative")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or("clock-overflow")
}

pub(super) fn instant(ns: u64) -> Result<Instant> {
    let local = Instant::now();
    let now = monotonic_ns()?;
    if ns <= now {
        return Err("deadline-expired");
    }
    local
        .checked_add(Duration::from_nanos(ns - now))
        .ok_or("deadline-overflow")
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeTools {
    pub manager: [u8; 32],
    pub systemd_run: [u8; 32],
    pub systemctl: [u8; 32],
    pub busctl: [u8; 32],
    pub bubblewrap: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    pub schema: u32,
    pub nonce: String,
    pub client_uid: u32,
    pub execution_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_deadline_ns: Option<u64>,
    pub boot: String,
    pub journal: PathBuf,
    pub stage: PathBuf,
    pub helper: PathBuf,
    pub gate: PathBuf,
    pub renderer: PathBuf,
    pub helper_sha: [u8; 32],
    pub gate_sha: [u8; 32],
    pub renderer_sha: [u8; 32],
    pub header: RequestHeader,
    pub channel: PathBuf,
    pub tools: NativeTools,
}
/// Only a root-created exact candidate descriptor can construct admission. No boolean bypass.
pub struct Admission {
    d: Descriptor,
    helper: File,
    gate: File,
    renderer: File,
    end: Instant,
}
pub(super) fn root_ancestry(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err("root-path-relative");
    }
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        match part {
            std::path::Component::Normal(p) => current.push(p),
            _ => return Err("root-path-component"),
        }
        let m = fs::symlink_metadata(&current).map_err(|_| "root-path-ancestry")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("root-path-ancestor-owner");
        }
    }
    Ok(())
}
pub(super) fn root_regular(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("candidate-path");
    }
    root_ancestry(path.parent().ok_or("candidate-parent")?)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|_| "candidate-open")?;
    let m = f.metadata().map_err(|_| "candidate-stat")?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o6000 != 0 {
        return Err("candidate-owner");
    }
    Ok(f)
}
impl Admission {
    pub fn read(path: &Path) -> Result<Self> {
        if nix::unistd::getuid().as_raw() != 0 || nix::unistd::geteuid().as_raw() != 0 {
            return Err("controller-root");
        }
        let mut fd = root_regular(path)?;
        if fd.metadata().map_err(|_| "descriptor-stat")?.mode() & 0o077 != 0 {
            return Err("descriptor-private");
        }
        let d: Descriptor = serde_json::from_slice(&authority::read_file(
            &mut fd,
            super::broker_protocol::HEADER_LIMIT + 65536,
        )?)
        .map_err(|_| "descriptor-json")?;
        if d.schema != d.header.schema
            || d.nonce != d.header.nonce
            || d.client_uid != d.header.caller_uid
            || d.boot != d.header.boot
            || d.execution_ns != d.header.deadline_ns
            || d.total_deadline_ns != d.header.total_deadline_ns
            || d.renderer.to_str() != Some(d.header.executable.as_str())
            || d.renderer_sha != d.header.image_sha256
        {
            return Err("descriptor-schema");
        }
        Ownership::new(&d.nonce, d.client_uid)?;
        root_ancestry(&d.journal)?;
        root_ancestry(d.stage.parent().ok_or("stage-parent")?)?;
        let now = monotonic_ns()?;
        d.header.validate(now).map_err(|_| "request-admission")?;
        if d.execution_ns <= now || d.execution_ns - now > 120_000_000_000 {
            return Err("descriptor-budget");
        }
        let boot = String::from_utf8(authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?)
            .map_err(|_| "boot")?;
        if boot.trim() != d.boot {
            return Err("descriptor-boot");
        }
        let end = instant(d.execution_ns)?;
        for (path, digest) in [
            ("/usr/bin/systemd-run", d.tools.systemd_run),
            ("/usr/bin/systemctl", d.tools.systemctl),
            ("/usr/bin/busctl", d.tools.busctl),
            ("/usr/bin/bwrap", d.tools.bubblewrap),
        ] {
            let mut f = root_regular(Path::new(path))?;
            if authority::digest_file(&mut f, end)? != digest {
                return Err("native-tool-digest");
            }
        }
        let mut manager_image = File::open("/proc/1/exe").map_err(|_| "manager-image")?;
        if authority::digest_file(&mut manager_image, end)? != d.tools.manager {
            return Err("manager-image-digest");
        }
        let mut files = Vec::new();
        for (path, digest) in [
            (&d.helper, d.helper_sha),
            (&d.gate, d.gate_sha),
            (&d.renderer, d.renderer_sha),
        ] {
            let mut f = root_regular(path)?;
            if authority::digest_file(&mut f, end)? != digest {
                return Err("candidate-digest");
            }
            files.push(root_regular(path)?);
        }
        let helper = files.remove(0);
        let mut gate = files.remove(0);
        let mut renderer = files.remove(0);
        audit::static_elf(&authority::read_file(&mut gate, 64 * 1024 * 1024)?)?;
        audit::static_elf(&authority::read_file(&mut renderer, 64 * 1024 * 1024)?)?;
        let gate = root_regular(&d.gate)?;
        let renderer = root_regular(&d.renderer)?;
        Ok(Self {
            d,
            helper,
            gate,
            renderer,
            end,
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Started {
    nonce: String,
    bwrap: u32,
    gate: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeWait {
    nonce: String,
    bwrap: u32,
    code: Option<i32>,
    signal: Option<i32>,
}
/// Private message on the existing authenticated, held supervisor control socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelNative {
    operation: String,
    nonce: String,
    bwrap: u32,
    execution_ns: u64,
    total_deadline_ns: u64,
    boot: String,
}
impl CancelNative {
    fn validate(&self, nonce: &str, bwrap: u32, execution: u64, total: u64, boot: &str) -> Result<()> {
        if self.operation != "cancel-owned-native-v2"
            || self.nonce != nonce
            || self.bwrap != bwrap
            || self.execution_ns != execution
            || self.total_deadline_ns != total
            || self.boot != boot
        {
            return Err("private-native-cancel-binding");
        }
        Ok(())
    }
}
/// Closed private ownership seam: models exercise real production decisions without processes.
trait OwnedNativeParent {
    fn poll(&mut self) -> std::io::Result<Option<ExitStatus>>;
    fn kill_owned(&mut self) -> std::io::Result<()>;
}
impl OwnedNativeParent for Child {
    fn poll(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.try_wait()
    }
    fn kill_owned(&mut self) -> std::io::Result<()> {
        self.kill()
    }
}
fn cancel_unreaped(parent: &mut impl OwnedNativeParent) -> Result<Option<ExitStatus>> {
    if let Some(status) = parent.poll().map_err(|_| "bwrap-wait")? {
        return Ok(Some(status));
    }
    parent.kill_owned().map_err(|_| "owned-native-kill")?;
    Ok(None)
}
fn poll_reaped(parent: &mut impl OwnedNativeParent, now: Instant, end: Instant) -> Result<Option<ExitStatus>> {
    if now >= end {
        return Err("native-reap-deadline");
    }
    parent.poll().map_err(|_| "bwrap-wait")
}
fn reap_end(cleanup: Instant) -> Instant {
    // Two seconds remain inside the same original ceiling for work stop and retirement.
    cleanup.checked_sub(Duration::from_secs(2)).unwrap_or(cleanup)
}

fn send<T: Serialize>(socket: &mut UnixStream, value: &T, end: Instant) -> Result<()> {
    let mut b = serde_json::to_vec(value).map_err(|_| "control-encode")?;
    if b.len() > 65536 {
        return Err("control-budget");
    }
    b.push(b'\n');
    super::broker_protocol::write_exact(socket, &b, end).map_err(|_| "control-write")
}
fn recv<T: for<'a> Deserialize<'a>>(socket: &mut UnixStream, end: Instant) -> Result<T> {
    recv_checked(socket, end, None)
}
fn recv_checked<T: for<'a> Deserialize<'a>>(
    socket: &mut UnixStream,
    end: Instant,
    client: Option<&UnixStream>,
) -> Result<T> {
    let mut bytes = Vec::new();
    loop {
        if client.map(client_write_closed).transpose()? == Some(true) {
            return Err("caller-cancelled-during-supervisor-setup");
        }
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|n| !n.is_zero())
            .ok_or("control-expired")?;
        socket
            .set_read_timeout(Some(remaining.min(super::broker_protocol::IO_POLL)))
            .map_err(|_| "control-timeout")?;
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(0) => return Err("control-eof"),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                bytes.push(byte[0]);
                if bytes.len() > 65536 {
                    return Err("control-budget");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => (),
            Err(_) => return Err("control-read"),
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| "control-schema")
}
#[derive(Clone)]
struct CleanupClock {
    value: Arc<Mutex<Option<Instant>>>,
    ceiling: Instant,
}
impl CleanupClock {
    fn new(native_end: Instant) -> Result<Self> {
        Ok(Self {
            value: Arc::new(Mutex::new(None)),
            ceiling: super::broker_protocol::receipt_end(native_end).map_err(|_| "cleanup-overflow")?,
        })
    }
    fn bounded(ceiling: Instant) -> Self {
        Self {
            value: Arc::new(Mutex::new(None)),
            ceiling,
        }
    }
    fn begin(&self) -> Result<Instant> {
        let mut value = self.value.lock().map_err(|_| "cleanup-clock-poisoned")?;
        Ok(*value.get_or_insert_with(|| (Instant::now() + Duration::from_secs(10)).min(self.ceiling)))
    }
}
struct ExecObserver {
    journal: Journal,
    gate: HeldPid,
    supervisor: HeldPid,
    bwrap: HeldPid,
    parent_notice: Vec<u8>,
    native_wait: Option<NativeWait>,
    watch: HeldPid,
    uid: u32,
    lease_invocation: String,
    work_invocation: String,
    watch_invocation: String,
    helper_sha: [u8; 32],
    setup: audit::Setup,
    outputs: [(authority::Object, u64); 2],
    permit: Option<RootPermit>,
    gate_sha: [u8; 32],
    renderer_sha: [u8; 32],
    spec: LaunchSpec,
    memory: usize,
    pids: usize,
    cgroup: PathBuf,
    end: Instant,
    control: UnixStream,
    client: UnixStream,
    cleanup_end: Option<Instant>,
    cleanup_clock: CleanupClock,
    cancel_sent: bool,
    cancellation_cause: Option<&'static str>,
}
fn native_binding(n: &NativeWait, nonce: &str, bwrap: u32) -> Result<()> {
    if n.nonce != nonce
        || n.bwrap != bwrap
        || n.code.is_some() == n.signal.is_some()
        || n.code.is_some_and(|code| !(0..=255).contains(&code))
        || n.signal.is_some_and(|signal| !(1..=64).contains(&signal))
    {
        return Err("native-wait-binding");
    }
    Ok(())
}
// Shared by normal post-detach completion; malformed evidence can never authorize native success.
fn bound_native_reap(native: Option<&NativeWait>, nonce: &str, bwrap: u32) -> Result<()> {
    native_binding(native.ok_or("native-reap-unproved")?, nonce, bwrap)
}
fn native_completion(n: &NativeWait, nonce: &str, bwrap: u32) -> Result<bool> {
    native_binding(n, nonce, bwrap)?;
    Ok(n.code == Some(0))
}
impl ExecObserver {
    fn request_native_cancel(&mut self, end: Instant) -> Result<()> {
        if self.native_wait.is_some() || self.cancel_sent {
            return Ok(());
        }
        let record = &self.journal.record;
        let message = CancelNative {
            operation: "cancel-owned-native-v2".into(),
            nonce: record.ownership.nonce.clone(),
            bwrap: self.bwrap.pid,
            execution_ns: record.execution_ns,
            total_deadline_ns: record.total_end_ns()?,
            boot: record.boot.clone(),
        };
        send(&mut self.control, &message, end)?;
        self.cancel_sent = true;
        Ok(())
    }
    fn poll_parent(&mut self) -> Result<bool> {
        if self.native_wait.is_none() {
            loop {
                let mut byte = [0];
                match self.control.read(&mut byte) {
                    Ok(0) => return Ok(false),
                    Ok(_) if byte[0] == b'\n' => {
                        let n: NativeWait =
                            serde_json::from_slice(&self.parent_notice).map_err(|_| "native-wait-schema")?;
                        native_binding(&n, &self.journal.record.ownership.nonce, self.bwrap.pid)?;
                        self.native_wait = Some(n);
                        break;
                    }
                    Ok(_) => {
                        self.parent_notice.push(byte[0]);
                        if self.parent_notice.len() > 65536 {
                            return Err("native-wait-budget");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                    Err(_) => return Err("native-wait-read"),
                }
            }
        }
        self.bwrap.gone()?;
        Ok(true)
    }
    fn recheck_manager(&self) -> Result<()> {
        let own = &self.journal.record.ownership;
        let lease = SystemManager::show(&own.lease, own, self.end)?;
        let allocation = SystemManager::allocation(own, &lease, self.end)?;
        if allocation.uid != self.uid || allocation.invocation != self.lease_invocation {
            return Err("lease-lifetime-changed");
        }
        let work = SystemManager::show(&own.work, own, self.end)?;
        if work.get("InvocationID")? != self.work_invocation
            || work.get("MainPID")?.parse::<u32>().map_err(|_| "supervisor-pid")? != self.supervisor.pid
            || Path::new(&format!("/sys/fs/cgroup{}", work.get("ControlGroup")?)) != self.cgroup.as_path()
        {
            return Err("work-invocation-changed");
        }
        let watch = SystemManager::show(&own.watch, own, self.end)?;
        if watch.get("InvocationID")? != self.watch_invocation
            || watch.get("MainPID")?.parse::<u32>().map_err(|_| "watch-pid")? != self.watch.pid
        {
            return Err("watch-invocation-changed");
        }
        for held in [&self.supervisor, &self.watch] {
            held.verify()?;
            let mut f = File::open(format!("/proc/{}/exe", held.pid)).map_err(|_| "helper-exe")?;
            if authority::digest_file(&mut f, self.end)? != self.helper_sha {
                return Err("helper-exe-digest");
            }
        }
        if authority::bounded(&PathBuf::from(format!("/proc/{}/cgroup", self.gate.pid)), 4096)?
            != format!("0::{}\n", work.get("ControlGroup")?).as_bytes()
        {
            return Err("gate-unit-cgroup");
        }
        Ok(())
    }
}
impl Observer for ExecObserver {
    fn bound_identity(&mut self) -> Result<()> {
        self.recheck_manager()?;
        self.gate.verify()?;
        self.supervisor.verify()?;
        self.watch.verify()?;
        audit::credentials(self.gate.pid, self.uid)?;
        audit::single_thread(self.gate.pid)?;
        let mut f = File::open(format!("/proc/{}/exe", self.gate.pid)).map_err(|_| "gate-exe")?;
        if authority::digest_file(&mut f, self.end)? != self.gate_sha {
            return Err("gate-digest");
        }
        if authority::bounded(&PathBuf::from(format!("/proc/{}/cmdline", self.gate.pid)), 65536)?
            != format!(
                "/scratch/gate\0{}\0{}\0",
                self.journal.record.ownership.nonce,
                self.spec.encoded()?
            )
            .as_bytes()
        {
            return Err("gate-argv");
        }
        let work = SystemManager::show(
            &self.journal.record.ownership.work,
            &self.journal.record.ownership,
            self.end,
        )?;
        SystemManager::verify_watch(&self.journal.record.ownership, &work, self.end)?;
        Ok(())
    }
    fn permit(&mut self) -> Result<()> {
        self.bound_identity()?;
        self.journal.record.phase = "trace-armed".into();
        self.journal.persist()?;
        self.permit
            .take()
            .ok_or("permit-used")?
            .send_once(&self.journal.record.ownership.nonce, self.end)
            .map_err(|_| "permit-send")?;
        self.journal.record.phase = "permit-sent".into();
        self.journal.persist()
    }
    fn final_stop(&mut self) -> Result<()> {
        self.recheck_manager()?;
        self.watch.verify()?;
        self.supervisor.verify()?;
        let work = SystemManager::show(
            &self.journal.record.ownership.work,
            &self.journal.record.ownership,
            self.end,
        )?;
        SystemManager::verify_watch(&self.journal.record.ownership, &work, self.end)?;
        audit::final_stop(
            &self.gate,
            self.uid,
            &self.setup,
            self.outputs,
            self.renderer_sha,
            &audit::ExecutionAudit {
                plan: &self.spec.plan,
                memory: self.memory,
                pids: self.pids,
                cgroup: &self.cgroup,
                deadline: self.end,
            },
        )?;
        self.journal.record.phase = "exec-verified".into();
        self.journal.persist()
    }
    fn cancelled(&mut self) -> bool {
        if self.cancellation_cause.is_none() {
            self.cancellation_cause = poll_cancellation(
                &self.client,
                &self.control,
                self.native_wait.is_some(),
                Instant::now(),
                self.end,
            );
        }
        self.cancellation_cause.is_some()
    }
    fn terminate_owned(&mut self) -> Result<()> {
        let end = self.cleanup_clock.begin()?;
        self.cleanup_end = Some(end);
        self.request_native_cancel(reap_end(end))
    }
    fn cleanup_ceiling(&self) -> Option<Instant> {
        self.cleanup_end.map(reap_end)
    }
    fn real_parent_reaped(&mut self) -> Result<bool> {
        self.poll_parent()
    }
}
fn poll_cancellation(
    client: &UnixStream,
    control: &UnixStream,
    native_reaped: bool,
    now: Instant,
    execution_end: Instant,
) -> Option<&'static str> {
    if now >= execution_end {
        return Some("execution-deadline");
    }
    match client_write_closed(client) {
        Ok(true) => return Some("caller-cancelled"),
        Ok(false) => (),
        Err(_) => return Some("caller-channel-failed"),
    }
    if native_reaped {
        return None;
    }
    let mut byte = [0];
    match rustix::net::recv(
        control,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => None,
        Ok((0, 0)) | Err(_) => Some("native-parent-disconnected"),
        Ok(_) => None,
    }
}
pub(super) fn client_write_closed(client: &UnixStream) -> Result<bool> {
    let mut byte = [0];
    match rustix::net::recv(
        client,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Ok((0, 0)) => Ok(true),
        Ok(_) => Ok(false),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(false),
        Err(_) => Err("caller-channel-read"),
    }
}
#[derive(Debug)]
pub struct Outcome {
    pub native_code: Option<i32>,
    pub native_signal: Option<i32>,
    pub package: Option<PackagedChart>,
    pub cause: Option<&'static str>,
    pub quarantined: bool,
    pub cleanup_ns: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Actual private route. Calling requires a freshly provisioned descriptor; this source pass never calls it.
fn created_intent_binding(created: Option<&Record>, actual: &Record) -> Result<()> {
    let created = created.ok_or("cleanup-intent-unowned")?;
    created.validate()?;
    actual.validate()?;
    if created.schema != actual.schema
        || created.ownership != actual.ownership
        || created.controller_pid != actual.controller_pid
        || created.controller_start != actual.controller_start
        || created.boot != actual.boot
        || created.execution_ns != actual.execution_ns
        || created.total_deadline_ns != actual.total_deadline_ns
        || created.stage != actual.stage
    {
        return Err("cleanup-invocation-binding");
    }
    Ok(())
}

pub fn controller(admission: Admission, client: UnixStream) -> Result<Outcome> {
    let dir = admission.d.journal.clone();
    let nonce = admission.d.nonce.clone();
    let cleanup_clock = if admission.d.header.schema == super::broker_protocol::CONTROLLED_SCHEMA {
        CleanupClock::bounded(instant(
            admission.d.header.total_end_ns().map_err(|_| "total-deadline")?,
        )?)
    } else {
        CleanupClock::new(admission.end)?
    };
    // Only successful durable creation in THIS attempt grants error cleanup ownership.
    let mut created_intent = None;
    let result = controller_inner(admission, client, cleanup_clock.clone(), &mut created_intent);
    if let (Err(cause), Some(created)) = (&result, created_intent.as_ref()) {
        if let Ok(mut j) = Journal::load_writer(&dir, &nonce) {
            if created_intent_binding(Some(created), &j.record).is_ok() {
                if let Ok(cleanup) = cleanup_clock.begin() {
                    let _ = SystemManager::terminate(&j, cleanup);
                    let _ = j.reconcile_pending_after_stop();
                }
                j.record.phase = "quarantined".into();
                if j.record.cause.is_none() {
                    j.record.cause = Some((*cause).into());
                }
                let _ = j.persist();
            }
        }
    }
    result
}
struct Prepared {
    d: Descriptor,
    end: Instant,
    gate: File,
    renderer: File,
    journal: Journal,
    manager: SystemManager,
    listener: UnixListener,
    socket: PathBuf,
    allocation: super::manager::Allocation,
    permit: RootPermit,
    output: RootOutput,
    error: RootOutput,
    spec: LaunchSpec,
    expected_package: Option<String>,
    client: UnixStream,
}
struct Running {
    d: Descriptor,
    observer: ExecObserver,
    output: RootOutput,
    error: RootOutput,
    allocation: super::manager::Allocation,
    listener: UnixListener,
    socket: PathBuf,
    package_dir: File,
    expected_package: Option<String>,
}
struct Drained {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    native: Option<NativeWait>,
    cause: Option<&'static str>,
}
fn controller_inner(
    admission: Admission,
    client: UnixStream,
    cleanup_clock: CleanupClock,
    created_intent: &mut Option<Record>,
) -> Result<Outcome> {
    let prepared = prepare(admission, client, created_intent)?;
    let Running {
        d,
        observer,
        output,
        error,
        allocation,
        listener,
        socket,
        package_dir,
        expected_package,
    } = observe(prepared, cleanup_clock)?;
    let (observer, trace) = trace(observer)?;
    let mut running = Running {
        d,
        observer,
        output,
        error,
        allocation,
        listener,
        socket,
        package_dir,
        expected_package,
    };
    let drained = drain(&mut running, &trace);
    finish(running, drained)
}
fn prepare(admission: Admission, mut client: UnixStream, created_intent: &mut Option<Record>) -> Result<Prepared> {
    let Admission {
        d,
        helper: _helper,
        gate,
        renderer,
        end,
    } = admission;
    d.header
        .validate(monotonic_ns()?)
        .map_err(|_| "request-expired-before-intent")?;
    if client_write_closed(&client)? {
        return Err("caller-cancelled-before-intent");
    }
    let controller = HeldPid::open(std::process::id())?;
    let ownership = Ownership::new(&d.nonce, d.client_uid)?;
    let record = Record {
        schema: d.schema,
        ownership,
        controller_pid: controller.pid,
        controller_start: controller.start,
        boot: d.boot.clone(),
        execution_ns: d.execution_ns,
        total_deadline_ns: d.total_deadline_ns,
        cleanup_ns: None,
        uid: None,
        phase: "intent".into(),
        cause: None,
        stage: d.stage.clone(),
    };
    let mut journal = Journal::create(&d.journal, record)?;
    *created_intent = Some(journal.record.clone());
    drop(controller);
    let manager = SystemManager {
        helper: d.helper.clone(),
        journal_dir: d.journal.clone(),
        stage: d.stage.clone(),
    };
    // Stage/socket are root owned. Ordinary clients can connect but cannot pass held credentials.
    fs::create_dir(&d.stage).map_err(|_| "stage-create")?;
    fs::set_permissions(&d.stage, fs::Permissions::from_mode(0o711)).map_err(|_| "stage-mode")?;
    let socket = d.stage.join("control");
    let listener = UnixListener::bind(&socket).map_err(|_| "control-bind")?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).map_err(|_| "control-mode")?;
    listener.set_nonblocking(true).map_err(|_| "control-nonblock")?;
    let allocation = manager.create_lease(&journal, end)?;
    journal.record.uid = Some(allocation.uid);
    journal.record.phase = "lease-active".into();
    journal.persist()?;
    audit::census(allocation.uid, &[], end)?;
    let permit = RootPermit::new().map_err(|_| "permit-create")?;
    let output = RootOutput::create()?;
    let error = RootOutput::create()?;
    manager.start_watch(&journal, end)?;
    let (spec, expected_package) = prepare_project(&d, &mut client, allocation.uid, end)?;
    Ok(Prepared {
        d,
        end,
        gate,
        renderer,
        journal,
        manager,
        listener,
        socket,
        allocation,
        permit,
        output,
        error,
        spec,
        expected_package,
        client,
    })
}
fn prepare_project(
    d: &Descriptor,
    client: &mut UnixStream,
    uid: u32,
    end: Instant,
) -> Result<(LaunchSpec, Option<String>)> {
    // Metadata alone arrived outside the execution slice. Body reception and all staging occur here.
    let snapshot = d.header.decode_snapshot(client, end).map_err(|_| "snapshot-frame")?;
    let request = d.header.admit(snapshot).map_err(|_| "request-catalogue")?;
    let expected_package = if request.command == super::super::RenderCommand::HelmPackage {
        Some(super::super::input::expected_package(&request.snapshot).map_err(|_| "package-name")?)
    } else {
        None
    };
    let input = d.stage.join("input");
    super::transport::stage(&input, &request.snapshot, uid, end)?;
    let mut argv = request.argv.clone();
    if expected_package.is_some() {
        *argv.last_mut().ok_or("package-argv")? = "/scratch/packages".into();
    }
    let spec = LaunchSpec {
        input,
        plan: GatePlan {
            argv,
            env: super::transport::environment(),
        },
    };
    Ok((spec, expected_package))
}
struct StartedSupervisor {
    d: Descriptor,
    end: Instant,
    journal: Journal,
    listener: UnixListener,
    socket: PathBuf,
    allocation: super::manager::Allocation,
    permit: RootPermit,
    output: RootOutput,
    error: RootOutput,
    spec: LaunchSpec,
    expected_package: Option<String>,
    client: UnixStream,
    supervisor: HeldPid,
    control: UnixStream,
    started: Started,
}
fn start_supervisor(prepared: Prepared) -> Result<StartedSupervisor> {
    let Prepared {
        d,
        end,
        gate,
        renderer,
        journal,
        manager,
        listener,
        socket,
        allocation,
        mut permit,
        mut output,
        mut error,
        spec,
        expected_package,
        client,
    } = prepared;
    if client_write_closed(&client)? {
        return Err("caller-cancelled-before-work");
    }
    manager.start_work(&journal, end, &d.header)?;
    let work = SystemManager::show(&journal.record.ownership.work, &journal.record.ownership, end)?;
    let supervisor = HeldPid::open(work.get("MainPID")?.parse().map_err(|_| "supervisor-pid")?)?;
    audit::credentials(supervisor.pid, allocation.uid)?;
    let mut control = loop {
        if Instant::now() >= end {
            return Err("accept-deadline");
        }
        match listener.accept() {
            Ok((s, _)) => {
                if authority::peer(&s, &supervisor, allocation.uid).is_ok() {
                    break s;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err("accept"),
        }
    };
    let ready: String = recv_checked(&mut control, end, Some(&client))?;
    if ready != d.nonce {
        return Err("supervisor-nonce");
    }
    let fds = vec![
        permit.gate_for_transfer().map_err(|_| "permit-transfer")?,
        OwnedFd::from(gate),
        OwnedFd::from(renderer),
        output.take_write()?,
        error.take_write()?,
    ];
    authority::send_rights(&control, &supervisor, allocation.uid, &d.nonce, fds, end)?;
    send(
        &mut control,
        &(
            d.execution_ns,
            d.header.total_end_ns().map_err(|_| "total-deadline")?,
            d.boot.clone(),
            spec.clone(),
        ),
        end,
    )?;
    let started: Started = recv_checked(&mut control, end, Some(&client))?;
    if started.nonce != d.nonce || started.gate <= 1 || started.bwrap <= 1 {
        return Err("started-binding");
    }
    Ok(StartedSupervisor {
        d,
        end,
        journal,
        listener,
        socket,
        allocation,
        permit,
        output,
        error,
        spec,
        expected_package,
        client,
        supervisor,
        control,
        started,
    })
}
fn observe(prepared: Prepared, cleanup_clock: CleanupClock) -> Result<Running> {
    let StartedSupervisor {
        d,
        end,
        journal,
        listener,
        socket,
        allocation,
        permit,
        output,
        error,
        spec,
        expected_package,
        client,
        supervisor,
        control,
        started,
    } = start_supervisor(prepared)?;
    let bwrap = HeldPid::open(started.bwrap)?;
    let gate = HeldPid::open(u32::try_from(started.gate).map_err(|_| "gate-pid")?)?;
    audit::credentials(bwrap.pid, allocation.uid)?;
    let setup = audit::setup(&gate, allocation.uid)?;
    let work = SystemManager::show(&journal.record.ownership.work, &journal.record.ownership, end)?;
    let watch = SystemManager::verify_watch(&journal.record.ownership, &work, end)?;
    let cg = work.get("ControlGroup")?;
    if !cg.starts_with(&format!("/klrenderer{}.slice/", d.nonce))
        || cg.contains("..")
        || !cg.ends_with(&journal.record.ownership.work)
    {
        return Err("work-cgroup");
    }
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup{cg}"));
    audit::limits(&cgroup, d.header.memory_bytes, d.header.pids)?;
    super::transport::verify_execution_slice(&d.header, std::process::id(), end)?;
    control.set_nonblocking(true).map_err(|_| "control-nonblock")?;
    let work_invocation = work.get("InvocationID")?.to_string();
    let watch_invocation = SystemManager::show(&journal.record.ownership.watch, &journal.record.ownership, end)?
        .get("InvocationID")?
        .to_string();
    let package_dir =
        File::open(format!("/proc/{}/root/scratch/packages", gate.pid)).map_err(|_| "package-directory")?;
    let observer = ExecObserver {
        journal,
        gate,
        supervisor,
        bwrap,
        parent_notice: Vec::new(),
        native_wait: None,
        watch,
        uid: allocation.uid,
        lease_invocation: allocation.invocation.clone(),
        work_invocation,
        watch_invocation,
        helper_sha: d.helper_sha,
        setup,
        outputs: [(output.object, output.flags), (error.object, error.flags)],
        permit: Some(permit),
        gate_sha: d.gate_sha,
        renderer_sha: d.renderer_sha,
        spec,
        memory: d.header.memory_bytes,
        pids: d.header.pids,
        cgroup,
        end,
        control,
        client,
        cleanup_end: None,
        cleanup_clock,
        cancel_sent: false,
        cancellation_cause: None,
    };
    Ok(Running {
        d,
        observer,
        output,
        error,
        allocation,
        listener,
        socket,
        package_dir,
        expected_package,
    })
}
fn drain_pipe(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    maximum: usize,
    end: Instant,
    cancellation: &mut impl FnMut() -> Option<&'static str>,
) -> Result<bool> {
    let mut chunk = [0; 4096];
    loop {
        if let Some(cause) = cancellation() {
            return Err(cause);
        }
        if Instant::now() >= end {
            return Err("drain-execution-timeout");
        }
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                let available = maximum.saturating_sub(bytes.len());
                bytes.extend_from_slice(&chunk[..n.min(available)]);
                if n > available {
                    return Err("output-budget");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err("output-read"),
        }
    }
}
fn drain(running: &mut Running, trace: &tracer::TraceResult) -> Drained {
    let observer = &mut running.observer;
    let mut result = Drained {
        stdout: Vec::new(),
        stderr: Vec::new(),
        native: observer.native_wait.clone(),
        cause: if trace.witnessed_and_detached {
            None
        } else {
            observer.cancellation_cause.or(Some(trace.original_cause))
        },
    };
    let mut done = [false; 2];
    while result.cause.is_none() && (result.native.is_none() || !done.iter().all(|v| *v)) {
        if Instant::now() >= observer.end {
            result.cause = Some("execution-timeout");
            break;
        }
        if observer.cancelled() {
            result.cause = observer.cancellation_cause.or(Some("caller-cancelled"));
            break;
        }
        for (i, (pipe, bytes, maximum)) in [
            (
                &mut running.output.read,
                &mut result.stdout,
                running.d.header.stdout_bytes,
            ),
            (
                &mut running.error.read,
                &mut result.stderr,
                running.d.header.stderr_bytes,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            match drain_pipe(pipe, bytes, maximum, observer.end, &mut || {
                if observer.cancelled() {
                    observer.cancellation_cause
                } else {
                    None
                }
            }) {
                Ok(eof) => done[i] = eof,
                Err(cause) => {
                    result.cause = Some(cause);
                    break;
                }
            }
        }
        if result.cause.is_some() {
            break;
        }
        if result.native.is_none() {
            match observer.poll_parent() {
                Ok(true) => result.native.clone_from(&observer.native_wait),
                Ok(false) => (),
                Err(cause) => result.cause = Some(cause),
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    if observer.cancelled() {
        result.cause = result.cause.or(observer.cancellation_cause);
    }
    result
}
fn trace(observer: ExecObserver) -> Result<(ExecObserver, tracer::TraceResult)> {
    thread::spawn(move || {
        let mut observer = observer;
        let mut kernel =
            tracer::LinuxKernel::new_on_owning_thread(i32::try_from(observer.gate.pid).map_err(|_| "gate-pid")?)?;
        let end = observer.end;
        let cleanup = reap_end(observer.cleanup_clock.ceiling);
        let trace = tracer::trace_gate_until(&mut kernel, &mut observer, end, cleanup);
        Ok::<_, &'static str>((observer, trace))
    })
    .join()
    .map_err(|_| "tracer-died-watchdog-owns-cleanup")?
}
fn collect_result_package(
    package_dir: &File,
    expected_package: Option<&str>,
    maximum: usize,
    used: usize,
    end: Instant,
    cause: &mut Option<&'static str>,
) -> Option<PackagedChart> {
    if cause.is_none() {
        match super::transport::collect_package(package_dir, expected_package, maximum.saturating_sub(used), end) {
            Ok(package) => package,
            Err(reason) => {
                *cause = Some(reason);
                None
            }
        }
    } else {
        None
    }
}
fn verify_native_cleanup(
    observer: &ExecObserver,
    native: Option<&NativeWait>,
    nonce: &str,
    uid: u32,
    cleanup: Instant,
    cause: &mut Option<&'static str>,
) -> bool {
    let mut proved = bound_native_reap(native, nonce, observer.bwrap.pid).is_ok();
    if let Some(n) = native {
        match native_completion(n, nonce, observer.bwrap.pid) {
            Ok(true) => {}
            Ok(false) => *cause = cause.or(Some("native-exit")),
            Err(reason) => {
                *cause = cause.or(Some(reason));
                proved = false;
            }
        }
    } else {
        proved = false;
    }
    if audit::empty_group(&observer.cgroup, cleanup).is_err() {
        proved = false;
    }
    if observer.bwrap.gone().is_err() || observer.gate.gone().is_err() || observer.supervisor.gone().is_err() {
        proved = false;
    }
    if audit::census(uid, &[], cleanup).is_err() {
        proved = false;
    }
    proved
}
fn await_requested_native_wait(observer: &mut ExecObserver, native: &mut Option<NativeWait>, ack_end: Instant) {
    if native.is_none() && observer.request_native_cancel(ack_end).is_ok() {
        while Instant::now() < ack_end {
            match observer.poll_parent() {
                Ok(true) => {
                    native.clone_from(&observer.native_wait);
                    break;
                }
                Ok(false) => thread::sleep(Duration::from_millis(2)),
                Err(_) => break,
            }
        }
    }
}

fn set_cleaning_record(journal: &mut Journal, cleanup: Instant, cause: Option<&'static str>) -> Result<()> {
    let sample = monotonic_ns()?;
    let local = Instant::now();
    journal.record.cleanup_ns = Some(
        sample
            .checked_add(
                u64::try_from(cleanup.saturating_duration_since(local).as_nanos()).map_err(|_| "cleanup-clock")?,
            )
            .ok_or("cleanup-clock")?
            .min(journal.record.total_end_ns()?),
    );
    journal.record.phase = "cleaning".into();
    journal.record.cause = cause.map(str::to_string);
    Ok(())
}

fn retain_cleanup_cause(journal: &mut Journal, cause: Option<&'static str>, proved: bool) {
    journal.record.cause = cause
        .or(if proved { None } else { Some("cleanup-unproved") })
        .map(str::to_string);
    if !proved {
        journal.record.phase = "quarantined".into();
        let _ = journal.persist();
    }
}

fn finish(running: Running, drained: Drained) -> Result<Outcome> {
    let Running {
        d,
        mut observer,
        output,
        error,
        allocation,
        listener,
        socket,
        package_dir,
        expected_package,
    } = running;
    let Drained {
        stdout: out,
        stderr: err,
        mut native,
        mut cause,
    } = drained;
    let end = observer.end;
    let cleanup_clock = observer.cleanup_clock.clone();
    if observer.cancelled() {
        cause = cause.or(observer.cancellation_cause);
    }
    let package = collect_result_package(
        &package_dir,
        expected_package.as_deref(),
        d.header.stdout_bytes,
        out.len(),
        end,
        &mut cause,
    );
    drop(package_dir);
    if observer.cancelled() {
        cause = cause.or(observer.cancellation_cause);
    }
    let cleanup = cleanup_clock.begin()?;
    let ack_end = reap_end(cleanup);
    await_requested_native_wait(&mut observer, &mut native, ack_end);
    // Missing parent acknowledgement cannot become positive reap after whole-work fallback.

    // Owned kill occurs before any fresh cleanup persistence, including failed fsync.
    let terminated = SystemManager::terminate(&observer.journal, cleanup);
    set_cleaning_record(&mut observer.journal, cleanup, cause)?;
    let persisted = observer.journal.persist();
    let mut proved = terminated.is_ok() && persisted.is_ok();
    proved &= verify_native_cleanup(
        &observer,
        native.as_ref(),
        &d.nonce,
        allocation.uid,
        cleanup,
        &mut cause,
    );
    drop(observer.permit.take());
    drop(observer.control);
    drop(output);
    drop(error);
    drop(listener);
    if fs::remove_file(&socket).is_err()
        || super::transport::remove_input(&d.stage.join("input"), &d.header, cleanup).is_err()
        || fs::remove_dir(&d.stage).is_err()
    {
        proved = false;
    }
    if Instant::now() >= cleanup {
        proved = false;
    }
    retain_cleanup_cause(&mut observer.journal, cause, proved);
    if !proved {
        return Ok(Outcome {
            native_code: native.as_ref().and_then(|n| n.code),
            native_signal: native.as_ref().and_then(|n| n.signal),
            package,
            cause: cause.or(Some("cleanup-unproved")),
            quarantined: true,
            cleanup_ns: observer.journal.record.cleanup_ns.ok_or("cleanup-clock")?,
            stdout: out,
            stderr: err,
        });
    }
    let cleanup_ns = observer.journal.record.cleanup_ns.ok_or("cleanup-clock")?;
    observer.journal.record.phase = "cleanup-proved".into();
    observer.journal.persist()?;
    SystemManager::stop_watch(&observer.journal, cleanup)?;
    observer.watch.gone()?;
    drop(observer.bwrap);
    drop(allocation.lock);
    drop(observer.gate);
    drop(observer.supervisor);
    drop(observer.watch);
    drop(observer.setup);
    retire_owned(observer.journal, cleanup)?;
    Ok(Outcome {
        native_code: native.as_ref().and_then(|n| n.code),
        native_signal: native.as_ref().and_then(|n| n.signal),
        package,
        cause,
        quarantined: false,
        cleanup_ns,
        stdout: out,
        stderr: err,
    })
}

fn retire_owned(mut journal: Journal, cleanup: Instant) -> Result<()> {
    SystemManager::release(&journal, cleanup)?;
    journal.record.phase = "lease-released".into();
    journal.persist()?;
    if Instant::now() >= cleanup {
        return Err("retirement-deadline");
    }
    journal.retire()?;
    Ok(())
}

enum NativeCancelRequest {
    Idle,
    Closed,
    Message(CancelNative),
}

fn poll_native_cancel(control: &mut UnixStream, cancellation: &mut Vec<u8>) -> Result<NativeCancelRequest> {
    loop {
        let mut byte = [0];
        match control.read(&mut byte) {
            Ok(0) => return Ok(NativeCancelRequest::Closed),
            Ok(_) if byte[0] == b'\n' => {
                let message = serde_json::from_slice(cancellation).map_err(|_| "private-native-cancel-schema")?;
                return Ok(NativeCancelRequest::Message(message));
            }
            Ok(_) => {
                cancellation.push(byte[0]);
                if cancellation.len() > 1024 {
                    return Err("private-native-cancel-budget");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(NativeCancelRequest::Idle),
            Err(_) => return Err("private-native-cancel-read"),
        }
    }
}

pub fn supervisor(nonce: &str, stage: &Path, execution_ns: u64, total_ns: u64) -> Result<()> {
    if nix::unistd::getuid().as_raw() == 0 || nix::unistd::getuid() != nix::unistd::geteuid() {
        return Err("supervisor-dedicated-uid");
    }
    Ownership::new(nonce, 0)?;
    if execution_ns
        .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
        .is_none_or(|n| n > total_ns)
    {
        return Err("supervisor-total-binding");
    }
    let end = instant(execution_ns)?;
    let native_cleanup_ns = execution_ns
        .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
        .ok_or("supervisor-total-overflow")?
        .min(total_ns);
    let ack_end = reap_end(instant(native_cleanup_ns)?);
    let mut control =
        super::broker_protocol::connect_socket(&stage.join("control"), end).map_err(|_| "supervisor-connect")?;
    rustix::net::sockopt::set_socket_passcred(&control, true).map_err(|_| "supervisor-passcred")?;
    send(&mut control, &nonce, end)?;
    let mut rights = authority::receive_rights(&control, nonce, end)?;
    let permit = rights.remove(0);
    let gate = File::from(rights.remove(0));
    let renderer = File::from(rights.remove(0));
    let out = rights.remove(0);
    let err = rights.remove(0);
    let (deadline, total, original_boot, spec): (u64, u64, String, LaunchSpec) = recv(&mut control, end)?;
    let current_boot = String::from_utf8(authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?)
        .map_err(|_| "supervisor-boot")?;
    if deadline != execution_ns
        || total != total_ns
        || original_boot != current_boot.trim()
        || spec.input != stage.join("input")
    {
        return Err("supervisor-binding");
    }
    let mut held = bubblewrap_probe::launch_with_outputs(gate, renderer, permit, nonce, &spec, out, err)
        .map_err(|_| "bwrap-launch")?;
    let status = held.initial_status(end).map_err(|_| "bwrap-status")?;
    send(
        &mut control,
        &Started {
            nonce: nonce.into(),
            bwrap: held.real_parent.id(),
            gate: status.child_pid,
        },
        end,
    )?;
    control
        .set_nonblocking(true)
        .map_err(|_| "supervisor-control-nonblock")?;
    let mut cancellation = Vec::new();
    let mut reaping = false;
    let mut immediate = None;
    loop {
        let now = Instant::now();
        let status = if let Some(status) = immediate.take() {
            Some(status)
        } else {
            poll_reaped(&mut held.real_parent, now, ack_end)?
        };
        if let Some(status) = status {
            use std::os::unix::process::ExitStatusExt;
            send(
                &mut control,
                &NativeWait {
                    nonce: nonce.into(),
                    bwrap: held.real_parent.id(),
                    code: status.code(),
                    signal: status.signal(),
                },
                ack_end,
            )?;
            return Ok(());
        }
        if !reaping {
            let mut requested = now >= end;
            match poll_native_cancel(&mut control, &mut cancellation)? {
                NativeCancelRequest::Idle => {}
                NativeCancelRequest::Closed => requested = true,
                NativeCancelRequest::Message(message) => {
                    message.validate(nonce, held.real_parent.id(), execution_ns, total_ns, &original_boot)?;
                    requested = true;
                }
            }
            if requested {
                immediate = cancel_unreaped(&mut held.real_parent)?;
                reaping = true;
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Watchdog retains identity allocation; it never stops lease on any failure.
pub fn watchdog(dir: &Path, nonce: &str) -> Result<()> {
    if nix::unistd::geteuid().as_raw() != 0 {
        return Err("watch-root");
    }
    let mut j = Journal::load(dir, nonce)?;
    let original = j.record.execution_ns;
    let original_total = j.record.total_end_ns()?;
    let original_boot = j.record.boot.clone();
    let stop_at = original
        .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
        .ok_or("watch-total-overflow")?
        .min(original_total)
        .saturating_sub(1_000_000_000);
    let controller = HeldPid::open(j.record.controller_pid);
    loop {
        j = Journal::load(dir, nonce)?;
        if j.record.execution_ns != original
            || j.record.total_end_ns()? != original_total
            || j.record.boot != original_boot
        {
            return Err("watch-deadline-reset");
        }
        if j.record.phase == "lease-released" {
            return Ok(());
        }
        let now = monotonic_ns()?;
        let controller_gone = controller
            .as_ref()
            .map_or(true, |p| p.start != j.record.controller_start || p.verify().is_err());
        if controller_gone || now >= stop_at {
            let cleanup_ns = j.record.cleanup_ns.unwrap_or(original_total).min(original_total);
            let cleanup = instant(cleanup_ns)?;
            // Kill/stop FIRST. Persistence failure never bypasses the actual owned termination.
            let killed = SystemManager::terminate(&j, cleanup);
            let marker = dir.join(format!("{nonce}.watch-cleanup"));
            let persisted = (|| {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                    .open(marker)
                    .map_err(|_| "watch-marker")?;
                f.write_all(b"cleanup-required; lease retained\n")
                    .map_err(|_| "watch-marker-write")?;
                f.sync_all().map_err(|_| "watch-marker-sync")?;
                File::open(dir)
                    .map_err(|_| "watch-dir")?
                    .sync_all()
                    .map_err(|_| "watch-dir-sync")
            })();
            killed?;
            persisted?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn controlled_recovery_ceiling(record: &Record, pending: Option<&Record>, boot: &str) -> Result<u64> {
    record.validate()?;
    if record.schema != super::broker_protocol::CONTROLLED_SCHEMA || record.boot != boot {
        return Err("controlled-recovery-boot");
    }
    let total = record.total_end_ns()?;
    let mut ceiling = record.cleanup_ns.unwrap_or(total).min(total);
    if let Some(pending) = pending {
        // Reuse full immutable binding admission; no pending field can name new authority.
        super::journal::pending_binding(record, pending)?;
        ceiling = ceiling.min(pending.cleanup_ns.unwrap_or(total));
    }
    Ok(ceiling)
}
fn controlled_recovery_end_pending(
    record: &Record,
    pending: Option<&Record>,
    boot: &str,
    local: Instant,
    now_ns: u64,
) -> Result<Instant> {
    let remaining = controlled_recovery_ceiling(record, pending, boot)?
        .checked_sub(now_ns)
        .filter(|n| *n > 0)
        .ok_or("controlled-recovery-expired")?;
    local
        .checked_add(Duration::from_nanos(remaining))
        .ok_or("controlled-recovery-overflow")
}
#[cfg(test)]
fn controlled_recovery_end(record: &Record, boot: &str, local: Instant, now_ns: u64) -> Result<Instant> {
    controlled_recovery_end_pending(record, None, boot, local, now_ns)
}
fn remove_recovery_stage(stage: &Path) -> Result<()> {
    // Root-owned stage contains only fixed socket; refuse unexpected files rather than recursively deleting.
    root_ancestry(stage.parent().ok_or("recovery-stage-parent")?)?;
    if stage.exists() {
        let m = fs::symlink_metadata(stage).map_err(|_| "recovery-stage")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("recovery-stage-owner");
        }
        for e in fs::read_dir(stage).map_err(|_| "recovery-stage-scan")? {
            let e = e.map_err(|_| "recovery-stage-entry")?;
            if e.file_name() != "control" || !e.file_type().map_err(|_| "recovery-stage-type")?.is_socket() {
                return Err("recovery-stage-unexpected");
            }
            fs::remove_file(e.path()).map_err(|_| "recovery-stage-remove")?;
        }
        fs::remove_dir(stage).map_err(|_| "recovery-stage-remove")?;
    }
    Ok(())
}

/// Orphan reconciliation is cleanup-only and cannot send permits or restart execution.
pub fn recover(dir: &Path, nonce: &str) -> Result<()> {
    if nix::unistd::geteuid().as_raw() != 0 {
        return Err("recovery-root");
    }
    let mut j = Journal::load_writer(dir, nonce)?;
    let current_boot = String::from_utf8(authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?)
        .map_err(|_| "recovery-boot")?;
    if current_boot.trim() != j.record.boot {
        if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            return Err("controlled-recovery-boot");
        }
        return j.reconcile_after_reboot(current_boot.trim());
    }
    if authority::starttime(j.record.controller_pid) == Ok(j.record.controller_start) {
        return Err("controller-still-alive");
    }
    // Inspect a complete pending record before deriving authority for any owned stop.
    // Invalid/partial pending data grants nothing: only the existing live record may
    // authorize a bounded fallback, followed by failure with retained pending evidence.
    let pending = if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
        let inspection_end = instant(
            j.record
                .cleanup_ns
                .unwrap_or(j.record.total_end_ns()?)
                .min(j.record.total_end_ns()?),
        )?;
        j.inspect_pending(Some(inspection_end))
    } else {
        Ok(None)
    };
    let valid_pending = pending.as_ref().ok().and_then(Option::as_ref);
    let mut end = if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
        let local = Instant::now();
        controlled_recovery_end_pending(&j.record, valid_pending, current_boot.trim(), local, monotonic_ns()?)?
    } else {
        Instant::now() + Duration::from_secs(10)
    };
    // Do not persist before fixed owned stop; partial pending writes never suppress termination.
    let stopped = SystemManager::terminate(&j, end);
    if let Err(reason) = &pending {
        return stopped.and(Err(*reason));
    }
    j.reconcile_pending_after_stop_until(Some(end))?;
    if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
        // Promotion can only retain/tighten the admitted ceiling; never renew it.
        let selected = controlled_recovery_ceiling(&j.record, valid_pending, current_boot.trim())?;
        let local = Instant::now();
        end = end.min(controlled_recovery_end_pending(
            &j.record,
            valid_pending,
            current_boot.trim(),
            local,
            monotonic_ns()?,
        )?);
        j.record.cleanup_ns = Some(j.record.cleanup_ns.unwrap_or(selected).min(selected));
    }
    j.record.phase = "quarantined".into();
    if j.record.cause.is_none() {
        j.record.cause = Some("orphan-controller".into());
    }
    j.persist()?;
    stopped?;
    let work = SystemManager::show(&j.record.ownership.work, &j.record.ownership, end)?;
    if !["inactive", "failed"].contains(&work.get("ActiveState")?) {
        return Err("recovery-work-active");
    }
    let cg = work.get("ControlGroup")?;
    if !cg.is_empty() {
        if !cg.starts_with(&format!("/klrenderer{}.slice/", j.record.ownership.nonce))
            || cg.contains("..")
            || !cg.ends_with(&j.record.ownership.work)
        {
            return Err("recovery-group-binding");
        }
        audit::empty_group(&PathBuf::from(format!("/sys/fs/cgroup{cg}")), end)?;
    }
    let lease = SystemManager::show(&j.record.ownership.lease, &j.record.ownership, end)?;
    let allocation = SystemManager::allocation(&j.record.ownership, &lease, end)?;
    if j.record.uid.is_some() && j.record.uid != Some(allocation.uid) {
        return Err("recovery-allocation-changed");
    }
    j.record.uid = Some(allocation.uid);
    audit::census(allocation.uid, &[], end)?;
    remove_recovery_stage(&j.record.stage)?;
    if Instant::now() >= end {
        return Err("recovery-deadline");
    }
    if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
        // Orphan fallback has no authenticated real-parent wait acknowledgement.
        // Group/UID absence cannot manufacture one or authorize lease retirement.
        return Err("controlled-recovery-native-reap-unproved");
    }
    j.record.phase = "cleanup-proved".into();
    j.persist()?;
    SystemManager::stop_watch(&j, end)?;
    SystemManager::release(&j, end)?;
    j.record.phase = "lease-released".into();
    j.persist()?;
    if Instant::now() >= end {
        return Err("recovery-retire-deadline");
    }
    j.retire()
}

#[cfg(test)]
mod cleanup_contract_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    pub(super) fn intent() -> Result<Record> {
        let nonce = "a".repeat(32);
        Ok(Record {
            schema: 1,
            ownership: Ownership::new(&nonce, 1000)?,
            controller_pid: 20,
            controller_start: 4,
            boot: "00000000-0000-0000-0000-000000000000".into(),
            execution_ns: 5,
            total_deadline_ns: None,
            cleanup_ns: None,
            uid: None,
            phase: "intent".into(),
            cause: None,
            stage: format!("/var/lib/private/klspike-{nonce}").into(),
        })
    }
    #[test]
    fn cleanup_clock_never_renews_or_exceeds_the_original_absolute_ceiling() -> TestResult {
        let native_end = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .ok_or("test-deadline-underflow")?;
        let clock = CleanupClock::new(native_end)?;
        let expected = super::super::broker_protocol::receipt_end(native_end)?;
        assert_eq!(clock.begin()?, expected);
        assert_eq!(clock.begin()?, expected);
        let expired = CleanupClock::new(
            Instant::now()
                .checked_sub(Duration::from_secs(11))
                .ok_or("test-deadline-underflow")?,
        )?;
        assert!(expired.begin()? <= Instant::now());
        Ok(())
    }
    #[test]
    fn error_cleanup_requires_this_attempts_exact_created_durable_intent() -> TestResult {
        let created = intent()?;
        let bytes = serde_json::to_vec(&created)?;
        assert!(created_intent_binding(None, &created).is_err());
        let mut actual = created.clone();
        actual.controller_start += 1;
        assert!(created_intent_binding(Some(&created), &actual).is_err());
        actual = created.clone();
        actual.execution_ns += 1;
        assert!(created_intent_binding(Some(&created), &actual).is_err());
        actual = created.clone();
        actual.boot = "11111111-1111-1111-1111-111111111111".into();
        assert!(created_intent_binding(Some(&created), &actual).is_err());
        actual = created.clone();
        actual.phase = "quarantined".into();
        actual.uid = Some(61234);
        actual.cause = Some("original-failure".into());
        created_intent_binding(Some(&created), &actual)?;
        assert_eq!(serde_json::to_vec(&created)?, bytes);
        Ok(())
    }
    #[test]
    fn native_receipt_requires_bound_parent_nonce_and_exclusive_zero_exit() -> TestResult {
        let nonce = "a".repeat(32);
        let mut native = NativeWait {
            nonce: nonce.clone(),
            bwrap: 20,
            code: Some(0),
            signal: None,
        };
        assert!(native_completion(&native, &nonce, 20)?);
        native.code = Some(23);
        assert!(!native_completion(&native, &nonce, 20)?);
        native.code = Some(0);
        native.signal = Some(9);
        assert!(native_completion(&native, &nonce, 20).is_err());
        native.signal = None;
        assert!(native_completion(&native, &"b".repeat(32), 20).is_err());
        assert!(native_completion(&native, &nonce, 21).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod operation_reap_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    struct Parent {
        status: Option<ExitStatus>,
        kills: usize,
        polls: usize,
        fail_kill: bool,
    }
    impl OwnedNativeParent for Parent {
        fn poll(&mut self) -> std::io::Result<Option<ExitStatus>> {
            self.polls += 1;
            Ok(self.status)
        }
        fn kill_owned(&mut self) -> std::io::Result<()> {
            self.kills += 1;
            if self.fail_kill {
                Err(std::io::Error::other("modeled owned kill failure"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn owned_child_is_killed_only_while_unreaped_and_ack_requires_real_wait_status() -> TestResult {
        let mut parent = Parent {
            status: None,
            kills: 0,
            polls: 0,
            fail_kill: false,
        };
        assert!(cancel_unreaped(&mut parent)?.is_none());
        assert_eq!(parent.kills, 1);
        let now = Instant::now();
        let end = now + Duration::from_secs(1);
        assert!(poll_reaped(&mut parent, now, end)?.is_none());
        parent.status = Some(ExitStatus::from_raw(9));
        assert_eq!(poll_reaped(&mut parent, now, end)?.and_then(|s| s.signal()), Some(9));
        assert_eq!(cancel_unreaped(&mut parent)?.and_then(|s| s.signal()), Some(9));
        assert_eq!(parent.kills, 1);
        Ok(())
    }
    #[test]
    fn expired_reap_and_owned_kill_failure_never_create_acknowledgement() {
        let now = Instant::now();
        let mut parent = Parent {
            status: None,
            kills: 0,
            polls: 0,
            fail_kill: true,
        };
        assert!(poll_reaped(&mut parent, now, now).is_err());
        assert_eq!(parent.polls, 0);
        assert!(cancel_unreaped(&mut parent).is_err());
        assert_eq!(parent.kills, 1);
        assert!(parent.status.is_none());
    }
    #[test]
    fn private_cancel_binds_nonce_owned_child_boot_and_both_original_ends() -> TestResult {
        let nonce = "a".repeat(32);
        let boot = "00000000-0000-0000-0000-000000000000";
        let message = CancelNative {
            operation: "cancel-owned-native-v2".into(),
            nonce: nonce.clone(),
            bwrap: 20,
            execution_ns: 100,
            total_deadline_ns: 10_000_000_100,
            boot: boot.into(),
        };
        message.validate(&nonce, 20, 100, 10_000_000_100, boot)?;
        for (candidate, pid, execution, total, candidate_boot) in [
            ("wrong", 20, 100, 10_000_000_100, boot),
            (nonce.as_str(), 21, 100, 10_000_000_100, boot),
            (nonce.as_str(), 20, 101, 10_000_000_100, boot),
            (nonce.as_str(), 20, 100, 10_000_000_101, boot),
            (nonce.as_str(), 20, 100, 10_000_000_100, "wrong"),
        ] {
            assert!(
                message
                    .validate(candidate, pid, execution, total, candidate_boot)
                    .is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn missing_or_wrong_parent_wait_cannot_become_positive_reap() -> TestResult {
        let nonce = "a".repeat(32);
        assert!(bound_native_reap(None, &nonce, 20).is_err());
        let ack = NativeWait {
            nonce: nonce.clone(),
            bwrap: 20,
            code: None,
            signal: Some(9),
        };
        bound_native_reap(Some(&ack), &nonce, 20)?;
        assert!(bound_native_reap(Some(&ack), &nonce, 21).is_err());
        assert!(bound_native_reap(Some(&ack), "wrong", 20).is_err());
        assert!(!native_completion(&ack, &nonce, 20)?);
        Ok(())
    }
    #[test]
    fn cleanup_clock_is_capped_inside_total_and_repeated_calls_never_renew_it() -> TestResult {
        let total = Instant::now() + Duration::from_secs(1);
        let clock = CleanupClock::bounded(total);
        assert_eq!(clock.begin()?, total);
        assert_eq!(clock.begin()?, total);
        assert!(reap_end(total) < total);
        let mut record = cleanup_contract_tests::intent()?;
        record.schema = 2;
        record.total_deadline_ns = Some(record.execution_ns + 10_000_000_000);
        record.validate()?;
        let mut changed = record.clone();
        changed.total_deadline_ns = changed.total_deadline_ns.and_then(|n| n.checked_add(1));
        assert!(created_intent_binding(Some(&record), &changed).is_err());
        changed = record.clone();
        changed.cleanup_ns = changed.total_deadline_ns.and_then(|n| n.checked_add(1));
        assert!(changed.validate().is_err());
        Ok(())
    }
}

#[cfg(test)]
mod controlled_drain_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn authenticated_write_closure_is_detected_with_read_half_retained() -> TestResult {
        let (mut client, mut peer) = UnixStream::pair()?;
        assert!(!client_write_closed(&client)?);
        peer.write_all(b"queued-body")?;
        assert!(!client_write_closed(&client)?);
        let mut body = [0; 11];
        client.read_exact(&mut body)?;
        peer.shutdown(std::net::Shutdown::Write)?;
        assert!(client_write_closed(&client)?);
        client.write_all(b"receipt")?;
        let mut receipt = [0; 7];
        peer.read_exact(&mut receipt)?;
        assert_eq!(&receipt, b"receipt");
        Ok(())
    }
    #[test]
    fn available_output_drain_polls_cancellation_between_chunks_and_before_eof() {
        let bytes = vec![1; 8192];
        let mut pipe = std::io::Cursor::new(bytes);
        let mut out = Vec::new();
        let mut polls = 0;
        let result = drain_pipe(
            &mut pipe,
            &mut out,
            8192,
            Instant::now() + Duration::from_secs(1),
            &mut || {
                polls += 1;
                (polls == 2).then_some("caller-cancelled")
            },
        );
        assert_eq!(result, Err("caller-cancelled"));
        assert_eq!(out.len(), 4096);
        let mut finished = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            drain_pipe(
                &mut finished,
                &mut out,
                8192,
                Instant::now() + Duration::from_secs(1),
                &mut || Some("caller-cancelled")
            ),
            Err("caller-cancelled")
        );
    }
}

#[cfg(test)]
mod controlled_late_cancel_recovery_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn caller_cancellation_after_actual_native_ack_still_enters_cleanup() -> TestResult {
        let (client, peer) = UnixStream::pair()?;
        let (control, supervisor) = UnixStream::pair()?;
        supervisor.shutdown(std::net::Shutdown::Write)?;
        let now = Instant::now();
        let end = now + Duration::from_secs(1);
        assert_eq!(poll_cancellation(&client, &control, true, now, end), None);
        assert_eq!(
            poll_cancellation(&client, &control, false, now, end),
            Some("native-parent-disconnected")
        );
        peer.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(
            poll_cancellation(&client, &control, true, now, end),
            Some("caller-cancelled")
        );
        assert_eq!(
            poll_cancellation(&client, &control, true, end, end),
            Some("execution-deadline")
        );
        Ok(())
    }
    #[test]
    fn repeated_controlled_recovery_preserves_total_and_refuses_expiry_or_changed_boot() -> TestResult {
        let mut record = cleanup_contract_tests::intent()?;
        record.schema = 2;
        record.total_deadline_ns = Some(20_000_000_000);
        let now = Instant::now();
        let end = controlled_recovery_end(&record, &record.boot, now, 10_000_000_000)?;
        assert_eq!(end, now + Duration::from_secs(10));
        assert_eq!(
            controlled_recovery_end(&record, &record.boot, now + Duration::from_secs(1), 11_000_000_000)?,
            end
        );
        assert!(controlled_recovery_end(&record, &record.boot, now, 20_000_000_000).is_err());
        assert!(controlled_recovery_end(&record, &record.boot, now, 20_000_000_001).is_err());
        assert!(controlled_recovery_end(&record, "11111111-1111-1111-1111-111111111111", now, 10_000_000_000).is_err());
        assert_eq!(record.total_deadline_ns, Some(20_000_000_000));
        Ok(())
    }
}

#[cfg(test)]
mod persisted_cleanup_recovery_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn persisted_early_cleanup_remains_the_ceiling_across_recovery_and_exact_expiry() -> TestResult {
        let mut record = cleanup_contract_tests::intent()?;
        record.schema = 2;
        record.execution_ns = 20_000_000_000;
        record.total_deadline_ns = Some(30_000_000_000);
        record.cleanup_ns = Some(15_000_000_000);
        let now = Instant::now();
        let ceiling = controlled_recovery_end(&record, &record.boot, now, 10_000_000_000)?;
        assert_eq!(ceiling, now + Duration::from_secs(5));
        assert_eq!(
            controlled_recovery_end(&record, &record.boot, now + Duration::from_secs(4), 14_000_000_000)?,
            ceiling
        );
        assert_eq!(
            controlled_recovery_end(&record, &record.boot, now, 15_000_000_000),
            Err("controlled-recovery-expired")
        );
        assert_eq!(
            controlled_recovery_end(&record, &record.boot, now, 16_000_000_000),
            Err("controlled-recovery-expired")
        );
        assert_eq!(record.cleanup_ns, Some(15_000_000_000));
        assert_eq!(record.total_deadline_ns, Some(30_000_000_000));
        record.cleanup_ns = Some(30_000_000_001);
        assert!(controlled_recovery_end(&record, &record.boot, now, 10_000_000_000).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod pending_cleanup_recovery_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn interrupted_pending_cleanup_is_admitted_before_at_and_after_its_exact_expiry() -> TestResult {
        let mut live = cleanup_contract_tests::intent()?;
        live.schema = 2;
        live.execution_ns = 20_000_000_000;
        live.total_deadline_ns = Some(30_000_000_000);
        let mut pending = live.clone();
        pending.cleanup_ns = Some(15_000_000_000);
        let pending = super::super::journal::pending_candidate(&live, &serde_json::to_vec(&pending)?)?;
        let now = Instant::now();
        let end = controlled_recovery_end_pending(&live, Some(&pending), &live.boot, now, 14_000_000_000)?;
        assert_eq!(end, now + Duration::from_secs(1));
        for elapsed in [15_000_000_000, 16_000_000_000] {
            assert_eq!(
                controlled_recovery_end_pending(&live, Some(&pending), &live.boot, now, elapsed),
                Err("controlled-recovery-expired")
            );
        }
        super::super::journal::promotable_pending(&live, &pending)?;
        let promoted = pending.clone();
        assert_eq!(
            controlled_recovery_end_pending(
                &promoted,
                Some(&pending),
                &promoted.boot,
                now + Duration::from_millis(500),
                14_500_000_000
            )?,
            end
        );
        assert!(live.cleanup_ns.is_none());
        assert_eq!(
            controlled_recovery_ceiling(&promoted, Some(&pending), &promoted.boot)?,
            15_000_000_000
        );
        let mut wider = pending.clone();
        wider.cleanup_ns = Some(20_000_000_000);
        assert_eq!(
            controlled_recovery_ceiling(&promoted, Some(&wider), &promoted.boot)?,
            15_000_000_000
        );
        assert!(super::super::journal::promotable_pending(&promoted, &wider).is_err());
        Ok(())
    }
    #[test]
    fn invalid_pending_cannot_supply_deadlines_or_ownership_to_live_fallback() -> TestResult {
        let mut live = cleanup_contract_tests::intent()?;
        live.schema = 2;
        live.execution_ns = 20_000_000_000;
        live.total_deadline_ns = Some(30_000_000_000);
        live.cleanup_ns = Some(12_000_000_000);
        let now = Instant::now();
        for bytes in [b"{}".as_slice(), b"not-json", b"{\"cleanup_ns\":30000000000}"] {
            assert!(super::super::journal::pending_candidate(&live, bytes).is_err());
            assert_eq!(
                controlled_recovery_end_pending(&live, None, &live.boot, now, 11_000_000_000)?,
                now + Duration::from_secs(1)
            );
            assert_eq!(
                controlled_recovery_end_pending(&live, None, &live.boot, now, 12_000_000_000),
                Err("controlled-recovery-expired")
            );
        }
        let mut foreign = live.clone();
        foreign.ownership = Ownership::new(&"b".repeat(32), 1000)?;
        assert!(controlled_recovery_ceiling(&live, Some(&foreign), &live.boot).is_err());
        assert_eq!(controlled_recovery_ceiling(&live, None, &live.boot)?, 12_000_000_000);
        Ok(())
    }
}
