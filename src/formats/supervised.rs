//! Explicit selection and authenticated bounded client transport.
use super::{
    FormatCode, FormatError, OfflineRenderer, PackagedChart, RenderProvenance, RenderRequest, RendererOutput,
    RendererStatus, Result, ToolSelection,
    broker_protocol::{self, FailureCause, FileFrame, ReplyHeader, RequestHeader},
    renderer_broker::{authority, route},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Cloneable cancellation signal scoped only to explicitly selected renderer operations.
/// Cancelling never names a PID, unit, nonce or recovery action.
#[derive(Clone, Default)]
pub struct RendererCancellationToken(Arc<AtomicBool>);
impl RendererCancellationToken {
    /// Create an uncancelled token without I/O or runtime effects.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Irreversibly request cancellation of operations carrying this token.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
impl std::fmt::Debug for RendererCancellationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RendererCancellationToken").finish_non_exhaustive()
    }
}
/// Immutable caller total end and cancellation token, explicitly selected per execution.
/// Ten seconds of cleanup are reserved inside this absolute end. Reuse never renews it.
#[derive(Clone)]
pub struct RendererOperationControl {
    end: Instant,
    cancellation: RendererCancellationToken,
}
impl RendererOperationControl {
    /// Bind the original absolute caller end and shared cancellation signal.
    /// Construction performs no I/O; execution refuses an expired/insufficient context.
    #[must_use]
    pub fn new(end: Instant, cancellation: RendererCancellationToken) -> Self {
        Self { end, cancellation }
    }
    /// The unchanged caller total end.
    #[must_use]
    pub fn end(&self) -> Instant {
        self.end
    }
}
impl std::fmt::Debug for RendererOperationControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RendererOperationControl").finish_non_exhaustive()
    }
}
/// Pure conservative conversion: the monotonic sample precedes the local sample.
fn controlled_ends(end: Instant, local_now: Instant, monotonic_now: u64, cap: Duration) -> Result<(u64, u64)> {
    let remaining = end
        .checked_duration_since(local_now)
        .and_then(|n| u64::try_from(n.as_nanos()).ok())
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    let available = remaining
        .checked_sub(broker_protocol::CLEANUP_RESERVE_NS)
        .filter(|n| *n > 0)
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    let cap = u64::try_from(cap.as_nanos())
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    let execution = monotonic_now
        .checked_add(available.min(cap))
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    let total = monotonic_now
        .checked_add(remaining)
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    Ok((execution, total))
}

struct ClientCancellation<'a> {
    control: Option<&'a RendererOperationControl>,
    signalled: bool,
}
impl ClientCancellation<'_> {
    fn poll(&mut self, socket: &mut UnixStream) -> Result<()> {
        if !self.signalled && self.control.is_some_and(|c| c.cancellation.is_cancelled()) {
            socket
                .shutdown(Shutdown::Write)
                .map_err(|_| FormatError::new(FormatCode::RendererFailed))?;
            self.signalled = true;
        }
        Ok(())
    }
    fn write_check(&mut self, socket: &mut UnixStream) -> Result<()> {
        self.poll(socket)?;
        if self.signalled {
            return Err(FormatError::new(FormatCode::RendererFailed));
        }
        Ok(())
    }
}

/// Explicit preprovisioned root system-broker socket and exact broker image identity.
#[derive(Clone)]
pub struct BrokerSelection {
    pub(crate) socket: PathBuf,
    pub(crate) image_sha256: [u8; 32],
}
impl BrokerSelection {
    /// Select a canonical absolute Unix socket and its independently verified broker image digest.
    /// No process, service, installation or privilege escalation is performed.
    /// # Errors
    /// Rejects ambiguous paths and empty digests.
    pub fn new(socket: PathBuf, image_sha256: [u8; 32]) -> Result<Self> {
        if !canonical(&socket) || image_sha256 == [0; 32] {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        Ok(Self { socket, image_sha256 })
    }
}
impl std::fmt::Debug for BrokerSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerSelection").finish_non_exhaustive()
    }
}
/// Exact caller selection matched byte-for-byte against the independently provisioned broker registry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredTool {
    pub(crate) profile: String,
    pub(crate) executable: String,
    pub(crate) image_sha256: [u8; 32],
    pub(crate) provenance: Vec<u8>,
}
impl RegisteredTool {
    /// Bind a frozen profile, canonical executable path, held image digest and canonical provenance.
    /// The root broker independently authenticates its own matching registration and static image.
    /// # Errors
    /// Rejects unknown profiles, ambiguous paths, empty digest or unbounded provenance.
    pub fn new(
        profile: String,
        executable: String,
        image_sha256: [u8; 32],
        provenance: RenderProvenance,
    ) -> Result<Self> {
        ToolSelection::new(&profile, &executable, provenance.clone())?;
        if !canonical(Path::new(&executable)) || image_sha256 == [0; 32] {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        Ok(Self {
            profile,
            executable,
            image_sha256,
            provenance: provenance.0,
        })
    }
}
impl std::fmt::Debug for RegisteredTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredTool")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
/// Explicit finite registry and caller-lowered aggregate process/swap limits.
#[derive(Clone)]
pub struct RuntimeSelection {
    pub(crate) tools: Vec<RegisteredTool>,
    pub(crate) swap_bytes: usize,
    pub(crate) pids: usize,
}
impl RuntimeSelection {
    /// Select exact preprovisioned images, zero swap, and a process ceiling at most 64.
    /// # Errors
    /// Refuses duplicates, empty/oversized registries, nonzero swap or raised process ceilings.
    pub fn new(tools: Vec<RegisteredTool>, swap_bytes: usize, pids: usize) -> Result<Self> {
        if tools.is_empty()
            || tools.len() > 8
            || swap_bytes != 0
            || pids == 0
            || pids > 64
            || tools.iter().map(|t| &t.profile).collect::<BTreeSet<_>>().len() != tools.len()
        {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        for tool in &tools {
            RegisteredTool::new(
                tool.profile.clone(),
                tool.executable.clone(),
                tool.image_sha256,
                RenderProvenance::new(&tool.provenance)?,
            )?;
        }
        Ok(Self {
            tools,
            swap_bytes,
            pids,
        })
    }
}
impl std::fmt::Debug for RuntimeSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeSelection")
            .field("profiles", &self.tools.len())
            .field("pids", &self.pids)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy)]
struct ReplyContext<'a> {
    request: &'a RenderRequest,
    start: Instant,
    end: Instant,
    control: Option<&'a RendererOperationControl>,
}

/// Opt-in Linux renderer using only an explicitly selected preprovisioned system broker.
/// There is no installation, sudo, user-manager fallback, tool substitution or cluster access.
pub struct SupervisedRenderer {
    broker: BrokerSelection,
    runtime: RuntimeSelection,
    last_failure: Option<FailureCause>,
}
impl SupervisedRenderer {
    /// Validate explicit selections without starting a service or executing a renderer.
    /// # Errors
    /// Rejects invalid configuration; runtime absence is reported by `execute`.
    pub fn new(broker: BrokerSelection, runtime: RuntimeSelection) -> Result<Self> {
        BrokerSelection::new(broker.socket.clone(), broker.image_sha256)?;
        RuntimeSelection::new(runtime.tools.clone(), runtime.swap_bytes, runtime.pids)?;
        Ok(Self {
            broker,
            runtime,
            last_failure: None,
        })
    }
    /// Fixed cause of the most recent supervised failure, never a protected diagnostic string.
    #[must_use]
    pub const fn last_failure(&self) -> Option<FailureCause> {
        self.last_failure
    }
    fn make_header(
        &self,
        request: &RenderRequest,
        end: Instant,
        control: Option<&RendererOperationControl>,
    ) -> Result<(RequestHeader, Vec<u8>)> {
        let tool = self
            .runtime
            .tools
            .iter()
            .find(|t| {
                t.profile == request.tool.profile
                    && t.executable == request.tool.executable
                    && t.provenance == request.tool.provenance().0
            })
            .ok_or_else(|| FormatError::new(FormatCode::RendererUnavailable))?;
        let original_boot = boot()?;
        let now = route::monotonic_ns().map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
        let local_now = Instant::now();
        let (execution_ns, total_deadline_ns) = if let Some(control) = control {
            if control.cancellation.is_cancelled() {
                return Err(FormatError::new(FormatCode::RendererFailed));
            }
            let (execution, total) = controlled_ends(control.end, local_now, now, request.bounds.timeout)?;
            (execution, Some(total))
        } else {
            let remaining = u64::try_from(
                end.checked_duration_since(local_now)
                    .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?
                    .as_nanos(),
            )
            .map_err(|_| FormatError::new(FormatCode::LimitExceeded))?;
            (
                now.checked_add(remaining)
                    .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?,
                None,
            )
        };
        if boot()? != original_boot {
            return Err(FormatError::new(FormatCode::RendererUnavailable));
        }
        let mut random = [0; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
        let nonce = random
            .iter()
            .flat_map(|b| {
                [
                    char::from(b"0123456789abcdef"[usize::from(b >> 4)]),
                    char::from(b"0123456789abcdef"[usize::from(b & 15)]),
                ]
            })
            .collect::<String>();
        let timeout_ns = u64::try_from(request.bounds.timeout.as_nanos())
            .map_err(|_| FormatError::new(FormatCode::LimitExceeded))?;
        let header = RequestHeader {
            schema: if control.is_some() {
                broker_protocol::CONTROLLED_SCHEMA
            } else {
                broker_protocol::SCHEMA
            },
            nonce,
            boot: original_boot,
            caller_uid: nix::unistd::getuid().as_raw(),
            caller_pid: std::process::id(),
            caller_start: authority::starttime(std::process::id())
                .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?,
            deadline_ns: execution_ns,
            total_deadline_ns,
            command: request.command.ledger_id().into(),
            profile: tool.profile.clone(),
            executable: tool.executable.clone(),
            image_sha256: tool.image_sha256,
            provenance: tool.provenance.clone(),
            argv: request.argv.clone(),
            timeout_ns,
            stdout_bytes: request.bounds.stdout_bytes,
            stderr_bytes: request.bounds.stderr_bytes,
            memory_bytes: request.bounds.memory_bytes,
            swap_bytes: self.runtime.swap_bytes,
            pids: self.runtime.pids,
            files: request
                .snapshot
                .files
                .values()
                .map(|f| FileFrame {
                    path: f.path.clone(),
                    length: f.bytes.len(),
                    sha256: broker_protocol::digest(&f.bytes),
                    provenance: f.provenance.0.clone(),
                })
                .collect(),
        };
        header.validate(now)?;
        let bytes = serde_json::to_vec(&header).map_err(|_| FormatError::new(FormatCode::InvalidProject))?;
        if bytes.len() > broker_protocol::HEADER_LIMIT {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        Ok((header, bytes))
    }
    fn read_reply(
        &mut self,
        header: RequestHeader,
        bytes: &[u8],
        socket: &mut UnixStream,
        context: ReplyContext<'_>,
    ) -> Result<RendererOutput> {
        let ReplyContext {
            request,
            start,
            end,
            control,
        } = context;
        let mut cancellation = ClientCancellation {
            control,
            signalled: false,
        };
        let reply: ReplyHeader =
            serde_json::from_slice(&broker_protocol::read_frame_checked(socket, 32768, end, &mut |s| {
                cancellation.poll(s)
            })?)
            .map_err(|_| FormatError::new(FormatCode::RendererFailed))?;
        validate_reply(&header, bytes, &reply)?;
        let stdout =
            broker_protocol::read_frame_checked(socket, reply.stdout_bytes, end, &mut |s| cancellation.poll(s))?;
        let stderr =
            broker_protocol::read_frame_checked(socket, reply.stderr_bytes, end, &mut |s| cancellation.poll(s))?;
        if stdout.len() != reply.stdout_bytes || stderr.len() != reply.stderr_bytes {
            return Err(FormatError::new(FormatCode::RendererFailed));
        }
        let package = if let Some((name, length)) = reply.package {
            let bytes = broker_protocol::read_frame_checked(socket, length, end, &mut |s| cancellation.poll(s))?;
            if bytes.len() != length {
                return Err(FormatError::new(FormatCode::RendererFailed));
            }
            Some(PackagedChart::new(name, bytes)?)
        } else {
            None
        };
        let status = match (reply.code, reply.signal) {
            (Some(0), None) => RendererStatus::Success,
            (Some(code), None) => RendererStatus::Exit(code),
            (None, Some(signal)) => RendererStatus::Signal(signal),
            _ => RendererStatus::Timeout,
        };
        let mut output = RendererOutput::new(header.profile, status, stdout, stderr, start.elapsed());
        output.package = package;
        output.failure_cause = reply.cause;
        let cancelled = control.is_some_and(|c| c.cancellation.is_cancelled());
        let total_expired = control.is_some() && Instant::now() >= end;
        if total_expired && output.failure_cause.is_none() {
            output.failure_cause = Some(FailureCause::Deadline);
        }
        if cancelled && output.failure_cause.is_none() {
            output.failure_cause = Some(FailureCause::Cancelled);
        }
        if total_expired
            || cancelled
            || reply.cause.is_some()
            || !reply.cleanup
            || status != RendererStatus::Success
            || (control.is_none() && output.elapsed >= request.bounds.timeout)
        {
            self.last_failure = reply.cause.or(Some(if total_expired {
                FailureCause::Deadline
            } else if cancelled {
                FailureCause::Cancelled
            } else {
                FailureCause::Cleanup
            }));
            let mut error = FormatError::new(if reply.cause == Some(FailureCause::Unavailable) {
                FormatCode::RendererUnavailable
            } else {
                FormatCode::RendererFailed
            });
            error.renderer_output = Some(Box::new(output));
            return Err(error);
        }
        Ok(output)
    }
    /// Execute with the caller's immutable total end and cancellation token.
    /// Existing `OfflineRenderer::execute` retains legacy v1 execution-plus-cleanup semantics.
    /// # Errors
    /// Refuses cancelled/expired/insufficient context and unavailable prerequisites before work;
    /// execution/cancellation requires the bound cleanup result within the original total end.
    pub fn execute_with_control(
        &mut self,
        request: &RenderRequest,
        control: &RendererOperationControl,
    ) -> Result<RendererOutput> {
        self.last_failure = None;
        if control.cancellation.is_cancelled() {
            self.last_failure = Some(FailureCause::Cancelled);
            return Err(FormatError::new(FormatCode::RendererFailed));
        }
        let result = self.execute_controlled(request, control);
        if let Err(error) = &result {
            if self.last_failure.is_none() {
                self.last_failure = Some(if control.cancellation.is_cancelled() {
                    FailureCause::Cancelled
                } else if Instant::now() >= control.end {
                    FailureCause::Deadline
                } else if error.code == FormatCode::RendererUnavailable {
                    FailureCause::Unavailable
                } else {
                    FailureCause::Admission
                });
            }
        }
        result
    }
    fn execute_controlled(
        &mut self,
        request: &RenderRequest,
        control: &RendererOperationControl,
    ) -> Result<RendererOutput> {
        let start = Instant::now();
        request.bounds.validate(request.command)?;
        let (header, bytes) = self.make_header(request, control.end, Some(control))?;
        let local = Instant::now();
        let now = route::monotonic_ns().map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
        let remaining = header
            .deadline_ns
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or_else(|| FormatError::new(FormatCode::RendererFailed))?;
        let execution_end = local
            .checked_add(Duration::from_nanos(remaining))
            .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
        let total_remaining = header
            .total_end_ns()?
            .checked_sub(now)
            .ok_or_else(|| FormatError::new(FormatCode::RendererFailed))?;
        let receipt_end = local
            .checked_add(Duration::from_nanos(total_remaining))
            .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?
            .min(control.end);
        if control.cancellation.is_cancelled() {
            return Err(FormatError::new(FormatCode::RendererFailed));
        }
        verify_socket(&self.broker.socket)?;
        let mut socket = broker_protocol::connect_socket(&self.broker.socket, execution_end)?;
        authenticate_broker_controlled(&socket, self.broker.image_sha256, execution_end, Some(control))?;
        let mut cancellation = ClientCancellation {
            control: Some(control),
            signalled: false,
        };
        let emitted = (|| {
            broker_protocol::write_frame_checked(&mut socket, &bytes, execution_end, &mut |s| {
                cancellation.write_check(s)
            })?;
            for file in request.snapshot.files.values() {
                broker_protocol::write_frame_checked(&mut socket, &file.bytes, execution_end, &mut |s| {
                    cancellation.write_check(s)
                })?;
            }
            Ok::<_, FormatError>(())
        })();
        if emitted.is_err() {
            // Retain this read half; never reconnect or allocate a renewed nonce/deadline.
            socket
                .shutdown(Shutdown::Write)
                .map_err(|_| FormatError::new(FormatCode::RendererFailed))?;
        }
        self.read_reply(
            header,
            &bytes,
            &mut socket,
            ReplyContext {
                request,
                start,
                end: receipt_end,
                control: Some(control),
            },
        )
    }
    fn execute_inner(&mut self, request: &RenderRequest) -> Result<RendererOutput> {
        let start = Instant::now();
        let end = start
            .checked_add(request.bounds.timeout)
            .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
        request.bounds.validate(request.command)?;
        let (header, bytes) = self.make_header(request, end, None)?;
        verify_socket(&self.broker.socket)?;
        let mut socket = broker_protocol::connect_socket(&self.broker.socket, end)?;
        authenticate_broker(&socket, self.broker.image_sha256, end)?;
        broker_protocol::write_frame(&mut socket, &bytes, end)?;
        for f in request.snapshot.files.values() {
            broker_protocol::write_frame(&mut socket, &f.bytes, end)?;
        }
        self.read_reply(
            header,
            &bytes,
            &mut socket,
            ReplyContext {
                request,
                start,
                end: broker_protocol::receipt_end(end)?,
                control: None,
            },
        )
    }
}
impl std::fmt::Debug for SupervisedRenderer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisedRenderer")
            .field("runtime", &self.runtime)
            .field("last_failure", &self.last_failure)
            .finish_non_exhaustive()
    }
}
impl OfflineRenderer for SupervisedRenderer {
    fn execute(&mut self, request: &RenderRequest) -> Result<RendererOutput> {
        self.last_failure = None;
        let result = self.execute_inner(request);
        if let Err(e) = &result {
            if self.last_failure.is_none() {
                self.last_failure = Some(if e.code == FormatCode::RendererUnavailable {
                    FailureCause::Unavailable
                } else {
                    FailureCause::Admission
                });
            }
        }
        result
    }
}
pub(crate) fn canonical(path: &Path) -> bool {
    path.is_absolute()
        && path.components().skip(1).all(|p| matches!(p, Component::Normal(_)))
        && path.to_str().is_some_and(|s| {
            !s.contains('\0') && !s.contains("//") && !s.contains("/./") && !s.ends_with("/.") && !s.ends_with('/')
        })
}
fn boot() -> Result<String> {
    let bytes = authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)
        .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let boot = String::from_utf8(bytes).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let boot = boot.trim();
    if !broker_protocol::valid_boot(boot) {
        return Err(FormatError::new(FormatCode::RendererUnavailable));
    }
    Ok(boot.into())
}
fn verify_socket(path: &Path) -> Result<()> {
    let mut ancestor = path.parent();
    while let Some(p) = ancestor {
        let m = fs::symlink_metadata(p).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(FormatError::new(FormatCode::RendererUnavailable));
        }
        ancestor = p.parent();
    }
    let m = fs::symlink_metadata(path).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    if !m.file_type().is_socket() || m.uid() != 0 {
        return Err(FormatError::new(FormatCode::RendererUnavailable));
    }
    Ok(())
}
fn authenticate_broker(socket: &UnixStream, digest: [u8; 32], end: Instant) -> Result<()> {
    authenticate_broker_controlled(socket, digest, end, None)
}
fn authenticate_broker_controlled(
    socket: &UnixStream,
    digest: [u8; 32],
    end: Instant,
    control: Option<&RendererOperationControl>,
) -> Result<()> {
    let peer =
        rustix::net::sockopt::socket_peercred(socket).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 {
        return Err(FormatError::new(FormatCode::RendererUnavailable));
    }
    let pid = u32::try_from(peer.pid.as_raw_nonzero().get())
        .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let held = authority::HeldPid::open(pid).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let mut image =
        File::open(format!("/proc/{pid}/exe")).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    if authority::digest_file_checked(&mut image, end, &mut || {
        if control.is_some_and(|c| c.cancellation.is_cancelled()) {
            Err("caller-cancelled")
        } else {
            Ok(())
        }
    })
    .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?
        != digest
    {
        return Err(FormatError::new(FormatCode::RendererUnavailable));
    }
    held.verify()
        .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))
}
pub(crate) fn validate_reply(header: &RequestHeader, bytes: &[u8], reply: &ReplyHeader) -> Result<()> {
    let artifact = reply.package.as_ref().map_or(0, |(_, n)| *n);
    let total_end = header.total_end_ns()?;
    if reply.schema != header.schema
        || reply.nonce != header.nonce
        || reply.request_sha256 != broker_protocol::digest(bytes)
        || reply.profile != header.profile
        || reply.image_sha256 != header.image_sha256
        || (reply.code.is_some() && reply.signal.is_some())
        || (reply.code.is_none() && reply.signal.is_none() && reply.cause.is_none())
        || reply.code.is_some_and(|c| !(0..=255).contains(&c))
        || reply.signal.is_some_and(|s| !(1..=64).contains(&s))
        || reply
            .stdout_bytes
            .checked_add(artifact)
            .is_none_or(|n| n > header.stdout_bytes)
        || reply.stderr_bytes > header.stderr_bytes
        || (reply.cleanup && reply.cleanup_ns.is_none())
        || reply.cleanup_ns.is_some_and(|ns| ns > total_end)
        || (reply.package.is_some() && header.command != RenderCommandId::PACKAGE)
        || (reply.is_success() && (header.command == RenderCommandId::PACKAGE) != reply.package.is_some())
    {
        return Err(FormatError::new(FormatCode::RendererFailed));
    }
    Ok(())
}
struct RenderCommandId;
impl RenderCommandId {
    const PACKAGE: &'static str = "helm-generated-package";
}

#[cfg(test)]
mod operation_control_tests {
    use super::*;
    use std::io::Write;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn total_conversion_reserves_cleanup_inside_end_and_request_cap_only_lowers_execution() -> TestResult {
        let now = Instant::now();
        let sample = 500;
        let end = now + Duration::from_secs(35);
        assert_eq!(
            controlled_ends(end, now, sample, Duration::from_secs(30))?,
            (sample + 25_000_000_000, sample + 35_000_000_000)
        );
        assert_eq!(
            controlled_ends(end, now, sample, Duration::from_secs(2))?,
            (sample + 2_000_000_000, sample + 35_000_000_000)
        );
        let later = now + Duration::from_secs(5);
        assert_eq!(
            controlled_ends(end, later, sample + 5_000_000_000, Duration::from_secs(30))?.1,
            sample + 35_000_000_000
        );
        Ok(())
    }
    #[test]
    fn expired_exact_reserve_insufficient_and_overflow_contexts_refuse() {
        let now = Instant::now();
        for end in [now, now + Duration::from_secs(9), now + Duration::from_secs(10)] {
            assert!(controlled_ends(end, now, 0, Duration::from_secs(30)).is_err());
        }
        assert!(controlled_ends(now + Duration::from_secs(11), now, u64::MAX, Duration::from_secs(1)).is_err());
        assert!(controlled_ends(now + Duration::from_secs(11), now, 0, Duration::ZERO).is_err());
    }
    #[test]
    fn clone_cancel_is_irreversible_and_control_end_never_changes() {
        let token = RendererCancellationToken::new();
        let end = Instant::now() + Duration::from_secs(20);
        let control = RendererOperationControl::new(end, token.clone());
        let cloned = control.clone();
        assert!(!cloned.cancellation.is_cancelled());
        token.cancel();
        token.cancel();
        assert!(cloned.cancellation.is_cancelled());
        assert_eq!(control.end(), end);
        assert_eq!(cloned.end(), end);
        assert!(!format!("{control:?}").contains("Instant"));
    }
    #[test]
    fn cancellation_half_closes_only_write_and_retains_the_bound_read_half() -> TestResult {
        let (mut client, mut peer) = UnixStream::pair()?;
        let token = RendererCancellationToken::new();
        let control = RendererOperationControl::new(Instant::now() + Duration::from_secs(20), token.clone());
        let mut cancellation = ClientCancellation {
            control: Some(&control),
            signalled: false,
        };
        token.cancel();
        cancellation.poll(&mut client)?;
        cancellation.poll(&mut client)?;
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte)?, 0);
        peer.write_all(b"bound cleanup receipt")?;
        let mut receipt = [0; 21];
        client.read_exact(&mut receipt)?;
        assert_eq!(&receipt, b"bound cleanup receipt");
        assert!(cancellation.write_check(&mut client).is_err());
        Ok(())
    }
    #[test]
    fn cancellation_is_checked_even_when_complete_reply_bytes_are_already_available() -> TestResult {
        let (mut client, mut peer) = UnixStream::pair()?;
        let token = RendererCancellationToken::new();
        let control = RendererOperationControl::new(Instant::now() + Duration::from_secs(20), token.clone());
        broker_protocol::write_frame(&mut peer, b"native output already available", control.end())?;
        token.cancel();
        let mut cancellation = ClientCancellation {
            control: Some(&control),
            signalled: false,
        };
        let bytes = broker_protocol::read_frame_checked(&mut client, 64, control.end(), &mut |s| cancellation.poll(s))?;
        assert_eq!(bytes, b"native output already available");
        assert!(cancellation.signalled);
        assert!(control.cancellation.is_cancelled());
        Ok(())
    }
}
