//! Bounded private protocol shared by the explicit client and system broker.
use super::{
    ExecutionBounds, FormatCode, FormatError, HelmContext, LocalFile, ProjectLimits, ProjectSnapshot, RenderCommand,
    RenderProvenance, RenderRequest, Result, ToolSelection,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

pub(crate) const HEADER_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const SCHEMA: u32 = 1;
pub(crate) const CONTROLLED_SCHEMA: u32 = 2;
pub(crate) const CLEANUP_RESERVE_NS: u64 = 10_000_000_000;
pub(crate) const IO_POLL: Duration = Duration::from_millis(10);
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileFrame {
    pub path: String,
    pub length: usize,
    pub sha256: [u8; 32],
    pub provenance: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestHeader {
    pub schema: u32,
    pub nonce: String,
    pub boot: String,
    pub caller_uid: u32,
    pub caller_pid: u32,
    pub caller_start: u64,
    pub deadline_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_deadline_ns: Option<u64>,
    pub command: String,
    pub profile: String,
    pub executable: String,
    pub image_sha256: [u8; 32],
    pub provenance: Vec<u8>,
    pub argv: Vec<String>,
    pub timeout_ns: u64,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub memory_bytes: usize,
    pub swap_bytes: usize,
    pub pids: usize,
    pub files: Vec<FileFrame>,
}
impl RequestHeader {
    pub fn total_end_ns(&self) -> Result<u64> {
        let legacy = || self.deadline_ns.checked_add(CLEANUP_RESERVE_NS);
        match (self.schema, self.total_deadline_ns) {
            (SCHEMA, None) => legacy(),
            (CONTROLLED_SCHEMA, Some(total)) if legacy().is_some_and(|minimum| total >= minimum) => Some(total),
            _ => None,
        }
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))
    }
    pub fn command(&self) -> Result<RenderCommand> {
        [
            RenderCommand::HelmTemplate,
            RenderCommand::HelmGeneratedTemplate,
            RenderCommand::HelmLint,
            RenderCommand::HelmPackage,
            RenderCommand::KustomizeBuild,
            RenderCommand::KubectlKustomize,
        ]
        .into_iter()
        .find(|v| v.ledger_id() == self.command)
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))
    }
    pub fn bounds(&self) -> ExecutionBounds {
        ExecutionBounds {
            timeout: Duration::from_nanos(self.timeout_ns),
            stdout_bytes: self.stdout_bytes,
            stderr_bytes: self.stderr_bytes,
            memory_bytes: self.memory_bytes,
        }
    }
    pub fn validate(&self, now_ns: u64) -> Result<()> {
        let command = self.command()?;
        self.bounds().validate(command)?;
        self.total_end_ns()?;
        if !matches!(self.schema, SCHEMA | CONTROLLED_SCHEMA)
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_boot(&self.boot)
            || self.caller_pid > i32::MAX as u32
            || self.caller_pid <= 1
            || self.caller_start == 0
            || self.deadline_ns <= now_ns
            || self.deadline_ns - now_ns > self.timeout_ns
            || self.swap_bytes != 0
            || self.pids == 0
            || self.pids > 64
            || self.argv.len() > 1024
            || self.argv.iter().map(|v| v.len() + 1).sum::<usize>() > 32768
            || self.argv.iter().any(|v| v.contains('\0'))
            || self.files.is_empty()
            || self.files.len() > ProjectLimits::default().files
        {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        ToolSelection::new(
            &self.profile,
            &self.executable,
            RenderProvenance::new(&self.provenance)?,
        )?;
        let mut total = 0usize;
        for f in &self.files {
            total = total
                .checked_add(f.length)
                .and_then(|n| n.checked_add(f.path.len()))
                .and_then(|n| n.checked_add(f.provenance.len()))
                .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
        }
        if total > ProjectLimits::default().bytes {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        // Reuse the independent path/provenance admission, without allocating body bytes.
        ProjectSnapshot::new(
            self.files
                .iter()
                .map(|f| {
                    Ok(LocalFile::new(
                        f.path.clone(),
                        Vec::new(),
                        RenderProvenance::new(&f.provenance)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            ProjectLimits::default(),
        )?;
        Ok(())
    }
    pub fn decode_snapshot(&self, socket: &mut UnixStream, end: Instant) -> Result<ProjectSnapshot> {
        let mut files = Vec::new();
        for f in &self.files {
            let bytes = read_frame(socket, f.length, end)?;
            if bytes.len() != f.length || digest(&bytes) != f.sha256 {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
            files.push(LocalFile::new(
                f.path.clone(),
                bytes,
                RenderProvenance::new(&f.provenance)?,
            ));
        }
        ProjectSnapshot::new(files, ProjectLimits::default())
    }
    pub fn admit(&self, snapshot: ProjectSnapshot) -> Result<RenderRequest> {
        let tool = ToolSelection::new(
            &self.profile,
            &self.executable,
            RenderProvenance::new(&self.provenance)?,
        )?;
        let command = self.command()?;
        let bad = || FormatError::new(FormatCode::InvalidProject);
        let a = &self.argv;
        let request = match command {
            RenderCommand::HelmTemplate | RenderCommand::HelmGeneratedTemplate => {
                if a.len() < 11
                    || a[0] != "template"
                    || a[3] != "--namespace"
                    || a[5] != "--values"
                    || a[7] != "--kube-version"
                    || a[9] != "--include-crds"
                    || a[10] != "--dry-run=client"
                {
                    return Err(bad());
                }
                let mut api_versions = Vec::new();
                let mut upgrade = false;
                let mut i = 11;
                while i < a.len() {
                    if a[i] == "--api-versions" && !upgrade {
                        api_versions.push(a.get(i + 1).ok_or_else(bad)?.clone());
                        i += 2;
                    } else if a[i] == "--is-upgrade" && i + 1 == a.len() {
                        upgrade = true;
                        i += 1;
                    } else {
                        return Err(bad());
                    }
                }
                let mut request = super::plan_helm(
                    snapshot,
                    tool,
                    &HelmContext {
                        chart: a[2].strip_prefix("./").ok_or_else(bad)?.into(),
                        values: a[6].strip_prefix("./").ok_or_else(bad)?.into(),
                        release: a[1].clone(),
                        namespace: a[4].clone(),
                        kubernetes_patch: a[8].clone(),
                        api_versions,
                        upgrade,
                    },
                    self.bounds(),
                )?;
                request.command = command;
                request
            }
            RenderCommand::KustomizeBuild | RenderCommand::KubectlKustomize => {
                if a.len() != 2 {
                    return Err(bad());
                }
                super::plan_kustomize(snapshot, tool, a[1].strip_prefix("./").ok_or_else(bad)?, self.bounds())?
            }
            RenderCommand::HelmLint | RenderCommand::HelmPackage => {
                let expected = if command == RenderCommand::HelmLint {
                    vec!["lint", "./.", "--strict"]
                } else {
                    vec!["package", "./.", "--destination", "./packages"]
                };
                if a.iter().map(String::as_str).collect::<Vec<_>>() != expected {
                    return Err(bad());
                }
                // Generated validation admits the same bounded local chart/dependency graph as template.
                let context = HelmContext {
                    chart: ".".into(),
                    values: "values.yaml".into(),
                    release: "offline".into(),
                    namespace: "default".into(),
                    kubernetes_patch: "1.20.15".into(),
                    api_versions: Vec::new(),
                    upgrade: false,
                };
                let mut request = super::plan_helm(snapshot, tool, &context, self.bounds())?;
                request.command = command;
                request.argv.clone_from(a);
                request
            }
        };
        if request.command != command || request.argv != self.argv {
            return Err(bad());
        }
        let row = command.row()?;
        if !row["profile_ids"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|v| v.as_str() == Some(self.profile.as_str())))
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        Ok(request)
    }
}
pub(crate) fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn read_frame(socket: &mut UnixStream, max: usize, end: Instant) -> Result<Vec<u8>> {
    let mut length = [0; 8];
    read_exact(socket, &mut length, end)?;
    let length =
        usize::try_from(u64::from_be_bytes(length)).map_err(|_| FormatError::new(FormatCode::LimitExceeded))?;
    if length > max {
        return Err(FormatError::new(FormatCode::LimitExceeded));
    }
    let mut bytes = vec![0; length];
    read_exact(socket, &mut bytes, end)?;
    Ok(bytes)
}
/// The one absolute upper bound for cleanup and final transport; never renew it.
pub(crate) fn receipt_end(native_end: Instant) -> Result<Instant> {
    native_end
        .checked_add(Duration::from_secs(10))
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))
}
pub(crate) fn read_exact(socket: &mut UnixStream, bytes: &mut [u8], end: Instant) -> Result<()> {
    read_exact_checked(socket, bytes, end, &mut |_| Ok(()))
}
pub(crate) fn read_exact_checked(
    socket: &mut UnixStream,
    bytes: &mut [u8],
    end: Instant,
    check: &mut impl FnMut(&mut UnixStream) -> Result<()>,
) -> Result<()> {
    let mut used = 0;
    loop {
        check(socket)?;
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|n| !n.is_zero())
            .ok_or_else(|| FormatError::new(FormatCode::RendererFailed))?;
        if used == bytes.len() {
            return Ok(());
        }
        socket
            .set_read_timeout(Some(remaining.min(IO_POLL)))
            .map_err(|_| FormatError::new(FormatCode::RendererFailed))?;
        let upper = (used + 65536).min(bytes.len());
        match socket.read(&mut bytes[used..upper]) {
            Ok(0) => return Err(FormatError::new(FormatCode::RendererFailed)),
            Ok(n) => used += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                std::thread::sleep(IO_POLL.min(end.saturating_duration_since(Instant::now())));
            }
            Err(_) => return Err(FormatError::new(FormatCode::RendererFailed)),
        }
    }
}
pub(crate) fn write_exact(socket: &mut UnixStream, bytes: &[u8], end: Instant) -> Result<()> {
    write_exact_checked(socket, bytes, end, &mut |_| Ok(()))
}
pub(crate) fn write_exact_checked(
    socket: &mut UnixStream,
    bytes: &[u8],
    end: Instant,
    check: &mut impl FnMut(&mut UnixStream) -> Result<()>,
) -> Result<()> {
    let mut used = 0;
    loop {
        check(socket)?;
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|n| !n.is_zero())
            .ok_or_else(|| FormatError::new(FormatCode::RendererFailed))?;
        if used == bytes.len() {
            return Ok(());
        }
        socket
            .set_write_timeout(Some(remaining.min(IO_POLL)))
            .map_err(|_| FormatError::new(FormatCode::RendererFailed))?;
        let upper = (used + 65536).min(bytes.len());
        match socket.write(&bytes[used..upper]) {
            Ok(0) => return Err(FormatError::new(FormatCode::RendererFailed)),
            Ok(n) => used += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                std::thread::sleep(IO_POLL.min(end.saturating_duration_since(Instant::now())));
            }
            Err(_) => return Err(FormatError::new(FormatCode::RendererFailed)),
        }
    }
}
pub(crate) fn read_frame_checked(
    socket: &mut UnixStream,
    max: usize,
    end: Instant,
    check: &mut impl FnMut(&mut UnixStream) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut length = [0; 8];
    read_exact_checked(socket, &mut length, end, check)?;
    let length =
        usize::try_from(u64::from_be_bytes(length)).map_err(|_| FormatError::new(FormatCode::LimitExceeded))?;
    if length > max {
        return Err(FormatError::new(FormatCode::LimitExceeded));
    }
    let mut bytes = vec![0; length];
    read_exact_checked(socket, &mut bytes, end, check)?;
    Ok(bytes)
}
pub(crate) fn write_frame(socket: &mut UnixStream, bytes: &[u8], end: Instant) -> Result<()> {
    write_frame_checked(socket, bytes, end, &mut |_| Ok(()))
}
pub(crate) fn write_frame_checked(
    socket: &mut UnixStream,
    bytes: &[u8],
    end: Instant,
    check: &mut impl FnMut(&mut UnixStream) -> Result<()>,
) -> Result<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| FormatError::new(FormatCode::LimitExceeded))?
        .to_be_bytes();
    write_exact_checked(socket, &length, end, check)?;
    write_exact_checked(socket, bytes, end, check)
}
pub(crate) fn connect_socket(path: &std::path::Path, end: Instant) -> Result<UnixStream> {
    use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    if Instant::now() >= end {
        return Err(FormatError::new(FormatCode::RendererUnavailable));
    }
    let address = SocketAddrUnix::new(path).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    // A saturated local socket is unavailable; a blocking connect cannot consume a renewed deadline.
    net::connect(&fd, &address).map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    let socket = UnixStream::from(fd);
    socket
        .set_nonblocking(false)
        .map_err(|_| FormatError::new(FormatCode::RendererUnavailable))?;
    Ok(socket)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplyHeader {
    pub schema: u32,
    pub nonce: String,
    pub request_sha256: [u8; 32],
    pub profile: String,
    pub image_sha256: [u8; 32],
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub cause: Option<FailureCause>,
    pub cleanup: bool,
    pub cleanup_ns: Option<u64>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub package: Option<(String, usize)>,
}
/// Fixed supervisor failure categories; private diagnostics never become failure strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FailureCause {
    /// The selected broker or exact registered image is unavailable.
    Unavailable,
    /// An admission, peer or kernel invariant failed.
    Admission,
    /// The original total deadline expired.
    Deadline,
    /// The caller cancelled this explicitly controlled operation.
    Cancelled,
    /// Output or package exceeded its allowance.
    OutputLimit,
    /// Native execution failed.
    Native,
    /// Cleanup could not be independently proved.
    Cleanup,
}

impl ReplyHeader {
    pub fn is_success(&self) -> bool {
        self.code == Some(0) && self.signal.is_none() && self.cause.is_none() && self.cleanup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn boot_context_rejects_malformed_uuid_before_controlled_admission() {
        assert!(valid_boot("00000000-0000-0000-0000-000000000000"));
        for boot in [
            "",
            "00000000-0000-0000-0000-00000000000",
            "000000000000000000000000000000000000",
            "00000000-0000-0000-0000-00000000000G",
        ] {
            assert!(!valid_boot(boot));
            let mut request = header();
            request.schema = CONTROLLED_SCHEMA;
            request.total_deadline_ns = Some(request.deadline_ns + CLEANUP_RESERVE_NS);
            request.boot = boot.into();
            assert!(request.validate(1).is_err());
        }
    }
    #[test]
    fn v2_requires_both_original_ends_and_never_accepts_v1_downgrade() -> TestResult {
        let mut h = header();
        let legacy = serde_json::to_value(&h)?;
        assert!(legacy.get("total_deadline_ns").is_none());
        h.schema = CONTROLLED_SCHEMA;
        assert!(h.validate(1).is_err());
        h.total_deadline_ns = Some(h.deadline_ns + CLEANUP_RESERVE_NS);
        h.validate(1)?;
        assert_eq!(h.total_end_ns()?, h.deadline_ns + CLEANUP_RESERVE_NS);
        h.total_deadline_ns = Some(h.deadline_ns + CLEANUP_RESERVE_NS - 1);
        assert!(h.validate(1).is_err());
        h.total_deadline_ns = Some(h.deadline_ns + CLEANUP_RESERVE_NS);
        h.schema = SCHEMA;
        assert!(h.validate(1).is_err());
        h.schema = CONTROLLED_SCHEMA;
        assert!(h.validate(h.deadline_ns).is_err());
        h.deadline_ns = u64::MAX;
        assert!(h.total_end_ns().is_err());
        Ok(())
    }
    #[test]
    fn v2_reply_must_match_the_exact_schema_and_original_total_cleanup_ceiling() -> TestResult {
        let mut h = header();
        h.schema = CONTROLLED_SCHEMA;
        h.total_deadline_ns = Some(h.deadline_ns + CLEANUP_RESERVE_NS);
        let raw = serde_json::to_vec(&h)?;
        let mut reply = ReplyHeader {
            schema: CONTROLLED_SCHEMA,
            nonce: h.nonce.clone(),
            request_sha256: digest(&raw),
            profile: h.profile.clone(),
            image_sha256: h.image_sha256,
            code: Some(0),
            signal: None,
            cause: None,
            cleanup: true,
            cleanup_ns: h.total_deadline_ns,
            stdout_bytes: 0,
            stderr_bytes: 0,
            package: None,
        };
        super::super::supervised::validate_reply(&h, &raw, &reply)?;
        reply.cleanup_ns = h.total_deadline_ns.and_then(|n| n.checked_add(1));
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        reply.cleanup_ns = h.total_deadline_ns;
        reply.schema = SCHEMA;
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        Ok(())
    }
    fn header() -> RequestHeader {
        RequestHeader {
            schema: 1,
            nonce: "a".repeat(32),
            boot: "00000000-0000-0000-0000-000000000000".into(),
            caller_uid: 1000,
            caller_pid: 10,
            caller_start: 10,
            deadline_ns: 100,
            total_deadline_ns: None,
            command: "kustomize-build".into(),
            profile: "kustomize-5.8.3".into(),
            executable: "/root/official/kustomize".into(),
            image_sha256: [1; 32],
            provenance: b"canonical receipt".to_vec(),
            argv: vec!["build".into(), "./.".into()],
            timeout_ns: 1000,
            stdout_bytes: 1024,
            stderr_bytes: 1024,
            memory_bytes: 512 * 1024 * 1024,
            swap_bytes: 0,
            pids: 64,
            files: vec![FileFrame {
                path: "kustomization.yaml".into(),
                length: 14,
                sha256: digest(b"resources: []\n"),
                provenance: b"supplied revision".to_vec(),
            }],
        }
    }
    #[test]
    fn metadata_rejects_unknown_fields_and_unbounded_frames() -> TestResult {
        let h = header();
        h.validate(1)?;
        let mut value = serde_json::to_value(h)?;
        value["arbitrary_command"] = serde_json::json!("apply");
        assert!(serde_json::from_value::<RequestHeader>(value).is_err());
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&u64::MAX.to_be_bytes())?;
        assert!(
            matches!(read_frame(&mut receiver,16,Instant::now()+Duration::from_secs(1)),Err(e) if e.code==FormatCode::LimitExceeded)
        );
        Ok(())
    }
    #[test]
    fn partial_frame_progress_never_renews_the_original_deadline() -> TestResult {
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_all(&16_u64.to_be_bytes())?;
        sender.write_all(&[1])?;
        let end = Instant::now() + Duration::from_millis(80);
        let writer = std::thread::spawn(move || {
            for _ in 1..16 {
                std::thread::sleep(Duration::from_millis(20));
                if sender.write_all(&[1]).is_err() {
                    break;
                }
            }
        });
        let result = read_frame(&mut receiver, 16, end);
        drop(receiver);
        writer.join().map_err(|_| "partial-frame writer panicked")?;
        assert!(matches!(result, Err(e) if e.code == FormatCode::RendererFailed));
        Ok(())
    }
    #[test]
    fn final_receipt_can_cross_native_deadline_but_never_the_cleanup_ceiling() -> TestResult {
        let (mut sender, mut receiver) = UnixStream::pair()?;
        let native_end = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("test-deadline-underflow")?;
        let cleanup = receipt_end(native_end)?;
        assert_eq!(cleanup, native_end + Duration::from_secs(10));
        write_frame(&mut sender, b"bounded failure receipt", cleanup)?;
        assert_eq!(read_frame(&mut receiver, 64, cleanup)?, b"bounded failure receipt");
        let expired = receipt_end(
            Instant::now()
                .checked_sub(Duration::from_secs(11))
                .ok_or("test-deadline-underflow")?,
        )?;
        assert!(read_frame(&mut receiver, 64, expired).is_err());
        assert!(read_exact(&mut receiver, &mut [], expired).is_err());
        assert!(write_exact(&mut sender, &[], expired).is_err());
        assert!(write_frame(&mut sender, b"late receipt", expired).is_err());
        Ok(())
    }
    #[test]
    fn metadata_admission_binds_original_deadline_and_snapshot_paths() -> TestResult {
        let h = header();
        h.validate(1)?;
        let mut altered = h.clone();
        altered.deadline_ns = 1002;
        assert!(altered.validate(1).is_err());
        altered = h.clone();
        altered.files[0].path = "../credential".into();
        assert!(altered.validate(1).is_err());
        altered = h.clone();
        altered.files[0].length = usize::MAX;
        assert!(altered.validate(1).is_err());
        altered = h.clone();
        altered.swap_bytes = 1;
        assert!(altered.validate(1).is_err());
        altered = h.clone();
        altered.pids = 65;
        assert!(altered.validate(1).is_err());
        altered = h.clone();
        altered.boot = "z".repeat(36);
        assert!(altered.validate(1).is_err());
        Ok(())
    }
    #[test]
    fn controller_reconstructs_catalogue_and_refuses_argv_injection() -> TestResult {
        let h = header();
        let snapshot = || {
            ProjectSnapshot::new(
                vec![LocalFile::new(
                    "kustomization.yaml".into(),
                    b"resources: []\n".to_vec(),
                    RenderProvenance::new(b"source")?,
                )],
                ProjectLimits::default(),
            )
        };
        h.admit(snapshot()?)?;
        for argv in [
            vec!["build", "./.", "--enable-exec"],
            vec!["apply", "./."],
            vec!["build", "/etc"],
            vec!["build", "https://example.invalid/base"],
        ] {
            let mut altered = h.clone();
            altered.argv = argv.into_iter().map(String::from).collect();
            assert!(altered.admit(snapshot()?).is_err());
        }
        Ok(())
    }
    #[test]
    fn native_zero_and_bound_success_require_cleanup_and_exclusive_status() -> TestResult {
        let h = header();
        let raw = serde_json::to_vec(&h)?;
        let mut reply = ReplyHeader {
            schema: 1,
            nonce: h.nonce.clone(),
            request_sha256: digest(&raw),
            profile: h.profile.clone(),
            image_sha256: h.image_sha256,
            code: Some(0),
            signal: None,
            cause: None,
            cleanup: true,
            cleanup_ns: Some(100),
            stdout_bytes: 0,
            stderr_bytes: 0,
            package: None,
        };
        super::super::supervised::validate_reply(&h, &raw, &reply)?;
        assert!(reply.is_success());
        reply.cleanup = false;
        assert!(!reply.is_success());
        reply.cleanup = true;
        reply.signal = Some(9);
        assert!(!reply.is_success());
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        reply.signal = None;
        reply.nonce = "b".repeat(32);
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        reply.nonce = h.nonce.clone();
        reply.request_sha256 = [2; 32];
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        reply.request_sha256 = digest(&raw);
        reply.image_sha256 = [2; 32];
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        reply.image_sha256 = h.image_sha256;
        reply.stdout_bytes = h.stdout_bytes;
        reply.package = Some(("chart-1.tgz".into(), 1));
        assert!(super::super::supervised::validate_reply(&h, &raw, &reply).is_err());
        Ok(())
    }
}
