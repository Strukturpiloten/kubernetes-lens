//! Root-owned closed broker transport and nonce-owned aggregate execution containment.
use super::super::{PackagedChart, ProjectSnapshot, supervised::RegisteredTool};
use super::{
    Result, audit,
    authority::{self, HeldPid},
    broker_protocol::{self, FailureCause, ReplyHeader, RequestHeader},
    manager::SystemManager,
    route::{self, Descriptor, NativeTools},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    journal: PathBuf,
    stage_root: PathBuf,
    transport_root: PathBuf,
    helper: PathBuf,
    gate: PathBuf,
    helper_sha: [u8; 32],
    gate_sha: [u8; 32],
    tools: NativeTools,
    registrations: Vec<RegisteredTool>,
}
fn root() -> Result<()> {
    if nix::unistd::getuid().as_raw() != 0 || nix::unistd::geteuid().as_raw() != 0 {
        Err("root-system-broker-required")
    } else {
        Ok(())
    }
}
fn private_directory(path: &Path) -> Result<()> {
    route::root_ancestry(path)?;
    if fs::metadata(path).map_err(|_| "private-directory")?.mode() & 0o777 != 0o700 {
        return Err("private-directory-mode");
    }
    Ok(())
}
fn load_config(path: &Path, end: Instant) -> Result<Config> {
    root()?;
    let mut f = route::root_regular(path)?;
    if f.metadata().map_err(|_| "config-stat")?.mode() & 0o077 != 0 {
        return Err("config-private");
    }
    let config: Config = serde_json::from_slice(&authority::read_file(&mut f, 65536)?).map_err(|_| "config-schema")?;
    if config.schema != 1
        || config.registrations.is_empty()
        || config.registrations.len() > 8
        || config
            .registrations
            .iter()
            .map(|t| &t.profile)
            .collect::<BTreeSet<_>>()
            .len()
            != config.registrations.len()
    {
        return Err("config-admission");
    }
    for p in [&config.journal, &config.transport_root] {
        private_directory(p)?;
    }
    route::root_ancestry(&config.stage_root)?;
    let mut ancestor = Some(config.stage_root.as_path());
    while let Some(path) = ancestor {
        if fs::metadata(path).map_err(|_| "stage-ancestor")?.mode() & 0o001 == 0 {
            return Err("stage-ancestor-unsearchable");
        }
        ancestor = path.parent();
    }
    if fs::metadata(&config.stage_root).map_err(|_| "stage-root")?.mode() & 0o777 != 0o711 {
        return Err("stage-root-mode");
    }
    let mut image = File::open("/proc/self/exe").map_err(|_| "broker-image")?;
    if authority::digest_file(&mut image, end)? != config.helper_sha {
        return Err("broker-image-digest");
    }
    for (path, digest) in [(&config.helper, config.helper_sha), (&config.gate, config.gate_sha)] {
        let mut image = route::root_regular(path)?;
        if authority::digest_file(&mut image, end)? != digest {
            return Err("broker-candidate-digest");
        }
    }
    for registration in &config.registrations {
        RegisteredTool::new(
            registration.profile.clone(),
            registration.executable.clone(),
            registration.image_sha256,
            super::super::RenderProvenance::new(&registration.provenance).map_err(|_| "registration-provenance")?,
        )
        .map_err(|_| "registration-admission")?;
    }
    for (path, digest) in [
        ("/usr/bin/systemd-run", config.tools.systemd_run),
        ("/usr/bin/systemctl", config.tools.systemctl),
        ("/usr/bin/busctl", config.tools.busctl),
        ("/usr/bin/bwrap", config.tools.bubblewrap),
    ] {
        let mut image = route::root_regular(Path::new(path))?;
        if authority::digest_file(&mut image, end)? != digest {
            return Err("administrative-image-digest");
        }
    }
    let mut manager_image = File::open("/proc/1/exe").map_err(|_| "manager-image")?;
    if authority::digest_file(&mut manager_image, end)? != config.tools.manager {
        return Err("administrative-manager-digest");
    }
    Ok(config)
}
fn monotonic_end(ns: u64) -> Result<Instant> {
    let local = Instant::now();
    let now = route::monotonic_ns()?;
    if ns <= now {
        return Err("original-deadline");
    }
    local
        .checked_add(Duration::from_nanos(ns - now))
        .ok_or("deadline-overflow")
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "directory-sync")
}
fn durable<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .map_err(|_| "descriptor-create")?;
    let bytes = serde_json::to_vec(value).map_err(|_| "descriptor-encode")?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| "descriptor-sync")?;
    sync_directory(path.parent().ok_or("descriptor-parent")?)
}
fn slice_name(header: &RequestHeader) -> String {
    format!("klrenderer{}.slice", header.nonce)
}
fn controller_name(header: &RequestHeader) -> String {
    format!("klspike-{}-controller.service", header.nonce)
}
fn slice_path(header: &RequestHeader) -> PathBuf {
    PathBuf::from(format!("/sys/fs/cgroup/{}", slice_name(header)))
}
fn start_slice(header: &RequestHeader, end: Instant) -> Result<()> {
    header.validate(route::monotonic_ns()?).map_err(|_| "request-bounds")?;
    let slice = slice_name(header);
    // Only nonce-owned properties are changed. There is no user@ or persistent/foreign cgroup path.
    SystemManager::command("/usr/bin/systemctl", &["start".into(), slice.clone()], end, end)?;
    SystemManager::command(
        "/usr/bin/systemctl",
        &[
            "set-property".into(),
            "--runtime".into(),
            slice,
            format!("MemoryMax={}", header.memory_bytes),
            "MemorySwapMax=0".into(),
            format!("TasksMax={}", header.pids),
            "CPUQuota=100%".into(),
            "CPUQuotaPeriodSec=100ms".into(),
        ],
        end,
        end,
    )?;
    audit::limits(&slice_path(header), header.memory_bytes, header.pids)
}
fn start_controller(d: &Descriptor, path: &Path, end: Instant) -> Result<()> {
    let total = d.header.total_end_ns().map_err(|_| "total-deadline")?;
    let initial = super::manager::initial_runtime(d.execution_ns, total, route::monotonic_ns()?)? / 1000;
    let args = vec![
        "--quiet".into(),
        format!("--unit={}", controller_name(&d.header)),
        format!("--slice={}", slice_name(&d.header)),
        "--property=Type=exec".into(),
        "--property=User=root".into(),
        "--property=Restart=no".into(),
        "--property=KillMode=control-group".into(),
        "--property=SendSIGKILL=yes".into(),
        "--property=Delegate=no".into(),
        format!("--property=RuntimeMaxSec={}us", initial),
        "--property=RuntimeRandomizedExtraSec=0".into(),
        "--property=TimeoutStopSec=1s".into(),
        "--property=TimeoutStopFailureMode=terminate".into(),
        d.helper.to_str().ok_or("helper-path")?.into(),
        "controller".into(),
        path.to_str().ok_or("descriptor-path")?.into(),
    ];
    SystemManager::command("/usr/bin/systemd-run", &args, end, end)?;
    SystemManager::bound_runtime(
        &controller_name(&d.header),
        &d.nonce,
        d.execution_ns,
        total,
        initial,
        end,
    )?;
    Ok(())
}
fn controller_binding(d: &Descriptor, end: Instant) -> Result<HeldPid> {
    let unit = controller_name(&d.header);
    let out = SystemManager::command(
        "/usr/bin/systemctl",
        &[
            "show".into(),
            unit.clone(),
            "--property=Id,MainPID,InvocationID,ControlGroup,User,Restart,KillMode,SendSIGKILL,Delegate,Slice".into(),
        ],
        end,
        end,
    )?;
    let props = super::manager::parse_show(&out)?;
    let cg = format!("/{}/{unit}", slice_name(&d.header));
    if props.get("Id")? != unit
        || props.get("ControlGroup")? != cg
        || props.get("User")? != "root"
        || props.get("Restart")? != "no"
        || props.get("KillMode")? != "control-group"
        || props.get("SendSIGKILL")? != "yes"
        || props.get("Delegate")? != "no"
        || props.get("Slice")? != slice_name(&d.header)
        || props.get("InvocationID")?.len() != 32
    {
        return Err("controller-unit-binding");
    }
    let held = HeldPid::open(props.get("MainPID")?.parse().map_err(|_| "controller-pid")?)?;
    audit::credentials(held.pid, 0)?;
    let mut f = File::open(format!("/proc/{}/exe", held.pid)).map_err(|_| "controller-image")?;
    if authority::digest_file(&mut f, end)? != d.helper_sha {
        return Err("controller-image-digest");
    }
    if authority::bounded(&PathBuf::from(format!("/proc/{}/cmdline", held.pid)), 65536)?
        != format!(
            "{}\0controller\0{}\0",
            d.helper.display(),
            d.channel
                .parent()
                .ok_or("controller-descriptor-parent")?
                .join("descriptor.json")
                .display()
        )
        .as_bytes()
    {
        return Err("controller-literal-argv");
    }
    verify_execution_slice(&d.header, held.pid, end)?;
    Ok(held)
}
pub(super) fn verify_execution_slice(header: &RequestHeader, pid: u32, end: Instant) -> Result<()> {
    if Instant::now() >= end {
        return Err("execution-slice-deadline");
    }
    let expected = format!("0::/{}/{}\n", slice_name(header), controller_name(header));
    if authority::bounded(&PathBuf::from(format!("/proc/{pid}/cgroup")), 4096)? != expected.as_bytes() {
        return Err("controller-cgroup-binding");
    }
    audit::limits(&slice_path(header), header.memory_bytes, header.pids)
}
fn administrative_limits() -> Result<()> {
    let raw = authority::bounded(Path::new("/proc/self/cgroup"), 4096)?;
    let text = std::str::from_utf8(&raw).map_err(|_| "broker-cgroup")?;
    let path = text
        .trim()
        .strip_prefix("0::/system.slice/")
        .ok_or("broker-system-unit")?;
    if path.contains('/') || Path::new(path).extension() != Some(std::ffi::OsStr::new("service")) || path.contains("..")
    {
        return Err("broker-system-unit");
    }
    let base = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{path}"));
    for (file, maximum) in [("memory.max", 64 * 1024 * 1024), ("pids.max", 16)] {
        let raw = authority::bounded(&base.join(file), 128)?;
        let n = std::str::from_utf8(&raw)
            .map_err(|_| "broker-limit")?
            .trim()
            .parse::<u64>()
            .map_err(|_| "broker-limit")?;
        if n == 0 || n > maximum {
            return Err("broker-limit");
        }
    }
    if authority::bounded(&base.join("memory.swap.max"), 128)? != b"0\n" {
        return Err("broker-swap");
    }
    Ok(())
}
pub(super) fn serve(config_path: &Path, socket_path: &Path) -> Result<()> {
    root()?;
    administrative_limits()?;
    route::root_ancestry(socket_path.parent().ok_or("broker-socket-parent")?)?;
    let config = load_config(config_path, Instant::now() + Duration::from_secs(5))?;
    let listener = UnixListener::bind(socket_path).map_err(|_| "broker-bind")?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666)).map_err(|_| "broker-mode")?;
    let mut clients = listener.incoming();
    while let Some(ClientAdmission {
        mut client,
        header,
        raw,
        end,
    }) = next_admitted(&mut clients)?
    {
        let result = serve_request(&config, &header, &raw, &mut client, end);
        if let Err(reason) = result {
            let reply = ReplyHeader {
                schema: header.schema,
                nonce: header.nonce.clone(),
                request_sha256: broker_protocol::digest(&raw),
                profile: header.profile.clone(),
                image_sha256: header.image_sha256,
                code: None,
                signal: None,
                cause: Some(if reason == "registered-tool-unavailable" {
                    FailureCause::Unavailable
                } else {
                    FailureCause::Admission
                }),
                cleanup: false,
                cleanup_ns: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                package: None,
            };
            let receipt_end = if header.schema == broker_protocol::CONTROLLED_SCHEMA {
                monotonic_end(header.total_end_ns().map_err(|_| "total-deadline")?)?
            } else {
                broker_protocol::receipt_end(end).map_err(|_| "cleanup-overflow")?
            };
            let _sent = send_reply(&mut client, &reply, &[], &[], None, receipt_end);
        }
    }
    Err("broker-listener-ended")
}
struct ClientAdmission {
    client: UnixStream,
    header: RequestHeader,
    raw: Vec<u8>,
    end: Instant,
}
enum AdmissionError {
    Refused,
    Systemic(&'static str),
}
fn next_admitted(clients: &mut impl Iterator<Item = std::io::Result<UnixStream>>) -> Result<Option<ClientAdmission>> {
    next_admitted_with(clients, route::monotonic_ns, || {
        authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)
    })
}
fn next_admitted_with(
    clients: &mut impl Iterator<Item = std::io::Result<UnixStream>>,
    mut monotonic_ns: impl FnMut() -> Result<u64>,
    mut boot_id: impl FnMut() -> Result<Vec<u8>>,
) -> Result<Option<ClientAdmission>> {
    for client in clients {
        let mut client = match client {
            Ok(client) => client,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return Err("broker-accept"),
        };
        // Only pre-admission refusal is contained. Owned lifecycle errors keep their existing path.
        let (header, raw, end) = match admit_client(
            &mut client,
            Instant::now() + Duration::from_secs(5),
            &mut monotonic_ns,
            &mut boot_id,
        ) {
            Ok(admitted) => admitted,
            Err(AdmissionError::Refused) => continue,
            Err(AdmissionError::Systemic(reason)) => return Err(reason),
        };
        return Ok(Some(ClientAdmission {
            client,
            header,
            raw,
            end,
        }));
    }
    Ok(None)
}

/// Refusal here owns no durable intent, unit, slice, stage or identity lease.
fn admit_client(
    client: &mut UnixStream,
    admission_end: Instant,
    monotonic_ns: &mut impl FnMut() -> Result<u64>,
    boot_id: &mut impl FnMut() -> Result<Vec<u8>>,
) -> std::result::Result<(RequestHeader, Vec<u8>, Instant), AdmissionError> {
    let raw = broker_protocol::read_frame(client, broker_protocol::HEADER_LIMIT, admission_end)
        .map_err(|_| AdmissionError::Refused)?;
    let header: RequestHeader = serde_json::from_slice(&raw).map_err(|_| AdmissionError::Refused)?;
    let local = Instant::now();
    let now = monotonic_ns().map_err(|_| AdmissionError::Systemic("broker-admission-clock"))?;
    if header.deadline_ns <= now {
        return Err(AdmissionError::Refused);
    }
    let end = local
        .checked_add(Duration::from_nanos(header.deadline_ns - now))
        .ok_or(AdmissionError::Refused)?;
    header
        .validate(monotonic_ns().map_err(|_| AdmissionError::Systemic("broker-admission-clock"))?)
        .map_err(|_| AdmissionError::Refused)?;
    let peer = rustix::net::sockopt::socket_peercred(client).map_err(|_| AdmissionError::Refused)?;
    let caller = HeldPid::open(header.caller_pid).map_err(|_| AdmissionError::Refused)?;
    if peer.uid.as_raw() != header.caller_uid
        || u32::try_from(peer.pid.as_raw_nonzero().get()).map_err(|_| AdmissionError::Refused)? != header.caller_pid
        || caller.start != header.caller_start
    {
        return Err(AdmissionError::Refused);
    }
    let boot = boot_id().map_err(|_| AdmissionError::Systemic("broker-admission-boot"))?;
    if std::str::from_utf8(&boot)
        .map_err(|_| AdmissionError::Systemic("broker-admission-boot"))?
        .trim()
        != header.boot
    {
        return Err(AdmissionError::Refused);
    }
    Ok((header, raw, end))
}

struct Transport {
    root: PathBuf,
    descriptor: PathBuf,
    channel: PathBuf,
    listener: UnixListener,
    held: HeldPid,
}
fn prepare_transport(config: &Config, header: &RequestHeader, client: &UnixStream, end: Instant) -> Result<Transport> {
    let registration = config
        .registrations
        .iter()
        .find(|t| {
            t.profile == header.profile
                && t.executable == header.executable
                && t.image_sha256 == header.image_sha256
                && t.provenance == header.provenance
        })
        .ok_or("registered-tool-unavailable")?;
    let mut selected_image =
        route::root_regular(Path::new(&registration.executable)).map_err(|_| "registered-tool-unavailable")?;
    if authority::digest_file(&mut selected_image, end).map_err(|_| "registered-tool-unavailable")?
        != registration.image_sha256
    {
        return Err("registered-tool-unavailable");
    }
    drop(selected_image);
    let mut entries = 0;
    for e in fs::read_dir(&config.transport_root).map_err(|_| "transport-directory")? {
        let _entry = e.map_err(|_| "transport-entry")?;
        entries += 1;
        if entries >= 16 {
            return Err("transport-quarantine-budget");
        }
    }
    header
        .validate(route::monotonic_ns()?)
        .map_err(|_| "request-expired-before-cell")?;
    if route::client_write_closed(client)? {
        return Err("caller-cancelled-before-cell");
    }
    let root = config.transport_root.join(format!("klspike-{}", header.nonce));
    fs::create_dir(&root).map_err(|_| "transport-create")?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|_| "transport-mode")?;
    let descriptor = root.join("descriptor.json");
    let channel = root.join("controller");
    let d = Descriptor {
        schema: header.schema,
        nonce: header.nonce.clone(),
        client_uid: header.caller_uid,
        execution_ns: header.deadline_ns,
        total_deadline_ns: header.total_deadline_ns,
        boot: header.boot.clone(),
        journal: config.journal.clone(),
        stage: config.stage_root.join(format!("klspike-{}", header.nonce)),
        helper: config.helper.clone(),
        gate: config.gate.clone(),
        renderer: registration.executable.clone().into(),
        helper_sha: config.helper_sha,
        gate_sha: config.gate_sha,
        renderer_sha: registration.image_sha256,
        header: header.clone(),
        channel: channel.clone(),
        tools: config.tools.clone(),
    };
    durable(&descriptor, &d)?; // This immutable owned intent precedes every slice/controller mutation.
    let listener = UnixListener::bind(&channel).map_err(|_| "controller-channel")?;
    listener.set_nonblocking(true).map_err(|_| "controller-channel-mode")?;
    start_slice(header, end)?;
    start_controller(&d, &descriptor, end)?;
    let held = controller_binding(&d, end)?;
    Ok(Transport {
        root,
        descriptor,
        channel,
        listener,
        held,
    })
}
fn serve_request(
    config: &Config,
    header: &RequestHeader,
    raw: &[u8],
    client: &mut UnixStream,
    end: Instant,
) -> Result<()> {
    let Transport {
        root,
        descriptor,
        channel,
        listener,
        held,
    } = prepare_transport(config, header, client, end)?;
    let mut socket = loop {
        if Instant::now() >= end {
            return Err("controller-accept-deadline");
        }
        match listener.accept() {
            Ok((s, _)) => {
                authority::peer(&s, &held, 0)?;
                break s;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
            Err(_) => return Err("controller-accept"),
        }
    };
    authority::send_rights_count(
        &socket,
        &held,
        0,
        &header.nonce,
        vec![OwnedFd::from(client.try_clone().map_err(|_| "client-transfer")?)],
        end,
        1,
    )?;
    let receipt_end = if header.schema == broker_protocol::CONTROLLED_SCHEMA {
        monotonic_end(header.total_end_ns().map_err(|_| "total-deadline")?)?
    } else {
        broker_protocol::receipt_end(end).map_err(|_| "cleanup-overflow")?
    };
    let metadata = broker_protocol::read_frame(&mut socket, 32768, receipt_end).map_err(|_| "controller-reply")?;
    let mut reply: ReplyHeader = serde_json::from_slice(&metadata).map_err(|_| "controller-reply-schema")?;
    // Controller binds a canonical re-encoding; the broker binds the exact original wire metadata.
    reply.request_sha256 = broker_protocol::digest(raw);
    super::super::supervised::validate_reply(header, raw, &reply).map_err(|_| "controller-result-binding")?;
    let cleanup = monotonic_end(reply.cleanup_ns.unwrap_or_else(|| header.total_end_ns().unwrap_or(0)))?;
    let out = broker_protocol::read_frame(&mut socket, reply.stdout_bytes, cleanup).map_err(|_| "controller-stdout")?;
    let err = broker_protocol::read_frame(&mut socket, reply.stderr_bytes, cleanup).map_err(|_| "controller-stderr")?;
    let package = if let Some((name, n)) = &reply.package {
        Some(
            PackagedChart::new(
                name.clone(),
                broker_protocol::read_frame(&mut socket, *n, cleanup).map_err(|_| "controller-package")?,
            )
            .map_err(|_| "controller-package")?,
        )
    } else {
        None
    };
    if out.len() != reply.stdout_bytes
        || err.len() != reply.stderr_bytes
        || package.as_ref().map(|p| p.bytes.len()) != reply.package.as_ref().map(|(_, n)| *n)
    {
        return Err("controller-result-length");
    }
    // Remove only the nonce-owned controller/slice; work cleanup and retained leases are controller-owned.
    let stopped = SystemManager::command(
        "/usr/bin/systemctl",
        &["stop".into(), controller_name(header)],
        cleanup,
        cleanup,
    );
    let empty = stopped.is_ok() && held.gone().is_ok() && audit::empty_group(&slice_path(header), cleanup).is_ok();
    let retired = empty
        && SystemManager::command(
            "/usr/bin/systemctl",
            &["stop".into(), slice_name(header)],
            cleanup,
            cleanup,
        )
        .is_ok();
    if !retired {
        reply.cleanup = false;
        reply.cause = Some(FailureCause::Cleanup);
    }
    if retired && reply.cleanup {
        drop(socket);
        drop(listener);
        fs::remove_file(&channel).map_err(|_| "transport-channel-remove")?;
        fs::remove_file(&descriptor).map_err(|_| "transport-descriptor-remove")?;
        sync_directory(&root)?;
        fs::remove_dir(&root).map_err(|_| "transport-remove")?;
        sync_directory(&config.transport_root)?;
    }
    let mut byte = [0];
    if matches!(
        rustix::net::recv(
            &*client,
            &mut byte,
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT
        ),
        Ok((0, 0))
    ) {
        reply.cause = Some(FailureCause::Cancelled);
    }
    send_reply(client, &reply, &out, &err, package.as_ref(), cleanup)
}
pub(super) fn controller(path: &Path) -> Result<()> {
    root()?;
    let admission = route::Admission::read(path)?;
    let mut f = route::root_regular(path)?;
    let d: Descriptor = serde_json::from_slice(&authority::read_file(&mut f, broker_protocol::HEADER_LIMIT + 65536)?)
        .map_err(|_| "controller-descriptor")?;
    let end = monotonic_end(d.execution_ns)?;
    verify_execution_slice(&d.header, std::process::id(), end)?;
    let mut socket = broker_protocol::connect_socket(&d.channel, end).map_err(|_| "controller-connect")?;
    let mut rights = authority::receive_rights_count(&socket, &d.nonce, end, 1)?;
    let client = UnixStream::from(rights.remove(0));
    let outcome = route::controller(admission, client);
    let (code, signal, cause, cleanup, cleanup_ns, out, err, package) = match outcome {
        Ok(o) => (
            o.native_code,
            o.native_signal,
            o.cause.map(|c| {
                if c.contains("cancel") || c.contains("caller-or-supervisor-disconnected") {
                    FailureCause::Cancelled
                } else if c.contains("budget") {
                    FailureCause::OutputLimit
                } else if c.contains("timeout") || c.contains("deadline") {
                    FailureCause::Deadline
                } else if o.quarantined {
                    FailureCause::Cleanup
                } else {
                    FailureCause::Native
                }
            }),
            !o.quarantined,
            Some(o.cleanup_ns),
            o.stdout,
            o.stderr,
            o.package,
        ),
        Err(_) => (
            None,
            None,
            Some(FailureCause::Cleanup),
            false,
            None,
            Vec::new(),
            Vec::new(),
            None,
        ),
    };
    let raw = serde_json::to_vec(&d.header).map_err(|_| "request-encode")?;
    let original_total = d.header.total_end_ns().map_err(|_| "total-deadline")?;
    let reply = ReplyHeader {
        schema: d.schema,
        nonce: d.nonce,
        request_sha256: broker_protocol::digest(&raw),
        profile: d.header.profile,
        image_sha256: d.renderer_sha,
        code,
        signal,
        cause,
        cleanup,
        cleanup_ns,
        stdout_bytes: out.len(),
        stderr_bytes: err.len(),
        package: package.as_ref().map(|p| (p.name.clone(), p.bytes.len())),
    };
    // Stay in the exact bound unit until the broker stops it. A transient unit's normal GC
    // cannot race tail cleanup and masquerade as an unproved stop after successful rendering.
    let cleanup = monotonic_end(reply.cleanup_ns.unwrap_or(original_total))?;
    send_reply(&mut socket, &reply, &out, &err, package.as_ref(), cleanup)?;
    socket
        .set_read_timeout(Some(
            cleanup
                .checked_duration_since(Instant::now())
                .ok_or("controller-cleanup-expired")?,
        ))
        .map_err(|_| "controller-cleanup-timeout")?;
    let mut byte = [0];
    let _notice = socket.read(&mut byte).map_err(|_| "controller-await-owned-stop")?;
    Err("controller-broker-disconnected-before-owned-stop")
}
fn send_reply(
    socket: &mut UnixStream,
    reply: &ReplyHeader,
    out: &[u8],
    err: &[u8],
    package: Option<&PackagedChart>,
    end: Instant,
) -> Result<()> {
    let metadata = serde_json::to_vec(reply).map_err(|_| "reply-encode")?;
    for bytes in [&metadata[..], out, err] {
        broker_protocol::write_frame(socket, bytes, end).map_err(|_| "reply-write")?;
    }
    if let Some(p) = package {
        broker_protocol::write_frame(socket, &p.bytes, end).map_err(|_| "package-write")?;
    }
    Ok(())
}
pub(super) fn environment() -> BTreeMap<String, String> {
    [
        ("HOME", "/scratch/home"),
        ("TMPDIR", "/scratch"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("GOMAXPROCS", "2"),
        ("KUBECONFIG", "/scratch/no-kubeconfig"),
        ("XDG_CONFIG_HOME", "/scratch/config"),
        ("XDG_CACHE_HOME", "/scratch/cache"),
        ("XDG_DATA_HOME", "/scratch/data"),
        ("HELM_CONFIG_HOME", "/scratch/helm-config"),
        ("HELM_CACHE_HOME", "/scratch/helm-cache"),
        ("HELM_DATA_HOME", "/scratch/helm-data"),
        ("HELM_PLUGINS", "/scratch/no-plugins"),
    ]
    .into_iter()
    .map(|(a, b)| (a.into(), b.into()))
    .collect()
}
pub(super) fn stage(path: &Path, snapshot: &ProjectSnapshot, uid: u32, end: Instant) -> Result<()> {
    fs::create_dir(path).map_err(|_| "input-create")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| "input-mode")?;
    let mut directories = BTreeSet::from([path.to_path_buf()]);
    for f in snapshot.files.values() {
        if Instant::now() >= end {
            return Err("staging-deadline");
        }
        let destination = path.join(&f.path);
        let parent = destination.parent().ok_or("input-parent")?;
        let mut prefix = path.to_path_buf();
        for component in parent.strip_prefix(path).map_err(|_| "input-prefix")?.components() {
            prefix.push(component);
            if directories.insert(prefix.clone()) {
                fs::create_dir(&prefix).map_err(|_| "input-directory")?;
                fs::set_permissions(&prefix, fs::Permissions::from_mode(0o700)).map_err(|_| "input-directory-mode")?;
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(&destination)
            .map_err(|_| "input-file")?;
        for chunk in f.bytes.chunks(65536) {
            if Instant::now() >= end {
                return Err("staging-deadline");
            }
            file.write_all(chunk).map_err(|_| "input-write")?;
        }
        file.sync_all().map_err(|_| "input-sync")?;
        nix::unistd::chown(
            &destination,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(uid)),
        )
        .map_err(|_| "input-owner")?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400)).map_err(|_| "input-readonly")?;
    }
    for directory in directories.iter().rev() {
        nix::unistd::chown(
            directory,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(uid)),
        )
        .map_err(|_| "input-directory-owner")?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).map_err(|_| "input-directory-readonly")?;
        sync_directory(directory)?;
    }
    Ok(())
}
pub(super) fn remove_input(path: &Path, header: &RequestHeader, end: Instant) -> Result<()> {
    let mut directories = BTreeSet::new();
    for f in &header.files {
        if Instant::now() >= end {
            return Err("input-cleanup-deadline");
        }
        let target = path.join(&f.path);
        let m = fs::symlink_metadata(&target).map_err(|_| "input-cleanup-stat")?;
        if !m.is_file() || m.nlink() != 1 {
            return Err("input-cleanup-kind");
        }
        fs::remove_file(target).map_err(|_| "input-cleanup-file")?;
        let mut parent = Path::new(&f.path).parent();
        while let Some(p) = parent {
            directories.insert(path.join(p));
            parent = p.parent();
        }
    }
    for directory in directories.iter().rev() {
        fs::remove_dir(directory).map_err(|_| "input-cleanup-directory")?;
    }
    Ok(())
}
pub(super) fn collect_package(
    directory: &File,
    expected: Option<&str>,
    remaining: usize,
    end: Instant,
) -> Result<Option<PackagedChart>> {
    use rustix::fs::{self as rfs, Mode, OFlags};
    let scan = rfs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "package-scan")?;
    let mut entries = rustix::fs::Dir::new(scan).map_err(|_| "package-directory")?;
    let mut name = None;
    for entry in &mut entries {
        if Instant::now() >= end {
            return Err("package-deadline");
        }
        let entry = entry.map_err(|_| "package-entry")?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let value = std::str::from_utf8(bytes).map_err(|_| "package-name")?;
        if expected != Some(value) || name.replace(value.to_string()).is_some() {
            return Err("unexpected-package");
        }
    }
    let Some(expected) = expected else {
        return Ok(None);
    };
    if name.as_deref() != Some(expected) {
        return Err("missing-package");
    }
    let fd = rfs::openat(
        directory,
        expected,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "package-open")?;
    let mut f = File::from(fd);
    let m = f.metadata().map_err(|_| "package-stat")?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > u64::try_from(remaining).map_err(|_| "package-budget")?
    {
        return Err("package-budget");
    }
    let mut bytes = Vec::new();
    let mut chunk = vec![0; 65536];
    loop {
        if Instant::now() >= end {
            return Err("package-deadline");
        }
        let n = f.read(&mut chunk).map_err(|_| "package-read")?;
        if n == 0 {
            break;
        }
        if bytes.len().checked_add(n).is_none_or(|n| n > remaining) {
            return Err("package-budget");
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    if bytes.len() != usize::try_from(m.len()).map_err(|_| "package-size")? {
        return Err("package-changed");
    }
    PackagedChart::new(expected.into(), bytes)
        .map(Some)
        .map_err(|_| "package-artifact")
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn client_header() -> TestResultHeader {
        let file = b"resources: []\n";
        Ok(RequestHeader {
            schema: 1,
            nonce: "a".repeat(32),
            boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().into(),
            caller_uid: nix::unistd::getuid().as_raw(),
            caller_pid: std::process::id(),
            caller_start: authority::starttime(std::process::id())?,
            deadline_ns: route::monotonic_ns()? + 30_000_000_000,
            total_deadline_ns: None,
            command: "kustomize-build".into(),
            profile: "kustomize-5.8.3".into(),
            executable: "/root/official/kustomize".into(),
            image_sha256: [1; 32],
            provenance: b"official receipt".to_vec(),
            argv: vec!["build".into(), "./.".into()],
            timeout_ns: 30_000_000_000,
            stdout_bytes: 1024,
            stderr_bytes: 1024,
            memory_bytes: 512 * 1024 * 1024,
            swap_bytes: 0,
            pids: 64,
            files: vec![broker_protocol::FileFrame {
                path: "kustomization.yaml".into(),
                length: file.len(),
                sha256: broker_protocol::digest(file),
                provenance: b"supplied".to_vec(),
            }],
        })
    }
    type TestResultHeader = std::result::Result<RequestHeader, Box<dyn std::error::Error>>;
    #[test]
    fn rejected_clients_do_not_end_admission_or_reach_owned_lifecycle() -> TestResult {
        let mut clients = [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::Interrupted,
        ]
        .into_iter()
        .map(|kind| Err(std::io::Error::from(kind)))
        .collect::<Vec<_>>();
        for kind in 0..7 {
            let (mut writer, reader) = UnixStream::pair()?;
            match kind {
                0 => broker_protocol::write_frame(&mut writer, b"not JSON", Instant::now() + Duration::from_secs(1))?,
                1 => writer.write_all(&(u64::try_from(broker_protocol::HEADER_LIMIT)? + 1).to_be_bytes())?,
                2 => writer.write_all(&[0, 0, 0, 0])?,
                3..=5 => {
                    let mut header = client_header()?;
                    match kind {
                        3 => header.caller_start += 1,
                        4 => {
                            let first = if header.boot.starts_with('0') { "1" } else { "0" };
                            header.boot.replace_range(..1, first);
                        }
                        _ => header.deadline_ns = 0,
                    }
                    broker_protocol::write_frame(
                        &mut writer,
                        &serde_json::to_vec(&header)?,
                        Instant::now() + Duration::from_secs(1),
                    )?;
                }
                _ => {
                    let header = client_header()?;
                    broker_protocol::write_frame(
                        &mut writer,
                        &serde_json::to_vec(&header)?,
                        Instant::now() + Duration::from_secs(1),
                    )?;
                }
            }
            // Closing the refused/truncated caller must close only that connection.
            drop(writer);
            clients.push(Ok(reader));
        }
        let mut clients = clients.into_iter();
        let admitted = next_admitted(&mut clients)?.ok_or("valid caller was not admitted")?;
        assert_eq!(admitted.header.caller_start, authority::starttime(std::process::id())?);
        assert_eq!(admitted.header.nonce, "a".repeat(32));
        assert_eq!(clients.len(), 0);
        assert!(next_admitted(&mut clients)?.is_none());
        // No owned lifecycle callback/admin operation runs until next_admitted returns a caller.
        Ok(())
    }
    #[test]
    fn systemic_accept_failure_is_not_swallowed_as_a_client_refusal() {
        let mut clients = vec![Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))].into_iter();
        assert!(matches!(next_admitted(&mut clients), Err("broker-accept")));
    }
    #[test]
    fn global_admission_prerequisite_failures_propagate_before_owned_mutation() -> TestResult {
        // Inject both clock acquisition sites, boot-ID acquisition, and invalid local boot bytes.
        for failure in 0..4 {
            let header = client_header()?;
            let now = route::monotonic_ns()?;
            let mut clients = Vec::new();
            for _ in 0..2 {
                let (mut writer, reader) = UnixStream::pair()?;
                broker_protocol::write_frame(
                    &mut writer,
                    &serde_json::to_vec(&header)?,
                    Instant::now() + Duration::from_secs(1),
                )?;
                drop(writer);
                clients.push(Ok(reader));
            }
            let mut clients = clients.into_iter();
            let mut clock_reads = 0;
            let mut owned_mutations = 0;
            let result = next_admitted_with(
                &mut clients,
                || {
                    clock_reads += 1;
                    if failure == 0 || (failure == 1 && clock_reads == 2) {
                        Err("injected-global-clock-read")
                    } else {
                        Ok(now)
                    }
                },
                || match failure {
                    2 => Err("injected-global-boot-read"),
                    3 => Ok(vec![0xff]),
                    _ => Ok(header.boot.as_bytes().to_vec()),
                },
            )
            .inspect(|admitted| {
                // The production caller starts slice/controller/journal/stage operations only
                // when this boundary returns a caller. No administrative config enters admission.
                if admitted.is_some() {
                    owned_mutations += 1;
                }
            });
            let expected = if failure < 2 {
                "broker-admission-clock"
            } else {
                "broker-admission-boot"
            };
            assert!(matches!(result, Err(reason) if reason == expected));
            assert_eq!(owned_mutations, 0);
            assert_eq!(
                clients.len(),
                1,
                "a systemic failure must not silently consume following callers"
            );
        }
        Ok(())
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> std::io::Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kubernetes-lens-package-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
        fn open(&self) -> std::io::Result<File> {
            File::open(&self.0)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn packaging_accepts_only_expected_regular_artifact_and_shared_byte_allowance() -> TestResult {
        let directory = Directory::new()?;
        let fd = directory.open()?;
        let end = Instant::now() + Duration::from_secs(5);
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, end).is_err());
        fs::write(directory.0.join("chart-1.0.0.tgz"), b"123456")?;
        let package = collect_package(&fd, Some("chart-1.0.0.tgz"), 6, end)?.ok_or("missing expected package")?;
        assert_eq!(package.name, "chart-1.0.0.tgz");
        assert_eq!(package.bytes, b"123456");
        assert_eq!(
            collect_package(&fd, Some("chart-1.0.0.tgz"), 5, end).err(),
            Some("package-budget")
        );
        assert!(collect_package(&fd, None, 10, end).is_err());
        fs::write(directory.0.join("unexpected.txt"), b"x")?;
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, end).is_err());
        Ok(())
    }
    #[test]
    fn packaging_refuses_links_directories_and_original_deadline_expiry() -> TestResult {
        let directory = Directory::new()?;
        let fd = directory.open()?;
        let end = Instant::now() + Duration::from_secs(5);
        let target = directory.0.join("chart-1.0.0.tgz");
        std::os::unix::fs::symlink("/dev/null", &target)?;
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, end).is_err());
        fs::remove_file(&target)?;
        fs::create_dir(&target)?;
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, end).is_err());
        fs::remove_dir(&target)?;
        fs::write(&target, b"123")?;
        fs::hard_link(&target, directory.0.join("alias"))?;
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, end).is_err());
        assert!(collect_package(&fd, Some("chart-1.0.0.tgz"), 10, Instant::now()).is_err());
        Ok(())
    }
    #[test]
    fn environment_has_only_private_configuration_and_no_ambient_path() {
        let environment = environment();
        assert_eq!(
            environment.get("KUBECONFIG").map(String::as_str),
            Some("/scratch/no-kubeconfig")
        );
        assert_eq!(
            environment.get("HELM_PLUGINS").map(String::as_str),
            Some("/scratch/no-plugins")
        );
        assert!(!environment.contains_key("PATH"));
        assert!(!environment.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(
            environment
                .values()
                .all(|v| v == "C" || v == "2" || v.starts_with("/scratch"))
        );
    }
}
