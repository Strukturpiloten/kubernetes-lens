//! Default-off pre-permit rendezvous. The witness body remains outside product authority.
use super::{Result, audit, authority, broker_protocol, route, wait_observer};
use rustix::net::{self, SocketAddrUnix};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const PROFILE: &str = "root-pre-permit-input-view-witness-v1";
const OFFER_LIMIT: usize = 4096;
const ACK_LIMIT: usize = 2048;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    schema: u32,
    profile: String,
    socket: PathBuf,
    boot: String,
    grant_nonce: String,
    observer: Actor,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    pid: u32,
    start: u64,
    uid: u32,
    gid: u32,
    image_sha256: String,
    cmdline_sha256: String,
}
fn lower_hex(raw: &str, length: usize) -> bool {
    raw.len() == length && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Selection {
    pub fn validate_shape(&self) -> Result<()> {
        let path = self.socket.to_str().ok_or("input-view-socket-encoding")?;
        if self.schema != 1
            || self.profile != PROFILE
            || !lower_hex(&self.grant_nonce, 32)
            || self.observer.pid <= 1
            || self.observer.start == 0
            || self.observer.uid != 0
            || self.observer.gid != 0
            || !lower_hex(&self.observer.image_sha256, 64)
            || !lower_hex(&self.observer.cmdline_sha256, 64)
            || !self.socket.is_absolute()
            || path.contains('\0')
            || path.split('/').skip(1).any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("input-view-selection");
        }
        // The actual implementation's sockaddr_un limit, including its terminator.
        SocketAddrUnix::new(&self.socket).map_err(|_| "input-view-socket-length")?;
        let boot = self.boot.as_bytes();
        if boot.len() != 36
            || !boot.iter().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
        {
            return Err("input-view-boot");
        }
        Ok(())
    }
    pub fn validate_request(&self, header: &broker_protocol::RequestHeader, observer: bool) -> Result<()> {
        self.validate_shape()?;
        if header.schema != broker_protocol::CONTROLLED_SCHEMA
            || !observer
            || self.boot != header.boot
            || self.grant_nonce == header.nonce
        {
            return Err("input-view-controlled-origin");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectIdentity {
    dev: u64,
    ino: u64,
}
impl From<authority::Object> for ObjectIdentity {
    fn from(o: authority::Object) -> Self {
        Self { dev: o.dev, ino: o.ino }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    schema: u32,
    profile: String,
    grant_nonce: String,
    request_nonce: String,
    request_sha256: String,
    boot: String,
    execution_ns: u64,
    total_ns: u64,
    controller: wait_observer::Identity,
    supervisor: wait_observer::Identity,
    bwrap: wait_observer::Identity,
    gate: wait_observer::Identity,
    tracer: wait_observer::Identity,
    leased_uid: u32,
    leased_gid: u32,
    work_invocation: String,
    ready_ns: u64,
    descriptor_object: ObjectIdentity,
    origin_object: ObjectIdentity,
    stage_input_object: ObjectIdentity,
    input_object: ObjectIdentity,
    mount_namespace_object: ObjectIdentity,
    cgroup_object: ObjectIdentity,
    origin_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    schema: u32,
    profile: String,
    grant_nonce: String,
    request_nonce: String,
    request_sha256: String,
    offer_sha256: String,
    witness_sha256: String,
    capture_started_ns: u64,
    capture_finished_ns: u64,
}
fn compact_body(body: &[u8]) -> Result<()> {
    let mut quoted = false;
    let mut escaped = false;
    for byte in body {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if byte.is_ascii_whitespace() {
            return Err("input-view-json-not-compact");
        }
    }
    Ok(())
}
fn acknowledge(body: &[u8], offer: &Offer, offer_body: &[u8], now: u64) -> Result<()> {
    compact_body(body)?;
    let ack: Ack = serde_json::from_slice(body).map_err(|_| "input-view-ack-json")?;
    if ack.schema != 1
        || ack.profile != PROFILE
        || ack.grant_nonce != offer.grant_nonce
        || ack.request_nonce != offer.request_nonce
        || ack.request_sha256 != offer.request_sha256
        || ack.offer_sha256 != wait_observer::hex(&broker_protocol::digest(offer_body))
        || !lower_hex(&ack.witness_sha256, 64)
        || offer.ready_ns > ack.capture_started_ns
        || ack.capture_started_ns > ack.capture_finished_ns
        || ack.capture_finished_ns > now
        || now >= offer.execution_ns
    {
        return Err("input-view-ack-binding");
    }
    Ok(())
}

// Full local facts are retained privately; wire object identities contain only dev/ino.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Facts {
    object: authority::Object,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl Facts {
    fn of(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(|_| "input-view-stat")?;
        Ok(Self {
            object: authority::Object::of(file)?,
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        })
    }
}
struct Binding {
    file: File,
    path: PathBuf,
    facts: Facts,
    proc_link: bool,
}
impl Binding {
    fn held(file: File, path: &Path, kind: u32, proc_link: bool) -> Result<Self> {
        let facts = Facts::of(&file)?;
        if facts.object.kind != kind {
            return Err("input-view-object-kind");
        }
        let binding = Self {
            file,
            path: path.into(),
            facts,
            proc_link,
        };
        binding.recheck()?;
        Ok(binding)
    }
    fn directory(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_DIRECTORY.bits() | nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)
            .map_err(|_| "input-view-directory")?;
        Self::held(file, path, 0o040_000, false)
    }
    fn proc_directory(path: &Path) -> Result<Self> {
        // Intentional kernel proc magic links: held gate root and cwd, never caller links.
        Self::held(
            File::open(path).map_err(|_| "input-view-proc-directory")?,
            path,
            0o040_000,
            true,
        )
    }
    fn recheck(&self) -> Result<()> {
        if !self.proc_link
            && fs::symlink_metadata(&self.path)
                .map_err(|_| "input-view-path-stat")?
                .file_type()
                .is_symlink()
        {
            return Err("input-view-object-symlink");
        }
        let m = fs::metadata(&self.path).map_err(|_| "input-view-path-stat")?;
        let live = Facts {
            object: authority::Object::path(&self.path)?,
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        };
        if Facts::of(&self.file)? != self.facts || live != self.facts {
            return Err("input-view-object-replaced");
        }
        Ok(())
    }
    fn identity(&self) -> ObjectIdentity {
        self.facts.object.into()
    }
}
pub(super) struct DescriptorBinding {
    binding: Binding,
    sha: [u8; 32],
}
impl DescriptorBinding {
    pub fn new(file: File, path: &Path, raw: &[u8]) -> Result<Self> {
        Ok(Self {
            binding: Binding::held(file, path, 0o100_000, false)?,
            sha: broker_protocol::digest(raw),
        })
    }
    fn recheck(&mut self, end: Instant, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.binding.recheck()?;
        self.binding
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "input-view-descriptor-seek")?;
        if authority::digest_file_checked(&mut self.binding.file, end, check)? != self.sha {
            return Err("input-view-descriptor-changed");
        }
        self.binding.recheck()
    }
}

fn published_origin(
    path: &Path,
    expected: &wait_observer::Origin,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<(Binding, [u8; 32])> {
    check()?;
    let mut origin = Binding::held(route::root_regular(path)?, path, 0o100_000, false)?;
    let raw = authority::read_file(&mut origin.file, 65_536)?;
    check()?;
    let parsed: wait_observer::Origin = serde_json::from_slice(&raw).map_err(|_| "input-view-origin-json")?;
    if &parsed != expected {
        return Err("input-view-origin-changed");
    }
    origin.recheck()?;
    Ok((origin, broker_protocol::digest(&raw)))
}

fn held_namespace(pid: u32, kind: &str, expected: authority::Object) -> Result<Binding> {
    let path = PathBuf::from(format!("/proc/{pid}/ns/{kind}"));
    let binding = Binding::held(
        File::open(&path).map_err(|_| "input-view-gate-namespace")?,
        &path,
        0o100_000,
        true,
    )?;
    if binding.facts.object != expected {
        return Err("input-view-setup-namespace");
    }
    Ok(binding)
}
fn held_roles(
    origin: &wait_observer::Origin,
    gate: &wait_observer::Identity,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<authority::HeldPid>> {
    let identities = [
        &origin.controller,
        &origin.supervisor,
        &origin.bwrap,
        gate,
        &origin.tracer,
    ];
    let mut processes = Vec::new();
    for identity in identities {
        check()?;
        if processes.iter().any(|p: &authority::HeldPid| p.pid == identity.pid) {
            return Err("input-view-role-alias");
        }
        let p = authority::HeldPid::open(identity.pid)?;
        if p.start != identity.start {
            return Err("input-view-role-start");
        }
        processes.push(p);
    }
    Ok(processes)
}

pub(super) struct Input<'a> {
    pub descriptor: &'a route::Descriptor,
    pub origin: &'a wait_observer::Origin,
    pub origin_path: &'a Path,
    pub gate: wait_observer::Identity,
    pub cgroup: &'a Path,
    pub namespaces: [authority::Object; 3],
}
pub(super) struct Retained {
    descriptor: DescriptorBinding,
    origin: Binding,
    origin_sha: [u8; 32],
    objects: Vec<Binding>,
    processes: Vec<authority::HeldPid>,
    offer: Offer,
    end: Instant,
    rendezvous: Option<(Endpoint, Peer, UnixStream)>,
}
impl Retained {
    pub fn prepare(
        input: Input<'_>,
        mut descriptor: DescriptorBinding,
        check: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        check()?;
        let d = input.descriptor;
        let o = input.origin;
        let selection = d.input_view_witness.as_ref().ok_or("input-view-selection-missing")?;
        selection.validate_request(&d.header, d.observer.is_some())?;
        let end = route::instant(d.execution_ns)?;
        descriptor.recheck(end, check)?;
        if o.nonce != d.nonce
            || o.boot != d.boot
            || o.request_sha256 != d.request_sha256.ok_or("input-view-request")?
            || o.execution_ns != d.execution_ns
            || o.total_ns != d.header.total_end_ns().map_err(|_| "input-view-total")?
            || o.controller.pid != std::process::id()
            || o.uid != o.gid
            || o.uid == 0
        {
            return Err("input-view-origin-binding");
        }
        let processes = held_roles(o, &input.gate, check)?;
        let (origin, origin_sha) = published_origin(input.origin_path, o, check)?;
        let gate = input.gate.pid;
        let stage_parent = Binding::directory(&d.stage)?;
        let stage = Binding::directory(&d.stage.join("input"))?;
        if stage.facts.uid != o.uid || stage.facts.gid != o.gid || stage.facts.mode & 0o7777 != 0o500 {
            return Err("input-view-stage-owner-mode");
        }
        let mounted = Binding::directory(&PathBuf::from(format!("/proc/{gate}/root/input")))?;
        let root = Binding::proc_directory(&PathBuf::from(format!("/proc/{gate}/root")))?;
        let cwd = Binding::proc_directory(&PathBuf::from(format!("/proc/{gate}/cwd")))?;
        if stage.facts != mounted.facts
            || cwd.facts != mounted.facts
            || root.facts.uid != o.uid
            || root.facts.gid != o.gid
            || root.facts.mode & 0o6022 != 0
        {
            return Err("input-view-mounted-input");
        }
        let ns_path = PathBuf::from(format!("/proc/{gate}/ns/mnt"));
        let mount = Binding::held(
            File::open(&ns_path).map_err(|_| "input-view-mount-namespace")?,
            &ns_path,
            0o100_000,
            true,
        )?;
        if input.namespaces[2] != mount.facts.object {
            return Err("input-view-setup-namespace");
        }
        let user = held_namespace(gate, "user", input.namespaces[0])?;
        let pid = held_namespace(gate, "pid", input.namespaces[1])?;
        let cgroup = Binding::directory(input.cgroup)?;
        if cgroup.facts.uid != 0 || cgroup.facts.gid != 0 || cgroup.facts.mode & 0o022 != 0 {
            return Err("input-view-cgroup-owner-mode");
        }
        let offer = Offer {
            schema: 1,
            profile: PROFILE.into(),
            grant_nonce: selection.grant_nonce.clone(),
            request_nonce: d.nonce.clone(),
            request_sha256: wait_observer::hex(&o.request_sha256),
            boot: d.boot.clone(),
            execution_ns: d.execution_ns,
            total_ns: o.total_ns,
            controller: o.controller.clone(),
            supervisor: o.supervisor.clone(),
            bwrap: o.bwrap.clone(),
            gate: input.gate,
            tracer: o.tracer.clone(),
            leased_uid: o.uid,
            leased_gid: o.gid,
            work_invocation: o.work_invocation.clone(),
            ready_ns: o.readiness_complete_ns,
            descriptor_object: descriptor.binding.identity(),
            origin_object: origin.identity(),
            stage_input_object: stage.identity(),
            input_object: mounted.identity(),
            mount_namespace_object: mount.identity(),
            cgroup_object: cgroup.identity(),
            origin_sha256: wait_observer::hex(&origin_sha),
        };
        check()?;
        Ok(Self {
            descriptor,
            origin,
            origin_sha,
            objects: vec![stage_parent, stage, mounted, root, cwd, user, pid, mount, cgroup],
            processes,
            offer,
            end,
            rendezvous: None,
        })
    }
    pub fn recheck(&mut self, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        check()?;
        if let Some((endpoint, peer, socket)) = self.rendezvous.as_mut() {
            endpoint.recheck()?;
            peer.check_socket(socket)?;
            peer.recheck(check, true)?;
        }
        for (index, p) in self.processes.iter().enumerate() {
            check()?;
            p.verify()?;
            audit::credentials(p.pid, if index == 0 { 0 } else { self.offer.leased_uid })?;
            audit::single_thread(p.pid)?;
        }
        for o in &self.objects {
            check()?;
            o.recheck()?;
        }
        self.descriptor.recheck(self.end, check)?;
        self.origin.recheck()?;
        self.origin
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "input-view-origin-seek")?;
        if authority::digest_file_checked(&mut self.origin.file, self.end, check)? != self.origin_sha {
            return Err("input-view-origin-changed");
        }
        self.origin.recheck()?;
        check()
    }
    pub fn exchange(&mut self, selection: &Selection, check: &mut impl FnMut() -> Result<()>) -> Result<()> {
        self.recheck(check)?;
        let endpoint = Endpoint::hold(&selection.socket, check)?;
        let mut peer = Peer::hold(&selection.observer, &selection.boot, self.end, check)?;
        if self.processes.iter().any(|p| p.pid == peer.process.pid) {
            return Err("input-view-peer-role-alias");
        }
        check()?;
        let fd = net::socket_with(
            net::AddressFamily::UNIX,
            net::SocketType::STREAM,
            net::SocketFlags::NONBLOCK | net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| "input-view-socket")?;
        net::sockopt::set_socket_passcred(&fd, true).map_err(|_| "input-view-passcred")?;
        // A single nonblocking connect. Backlog/pending/unavailable connections refuse;
        // no retry, reconnect, second peer, or unbounded blocking connect is permitted.
        net::connect(
            &fd,
            &SocketAddrUnix::new(&selection.socket).map_err(|_| "input-view-address")?,
        )
        .map_err(|_| "input-view-connect")?;
        let socket = UnixStream::from(fd);
        endpoint.recheck()?;
        peer.check_socket(&socket)?;
        peer.recheck(check, true)?;
        let body = serde_json::to_vec(&self.offer).map_err(|_| "input-view-offer-json")?;
        let packet = frame(&body, OFFER_LIMIT)?;
        let sender = peer.sender();
        let mut progress = || {
            check()?;
            endpoint.recheck()?;
            peer.recheck(check, false)?;
            Ok(())
        };
        send_frame(&socket, &packet, &mut progress)?;
        net::shutdown(&socket, net::Shutdown::Write).map_err(|_| "input-view-half-close")?;
        let ack = receive_frame(&socket, ACK_LIMIT, sender, &mut progress)?;
        acknowledge(&ack, &self.offer, &body, route::monotonic_ns()?)?;
        peer.check_socket(&socket)?;
        peer.recheck(check, true)?;
        endpoint.recheck()?;
        self.rendezvous = Some((endpoint, peer, socket));
        self.recheck(check)
    }
}

struct Endpoint {
    ancestors: Vec<Binding>,
    node: Binding,
}
impl Endpoint {
    fn hold(path: &Path, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        route::root_ancestry(path.parent().ok_or("input-view-socket-parent")?)?;
        let mut current = PathBuf::from("/");
        let mut ancestors = vec![Binding::directory(&current)?];
        for c in path.parent().ok_or("input-view-socket-parent")?.components().skip(1) {
            check()?;
            current.push(c);
            ancestors.push(Binding::directory(&current)?);
        }
        let parent = ancestors.last().ok_or("input-view-socket-parent")?;
        if parent.facts.uid != 0 || parent.facts.gid != 0 || parent.facts.mode & 0o7777 != 0o700 {
            return Err("input-view-socket-parent-private");
        }
        let m = fs::symlink_metadata(path).map_err(|_| "input-view-socket-node")?;
        if !m.file_type().is_socket() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o600 {
            return Err("input-view-socket-node-private");
        }
        let file = File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| "input-view-socket-node-open")?,
        );
        let result = Self {
            ancestors,
            node: Binding::held(file, path, 0o140_000, false)?,
        };
        result.recheck()?;
        check()?;
        Ok(result)
    }
    fn recheck(&self) -> Result<()> {
        for a in &self.ancestors {
            let m = fs::symlink_metadata(&a.path).map_err(|_| "input-view-socket-ancestry")?;
            if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 {
                return Err("input-view-socket-ancestry");
            }
            a.recheck()?;
        }
        if !fs::symlink_metadata(&self.node.path)
            .map_err(|_| "input-view-socket-node")?
            .file_type()
            .is_socket()
        {
            return Err("input-view-socket-node");
        }
        self.node.recheck()
    }
}
struct Peer {
    actor: Actor,
    boot: String,
    process: authority::HeldPid,
    proc: Binding,
    user: Binding,
    pid: Binding,
    controller_pid: File,
    image: Binding,
    cgroup: Binding,
    cgroup_bytes: Vec<u8>,
    end: Instant,
}
impl Peer {
    fn hold(actor: &Actor, boot: &str, end: Instant, check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        let process = authority::HeldPid::open(actor.pid)?;
        if process.start != actor.start {
            return Err("input-view-peer-start");
        }
        let path = PathBuf::from(format!("/proc/{}", actor.pid));
        let proc = Binding::directory(&path)?;
        let user_path = path.join("ns/user");
        let user = Binding::held(
            File::open(&user_path).map_err(|_| "input-view-peer-user")?,
            &user_path,
            0o100_000,
            true,
        )?;
        wait_observer::initial_namespace(&user.file)?;
        let pid_path = path.join("ns/pid");
        let pid = Binding::held(
            File::open(&pid_path).map_err(|_| "input-view-peer-pid")?,
            &pid_path,
            0o100_000,
            true,
        )?;
        let controller_pid = File::open("/proc/self/ns/pid").map_err(|_| "input-view-controller-pid")?;
        if authority::Object::of(&controller_pid)? != pid.facts.object {
            return Err("input-view-peer-pid-namespace");
        }
        let image_path = path.join("exe");
        let image = Binding::held(
            File::open(&image_path).map_err(|_| "input-view-peer-image")?,
            &image_path,
            0o100_000,
            true,
        )?;
        if image.facts.uid != 0 || image.facts.gid != 0 || image.facts.mode & 0o6022 != 0 {
            return Err("input-view-peer-image-owner");
        }
        let cgroup_bytes = authority::bounded(&path.join("cgroup"), 4096)?;
        let raw = std::str::from_utf8(&cgroup_bytes).map_err(|_| "input-view-peer-cgroup")?;
        let relative = raw
            .strip_prefix("0::/")
            .and_then(|s| s.strip_suffix('\n'))
            .ok_or("input-view-peer-cgroup")?;
        if relative.split('/').any(|p| p == "." || p == ".." || p.is_empty()) {
            return Err("input-view-peer-cgroup");
        }
        let cgroup = Binding::directory(&PathBuf::from(format!("/sys/fs/cgroup/{relative}")))?;
        if cgroup.facts.uid != 0 || cgroup.facts.gid != 0 || cgroup.facts.mode & 0o022 != 0 {
            return Err("input-view-peer-cgroup-owner");
        }
        let mut result = Self {
            actor: actor.clone(),
            boot: boot.into(),
            process,
            proc,
            user,
            pid,
            controller_pid,
            image,
            cgroup,
            cgroup_bytes,
            end,
        };
        result.recheck(check, true)?;
        Ok(result)
    }
    fn sender(&self) -> wait_observer::Sender {
        wait_observer::Sender {
            pid: self.process.pid,
            uid: 0,
            gid: 0,
        }
    }
    fn check_socket(&self, socket: &UnixStream) -> Result<()> {
        let c = net::sockopt::socket_peercred(socket).map_err(|_| "input-view-peercred")?;
        if c.pid.as_raw_nonzero().get().unsigned_abs() != self.process.pid || c.uid.as_raw() != 0 || c.gid.as_raw() != 0
        {
            return Err("input-view-peercred");
        }
        Ok(())
    }
    fn recheck(&mut self, check: &mut impl FnMut() -> Result<()>, hash_image: bool) -> Result<()> {
        check()?;
        self.process.verify()?;
        audit::credentials(self.process.pid, 0)?;
        audit::single_thread(self.process.pid)?;
        for binding in [&self.proc, &self.user, &self.pid, &self.image, &self.cgroup] {
            check()?;
            binding.recheck()?;
        }
        wait_observer::initial_namespace(&self.user.file)?;
        if authority::Object::of(&self.controller_pid)? != self.pid.facts.object
            || authority::Object::path(Path::new("/proc/self/ns/pid"))? != self.pid.facts.object
            || authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?
                != format!("{}\n", self.boot).as_bytes()
            || authority::bounded(&self.proc.path.join("cgroup"), 4096)? != self.cgroup_bytes
        {
            return Err("input-view-peer-live-binding");
        }
        let cmdline = authority::bounded(&self.proc.path.join("cmdline"), 65_536)?;
        if wait_observer::hex(&broker_protocol::digest(&cmdline)) != self.actor.cmdline_sha256 {
            return Err("input-view-peer-cmdline");
        }
        if hash_image {
            self.image
                .file
                .seek(SeekFrom::Start(0))
                .map_err(|_| "input-view-peer-image-seek")?;
            if wait_observer::hex(&authority::digest_file_checked(&mut self.image.file, self.end, check)?)
                != self.actor.image_sha256
            {
                return Err("input-view-peer-image-digest");
            }
            self.image.recheck()?;
        }
        check()
    }
}
fn frame(body: &[u8], cap: usize) -> Result<Vec<u8>> {
    if body.is_empty() || body.len() > cap {
        return Err("input-view-frame-cap");
    }
    let length = u64::try_from(body.len()).map_err(|_| "input-view-frame-cap")?;
    let mut bytes = length.to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    Ok(bytes)
}
fn send_frame(socket: &UnixStream, frame: &[u8], check: &mut impl FnMut() -> Result<()>) -> Result<()> {
    let mut offset = 0;
    while offset < frame.len() {
        check()?;
        match net::send(
            socket,
            &frame[offset..],
            net::SendFlags::DONTWAIT | net::SendFlags::NOSIGNAL,
        ) {
            Ok(0) => return Err("input-view-send-zero"),
            Ok(n) => offset += n,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => thread::sleep(Duration::from_millis(2)),
            Err(_) => return Err("input-view-send"),
        }
    }
    check()
}
#[derive(Default)]
struct FrameReader {
    bytes: Vec<u8>,
    declared: Option<usize>,
}
impl FrameReader {
    fn feed(&mut self, chunk: &wait_observer::AckChunk, cap: usize, sender: wait_observer::Sender) -> Result<()> {
        if chunk.invalid
            || chunk.credentials != [sender]
            || chunk.bytes.is_empty()
            || self
                .bytes
                .len()
                .checked_add(chunk.bytes.len())
                .is_none_or(|n| n > cap + 8)
        {
            return Err("input-view-frame-credentials-or-cap");
        }
        self.bytes.extend_from_slice(&chunk.bytes);
        if self.declared.is_none() && self.bytes.len() >= 8 {
            let prefix: [u8; 8] = self.bytes[..8].try_into().map_err(|_| "input-view-frame-prefix")?;
            let size = usize::try_from(u64::from_be_bytes(prefix)).map_err(|_| "input-view-frame-cap")?;
            if size == 0 || size > cap {
                return Err("input-view-frame-cap");
            }
            self.declared = Some(size);
        }
        if self.declared.is_some_and(|size| self.bytes.len() > size + 8) {
            return Err("input-view-frame-trailing");
        }
        Ok(())
    }
    fn complete(&self) -> bool {
        self.declared.is_some_and(|size| self.bytes.len() == size + 8)
    }
    fn eof(self) -> Result<Vec<u8>> {
        let size = self.declared.ok_or("input-view-frame-truncated")?;
        if self.bytes.len() != size + 8 {
            return Err("input-view-frame-truncated");
        }
        Ok(self.bytes[8..].to_vec())
    }
}
fn receive_frame(
    socket: &UnixStream,
    cap: usize,
    sender: wait_observer::Sender,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut reader = FrameReader::default();
    loop {
        check()?;
        // Sole local reader, no concurrent close/shutdown, default SO_PEEK_OFF=-1,
        // ordinary in-band stream. Reuse the reviewed plain-PEEK-before-typed-buffer
        // guard: EAGAIN is pending, zero PEEK alone is EOF, reader races refuse.
        if reader.complete() {
            let mut probe = [0; 1];
            match net::recv(socket, &mut probe[..], net::RecvFlags::DONTWAIT | net::RecvFlags::PEEK) {
                Ok((0, _)) => {
                    check()?;
                    return reader.eof();
                }
                Ok(_) => return Err("input-view-frame-trailing"),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => return Err("input-view-eof-peek"),
            }
        }
        match wait_observer::receive_ack_chunk(socket)? {
            Some(chunk) if chunk.bytes.is_empty() => {
                check()?;
                return reader.eof();
            }
            Some(chunk) => reader.feed(&chunk, cap, sender)?,
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage};
    use std::{
        io::{IoSlice, Write},
        mem::MaybeUninit,
        sync::atomic::{AtomicU64, Ordering},
    };
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    // Independently authored wire vectors; their hashes were calculated using Python hashlib.
    const OFFER: &[u8] = br#"{"schema":1,"profile":"root-pre-permit-input-view-witness-v1","grant_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_sha256":"1111111111111111111111111111111111111111111111111111111111111111","boot":"12345678-1234-1234-1234-123456789abc","execution_ns":100,"total_ns":10000000100,"controller":{"pid":2,"start":10},"supervisor":{"pid":3,"start":11},"bwrap":{"pid":4,"start":12},"gate":{"pid":5,"start":13},"tracer":{"pid":6,"start":14},"leased_uid":60000,"leased_gid":60000,"work_invocation":"12345678123412341234123456789abc","ready_ns":20,"descriptor_object":{"dev":1,"ino":2},"origin_object":{"dev":1,"ino":3},"stage_input_object":{"dev":1,"ino":4},"input_object":{"dev":1,"ino":4},"mount_namespace_object":{"dev":2,"ino":5},"cgroup_object":{"dev":3,"ino":6},"origin_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}"#;
    const SELECTION: &[u8] = br#"{"schema":1,"profile":"root-pre-permit-input-view-witness-v1","socket":"/run/witness/socket","boot":"12345678-1234-1234-1234-123456789abc","grant_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observer":{"pid":7,"start":15,"uid":0,"gid":0,"image_sha256":"0000000000000000000000000000000000000000000000000000000000000000","cmdline_sha256":"3333333333333333333333333333333333333333333333333333333333333333"}}"#;
    fn ack_vector() -> Vec<u8> {
        // Fixed independent digest; no product encoder is used to create the expected Ack.
        br#"{"schema":1,"profile":"root-pre-permit-input-view-witness-v1","grant_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_sha256":"1111111111111111111111111111111111111111111111111111111111111111","offer_sha256":"f21eb044bd9f5d7b800222873cdf49dc57f4d9a7e9fc034b0f66b3a24c67ec97","witness_sha256":"0000000000000000000000000000000000000000000000000000000000000000","capture_started_ns":21,"capture_finished_ns":22}"#.to_vec()
    }
    fn sender() -> wait_observer::Sender {
        wait_observer::Sender {
            pid: std::process::id(),
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }
    fn chunk(bytes: &[u8]) -> wait_observer::AckChunk {
        wait_observer::AckChunk {
            bytes: bytes.to_vec(),
            credentials: vec![sender()],
            invalid: false,
        }
    }
    fn original_header(schema: u32) -> broker_protocol::RequestHeader {
        broker_protocol::RequestHeader {
            schema,
            nonce: "a".repeat(32),
            boot: "12345678-1234-1234-1234-123456789abc".into(),
            caller_uid: 1000,
            caller_pid: 8,
            caller_start: 16,
            deadline_ns: 100,
            total_deadline_ns: Some(10_000_000_100),
            command: "kustomize-build".into(),
            profile: "kustomize-5.8.3".into(),
            executable: "/root/kustomize".into(),
            image_sha256: [1; 32],
            provenance: Vec::new(),
            argv: Vec::new(),
            timeout_ns: 20,
            stdout_bytes: 1024,
            stderr_bytes: 1024,
            memory_bytes: 64 * 1024 * 1024,
            swap_bytes: 0,
            pids: 16,
            files: Vec::new(),
        }
    }
    #[test]
    fn selection_has_closed_types_and_requires_controlled_original_request() -> TestResult {
        let selection: Selection = serde_json::from_slice(SELECTION)?;
        selection.validate_shape()?; // Zero-valued SHA is syntactically valid, never a verified image.
        selection.validate_request(&original_header(2), true)?;
        assert!(selection.validate_request(&original_header(1), true).is_err());
        assert!(selection.validate_request(&original_header(2), false).is_err());
        for (field, value) in [
            ("schema", serde_json::json!(true)),
            ("schema", serde_json::json!(1.0)),
            ("schema", serde_json::json!(-1)),
            ("schema", serde_json::json!(4_294_967_296_u64)),
            ("schema", serde_json::json!(2)),
            ("socket", serde_json::json!("/run//socket")),
            ("socket", serde_json::json!("/run/../socket")),
            ("socket", serde_json::json!("relative")),
            ("socket", serde_json::json!("/run/socket\u{0000}")),
            ("socket", serde_json::json!(format!("/run/{}", "a".repeat(110)))),
            ("grant_nonce", serde_json::json!("a".repeat(32))),
            ("boot", serde_json::json!("wrong")),
        ] {
            let mut value_object: serde_json::Value = serde_json::from_slice(SELECTION)?;
            value_object[field] = value;
            if let Ok(candidate) = serde_json::from_value::<Selection>(value_object) {
                assert!(
                    candidate.validate_request(&original_header(2), true).is_err(),
                    "{field}"
                );
            }
        }
        for (field, value) in [
            ("pid", serde_json::json!(1)),
            ("start", serde_json::json!(0)),
            ("uid", serde_json::json!(1)),
            ("gid", serde_json::json!(1)),
            ("image_sha256", serde_json::json!("A".repeat(64))),
            ("cmdline_sha256", serde_json::json!("a".repeat(63))),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(SELECTION)?;
            v["observer"][field] = value;
            let candidate: Selection = serde_json::from_value(v)?;
            assert!(candidate.validate_shape().is_err());
        }
        let duplicate = String::from_utf8(SELECTION.to_vec())?.replacen('{', "{\"schema\":1,", 1);
        assert!(serde_json::from_str::<Selection>(&duplicate).is_err());
        let mut unknown: serde_json::Value = serde_json::from_slice(SELECTION)?;
        unknown["evidence_path"] = serde_json::json!("/root/witness");
        assert!(serde_json::from_value::<Selection>(unknown).is_err());
        Ok(())
    }
    #[test]
    fn independent_ack_vector_binds_actual_offer_bytes_and_original_times() -> TestResult {
        let offer: Offer = serde_json::from_slice(OFFER)?;
        let body = ack_vector();
        acknowledge(&body, &offer, OFFER, 23)?;
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("profile", serde_json::json!("wrong")),
            ("grant_nonce", serde_json::json!("c".repeat(32))),
            ("request_nonce", serde_json::json!("c".repeat(32))),
            ("request_sha256", serde_json::json!("c".repeat(64))),
            ("offer_sha256", serde_json::json!("c".repeat(64))),
            ("witness_sha256", serde_json::json!("C".repeat(64))),
            ("capture_started_ns", serde_json::json!(19)),
            ("capture_started_ns", serde_json::json!(23)),
            ("capture_finished_ns", serde_json::json!(24)),
            ("capture_finished_ns", serde_json::json!(false)),
            ("capture_finished_ns", serde_json::json!(22.0)),
            ("capture_finished_ns", serde_json::json!(-1)),
            ("unknown", serde_json::json!(0)),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&body)?;
            v[field] = value;
            assert!(
                acknowledge(&serde_json::to_vec(&v)?, &offer, OFFER, 23).is_err(),
                "{field}"
            );
        }
        assert!(acknowledge(&body, &offer, OFFER, 100).is_err());
        let mut changed = OFFER.to_vec();
        changed.push(b' ');
        assert!(acknowledge(&body, &offer, &changed, 23).is_err());
        let duplicate = String::from_utf8(body.clone())?.replacen('{', "{\"schema\":1,", 1);
        assert!(acknowledge(duplicate.as_bytes(), &offer, OFFER, 23).is_err());
        let mut trailing = body;
        trailing.push(b' ');
        assert!(acknowledge(&trailing, &offer, OFFER, 23).is_err());
        Ok(())
    }
    #[test]
    fn frame_prefix_credentials_caps_and_trailing_bytes_fail_closed() -> TestResult {
        // Literal independent length-prefix vector: 3 bytes, not a serializer round trip.
        let literal = [0, 0, 0, 0, 0, 0, 0, 3, b'{', b'}', b'!'];
        let mut reader = FrameReader::default();
        for b in literal {
            reader.feed(&chunk(&[b]), 3, sender())?;
        }
        assert_eq!(reader.eof()?, b"{}!");
        for declared in [0, 4, u64::MAX] {
            let mut reader = FrameReader::default();
            assert!(reader.feed(&chunk(&declared.to_be_bytes()), 3, sender()).is_err());
        }
        for flags in 0..4 {
            let mut fragment = chunk(&literal);
            if flags == 0 {
                fragment.credentials.clear();
            }
            if flags == 1 {
                fragment.credentials.push(sender());
            }
            if flags == 2 {
                fragment.credentials[0].pid += 1;
            }
            if flags == 3 {
                fragment.invalid = true;
            }
            assert!(FrameReader::default().feed(&fragment, 3, sender()).is_err());
        }
        for length in 0..literal.len() {
            let mut reader = FrameReader::default();
            if length > 0 {
                reader.feed(&chunk(&literal[..length]), 3, sender())?;
            }
            assert!(reader.eof().is_err());
        }
        let mut reader = FrameReader::default();
        reader.feed(&chunk(&literal), 10, sender())?;
        assert!(reader.feed(&chunk(b"x"), 10, sender()).is_err());
        assert!(frame(b"", ACK_LIMIT).is_err());
        assert!(frame(&vec![0; ACK_LIMIT + 1], ACK_LIMIT).is_err());
        assert_eq!(frame(&vec![0; OFFER_LIMIT], OFFER_LIMIT)?.len(), OFFER_LIMIT + 8);
        Ok(())
    }
    #[test]
    fn kernel_stream_fragments_and_real_eof_do_not_accept_eagain() -> TestResult {
        let (mut writer, reader) = UnixStream::pair()?;
        net::sockopt::set_socket_passcred(&reader, true)?;
        let mut parsed = FrameReader::default();
        for byte in [0, 0, 0, 0, 0, 0, 0, 2, b'{', b'}'] {
            writer.write_all(&[byte])?;
            let fragment = wait_observer::receive_ack_chunk(&reader)?.ok_or("missing socket fragment")?;
            assert_eq!(fragment.bytes, [byte]);
            parsed.feed(&fragment, ACK_LIMIT, sender())?;
        }
        assert!(wait_observer::receive_ack_chunk(&reader)?.is_none());
        net::shutdown(&writer, net::Shutdown::Write)?;
        let eof = wait_observer::receive_ack_chunk(&reader)?.ok_or("missing EOF")?;
        assert!(eof.bytes.is_empty());
        assert!(eof.credentials.is_empty());
        assert_eq!(parsed.eof()?, b"{}");
        Ok(())
    }
    #[test]
    fn kernel_stream_missing_credentials_and_injected_rights_refuse() -> TestResult {
        let (mut writer, reader) = UnixStream::pair()?;
        writer.write_all(b"x")?;
        let fragment = wait_observer::receive_ack_chunk(&reader)?.ok_or("missing socket fragment")?;
        assert!(FrameReader::default().feed(&fragment, ACK_LIMIT, sender()).is_err());
        let (writer, reader) = UnixStream::pair()?;
        net::sockopt::set_socket_passcred(&reader, true)?;
        let file = File::open("/dev/null")?;
        let rights = [std::os::fd::AsFd::as_fd(&file)];
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut storage);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        net::sendmsg(&writer, &[IoSlice::new(b"x")], &mut ancillary, net::SendFlags::NOSIGNAL)?;
        let fragment = wait_observer::receive_ack_chunk(&reader)?.ok_or("missing socket fragment")?;
        assert!(FrameReader::default().feed(&fragment, ACK_LIMIT, sender()).is_err());
        Ok(())
    }
    #[test]
    fn bounded_receive_cancellation_after_complete_body_cannot_authorize_without_eof() -> TestResult {
        let (mut writer, reader) = UnixStream::pair()?;
        net::sockopt::set_socket_passcred(&reader, true)?;
        writer.write_all(&[0, 0, 0, 0, 0, 0, 0, 2, b'{', b'}'])?;
        let mut calls = 0;
        let result = receive_frame(&reader, ACK_LIMIT, sender(), &mut || {
            calls += 1;
            if calls >= 3 {
                Err("injected-cancellation")
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err("injected-cancellation")));
        assert_eq!(calls, 3);
        let result = send_frame(&writer, b"packet", &mut || Err("original-execution-expired"));
        assert!(matches!(result, Err("original-execution-expired")));
        Ok(())
    }
    #[test]
    fn completed_frame_requires_eof_and_rejects_later_positive_peek() -> TestResult {
        let (mut writer, reader) = UnixStream::pair()?;
        net::sockopt::set_socket_passcred(&reader, true)?;
        writer.write_all(&[0, 0, 0, 0, 0, 0, 0, 2, b'{', b'}'])?;
        net::shutdown(&writer, net::Shutdown::Write)?;
        assert_eq!(receive_frame(&reader, ACK_LIMIT, sender(), &mut || Ok(()))?, b"{}");
        let (mut writer, reader) = UnixStream::pair()?;
        net::sockopt::set_socket_passcred(&reader, true)?;
        writer.write_all(&[0, 0, 0, 0, 0, 0, 0, 2, b'{', b'}'])?;
        let mut calls = 0;
        let result = receive_frame(&reader, ACK_LIMIT, sender(), &mut || {
            calls += 1;
            if calls == 2 {
                writer.write_all(b"x").map_err(|_| "injected-write")?;
            }
            Ok(())
        });
        assert!(matches!(result, Err("input-view-frame-trailing")));
        let mut probe = [0; 1];
        assert_eq!(
            net::recv(&reader, &mut probe[..], net::RecvFlags::DONTWAIT | net::RecvFlags::PEEK)?.0,
            1
        );
        assert_eq!(probe, [b'x']); // Trailing refusal never constructs an ancillary receiver.
        Ok(())
    }
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> std::io::Result<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kl-issue41-source-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn retained_objects_refuse_same_path_replacements_symlinks_and_content_mutation() -> TestResult {
        let scratch = Scratch::new()?;
        let input = scratch.0.join("input");
        fs::create_dir(&input)?;
        let held = Binding::directory(&input)?;
        fs::rename(&input, scratch.0.join("old"))?;
        fs::create_dir(&input)?;
        assert!(held.recheck().is_err());
        fs::remove_dir(&input)?;
        std::os::unix::fs::symlink(scratch.0.join("old"), &input)?;
        assert!(held.recheck().is_err());
        let descriptor = scratch.0.join("descriptor");
        fs::write(&descriptor, b"original")?;
        let mut held = DescriptorBinding::new(File::open(&descriptor)?, &descriptor, b"original")?;
        held.recheck(Instant::now() + Duration::from_secs(1), &mut || Ok(()))?;
        let offer: Offer = serde_json::from_slice(OFFER)?;
        acknowledge(&ack_vector(), &offer, OFFER, 23)?;
        fs::write(&descriptor, b"mutated!")?; // Valid Ack cannot authorize same-inode mutation.
        assert!(
            held.recheck(Instant::now() + Duration::from_secs(1), &mut || Ok(()))
                .is_err()
        );
        Ok(())
    }
}
