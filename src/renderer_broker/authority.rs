//! Held kernel identities and bounded private SCM handoff. No public client FD API.
use super::Result;
use rustix::net::{self, RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{IoSlice, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|_| "read-open")?;
    read_file(&mut f, max)
}
pub fn read_file(f: &mut File, max: usize) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut b).map_err(|_| "read")?;
    if b.len() > max {
        return Err("read-budget");
    }
    Ok(b)
}
pub fn digest_file(f: &mut File, deadline: Instant) -> Result<[u8; 32]> {
    digest_file_checked(f, deadline, &mut || Ok(()))
}
pub fn digest_file_checked(
    f: &mut File,
    deadline: Instant,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut total = 0;
    let mut buf = vec![0; 65536];
    loop {
        check()?;
        if Instant::now() >= deadline {
            return Err("hash-deadline");
        }
        let n = f.read(&mut buf).map_err(|_| "hash-read")?;
        if n == 0 {
            break;
        }
        total += n;
        if total > 64 * 1024 * 1024 {
            return Err("hash-budget");
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}
pub fn starttime(pid: u32) -> Result<u64> {
    let b = bounded(&PathBuf::from(format!("/proc/{pid}/stat")), 4096)?;
    let s = std::str::from_utf8(&b).map_err(|_| "stat-encoding")?;
    s.rsplit_once(')')
        .ok_or("stat-fields")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("stat-start")?
        .parse()
        .map_err(|_| "stat-start")
}
pub struct HeldPid {
    pub pid: u32,
    pub start: u64,
    fd: OwnedFd,
}
impl HeldPid {
    pub fn open(pid: u32) -> Result<Self> {
        if pid <= 1 || pid > i32::MAX as u32 {
            return Err("pid-invalid");
        }
        let start = starttime(pid)?;
        let p = Pid::from_raw(i32::try_from(pid).map_err(|_| "pid-range")?).ok_or("pid-range")?;
        let fd = pidfd_open(p, PidfdFlags::NONBLOCK).map_err(|_| "pidfd-open")?;
        let held = Self { pid, start, fd };
        held.verify()?;
        Ok(held)
    }
    pub fn verify(&self) -> Result<()> {
        if starttime(self.pid)? != self.start {
            return Err("pid-reused");
        }
        let b = bounded(
            &PathBuf::from(format!("/proc/self/fdinfo/{}", self.fd.as_raw_fd())),
            4096,
        )?;
        let s = std::str::from_utf8(&b).map_err(|_| "pidfd-info")?;
        if !s
            .lines()
            .any(|l| l.strip_prefix("Pid:").and_then(|v| v.trim().parse::<u32>().ok()) == Some(self.pid))
        {
            return Err("pidfd-dead-or-mismatch");
        }
        Ok(())
    }
    pub fn gone(&self) -> Result<()> {
        let b = bounded(
            &PathBuf::from(format!("/proc/self/fdinfo/{}", self.fd.as_raw_fd())),
            4096,
        )?;
        let s = std::str::from_utf8(&b).map_err(|_| "pidfd-info")?;
        if !s.lines().any(|l| l.strip_prefix("Pid:").map(str::trim) == Some("-1")) {
            return Err("held-process-not-reaped");
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    pub dev: u64,
    pub ino: u64,
    pub kind: u32,
    pub rdev: u64,
}
impl Object {
    pub fn of(f: &File) -> Result<Self> {
        let m = f.metadata().map_err(|_| "object-stat")?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            kind: m.mode() & 0o170_000,
            rdev: m.rdev(),
        })
    }
    pub fn path(p: &Path) -> Result<Self> {
        let m = fs::metadata(p).map_err(|_| "object-stat")?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            kind: m.mode() & 0o170_000,
            rdev: m.rdev(),
        })
    }
}
pub struct RootOutput {
    pub read: File,
    pub object: Object,
    pub flags: u64,
    write: Option<OwnedFd>,
}
impl RootOutput {
    pub fn create() -> Result<Self> {
        if nix::unistd::geteuid().as_raw() != 0 {
            return Err("root-pipe-required");
        }
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|_| "pipe")?;
        let writer_flags = u64::from(rustix::fs::fcntl_getfl(&w).map_err(|_| "pipe-writer-flags")?.bits());
        let read = File::from(r);
        let object = Object::of(&read)?;
        let flags = rustix::fs::fcntl_getfl(&read).map_err(|_| "pipe-flags")?;
        rustix::fs::fcntl_setfl(&read, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| "pipe-nonblock")?;
        Ok(Self {
            read,
            object,
            flags: writer_flags,
            write: Some(w),
        })
    }
    pub fn take_write(&mut self) -> Result<OwnedFd> {
        self.write.take().ok_or("pipe-transferred")
    }
}
pub fn peer(socket: &UnixStream, pid: &HeldPid, uid: u32) -> Result<()> {
    pid.verify()?;
    let c = net::sockopt::socket_peercred(socket).map_err(|_| "peercred")?;
    if u32::try_from(c.pid.as_raw_nonzero().get()).map_err(|_| "recipient-pid")? != pid.pid
        || c.uid.as_raw() != uid
        || c.gid.as_raw() != uid
    {
        return Err("recipient-identity");
    }
    Ok(())
}
/// Recipient was accepted from its own connection, never `SO_PEERCRED` on the root permit pair.
pub fn send_rights(
    socket: &UnixStream,
    recipient: &HeldPid,
    uid: u32,
    nonce: &str,
    fds: Vec<OwnedFd>,
    deadline: Instant,
) -> Result<()> {
    send_rights_count(socket, recipient, uid, nonce, fds, deadline, 5)
}
pub fn send_rights_count(
    socket: &UnixStream,
    recipient: &HeldPid,
    uid: u32,
    nonce: &str,
    fds: Vec<OwnedFd>,
    deadline: Instant,
    count: usize,
) -> Result<()> {
    peer(socket, recipient, uid)?;
    if fds.len() != count || count > 5 || nonce.len() != 32 || Instant::now() >= deadline {
        return Err("handoff-bounds");
    }
    socket
        .set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|_| "handoff-timeout")?;
    let refs: Vec<_> = fds.iter().map(AsFd::as_fd).collect();
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&refs)) {
        return Err("handoff-buffer");
    }
    let n = net::sendmsg(
        socket,
        &[IoSlice::new(nonce.as_bytes())],
        &mut control,
        net::SendFlags::NOSIGNAL,
    )
    .map_err(|_| "handoff-send")?;
    if n != 32 {
        return Err("handoff-short");
    }
    recipient.verify()?;
    drop(fds);
    Ok(())
}
pub fn receive_rights(socket: &UnixStream, nonce: &str, deadline: Instant) -> Result<Vec<OwnedFd>> {
    receive_rights_count(socket, nonce, deadline, 5)
}
pub fn receive_rights_count(socket: &UnixStream, nonce: &str, deadline: Instant, count: usize) -> Result<Vec<OwnedFd>> {
    net::sockopt::set_socket_passcred(socket, true).map_err(|_| "passcred")?;
    let peer = net::sockopt::socket_peercred(socket).map_err(|_| "root-peer")?;
    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 {
        return Err("nonroot-handoff");
    }
    socket
        .set_read_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .ok_or("handoff-expired")?,
        ))
        .map_err(|_| "handoff-timeout")?;
    let mut bytes = [0; 33];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(6), ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let m = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        net::RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| "handoff-recv")?;
    if m.bytes != 32
        || m.flags.intersects(net::ReturnFlags::CTRUNC | net::ReturnFlags::TRUNC)
        || &bytes[..32] != nonce.as_bytes()
    {
        return Err("handoff-message");
    }
    let mut fds = Vec::new();
    let mut creds = 0;
    for c in ancillary.drain() {
        match c {
            RecvAncillaryMessage::ScmRights(rights) => fds.extend(rights),
            RecvAncillaryMessage::ScmCredentials(c) => {
                if c.uid.as_raw() != 0 || c.gid.as_raw() != 0 || c.pid != peer.pid {
                    return Err("handoff-credentials");
                }
                creds += 1;
            }
            _ => return Err("handoff-ancillary"),
        }
    }
    if fds.len() != count || count > 5 || creds != 1 {
        return Err("handoff-count");
    }
    Ok(fds)
}
