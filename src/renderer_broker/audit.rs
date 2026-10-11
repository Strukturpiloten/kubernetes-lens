//! Independent root exec-stop audit for the admitted static-ELF closure.
use super::{
    Result,
    authority::{HeldPid, Object, bounded, digest_file, read_file},
};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn proc(pid: u32, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{name}"))
}
fn text(path: &Path, max: usize) -> Result<String> {
    String::from_utf8(bounded(path, max)?).map_err(|_| "proc-encoding")
}
pub fn status(pid: u32) -> Result<BTreeMap<String, String>> {
    parse_status(&bounded(&proc(pid, "status"), 65536)?)
}
fn parse_status(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut r = BTreeMap::new();
    for l in std::str::from_utf8(raw).map_err(|_| "status-encoding")?.lines() {
        if let Some((k, v)) = l.split_once(':') {
            if r.insert(k.into(), v.trim().into()).is_some() {
                return Err("status-duplicate");
            }
        }
    }
    Ok(r)
}
pub fn credentials(pid: u32, uid: u32) -> Result<()> {
    let s = status(pid)?;
    credential_fields(&s, uid)
}
fn credential_fields(s: &BTreeMap<String, String>, uid: u32) -> Result<()> {
    for key in ["Uid", "Gid"] {
        let v: Vec<u32> = s
            .get(key)
            .ok_or("credential-missing")?
            .split_whitespace()
            .map(|v| v.parse().map_err(|_| "credential-number"))
            .collect::<Result<_>>()?;
        if v != vec![uid; 4] {
            return Err("credential-slots");
        }
    }
    if !s.get("Groups").ok_or("groups-missing")?.trim().is_empty() {
        return Err("supplementary-groups");
    }
    Ok(())
}
pub fn single_thread(pid: u32) -> Result<()> {
    let mut count = 0;
    for e in fs::read_dir(proc(pid, "task")).map_err(|_| "task-dir")? {
        let e = e.map_err(|_| "task-entry")?;
        if e.file_name().to_str() != Some(&pid.to_string()) {
            return Err("extra-thread");
        }
        count += 1;
    }
    if count != 1 {
        return Err("task-count");
    }
    Ok(())
}
pub fn census(uid: u32, allowed: &[u32], deadline: Instant) -> Result<()> {
    let mut count = 0;
    let mut charged = 0usize;
    for e in fs::read_dir("/proc").map_err(|_| "census-dir")? {
        let e = e.map_err(|_| "census-entry")?;
        let Some(pid) = e.file_name().to_str().and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        count += 1;
        if count > 16384 || Instant::now() >= deadline {
            return Err("census-budget");
        }
        if charged >= 64 * 1024 * 1024 {
            return Err("census-byte-budget");
        }
        let Ok(raw) = bounded(&proc(pid, "status"), 65536.min(64 * 1024 * 1024 - charged)) else {
            if proc(pid, "").exists() {
                return Err("census-unreadable");
            }
            continue;
        };
        charged += raw.len();
        let s = parse_status(&raw)?;
        for key in ["Uid", "Gid"] {
            let v = s.get(key).ok_or("census-credentials")?;
            for part in v.split_whitespace() {
                if part.parse::<u32>().map_err(|_| "census-number")? == uid && !allowed.contains(&pid) {
                    return Err("unrelated-uid-holder");
                }
            }
        }
    }
    Ok(())
}
#[derive(Debug, Clone)]
pub struct Load {
    pub address: u64,
    pub offset: u64,
    pub file: u64,
    pub memory: u64,
    pub flags: u32,
}
#[derive(Debug, Clone)]
pub struct StaticElf {
    pub loads: Vec<Load>,
    pub entry: u64,
}
fn u16le(b: &[u8], i: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or("elf-bounds")?
            .try_into()
            .map_err(|_| "elf-bounds")?,
    ))
}
fn u32le(b: &[u8], i: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or("elf-bounds")?
            .try_into()
            .map_err(|_| "elf-bounds")?,
    ))
}
fn u64le(b: &[u8], i: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8)
            .ok_or("elf-bounds")?
            .try_into()
            .map_err(|_| "elf-bounds")?,
    ))
}
pub fn static_elf(b: &[u8]) -> Result<StaticElf> {
    if b.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16le(b, 16)? != 2
        || u32le(b, 20)? != 1
        || u16le(b, 52)? != 64
        || u16le(b, 54)? != 56
    {
        return Err("elf-static-exec-only");
    }
    let machine = u16le(b, 18)?;
    if machine != 62 || !cfg!(target_arch = "x86_64") {
        return Err("elf-machine");
    }
    let entry = u64le(b, 24)?;
    let offset = usize::try_from(u64le(b, 32)?).map_err(|_| "elf-offset")?;
    let count = u16le(b, 56)? as usize;
    if count == 0 || count > 32 {
        return Err("elf-segment-count");
    }
    if offset.checked_add(count * 56).as_ref().is_none_or(|&end| end > b.len()) {
        return Err("elf-table-bounds");
    }
    let mut loads = Vec::new();
    for i in 0..count {
        let p = offset.checked_add(i * 56).ok_or("elf-overflow")?;
        let kind = u32le(b, p)?;
        if [2, 3].contains(&kind) {
            return Err("elf-interpreter-or-dynamic");
        }
        if kind == 0x6474_e551 && u32le(b, p + 4)? & 1 != 0 {
            return Err("elf-executable-stack");
        }
        if kind == 1 {
            let l = Load {
                flags: u32le(b, p + 4)?,
                offset: u64le(b, p + 8)?,
                address: u64le(b, p + 16)?,
                file: u64le(b, p + 32)?,
                memory: u64le(b, p + 40)?,
            };
            if l.file > l.memory
                || l.address.checked_add(l.memory).is_none()
                || l.offset
                    .checked_add(l.file)
                    .as_ref()
                    .is_none_or(|&v| v > b.len() as u64)
                || l.flags & !7 != 0
                || l.flags & 3 == 3
                || l.address % 4096 != l.offset % 4096
            {
                return Err("elf-load-policy");
            }
            loads.push(l);
        }
    }
    if !loads
        .iter()
        .any(|l| l.flags & 1 != 0 && entry >= l.address && entry < l.address + l.memory)
    {
        return Err("elf-entry");
    }
    Ok(StaticElf { loads, entry })
}
fn down(v: u64) -> u64 {
    v & !4095
}
fn up(v: u64) -> Result<u64> {
    v.checked_add(4095).map(down).ok_or("mapping-overflow")
}
pub fn validate_maps(raw: &str, elf: &StaticElf, exe: Object) -> Result<()> {
    let mut count = 0;
    let mut entry = false;
    for line in raw.lines() {
        count += 1;
        if count > 128 {
            return Err("mapping-count");
        }
        let v: Vec<_> = line.split_whitespace().collect();
        if v.len() < 5 {
            return Err("mapping-schema");
        }
        let (a, b) = v[0].split_once('-').ok_or("mapping-range")?;
        let lo = u64::from_str_radix(a, 16).map_err(|_| "mapping-address")?;
        let hi = u64::from_str_radix(b, 16).map_err(|_| "mapping-address")?;
        if lo >= hi {
            return Err("mapping-range");
        }
        let off = u64::from_str_radix(v[2], 16).map_err(|_| "mapping-offset")?;
        let ino: u64 = v[4].parse().map_err(|_| "mapping-inode")?;
        let flags = v[1];
        if flags.len() != 4 || flags.as_bytes()[3] != b'p' {
            return Err("mapping-shared");
        }
        let path = v.get(5).copied().unwrap_or("");
        if ino == exe.ino {
            let (major, minor) = v[3].split_once(':').ok_or("mapping-device")?;
            let major = u64::from_str_radix(major, 16).map_err(|_| "mapping-device")?;
            let minor = u64::from_str_radix(minor, 16).map_err(|_| "mapping-device")?;
            if major != u64::from(rustix::fs::major(exe.dev)) || minor != u64::from(rustix::fs::minor(exe.dev)) {
                return Err("mapping-object");
            }
            let permitted = elf.loads.iter().any(|l| {
                let end = up(l.address + l.file).unwrap_or(0);
                lo >= down(l.address)
                    && hi <= end
                    && off == down(l.offset) + (lo - down(l.address))
                    && (!flags.contains('x') || l.flags & 1 != 0)
                    && (!flags.contains('w') || l.flags & 2 != 0)
                    && (!flags.contains('r') || l.flags & 4 != 0)
            });
            if !permitted {
                return Err("mapping-load");
            }
            if flags.contains('x') && lo <= elf.entry && elf.entry < hi {
                entry = true;
            }
        } else if ino != 0 {
            return Err("mapping-unapproved-object");
        } else {
            match path {
                "[vdso]" if flags == "r-xp" => (),
                "[vvar]" | "[vvar_vclock]" if flags == "r--p" => (),
                "[stack]" if flags == "rw-p" && hi - lo <= 8 * 1024 * 1024 => (),
                "" if flags == "rw-p"
                    && elf.loads.iter().any(|l| {
                        l.flags & 2 != 0
                            && lo >= down(l.address + l.file)
                            && hi <= up(l.address + l.memory).unwrap_or(0)
                    }) => {}
                _ => return Err("mapping-anonymous-authority"),
            }
        }
    }
    if !entry {
        return Err("mapping-entry-missing");
    }
    Ok(())
}
#[derive(Debug)]
pub struct Setup {
    pub namespaces: BTreeMap<String, Object>,
    pub mountinfo: Vec<u8>,
    pub null: Object,
    pub null_held: OwnedFd,
    pub null_flags: u64,
    pub null_read: File,
}
fn namespace_policy(pid: u32, uid: u32) -> Result<BTreeMap<String, Object>> {
    let mut namespaces = BTreeMap::new();
    for n in ["user", "pid", "mnt", "net", "ipc", "uts", "cgroup"] {
        let object = Object::path(&proc(pid, &format!("ns/{n}")))?;
        if object == Object::path(&PathBuf::from(format!("/proc/self/ns/{n}")))? {
            return Err("host-namespace");
        }
        namespaces.insert(n.into(), object);
    }
    for map in ["uid_map", "gid_map"] {
        let raw = text(&proc(pid, map), 4096)?;
        let rows: Vec<_> = raw.split_whitespace().collect();
        if rows != vec!["0".to_string(), uid.to_string(), "1".to_string()] {
            return Err("uid-map");
        }
    }
    Ok(namespaces)
}
fn mounts(raw: &[u8]) -> Result<()> {
    let s = std::str::from_utf8(raw).map_err(|_| "mount-encoding")?;
    let mut root = false;
    let mut scratch = false;
    let mut proc_mount = false;
    let mut renderer = false;
    let mut count = 0;
    for line in s.lines() {
        count += 1;
        if count > 32 {
            return Err("mount-count");
        }
        let (left, right) = line.split_once(" - ").ok_or("mount-schema")?;
        let a: Vec<_> = left.split_whitespace().collect();
        let b: Vec<_> = right.split_whitespace().collect();
        if a.len() < 6 || b.len() < 3 {
            return Err("mount-schema");
        }
        let point = a[4];
        let opts = a[5].split(',').collect::<Vec<_>>();
        let fs = b[0];
        match point {
            "/" if fs == "tmpfs" && opts.contains(&"ro") => root = true,
            "/scratch"
                if fs == "tmpfs"
                    && opts.contains(&"rw")
                    && b[2].split(',').any(|o| o == "size=65536k" || o == "size=67108864") =>
            {
                scratch = true;
            }
            "/proc"
                if fs == "proc" && opts.contains(&"nosuid") && opts.contains(&"nodev") && opts.contains(&"noexec") =>
            {
                proc_mount = true;
            }
            "/input" if opts.contains(&"ro") => (),
            "/renderer" if fs == "tmpfs" && opts.contains(&"ro") && opts.contains(&"nosuid") => {
                renderer = true;
            }
            "/dev" if fs == "tmpfs" && opts.contains(&"nosuid") => (),
            "/dev/pts" if fs == "devpts" && opts.contains(&"nosuid") && opts.contains(&"noexec") => {}
            "/dev/shm" if fs == "tmpfs" && opts.contains(&"nosuid") && opts.contains(&"nodev") => {}
            "/dev/null" | "/dev/zero" | "/dev/full" | "/dev/random" | "/dev/urandom" | "/dev/tty"
                if opts.contains(&"nosuid") => {}
            _ => return Err("mount-outside-closure"),
        }
    }
    if !root || !scratch || !proc_mount || !renderer {
        return Err("mount-closure-missing");
    }
    Ok(())
}
fn proc_visibility(pid: u32) -> Result<()> {
    let root = proc(pid, "root/proc");
    let mut n = 0;
    for e in fs::read_dir(&root).map_err(|_| "sandbox-proc")? {
        let e = e.map_err(|_| "sandbox-proc-entry")?;
        if let Some(s) = e.file_name().to_str() {
            if s.bytes().all(|b| b.is_ascii_digit()) {
                if s != "1" {
                    return Err("outer-process-visible");
                }
                n += 1;
            }
        }
    }
    if n != 1 {
        return Err("sandbox-proc-one");
    }
    Ok(())
}
pub fn setup(held: &HeldPid, uid: u32) -> Result<Setup> {
    held.verify()?;
    credentials(held.pid, uid)?;
    single_thread(held.pid)?;
    let namespaces = namespace_policy(held.pid, uid)?;
    let mountinfo = bounded(&proc(held.pid, "mountinfo"), 65536)?;
    mounts(&mountinfo)?;
    proc_visibility(held.pid)?;
    let null_held = rustix::fs::open(
        proc(held.pid, "root/dev/null"),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "null-held-open")?;
    let held_stat = rustix::fs::fstat(&null_held).map_err(|_| "null-held-stat")?;
    let null = Object {
        dev: held_stat.st_dev,
        ino: held_stat.st_ino,
        kind: held_stat.st_mode & 0o170_000,
        rdev: held_stat.st_rdev,
    };
    if null.kind != 0o020_000 || rustix::fs::major(null.rdev) != 1 || rustix::fs::minor(null.rdev) != 3 {
        return Err("stdin-null-object");
    }
    let null_read = File::open(proc(held.pid, "root/dev/null")).map_err(|_| "null-read-open")?;
    if Object::of(&null_read)? != null {
        return Err("null-replaced");
    }
    let null_flags = u64::from(
        rustix::fs::fcntl_getfl(&null_read)
            .map_err(|_| "null-read-flags")?
            .bits(),
    );
    Ok(Setup {
        namespaces,
        mountinfo,
        null,
        null_held,
        null_flags,
        null_read,
    })
}
pub fn limits(cgroup: &Path, memory: usize, pids: usize) -> Result<()> {
    let memory = memory.to_string();
    let pids = pids.to_string();
    for (name, expected) in [
        ("memory.max", memory.as_str()),
        ("memory.swap.max", "0"),
        ("pids.max", pids.as_str()),
        ("cpu.max", "100000 100000"),
        ("cpu.max.burst", "0"),
    ] {
        let raw = text(&cgroup.join(name), 128)?;
        if raw.trim() != expected {
            return Err("cgroup-ceiling");
        }
    }
    Ok(())
}
fn fd_access(fd: u32, flags: u64) -> Result<()> {
    if fd > 2 || flags & 3 != u64::from(fd != 0) || flags & 0o10_000_000 != 0 {
        return Err("stdio-access");
    }
    Ok(())
}
fn fd_inventory(pid: u32, expected: [(Object, u64); 3]) -> Result<()> {
    let mut entries = Vec::new();
    for e in fs::read_dir(proc(pid, "fd")).map_err(|_| "fd-directory")? {
        let e = e.map_err(|_| "fd-entry")?;
        let fd: u32 = e
            .file_name()
            .to_str()
            .ok_or("fd-name")?
            .parse()
            .map_err(|_| "fd-number")?;
        if fd > 2 {
            return Err("extra-authority-fd");
        }
        entries.push(fd);
        let object = Object::path(&e.path())?;
        if object != expected[fd as usize].0 {
            return Err("stdio-object");
        }
        let info = text(&proc(pid, &format!("fdinfo/{fd}")), 4096)?;
        let flags = info.lines().find_map(|l| l.strip_prefix("flags:")).ok_or("fd-flags")?;
        let flags = u64::from_str_radix(flags.trim(), 8).map_err(|_| "fd-flags")?;
        fd_access(fd, flags)?;
        if flags & !0o2_000_000 != expected[fd as usize].1 {
            return Err("stdio-flags-changed");
        }
    }
    entries.sort_unstable();
    if entries != [0, 1, 2] {
        return Err("stdio-inventory");
    }
    Ok(())
}
pub struct ExecutionAudit<'a> {
    pub plan: &'a super::bubblewrap_probe::GatePlan,
    pub memory: usize,
    pub pids: usize,
    pub cgroup: &'a Path,
    pub deadline: Instant,
}
pub fn final_stop(
    held: &HeldPid,
    uid: u32,
    setup: &Setup,
    outputs: [(Object, u64); 2],
    digest: [u8; 32],
    execution: &ExecutionAudit<'_>,
) -> Result<()> {
    let ExecutionAudit {
        plan,
        memory,
        pids,
        cgroup,
        deadline,
    } = execution;
    let (memory, pids, deadline) = (*memory, *pids, *deadline);
    if Instant::now() >= deadline {
        return Err("audit-deadline");
    }
    held.verify()?;
    credentials(held.pid, uid)?;
    single_thread(held.pid)?;
    let s = status(held.pid)?;
    if s.get("NSpid").and_then(|v| v.split_whitespace().last()) != Some("1")
        || s.get("NoNewPrivs").map(String::as_str) != Some("1")
    {
        return Err("pid-one-or-nnp");
    }
    for k in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if u64::from_str_radix(s.get(k).ok_or("cap-missing")?, 16).map_err(|_| "cap-number")? != 0 {
            return Err("capability-authority");
        }
    }
    if namespace_policy(held.pid, uid)? != setup.namespaces
        || bounded(&proc(held.pid, "mountinfo"), 65536)? != setup.mountinfo
    {
        return Err("setup-changed");
    }
    mounts(&setup.mountinfo)?;
    proc_visibility(held.pid)?;
    limits(cgroup, memory, pids)?;
    if Object::of(&setup.null_read)? != setup.null
        || rustix::fs::fstat(&setup.null_held)
            .map_err(|_| "null-held-restat")?
            .st_ino
            != setup.null.ino
    {
        return Err("null-held-changed");
    }
    fd_inventory(held.pid, [(setup.null, setup.null_flags), outputs[0], outputs[1]])?;
    let mut argv = b"/renderer\0".to_vec();
    for arg in &plan.argv {
        argv.extend_from_slice(arg.as_bytes());
        argv.push(0);
    }
    let environment = bounded(&proc(held.pid, "environ"), 65536)?;
    let mut actual: Vec<_> = environment
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    actual.sort();
    let expected: Vec<_> = plan.env.iter().map(|(k, v)| format!("{k}={v}").into_bytes()).collect();
    if bounded(&proc(held.pid, "cmdline"), 65536)? != argv || actual != expected {
        return Err("argv-or-environment");
    }
    // /proc/PID/exe is a trusted kernel magiclink, opened only at the exact held stop.
    let mut f = File::open(proc(held.pid, "exe")).map_err(|_| "exec-object")?;
    let m = f.metadata().map_err(|_| "exec-stat")?;
    if !m.is_file() || m.mode() & 0o6000 != 0 {
        return Err("exec-kind-or-setid");
    }
    match rustix::fs::fgetxattr(&f, "security.capability", &mut [0; 128]) {
        Err(e) if e == rustix::io::Errno::NODATA => (),
        _ => return Err("exec-file-capability-or-unavailable"),
    }
    let exe = Object::of(&f)?;
    if digest_file(&mut f, deadline)? != digest {
        return Err("exec-digest");
    }
    let mut f = File::open(proc(held.pid, "exe")).map_err(|_| "exec-reopen")?;
    let elf = static_elf(&read_file(&mut f, 64 * 1024 * 1024)?)?;
    validate_maps(&text(&proc(held.pid, "maps"), 65536)?, &elf, exe)?;
    for p in ["scratch/gate", "run", "sys", "etc", "home", "root"] {
        if fs::symlink_metadata(proc(held.pid, &format!("root/{p}"))).is_ok() {
            return Err("helper-control-path");
        }
    }
    if text(&proc(held.pid, "cgroup"), 4096)?.trim()
        != format!(
            "0::/{}",
            cgroup
                .strip_prefix("/sys/fs/cgroup")
                .map_err(|_| "cgroup-root")?
                .display()
        )
    {
        return Err("cgroup-identity");
    }
    held.verify()?;
    if Instant::now() >= deadline {
        return Err("audit-deadline");
    }
    Ok(())
}
pub fn empty_group(path: &Path, deadline: Instant) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(m) if m.is_dir() => (),
        _ => return Err("cleanup-group-object"),
    }
    let mut pending = vec![path.to_path_buf()];
    let mut count = 0;
    while let Some(p) = pending.pop() {
        count += 1;
        if count > 256 || Instant::now() >= deadline {
            return Err("cleanup-group-budget");
        }
        if !text(&p.join("cgroup.procs"), 65536)?.trim().is_empty()
            || !text(&p.join("cgroup.threads"), 65536)?.trim().is_empty()
        {
            return Err("cleanup-group-nonempty");
        }
        for e in fs::read_dir(&p).map_err(|_| "cgroup-scan")? {
            let e = e.map_err(|_| "cgroup-entry")?;
            let kind = e.file_type().map_err(|_| "cgroup-kind")?;
            if kind.is_symlink() {
                return Err("cgroup-symlink");
            }
            if kind.is_dir() {
                pending.push(e.path());
            }
        }
    }
    Ok(())
}
