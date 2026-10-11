//! Root-private cold-boot reconciliation. No current-boot manager or UID operation.
use super::{Result, authority, journal::Record};
use rustix::fs::{self as rfs, AtFlags, Dir, Mode, OFlags};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_ACTIVE_FILES: usize = 48;
const MAX_RECORDS: usize = 16;
const MAX_ARCHIVES: usize = 256;
const RECORD_BYTES: usize = 32768;

fn budget(end: Instant) -> Result<()> {
    if Instant::now() >= end {
        Err("cold-deadline")
    } else {
        Ok(())
    }
}

pub(crate) fn stage_shape(record: &Record) -> Result<()> {
    let mut canonical = PathBuf::from("/");
    if !record.stage.is_absolute() {
        return Err("cold-stage-relative");
    }
    for part in record.stage.components().skip(1) {
        match part {
            Component::Normal(p) => canonical.push(p),
            _ => return Err("cold-stage-component"),
        }
    }
    if canonical.as_os_str() != record.stage.as_os_str()
        || record.stage.file_name().and_then(|v| v.to_str())
            != Some(format!("klspike-{}", record.ownership.nonce).as_str())
    {
        return Err("cold-stage-binding");
    }
    Ok(())
}

fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn current_boot() -> Result<String> {
    let bytes = authority::bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "cold-boot-encoding")?;
    let boot = text.trim();
    if !valid_boot(boot) {
        return Err("cold-boot-schema");
    }
    Ok(boot.into())
}

fn root_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("cold-root-relative");
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(rfs::open("/", flags, Mode::empty()).map_err(|_| "cold-root-open")?);
    let mut canonical = PathBuf::from("/");
    for part in path.components().skip(1) {
        let Component::Normal(part) = part else {
            return Err("cold-root-component");
        };
        check_root(&directory)?;
        directory = File::from(rfs::openat(&directory, part, flags, Mode::empty()).map_err(|_| "cold-root-open")?);
        canonical.push(part);
    }
    check_root(&directory)?;
    if canonical.as_os_str() != path.as_os_str() {
        return Err("cold-root-noncanonical");
    }
    Ok(directory)
}

fn check_root(directory: &File) -> Result<()> {
    let meta = directory.metadata().map_err(|_| "cold-root-stat")?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err("cold-root-owner");
    }
    Ok(())
}

fn private_directory(directory: &File) -> Result<()> {
    check_root(directory)?;
    if directory.metadata().map_err(|_| "cold-root-stat")?.mode() & 0o777 != 0o700 {
        return Err("cold-private-mode");
    }
    Ok(())
}

fn names(directory: &File, limit: usize, end: Instant) -> Result<Vec<String>> {
    budget(end)?;
    let scan = rfs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "cold-scan-open")?;
    let entries = Dir::read_from(&scan).map_err(|_| "cold-scan")?;
    let mut result = Vec::new();
    for entry in entries {
        budget(end)?;
        let entry = entry.map_err(|_| "cold-scan-entry")?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if result.len() == limit {
            return Err("cold-scan-budget");
        }
        result.push(std::str::from_utf8(bytes).map_err(|_| "cold-entry-name")?.into());
    }
    result.sort();
    Ok(result)
}

fn private_file(directory: &File, name: &str) -> Result<File> {
    let file = File::from(
        rfs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "cold-record-open")?,
    );
    let meta = file.metadata().map_err(|_| "cold-record-stat")?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
        return Err("cold-record-owner");
    }
    Ok(file)
}

fn record(directory: &File, name: &str, nonce: &str) -> Result<Record> {
    let mut file = private_file(directory, name)?;
    let value: Record =
        serde_json::from_slice(&authority::read_file(&mut file, RECORD_BYTES)?).map_err(|_| "cold-record-json")?;
    value.validate()?;
    stage_shape(&value)?;
    if value.ownership.nonce != nonce || !valid_boot(&value.boot) {
        return Err("cold-record-binding");
    }
    Ok(value)
}

fn filename(name: &str, suffix: &str) -> Result<String> {
    let nonce = name.strip_suffix(suffix).ok_or("cold-entry-unknown")?;
    super::journal::Ownership::new(nonce, 0)?;
    Ok(nonce.into())
}

fn same_ownership(old: &Record, pending: &Record) -> bool {
    old.schema == pending.schema
        && old.ownership == pending.ownership
        && old.controller_pid == pending.controller_pid
        && old.controller_start == pending.controller_start
        && old.boot == pending.boot
        && old.execution_ns == pending.execution_ns
        && old.total_deadline_ns == pending.total_deadline_ns
        && old.stage == pending.stage
        && (old.uid.is_none() || old.uid == pending.uid)
}

fn cold_archive(mut record: Record) -> Record {
    record.phase = "cold-boot-retired".into();
    if record.cause.is_none() {
        record.cause = Some("host-reboot".into());
    }
    record
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

struct Snapshot {
    records: BTreeMap<String, Record>,
    pending: BTreeMap<String, Record>,
    markers: Vec<String>,
    archived: BTreeMap<String, Record>,
}

fn snapshot(live: &File, archive: &File, end: Instant) -> Result<Snapshot> {
    let mut result = Snapshot {
        records: BTreeMap::new(),
        pending: BTreeMap::new(),
        markers: Vec::new(),
        archived: BTreeMap::new(),
    };
    for name in names(live, MAX_ACTIVE_FILES + 2, end)? {
        budget(end)?;
        if name == ".lock" || name == "archive" {
            continue;
        }
        if Path::new(&name).extension() == Some(std::ffi::OsStr::new("json")) {
            let nonce = filename(&name, ".json")?;
            result.records.insert(nonce.clone(), record(live, &name, &nonce)?);
        } else if name.ends_with(".pending") {
            let nonce = filename(&name, ".pending")?;
            result.pending.insert(nonce.clone(), record(live, &name, &nonce)?);
        } else if name.ends_with(".watch-cleanup") {
            let nonce = filename(&name, ".watch-cleanup")?;
            let mut marker = private_file(live, &name)?;
            authority::read_file(&mut marker, RECORD_BYTES)?;
            result.markers.push(nonce);
        } else {
            return Err("cold-entry-unknown");
        }
    }
    if result.records.len() > MAX_RECORDS {
        return Err("cold-record-budget");
    }
    for name in names(archive, MAX_ARCHIVES, end)? {
        budget(end)?;
        let nonce = filename(&name, ".json")?;
        let value = record(archive, &name, &nonce)?;
        if !["lease-released", "cold-boot-retired"].contains(&value.phase.as_str()) {
            return Err("cold-archive-phase");
        }
        result.archived.insert(nonce, value);
    }
    Ok(result)
}

fn plan(snapshot: &Snapshot, boot: &str, reserved: Option<&Path>) -> Result<Vec<Record>> {
    if !valid_boot(boot) {
        return Err("cold-boot-schema");
    }
    for (nonce, pending) in &snapshot.pending {
        let old = snapshot.records.get(nonce).ok_or("cold-pending-orphan")?;
        if !same_ownership(old, pending) {
            return Err("cold-pending-binding");
        }
    }
    for nonce in &snapshot.markers {
        if !snapshot.records.contains_key(nonce) {
            return Err("cold-marker-orphan");
        }
    }
    let records: Vec<_> = snapshot.records.values().collect();
    for (index, record) in records.iter().enumerate() {
        stage_shape(record)?;
        if reserved.is_some_and(|stage| overlaps(stage, &record.stage))
            || records[..index]
                .iter()
                .any(|other| overlaps(&record.stage, &other.stage))
        {
            return Err("cold-stage-overlap");
        }
    }
    let mut old = Vec::new();
    let mut additions = 0;
    for (nonce, record) in &snapshot.records {
        if record.boot == boot {
            if snapshot.archived.contains_key(nonce) {
                return Err("cold-current-archive-overlap");
            }
            continue;
        }
        if record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            return Err("cold-controlled-boot-quarantine");
        }
        let latest = snapshot.pending.get(nonce).unwrap_or(record);
        let terminal = cold_archive(latest.clone());
        if let Some(archived) = snapshot.archived.get(nonce) {
            // Normal retire may durably archive lease-released before retiring its live record.
            // Authenticate that exact terminal pair without rewriting historical normal evidence.
            let expected = if archived.phase == "lease-released" && latest.phase == "lease-released" {
                latest
            } else {
                &terminal
            };
            if serde_json::to_vec(expected).map_err(|_| "cold-encode")?
                != serde_json::to_vec(archived).map_err(|_| "cold-encode")?
            {
                return Err("cold-archive-binding");
            }
            old.push(archived.clone());
        } else {
            additions += 1;
            old.push(terminal);
        }
    }
    if snapshot.archived.len() + additions > MAX_ARCHIVES {
        return Err("cold-archive-budget");
    }
    Ok(old)
}

fn remove_stage(record: &Record, end: Instant) -> Result<()> {
    budget(end)?;
    stage_shape(record)?;
    let parent = root_directory(record.stage.parent().ok_or("cold-stage-parent")?)?;
    let name = record.stage.file_name().ok_or("cold-stage-name")?;
    let stage = match rfs::openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(_) => return Err("cold-stage-open"),
    };
    check_root(&stage)?;
    if stage.metadata().map_err(|_| "cold-stage-stat")?.mode() & 0o777 != 0o711 {
        return Err("cold-stage-mode");
    }
    let entries = names(&stage, 1, end)?;
    for entry in entries {
        budget(end)?;
        if entry != "control" {
            return Err("cold-stage-unexpected");
        }
        let metadata = rfs::statat(&stage, "control", AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "cold-control-stat")?;
        if metadata.st_uid != 0
            || metadata.st_mode & 0o170_000 != 0o140_000
            || metadata.st_mode & 0o777 != 0o666
            || metadata.st_nlink != 1
        {
            return Err("cold-control-owner");
        }
        rfs::unlinkat(&stage, "control", AtFlags::empty()).map_err(|_| "cold-control-unlink")?;
    }
    stage.sync_all().map_err(|_| "cold-stage-sync")?;
    let held = stage.metadata().map_err(|_| "cold-stage-stat")?;
    let actual = rfs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| "cold-stage-path-stat")?;
    if actual.st_dev != held.dev() || actual.st_ino != held.ino() {
        return Err("cold-stage-replaced");
    }
    budget(end)?;
    rfs::unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|_| "cold-stage-unlink")?;
    parent.sync_all().map_err(|_| "cold-stage-parent-sync")
}

fn retire_after_archive(
    file_sync: impl FnOnce() -> Result<()>,
    directory_sync: impl FnOnce() -> Result<()>,
    retire: impl FnOnce() -> Result<()>,
) -> Result<()> {
    file_sync()?;
    directory_sync()?;
    retire()
}

pub(crate) fn reconcile(dir: &Path, boot: &str, reserved: Option<&Path>) -> Result<()> {
    reconcile_until(dir, boot, reserved, Instant::now() + Duration::from_secs(10))
}
pub(crate) fn reconcile_until(dir: &Path, boot: &str, reserved: Option<&Path>, end: Instant) -> Result<()> {
    budget(end)?;
    // Caller holds the exclusive journal writer lock. The kernel boot witness is never caller-selected.
    if current_boot()? != boot {
        return Err("cold-current-boot-binding");
    }
    let live = root_directory(dir)?;
    private_directory(&live)?;
    let archive = File::from(
        rfs::openat(
            &live,
            "archive",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "cold-archive-open")?,
    );
    private_directory(&archive)?;
    let snapshot = snapshot(&live, &archive, end)?;
    let old = plan(&snapshot, boot, reserved)?;
    // Validate the complete plan before any deletion. Stale allocations and manager units are never queried.
    for record in old {
        budget(end)?;
        remove_stage(&record, end)?;
        let nonce = &record.ownership.nonce;
        let name = format!("{nonce}.json");
        let archive_file = if snapshot.archived.contains_key(nonce) {
            // Matching bytes can survive a failed earlier sync without being durable.
            // Reopen only the authenticated root-private file relative to the held archive.
            private_file(&archive, &name)?
        } else {
            let bytes = serde_json::to_vec(&record).map_err(|_| "cold-encode")?;
            if bytes.len() > RECORD_BYTES {
                return Err("cold-record-budget");
            }
            let mut file = File::from(
                rfs::openat(
                    &archive,
                    name.as_str(),
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|_| "cold-archive-create")?,
            );
            file.write_all(&bytes).map_err(|_| "cold-archive-write")?;
            file
        };
        retire_after_archive(
            || {
                budget(end)?;
                archive_file.sync_all().map_err(|_| "cold-archive-sync")
            },
            || {
                budget(end)?;
                archive.sync_all().map_err(|_| "cold-archive-dir-sync")
            },
            || {
                budget(end)?;
                for suffix in [".pending", ".watch-cleanup"] {
                    let name = format!("{nonce}{suffix}");
                    match rfs::unlinkat(&live, name.as_str(), AtFlags::empty()) {
                        Ok(()) | Err(rustix::io::Errno::NOENT) => (),
                        Err(_) => return Err("cold-aux-retire"),
                    }
                }
                rfs::unlinkat(&live, name.as_str(), AtFlags::empty()).map_err(|_| "cold-record-retire")?;
                live.sync_all().map_err(|_| "cold-live-sync")
            },
        )?;
    }
    Ok(())
}
