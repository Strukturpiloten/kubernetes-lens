//! Durable intent precedes every manager mutation. Unproved cleanup retains the lease.
use super::{Result, authority::bounded};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ownership {
    pub nonce: String,
    pub lease: String,
    pub work: String,
    pub watch: String,
    pub username: String,
    pub client_uid: u32,
}
impl Ownership {
    pub fn new(nonce: &str, client_uid: u32) -> Result<Self> {
        if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("nonce");
        }
        let number = u128::from_str_radix(nonce, 16).map_err(|_| "nonce")?;
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut username = String::from("kls");
        for i in (0..26).rev() {
            username.push(alphabet[((number >> (5 * i)) & 31) as usize] as char);
        }
        let prefix = format!("klspike-{nonce}");
        Ok(Self {
            nonce: nonce.into(),
            lease: format!("{prefix}-lease.service"),
            work: format!("{prefix}-work.service"),
            watch: format!("{prefix}-watch.service"),
            username,
            client_uid,
        })
    }
    pub fn validate(&self) -> Result<()> {
        if *self != Self::new(&self.nonce, self.client_uid)? {
            return Err("ownership-binding");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u32,
    pub ownership: Ownership,
    pub controller_pid: u32,
    pub controller_start: u64,
    pub boot: String,
    pub execution_ns: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_deadline_ns: Option<u64>,
    pub cleanup_ns: Option<u64>,
    pub uid: Option<u32>,
    pub phase: String,
    pub cause: Option<String>,
    pub stage: PathBuf,
}
impl Record {
    pub fn total_end_ns(&self) -> Result<u64> {
        match (self.schema, self.total_deadline_ns) {
            (1, None) => self
                .execution_ns
                .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS),
            (2, Some(total))
                if self
                    .execution_ns
                    .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
                    .is_some_and(|minimum| total >= minimum) =>
            {
                Some(total)
            }
            _ => None,
        }
        .ok_or("journal-total-deadline")
    }

    pub fn validate(&self) -> Result<()> {
        self.ownership.validate()?;
        super::cold_boot::stage_shape(self)?;
        let total = self.total_end_ns()?;
        if self.controller_pid <= 1
            || self.execution_ns == 0
            || self.boot.len() != 36
            || self.cleanup_ns.is_some_and(|cleanup| cleanup > total)
        {
            return Err("journal-schema");
        }
        Ok(())
    }
}
/// Pure complete-pending admission shared by read-only inspection and promotion.
pub(super) fn pending_candidate(live: &Record, bytes: &[u8]) -> Result<Record> {
    if bytes.len() > 32768 {
        return Err("pending-budget");
    }
    let candidate: Record = serde_json::from_slice(bytes).map_err(|_| "pending-incomplete-quarantine")?;
    pending_binding(live, &candidate)?;
    Ok(candidate)
}
pub(super) fn pending_binding(live: &Record, candidate: &Record) -> Result<()> {
    live.validate()?;
    candidate.validate()?;
    if candidate.schema != live.schema
        || candidate.ownership != live.ownership
        || candidate.controller_pid != live.controller_pid
        || candidate.controller_start != live.controller_start
        || candidate.boot != live.boot
        || candidate.execution_ns != live.execution_ns
        || candidate.total_deadline_ns != live.total_deadline_ns
        || candidate.stage != live.stage
        || live.uid.is_some() && candidate.uid != live.uid
    {
        return Err("pending-ownership-changed");
    }
    Ok(())
}
pub(super) fn promotable_pending(live: &Record, candidate: &Record) -> Result<()> {
    pending_binding(live, candidate)?;
    // Reject a widening interrupted write instead of exposing an enlarged live end
    // during rename or a crash. A valid tighter pending write promotes unchanged.
    if live
        .cleanup_ns
        .is_some_and(|old| candidate.cleanup_ns.is_none_or(|new| new > old))
    {
        return Err("pending-cleanup-renewal");
    }
    Ok(())
}
fn pending_budget(end: Option<Instant>) -> Result<()> {
    if end.is_some_and(|end| Instant::now() >= end) {
        return Err("pending-deadline");
    }
    Ok(())
}
pub struct Journal {
    dir: PathBuf,
    pub record: Record,
    writer: Option<File>,
}
fn directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| "journal-dir")?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
        return Err("journal-dir-owner");
    }
    Ok(())
}
fn syncdir(path: &Path) -> Result<()> {
    File::open(path)
        .map_err(|_| "journal-dir-open")?
        .sync_all()
        .map_err(|_| "journal-dir-sync")
}
fn writer_lock(dir: &Path) -> Result<File> {
    directory(dir)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(dir.join(".lock"))
        .map_err(|_| "journal-lock-open")?;
    let m = f.metadata().map_err(|_| "journal-lock-stat")?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 {
        return Err("journal-lock-owner");
    }
    rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| "journal-writer-busy")?;
    Ok(f)
}
impl Journal {
    pub fn create(dir: &Path, record: Record) -> Result<Self> {
        directory(dir)?;
        directory(&dir.join("archive"))?;
        record.validate()?;
        if record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            super::route::instant(record.execution_ns)?;
        }
        let writer = writer_lock(dir)?;
        if record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            super::cold_boot::reconcile_until(
                dir,
                &record.boot,
                Some(&record.stage),
                super::route::instant(record.execution_ns)?,
            )?;
        } else {
            super::cold_boot::reconcile(dir, &record.boot, Some(&record.stage))?;
        }
        let mut active = 0;
        let mut archived = 0;
        for e in fs::read_dir(dir).map_err(|_| "journal-scan")? {
            let e = e.map_err(|_| "journal-scan")?;
            if e.file_name() != "archive" && e.file_name() != ".lock" {
                active += 1;
            }
        }
        for e in fs::read_dir(dir.join("archive")).map_err(|_| "archive-scan")? {
            e.map_err(|_| "archive-scan")?;
            archived += 1;
        }
        if active >= 16 || archived >= 256 {
            return Err("journal-admission-full");
        }
        let j = Self {
            dir: dir.into(),
            record,
            writer: Some(writer),
        };
        if j.path().exists()
            || j.dir
                .join("archive")
                .join(format!("{}.json", j.record.ownership.nonce))
                .exists()
        {
            return Err("nonce-reused");
        }
        if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            super::route::instant(j.record.execution_ns)?;
        }
        j.persist_new()?;
        Ok(j)
    }
    pub fn load(dir: &Path, nonce: &str) -> Result<Self> {
        directory(dir)?;
        Ownership::new(nonce, 0)?;
        let path = dir.join(format!("{nonce}.json"));
        let m = fs::symlink_metadata(&path).map_err(|_| "journal-metadata")?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o777 != 0o600 {
            return Err("journal-owner");
        }
        let record: Record = serde_json::from_slice(&bounded(&path, 32768)?).map_err(|_| "journal-json")?;
        record.validate()?;
        if record.ownership.nonce != nonce {
            return Err("journal-nonce");
        }
        Ok(Self {
            dir: dir.into(),
            record,
            writer: None,
        })
    }
    pub fn load_writer(dir: &Path, nonce: &str) -> Result<Self> {
        let writer = writer_lock(dir)?;
        let mut j = Self::load(dir, nonce)?;
        j.writer = Some(writer);
        Ok(j)
    }
    pub(crate) fn reconcile_after_reboot(&self, boot: &str) -> Result<()> {
        if self.writer.is_none() || boot == self.record.boot {
            return Err("cold-recovery-state");
        }
        if self.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            return Err("controlled-recovery-boot");
        }
        super::cold_boot::reconcile(&self.dir, boot, None)
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(format!("{}.json", self.record.ownership.nonce))
    }
    fn write_new(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(&self.record).map_err(|_| "journal-encode")?;
        if bytes.len() > 32768 {
            return Err("journal-budget");
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)
            .map_err(|_| "journal-create")?;
        f.write_all(&bytes).map_err(|_| "journal-write")?;
        f.sync_all().map_err(|_| "journal-sync")?;
        Ok(())
    }
    fn persist_new(&self) -> Result<()> {
        self.write_new(&self.path())?;
        syncdir(&self.dir)
    }
    pub fn persist(&self) -> Result<()> {
        let pending = self.dir.join(format!("{}.pending", self.record.ownership.nonce));
        self.write_new(&pending)?;
        fs::rename(&pending, self.path()).map_err(|_| "journal-rename")?;
        syncdir(&self.dir)
    }
    pub fn verify_durable(&self) -> Result<()> {
        let disk = Self::load(&self.dir, &self.record.ownership.nonce)?;
        if serde_json::to_vec(&disk.record).map_err(|_| "journal-encode")?
            != serde_json::to_vec(&self.record).map_err(|_| "journal-encode")?
        {
            return Err("journal-not-durable");
        }
        Ok(())
    }
    /// Bounded, read-only inspection; never promotes, syncs or writes pending bytes.
    pub fn inspect_pending(&self, end: Option<Instant>) -> Result<Option<Record>> {
        pending_budget(end)?;
        let pending = self.dir.join(format!("{}.pending", self.record.ownership.nonce));
        let metadata = match fs::symlink_metadata(&pending) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(m) if m.is_file() && m.uid() == 0 && m.mode() & 0o777 == 0o600 && m.nlink() == 1 => m,
            _ => return Err("pending-owner"),
        };
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(&pending)
            .map_err(|_| "pending-open")?;
        let held = file.metadata().map_err(|_| "pending-stat")?;
        if held.dev() != metadata.dev()
            || held.ino() != metadata.ino()
            || !held.is_file()
            || held.uid() != 0
            || held.mode() & 0o777 != 0o600
            || held.nlink() != 1
        {
            return Err("pending-owner-changed");
        }
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            pending_budget(end)?;
            let upper = (32769 - bytes.len()).min(chunk.len());
            let count = file.read(&mut chunk[..upper]).map_err(|_| "pending-read")?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.len() > 32768 {
                return Err("pending-budget");
            }
        }
        pending_budget(end)?;
        pending_candidate(&self.record, &bytes).map(Some)
    }
    pub fn reconcile_pending_after_stop(&mut self) -> Result<()> {
        self.reconcile_pending_after_stop_until(None)
    }
    pub fn reconcile_pending_after_stop_until(&mut self, end: Option<Instant>) -> Result<()> {
        let Some(candidate) = self.inspect_pending(end)? else {
            return Ok(());
        };
        promotable_pending(&self.record, &candidate)?;
        pending_budget(end)?;
        let pending = self.dir.join(format!("{}.pending", self.record.ownership.nonce));
        File::open(&pending)
            .map_err(|_| "pending-open")?
            .sync_all()
            .map_err(|_| "pending-sync")?;
        pending_budget(end)?;
        fs::rename(&pending, self.path()).map_err(|_| "pending-promote")?;
        syncdir(&self.dir)?;
        self.record = candidate;
        Ok(())
    }
    pub fn retire(self) -> Result<()> {
        if self.record.phase != "lease-released" {
            return Err("retire-before-release");
        }
        let archive = self.dir.join("archive");
        self.write_new(&archive.join(format!("{}.json", self.record.ownership.nonce)))?;
        syncdir(&archive)?;
        let marker = self.dir.join(format!("{}.watch-cleanup", self.record.ownership.nonce));
        match fs::remove_file(marker) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("watch-marker-retire"),
        }
        fs::remove_file(self.path()).map_err(|_| "journal-retire")?;
        syncdir(&self.dir)
    }
}

#[cfg(test)]
mod complete_pending_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn live() -> Result<Record> {
        let nonce = "a".repeat(32);
        Ok(Record {
            schema: 2,
            ownership: Ownership::new(&nonce, 1000)?,
            controller_pid: 20,
            controller_start: 4,
            boot: "00000000-0000-0000-0000-000000000000".into(),
            execution_ns: 20_000_000_000,
            total_deadline_ns: Some(30_000_000_000),
            cleanup_ns: None,
            uid: Some(61000),
            phase: "intent".into(),
            cause: None,
            stage: format!("/var/lib/private/klspike-{nonce}").into(),
        })
    }
    #[test]
    fn complete_owned_pending_admits_original_bindings_but_partial_foreign_and_malformed_do_not() -> TestResult {
        let live = live()?;
        let mut pending = live.clone();
        pending.cleanup_ns = Some(15_000_000_000);
        let bytes = serde_json::to_vec(&pending)?;
        assert_eq!(pending_candidate(&live, &bytes)?.cleanup_ns, Some(15_000_000_000));
        for bytes in [
            &bytes[..bytes.len() - 1],
            b"{}",
            b"not-json",
            b"{\"cleanup_ns\":15000000000}",
        ] {
            assert!(pending_candidate(&live, bytes).is_err());
        }
        assert!(pending_candidate(&live, &vec![b' '; 32769]).is_err());
        let mut foreign = pending.clone();
        foreign.ownership = Ownership::new(&"b".repeat(32), 1000)?;
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending.clone();
        foreign.boot = "11111111-1111-1111-1111-111111111111".into();
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending.clone();
        foreign.execution_ns -= 1;
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending.clone();
        foreign.total_deadline_ns = Some(31_000_000_000);
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending.clone();
        foreign.controller_start += 1;
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending.clone();
        foreign.uid = Some(61001);
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        foreign = pending;
        foreign.cleanup_ns = Some(30_000_000_001);
        assert!(pending_candidate(&live, &serde_json::to_vec(&foreign)?).is_err());
        assert!(live.cleanup_ns.is_none());
        Ok(())
    }
    #[test]
    fn promotion_and_retries_keep_the_shorter_persisted_end_and_refuse_widening() -> TestResult {
        let mut live = live()?;
        let mut pending = live.clone();
        pending.cleanup_ns = Some(15_000_000_000);
        promotable_pending(&live, &pending)?;
        live = pending.clone(); // Exact durable promotion preserves the tighter bytes.
        promotable_pending(&live, &pending)?;
        assert_eq!(live.cleanup_ns, Some(15_000_000_000));
        pending.cleanup_ns = Some(20_000_000_000);
        assert_eq!(promotable_pending(&live, &pending), Err("pending-cleanup-renewal"));
        pending.cleanup_ns = None;
        assert_eq!(promotable_pending(&live, &pending), Err("pending-cleanup-renewal"));
        pending.cleanup_ns = Some(14_000_000_000);
        promotable_pending(&live, &pending)?;
        live = pending.clone();
        promotable_pending(&live, &pending)?;
        assert_eq!(live.cleanup_ns, Some(14_000_000_000));
        Ok(())
    }
}
