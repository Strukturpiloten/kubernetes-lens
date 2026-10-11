//! Concrete fixed Manager transport. No user-selected unit, program or properties.
use super::{
    Result,
    authority::HeldPid,
    journal::{Journal, Ownership},
};
use nix::unistd::{Group, User};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct SystemManager {
    pub helper: PathBuf,
    pub journal_dir: PathBuf,
    pub stage: PathBuf,
}
pub struct Allocation {
    pub uid: u32,
    pub lock: File,
    pub invocation: String,
}
pub struct Unit {
    pub values: BTreeMap<String, String>,
}
impl Unit {
    pub fn get(&self, key: &str) -> Result<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .ok_or("manager-property-missing")
    }
}
fn collect(
    child: &mut Child,
    end: Instant,
    cleanup: Instant,
    mut stdout: impl Read,
    mut stderr: impl Read,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut status = None;
    loop {
        let mut buf = [0; 4096];
        for (pipe, data) in [
            (&mut stdout as &mut dyn Read, &mut out),
            (&mut stderr as &mut dyn Read, &mut err),
        ] {
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        data.extend_from_slice(&buf[..n]);
                        if data.len() > 65536 {
                            let _ = child.kill();
                            return reap(child, cleanup).and(Err("manager-output-budget"));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        let _ = child.kill();
                        return reap(child, cleanup).and(Err("manager-read"));
                    }
                }
            }
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| "manager-wait")?;
        }
        if let Some(s) = status {
            return if s.success() { Ok(out) } else { Err("manager-failed") };
        }
        if Instant::now() >= end {
            let _ = child.kill();
            return reap(child, cleanup).and(Err("manager-timeout"));
        }
        thread::sleep(Duration::from_millis(2));
    }
}
pub fn reserve(allowance: Duration) -> Duration {
    Duration::from_millis(250).min(allowance / 2)
}
fn reap(child: &mut Child, end: Instant) -> Result<()> {
    loop {
        if child.try_wait().map_err(|_| "helper-reap")?.is_some() {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err("helper-unreaped");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
// Reviewed upstream systemd 261.3 (matching the installed version) allows 250ms
// event timer accuracy. Actual packaged behavior remains native acceptance. The admitted
// no-ExecStop/no-ExecStopPost policy can traverse STOP TERM/KILL and FINAL TERM/KILL.
// Reserve every signal wait, each timer's accuracy, runtime accuracy, and timestamp
// rounding. This is configured-timer arithmetic, never observed death/reap proof.
const TIMER_ACCURACY_NS: u64 = 250_000_000;
const STOP_TIMEOUT_NS: u64 = 1_000_000_000;
const STOP_SIGNAL_PHASES: u64 = 4;
const ACTIVATION_ROUNDING_NS: u64 = 1_000;
const MANAGER_TAIL_NS: u64 =
    TIMER_ACCURACY_NS + STOP_SIGNAL_PHASES * (STOP_TIMEOUT_NS + TIMER_ACCURACY_NS) + ACTIVATION_ROUNDING_NS;
const ACTIVATION_RESERVE_NS: u64 = 1_000_000_000;
fn effective_total(execution: u64, total: u64) -> Result<u64> {
    Ok(execution
        .checked_add(super::broker_protocol::CLEANUP_RESERVE_NS)
        .ok_or("service-total-overflow")?
        .min(total))
}
pub(super) fn initial_runtime(execution: u64, total: u64, now_ns: u64) -> Result<u64> {
    if now_ns >= execution {
        return Err("service-execution-expired");
    }
    effective_total(execution, total)?
        .checked_sub(now_ns)
        .and_then(|n| n.checked_sub(MANAGER_TAIL_NS + ACTIVATION_RESERVE_NS))
        .filter(|n| *n >= 1000)
        .ok_or("service-stop-budget")
}
fn activated_runtime(execution: u64, total: u64, activated_us: u64) -> Result<u64> {
    if activated_us == 0 {
        return Err("service-activation-unbound");
    }
    effective_total(execution, total)?
        .checked_sub(MANAGER_TAIL_NS)
        .and_then(|n| n.checked_sub(activated_us.checked_mul(1000)?))
        .filter(|n| *n >= 1000)
        .ok_or("service-runtime-expired")
}

fn admit_runtime_guard(guard_us: u64, maximum_ns: u64) -> Result<()> {
    if guard_us == 0 || guard_us.checked_mul(1000).is_none_or(|n| n > maximum_ns) {
        return Err("service-activation-too-late");
    }
    Ok(())
}

impl SystemManager {
    pub(super) fn bound_runtime(
        unit: &str,
        nonce: &str,
        execution: u64,
        total: u64,
        guard_us: u64,
        end: Instant,
    ) -> Result<()> {
        let own = Ownership::new(nonce, 0)?;
        if ![own.work, own.watch, format!("klspike-{nonce}-controller.service")].contains(&unit.to_string()) {
            return Err("service-runtime-unowned");
        }
        let raw = Self::command(
            "/usr/bin/systemctl",
            &[
                "show".into(),
                unit.into(),
                "--property=Id,InvocationID,ActiveEnterTimestampMonotonic,Type,KillMode,SendSIGKILL,TimeoutStopFailureMode,ExecStop,ExecStopPost".into(),
            ],
            end,
            end,
        )?;
        let active = parse_show(&raw)?;
        if active.get("Id")? != unit {
            return Err("service-runtime-binding");
        }
        if active.get("Type")? != "exec"
            || active.get("KillMode")? != "control-group"
            || active.get("SendSIGKILL")? != "yes"
            || active.get("TimeoutStopFailureMode")? != "terminate"
            || !active.get("ExecStop")?.is_empty()
            || !active.get("ExecStopPost")?.is_empty()
            || Self::duration_property(unit, "TimeoutStopUSec", end)? != STOP_TIMEOUT_NS / 1000
            || Self::duration_property(unit, "RuntimeRandomizedExtraUSec", end)? != 0
        {
            return Err("service-stop-policy-unadmitted");
        }
        let activated = active
            .get("ActiveEnterTimestampMonotonic")?
            .parse()
            .map_err(|_| "service-activation")?;
        let invocation = active.get("InvocationID")?;
        if invocation.len() != 32
            || !invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("service-runtime-invocation");
        }
        let maximum = activated_runtime(execution, total, activated)?;
        admit_runtime_guard(guard_us, maximum)?;
        // RuntimeMax is fixed at transient creation. Active-service mutation is unsupported;
        // an activation too late for the unchanged guard refuses before native permission.
        if Self::duration_property(unit, "RuntimeMaxUSec", end)? != guard_us {
            return Err("service-runtime-readback");
        }
        Ok(())
    }

    pub(super) fn command(exe: &str, args: &[String], end: Instant, cleanup: Instant) -> Result<Vec<u8>> {
        if !["/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/busctl"].contains(&exe)
            || args.iter().map(String::len).sum::<usize>() > 65536
        {
            return Err("manager-command-unadmitted");
        }
        if Instant::now() >= end {
            return Err("manager-expired");
        }
        let mut child = Command::new(exe)
            .args(args)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "manager-spawn")?;
        let stdout = child.stdout.take().ok_or("manager-stdout")?;
        let stderr = child.stderr.take().ok_or("manager-stderr")?;
        for fd in [&stdout as &dyn std::os::fd::AsFd, &stderr as &dyn std::os::fd::AsFd] {
            let flags = rustix::fs::fcntl_getfl(fd).map_err(|_| "helper-flags")?;
            rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| "helper-nonblock")?;
        }
        collect(&mut child, end, cleanup, stdout, stderr)
    }
    pub fn show(unit: &str, own: &Ownership, end: Instant) -> Result<Unit> {
        if ![&own.lease, &own.watch, &own.work].contains(&&unit.to_string()) {
            return Err("unit-unowned");
        }
        let args=vec!["show".into(),unit.into(),"--property=Id,User,Group,DynamicUser,ActiveState,SubState,MainPID,InvocationID,ControlGroup,Restart,KillMode,SendSIGKILL,Delegate,RuntimeMaxUSec,TimeoutStopUSec,BindsTo,After,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,CPUQuotaPeriodUSec".into()];
        let raw = Self::command("/usr/bin/systemctl", &args, end, end)?;
        let parsed = parse_show(&raw)?;
        if parsed.get("Id")? != unit {
            return Err("manager-unit-id");
        }
        Ok(parsed)
    }
    fn start(
        &self,
        j: &Journal,
        unit: &str,
        props: Vec<String>,
        role: &str,
        runtime: Option<u64>,
        end: Instant,
    ) -> Result<()> {
        j.verify_durable()?;
        let mut args = vec!["--quiet".into(), format!("--unit={unit}")];
        args.extend(props.into_iter().map(|p| format!("--property={p}")));
        args.push(self.helper.to_str().ok_or("helper-path")?.into());
        args.push(role.into());
        if role != "identity-lease" {
            args.push(self.journal_dir.to_str().ok_or("journal-path")?.into());
            args.push(j.record.ownership.nonce.clone());
        }
        if role == "supervisor" {
            args.push(self.stage.to_str().ok_or("stage-path")?.into());
            args.push(j.record.execution_ns.to_string());
            args.push(j.record.total_end_ns()?.to_string());
        }
        Self::command("/usr/bin/systemd-run", &args, end, end)?;
        if let Some(runtime) = runtime {
            Self::bound_runtime(
                unit,
                &j.record.ownership.nonce,
                j.record.execution_ns,
                j.record.total_end_ns()?,
                runtime,
                end,
            )?;
        }
        Ok(())
    }
    pub fn create_lease(&self, j: &Journal, end: Instant) -> Result<Allocation> {
        let o = &j.record.ownership;
        if User::from_name(&o.username).map_err(|_| "nss-user")?.is_some()
            || Group::from_name(&o.username).map_err(|_| "nss-group")?.is_some()
        {
            return Err("static-name-collision");
        }
        self.start(
            j,
            &o.lease,
            vec![
                "Type=oneshot".into(),
                "MemoryMax=16M".into(),
                "MemorySwapMax=0".into(),
                "TasksMax=4".into(),
                "RemainAfterExit=yes".into(),
                "DynamicUser=yes".into(),
                format!("User={}", o.username),
                format!("Group={}", o.username),
                "Restart=no".into(),
                "NoNewPrivileges=yes".into(),
                "ProtectSystem=strict".into(),
                "ProtectHome=yes".into(),
                "PrivateTmp=yes".into(),
                "TimeoutStartSec=5s".into(),
                "TimeoutStopSec=1s".into(),
            ],
            "identity-lease",
            None,
            end,
        )?;
        loop {
            let p = Self::show(&o.lease, o, end)?;
            if p.get("ActiveState")? == "active" && p.get("SubState")? == "exited" {
                return Self::allocation(o, &p, end);
            }
            if ["inactive", "failed"].contains(&p.get("ActiveState")?) {
                return Err("lease-not-active");
            }
            if Instant::now() >= end {
                return Err("lease-deadline");
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    pub fn allocation(o: &Ownership, p: &Unit, end: Instant) -> Result<Allocation> {
        if p.get("User")? != o.username
            || p.get("Group")? != o.username
            || p.get("DynamicUser")? != "yes"
            || p.get("ActiveState")? != "active"
            || p.get("SubState")? != "exited"
        {
            return Err("lease-properties");
        }
        let args = vec![
            "call".into(),
            "org.freedesktop.systemd1".into(),
            "/org/freedesktop/systemd1".into(),
            "org.freedesktop.systemd1.Manager".into(),
            "LookupDynamicUserByName".into(),
            "s".into(),
            o.username.clone(),
        ];
        let raw = Self::command("/usr/bin/busctl", &args, end, end)?;
        let uid = parse_uid(&raw)?;
        if !(61184..=65519).contains(&uid) || uid == o.client_uid {
            return Err("allocation-client-or-range");
        }
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(format!("/run/systemd/dynamic-uid/{uid}"))
            .map_err(|_| "allocation-lock-open")?;
        let m = lock.metadata().map_err(|_| "allocation-stat")?;
        if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err("allocation-lock-owner");
        }
        let clone = lock.try_clone().map_err(|_| "allocation-clone")?;
        let mut name = String::new();
        clone
            .take(129)
            .read_to_string(&mut name)
            .map_err(|_| "allocation-name")?;
        if name.trim() != o.username {
            return Err("allocation-name");
        }
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => (),
            Ok(()) => {
                let _ = rustix::fs::flock(&lock, rustix::fs::FlockOperation::Unlock);
                return Err("allocation-not-leased");
            }
            Err(_) => return Err("allocation-lock"),
        }
        Ok(Allocation {
            uid,
            lock,
            invocation: p.get("InvocationID")?.into(),
        })
    }
    pub fn start_watch(&self, j: &Journal, end: Instant) -> Result<()> {
        let runtime = initial_runtime(
            j.record.execution_ns,
            j.record.total_end_ns()?,
            super::route::monotonic_ns()?,
        )? / 1000;
        self.start(
            j,
            &j.record.ownership.watch,
            vec![
                "Type=exec".into(),
                "MemoryMax=64M".into(),
                "MemorySwapMax=0".into(),
                "TasksMax=16".into(),
                "User=root".into(),
                "Restart=no".into(),
                "KillMode=control-group".into(),
                "SendSIGKILL=yes".into(),
                format!("RuntimeMaxSec={runtime}us"),
                "RuntimeRandomizedExtraSec=0".into(),
                "TimeoutStopSec=1s".into(),
                "TimeoutStopFailureMode=terminate".into(),
            ],
            "watchdog",
            Some(runtime),
            end,
        )
    }
    pub fn start_work(&self, j: &Journal, end: Instant, request: &super::broker_protocol::RequestHeader) -> Result<()> {
        let o = &j.record.ownership;
        let runtime = initial_runtime(
            j.record.execution_ns,
            j.record.total_end_ns()?,
            super::route::monotonic_ns()?,
        )? / 1000;
        self.start(
            j,
            &o.work,
            vec![
                "Type=exec".into(),
                "DynamicUser=yes".into(),
                format!("User={}", o.username),
                format!("Group={}", o.username),
                "Restart=no".into(),
                "KillMode=control-group".into(),
                "SendSIGKILL=yes".into(),
                "Delegate=no".into(),
                format!("BindsTo={}", o.watch),
                format!("After={}", o.watch),
                format!("RuntimeMaxSec={runtime}us"),
                "RuntimeRandomizedExtraSec=0".into(),
                "TimeoutStopSec=1s".into(),
                "TimeoutStopFailureMode=terminate".into(),
                format!("MemoryMax={}", request.memory_bytes),
                "MemorySwapMax=0".into(),
                format!("TasksMax={}", request.pids),
                format!("Slice=klrenderer{}.slice", o.nonce),
                "CPUQuota=100%".into(),
                "CPUQuotaPeriodSec=100ms".into(),
                "NoNewPrivileges=yes".into(),
                "ProtectSystem=strict".into(),
                "ProtectHome=yes".into(),
                "PrivateTmp=yes".into(),
            ],
            "supervisor",
            Some(runtime),
            end,
        )
    }
    pub fn verify_watch(o: &Ownership, work: &Unit, end: Instant) -> Result<HeldPid> {
        let w = Self::show(&o.watch, o, end)?;
        if w.get("ActiveState")? != "active"
            || w.get("SubState")? != "running"
            || w.get("User")? != "root"
            || w.get("Restart")? != "no"
            || !work.get("BindsTo")?.split_whitespace().any(|n| n == o.watch)
            || !work.get("After")?.split_whitespace().any(|n| n == o.watch)
            || work.get("KillMode")? != "control-group"
            || work.get("SendSIGKILL")? != "yes"
            || work.get("Delegate")? != "no"
        {
            return Err("watchdog-properties");
        }
        let runtime = Self::duration_property(&o.work, "RuntimeMaxUSec", end)?;
        let watch_runtime = Self::duration_property(&o.watch, "RuntimeMaxUSec", end)?;
        let stop = Self::duration_property(&o.work, "TimeoutStopUSec", end)?;
        if runtime == 0
            || runtime > 130_000_000
            || watch_runtime < runtime
            || watch_runtime > 130_000_000
            || stop == 0
            || stop > 10_000_000
        {
            return Err("manager-runtime-backstop");
        }
        let held = HeldPid::open(w.get("MainPID")?.parse().map_err(|_| "watch-pid")?)?;
        super::audit::credentials(held.pid, 0)?;
        Ok(held)
    }
    fn duration_property(unit: &str, property: &str, end: Instant) -> Result<u64> {
        if !["RuntimeMaxUSec", "TimeoutStopUSec", "RuntimeRandomizedExtraUSec"].contains(&property) {
            return Err("manager-property-outside-scope");
        }
        let mut escaped = String::new();
        for b in unit.bytes() {
            if b.is_ascii_alphanumeric() {
                escaped.push(b as char);
            } else {
                escaped.push('_');
                escaped.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
                escaped.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
            }
        }
        let args = vec![
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            format!("/org/freedesktop/systemd1/unit/{escaped}"),
            "org.freedesktop.systemd1.Service".into(),
            property.into(),
        ];
        let raw = Self::command("/usr/bin/busctl", &args, end, end)?;
        parse_duration(&raw)
    }
    pub fn terminate(j: &Journal, end: Instant) -> Result<()> {
        let end = if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            end.min(super::route::instant(j.record.total_end_ns()?)?)
        } else {
            end
        };
        // Existing durable ownership is enough even if a new cleanup write failed.
        j.record.ownership.validate()?;
        let reserve = reserve(end.saturating_duration_since(Instant::now()));
        let operation = end.checked_sub(reserve).unwrap_or(end);
        let o = &j.record.ownership;
        let _ = Self::command(
            "/usr/bin/systemctl",
            &[
                "kill".into(),
                "--kill-whom=all".into(),
                "--signal=SIGKILL".into(),
                o.work.clone(),
            ],
            operation,
            end,
        );
        Self::command("/usr/bin/systemctl", &["stop".into(), o.work.clone()], operation, end)?;
        Ok(())
    }
    pub fn stop_watch(j: &Journal, end: Instant) -> Result<()> {
        let end = if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            end.min(super::route::instant(j.record.total_end_ns()?)?)
        } else {
            end
        };
        Self::command(
            "/usr/bin/systemctl",
            &["stop".into(), j.record.ownership.watch.clone()],
            end,
            end,
        )?;
        let p = Self::show(&j.record.ownership.watch, &j.record.ownership, end)?;
        if !["inactive", "failed"].contains(&p.get("ActiveState")?) {
            return Err("watch-release-ambiguous");
        }
        Ok(())
    }
    pub fn release(j: &Journal, end: Instant) -> Result<()> {
        let end = if j.record.schema == super::broker_protocol::CONTROLLED_SCHEMA {
            end.min(super::route::instant(j.record.total_end_ns()?)?)
        } else {
            end
        };
        if j.record.phase != "cleanup-proved" {
            return Err("release-unproved");
        }
        Self::command(
            "/usr/bin/systemctl",
            &["stop".into(), j.record.ownership.lease.clone()],
            end,
            end,
        )?;
        let p = Self::show(&j.record.ownership.lease, &j.record.ownership, end)?;
        if p.get("ActiveState")? != "inactive" {
            return Err("lease-release-ambiguous");
        }
        Ok(())
    }
}
pub fn parse_show(raw: &[u8]) -> Result<Unit> {
    if raw.len() > 65536 {
        return Err("show-budget");
    }
    let s = std::str::from_utf8(raw).map_err(|_| "show-utf8")?;
    let mut values = BTreeMap::new();
    for l in s.lines() {
        let (k, v) = l.split_once('=').ok_or("show-schema")?;
        if values.insert(k.into(), v.into()).is_some() {
            return Err("show-duplicate");
        }
    }
    Ok(Unit { values })
}
fn parse_uid(raw: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(raw).map_err(|_| "uid-utf8")?;
    let v: Vec<_> = s.split_whitespace().collect();
    if v.len() != 2 || v[0] != "u" {
        return Err("uid-schema");
    }
    v[1].parse().map_err(|_| "uid-number")
}
fn parse_duration(raw: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(raw).map_err(|_| "duration-encoding")?;
    let v: Vec<_> = s.split_whitespace().collect();
    if v.len() != 2 || v[0] != "t" {
        return Err("duration-signature");
    }
    v[1].parse().map_err(|_| "duration-value")
}

#[cfg(test)]
mod absolute_service_timer_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn activation_relative_runtime_and_stop_allowance_fit_original_absolute_end() -> TestResult {
        let execution = 30_000_000_000;
        let total = 40_000_000_000;
        assert_eq!(initial_runtime(execution, total, 20_000_000_000)?, 13_749_999_000);
        assert_eq!(
            initial_runtime(execution, total, execution),
            Err("service-execution-expired")
        );
        assert_eq!(
            initial_runtime(execution, total, execution + 1),
            Err("service-execution-expired")
        );
        let active = 5_000_000;
        let runtime = activated_runtime(execution, total, active)?;
        assert_eq!(active * 1000 + runtime + MANAGER_TAIL_NS, total);
        assert_eq!(activated_runtime(execution, total + 60_000_000_000, active)?, runtime);
        assert!(activated_runtime(execution, total, 0).is_err());
        assert!(activated_runtime(execution, total, total / 1000).is_err());
        assert!(activated_runtime(execution, total, u64::MAX).is_err());
        assert!(initial_runtime(execution, execution, execution).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod fixed_guard_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn creation_guard_accepts_exact_activation_boundary_and_refuses_later_without_rearm() -> TestResult {
        let execution = 40_000_000_000;
        let total = 50_000_000_000;
        let sampled = 30_000_000_000;
        let guard = initial_runtime(execution, total, sampled)? / 1000;
        let exact = (sampled + ACTIVATION_RESERVE_NS) / 1000;
        admit_runtime_guard(guard, activated_runtime(execution, total, exact)?)?;
        assert!(admit_runtime_guard(guard, activated_runtime(execution, total, exact + 1)?).is_err());
        assert!(admit_runtime_guard(0, u64::MAX).is_err());
        assert!(admit_runtime_guard(u64::MAX, u64::MAX).is_err());
        assert!(initial_runtime(execution, total, execution).is_err());
        assert_eq!(
            initial_runtime(execution, total + 60_000_000_000, sampled)? / 1000,
            guard
        );
        Ok(())
    }
}

#[cfg(test)]
mod complete_manager_tail_tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn runtime_jitter_and_stop_final_term_kill_waits_fit_original_end_with_rounding() -> TestResult {
        // Independent installed-policy expectation: runtime timer 250ms, then four
        // STOP/FINAL TERM/KILL waits of 1s each plus 250ms accuracy on every timer.
        let total = 30_000_000_000;
        let execution = 20_000_000_000;
        let activated_us = 1_000_000;
        let runtime_ns = activated_runtime(execution, total, activated_us)?;
        assert_eq!(runtime_ns, 23_749_999_000);
        let guard_us = runtime_ns / 1000;
        let latest_runtime = activated_us * 1000 + 999 + guard_us * 1000 + 250_000_000;
        let after_stop_term = latest_runtime + 1_000_000_000 + 250_000_000;
        let after_stop_kill = after_stop_term + 1_000_000_000 + 250_000_000;
        let after_final_term = after_stop_kill + 1_000_000_000 + 250_000_000;
        let after_final_kill = after_final_term + 1_000_000_000 + 250_000_000;
        assert_eq!(after_final_kill, total - 1);
        admit_runtime_guard(guard_us, runtime_ns)?;
        assert!(admit_runtime_guard(guard_us + 1, runtime_ns).is_err());
        assert!(admit_runtime_guard(guard_us, activated_runtime(execution, total, activated_us + 1)?).is_err());
        // The independently reviewed counterexample already exceeds total at STOP KILL,
        // before accounting for FINAL waits or timestamp rounding.
        let previous_guard = 28_000_000_000;
        assert!(1_000_000_000 + previous_guard + 250_000_000 + 2 * (1_000_000_000 + 250_000_000) > total);
        Ok(())
    }
}
