//! Safe launch/FD mapping prerequisite source; primary integrates the same-thread tracer.
//! Build dependencies: exact audited command-fds 0.3.3. No Cargo adoption here.
#![forbid(unsafe_code)]
use command_fds::{CommandFdExt, FdMapping};
use nix::unistd::{geteuid, getuid};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialStatus {
    #[serde(rename = "child-pid")]
    pub child_pid: i32,
    #[serde(rename = "cgroup-namespace")]
    pub cgroup_namespace: Option<u64>,
    #[serde(rename = "ipc-namespace")]
    pub ipc_namespace: Option<u64>,
    #[serde(rename = "mnt-namespace")]
    pub mnt_namespace: Option<u64>,
    #[serde(rename = "net-namespace")]
    pub net_namespace: Option<u64>,
    #[serde(rename = "pid-namespace")]
    pub pid_namespace: Option<u64>,
    #[serde(rename = "uts-namespace")]
    pub uts_namespace: Option<u64>,
}
fn read_status_line(socket: &mut UnixStream, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() < 65536 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| std::io::Error::other("original-status-deadline"))?;
        socket.set_read_timeout(Some(remaining))?;
        let mut byte = [0u8; 1];
        if socket.read(&mut byte)? != 1 {
            return Err(std::io::Error::other("status-eof"));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
    Err(std::io::Error::other("status-size"))
}

/// Construct ONLY in the root broker, never in the allocated supervisor.
pub struct RootPermit {
    sender: UnixStream,
    gate_half: Option<OwnedFd>,
}
impl RootPermit {
    pub fn new() -> std::io::Result<Self> {
        if getuid().as_raw() != 0 || geteuid().as_raw() != 0 {
            return Err(std::io::Error::other("root-permit-creator-required"));
        }
        let (sender, gate) = UnixStream::pair()?;
        Ok(Self {
            sender,
            gate_half: Some(OwnedFd::from(gate)),
        })
    }
    /// Transfer ONLY this half via bounded authenticated `SCM_RIGHTS` to the exact supervisor PID.
    pub fn gate_for_transfer(&mut self) -> std::io::Result<OwnedFd> {
        self.gate_half
            .take()
            .ok_or_else(|| std::io::Error::other("permit-half-already-transferred"))
    }
    /// Root sends only after trace armed, independent setup, watchdog and original deadline checks.
    pub fn send_once(mut self, nonce: &str, deadline: Instant) -> std::io::Result<()> {
        self.sender.set_write_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| std::io::Error::other("permit-deadline"))?,
        ))?;
        if self.gate_half.is_some()
            || nonce.len() != 32
            || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(std::io::Error::other("permit-not-transferred-or-nonce"));
        }
        self.sender.write_all(format!("KLRENDER1:{nonce}\n").as_bytes())?;
        self.sender.shutdown(Shutdown::Write)
    }
}

pub struct HeldLaunch {
    pub real_parent: Child,
    pub status_root: UnixStream,
}
impl HeldLaunch {
    pub fn initial_status(&mut self, deadline: Instant) -> std::io::Result<InitialStatus> {
        let line = read_status_line(&mut self.status_root, deadline)?;
        let status: InitialStatus =
            serde_json::from_slice(&line).map_err(|_| std::io::Error::other("status-schema"))?;
        if status.child_pid <= 1
            || [
                status.cgroup_namespace,
                status.ipc_namespace,
                status.mnt_namespace,
                status.net_namespace,
                status.pid_namespace,
                status.uts_namespace,
            ]
            .iter()
            .any(|v| v.is_none() || *v == Some(0))
        {
            return Err(std::io::Error::other("status-identity-or-namespace"));
        }
        Ok(status)
    }
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatePlan {
    pub argv: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub input: std::path::PathBuf,
    pub plan: GatePlan,
}
impl LaunchSpec {
    pub fn encoded(&self) -> super::Result<String> {
        serde_json::to_string(&self.plan).map_err(|_| "gate-plan")
    }
    pub fn argv(&self, nonce: &str) -> super::Result<Vec<String>> {
        let mut args: Vec<String> = [
            "--unshare-all",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
            "--uid",
            "0",
            "--gid",
            "0",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--tmpfs",
            "/",
            "--size",
            "67108864",
            "--tmpfs",
            "/scratch",
            "--dir",
            "/scratch/packages",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        args.push(self.input.to_str().ok_or("input-path")?.into());
        args.extend(
            [
                "/input",
                "--perms",
                "0500",
                "--file",
                "3",
                "/scratch/gate",
                "--perms",
                "0500",
                "--ro-bind-data",
                "5",
                "/renderer",
                "--remount-ro",
                "/",
                "--json-status-fd",
                "4",
                "--chdir",
                "/input",
                "/scratch/gate",
                nonce,
            ]
            .into_iter()
            .map(String::from),
        );
        args.push(self.encoded()?);
        Ok(args)
    }
}
pub fn launch_with_outputs(
    gate: File,
    renderer: File,
    gate_half_from_root: OwnedFd,
    nonce: &str,
    spec: &LaunchSpec,
    output: OwnedFd,
    error: OwnedFd,
) -> std::io::Result<HeldLaunch> {
    if nonce.len() != 32
        || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || getuid().as_raw() == 0
        || geteuid().as_raw() == 0
    {
        return Err(std::io::Error::other("dedicated-supervisor-required"));
    }
    let (status_root, status_child) = UnixStream::pair()?;
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .args(spec.argv(nonce).map_err(std::io::Error::other)?)
        .env_clear()
        .stdin(Stdio::from(gate_half_from_root))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(error));
    command
        .fd_mappings(vec![
            FdMapping {
                parent_fd: OwnedFd::from(gate),
                child_fd: 3,
            },
            FdMapping {
                parent_fd: OwnedFd::from(status_child),
                child_fd: 4,
            },
            FdMapping {
                parent_fd: OwnedFd::from(renderer),
                child_fd: 5,
            },
        ])
        .map_err(|_| std::io::Error::other("fd-map-collision"))?;
    let real_parent = command.spawn()?;
    Ok(HeldLaunch {
        real_parent,
        status_root,
    })
}
// Gate/renderer must be separately reviewed static ELF files. A loader/library bind is not added.
// Status is independently bounded/decoded before selecting the held host child PID.
// No permit occurs here; dropping root half yields fail-closed gate EOF.
// Caller must invoke owned cleanup on any abandoned HeldLaunch; Child drop does NOT kill.
