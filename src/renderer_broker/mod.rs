//! Privileged helper entry point for an explicitly provisioned system broker.
//! Configuration must be root owned, immutable to ordinary clients and independently reviewed.
//! This module neither installs the broker nor grants runtime admission.
mod audit;
pub(super) mod authority;
mod bubblewrap_probe;
mod cold_boot;
mod journal;
mod manager;
pub(super) mod route;
mod tracer;
mod transport;
use super::broker_protocol;
type Result<T> = std::result::Result<T, &'static str>;

/// Run one closed, explicitly provisioned helper role. Errors expose fixed categories only.
/// # Errors
/// Refuses non-root administration, unknown roles and unauthenticated configuration.
pub fn run_helper(arguments: &[String]) -> std::result::Result<(), &'static str> {
    use std::path::Path;
    if nix::unistd::getuid().as_raw() == 0 && nix::unistd::geteuid().as_raw() == 0 {
        nix::unistd::setgroups(&[]).map_err(|_| "administrative-supplementary-groups")?;
    }
    match arguments.get(1).map(String::as_str) {
        Some("identity-lease") if arguments.len() == 2 && nix::unistd::getuid().as_raw() != 0 => Ok(()),
        Some("broker") if arguments.len() == 4 => transport::serve(Path::new(&arguments[2]), Path::new(&arguments[3])),
        Some("controller") if arguments.len() == 3 => transport::controller(Path::new(&arguments[2])),
        Some("watchdog") if arguments.len() == 4 => route::watchdog(Path::new(&arguments[2]), &arguments[3]),
        Some("supervisor") if arguments.len() == 7 => route::supervisor(
            &arguments[3],
            Path::new(&arguments[4]),
            arguments[5].parse().map_err(|_| "deadline")?,
            arguments[6].parse().map_err(|_| "total-deadline")?,
        ),
        Some("recover") if arguments.len() == 4 => route::recover(Path::new(&arguments[2]), &arguments[3]),
        _ => Err("closed-helper-role"),
    }
}

/// Run the static gate. Its permit and descriptor sweep never replace the root audit.
#[cfg(target_os = "linux")]
pub fn run_gate() -> ! {
    use std::{
        fs::{self, File},
        io::Read,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let attempt = || -> std::result::Result<(), ()> {
        let arguments: Vec<_> = std::env::args().take(4).collect();
        if arguments.len() != 3
            || arguments[1].len() != 32
            || !arguments[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || arguments[2].len() > 65536
        {
            return Err(());
        }
        let plan: bubblewrap_probe::GatePlan = serde_json::from_str(&arguments[2]).map_err(|_| ())?;
        let expected = format!("KLRENDER1:{}\n", arguments[1]);
        let mut permit = Vec::new();
        std::io::stdin()
            .take(u64::try_from(expected.len() + 1).map_err(|_| ())?)
            .read_to_end(&mut permit)
            .map_err(|_| ())?;
        if permit != expected.as_bytes() {
            return Err(());
        }
        fs::remove_file("/scratch/gate").map_err(|_| ())?;
        let null = File::open("/dev/null").map_err(|_| ())?;
        close_fds::set_fds_cloexec(3, &[]);
        let _error = Command::new("/renderer")
            .args(plan.argv)
            .env_clear()
            .envs(plan.env)
            .current_dir("/input")
            .stdin(Stdio::from(null))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .exec();
        Err(())
    };
    let _result = attempt();
    std::process::exit(75)
}
