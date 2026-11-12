//! Private timing transport and safe ordinary-Cargo relay for the six-module self-test.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const MODULES: [&str; 6] = [
    "test_kind_runtime",
    "test_owned_qemu",
    "test_owned_host_view",
    "test_owned_guest_stage",
    "test_owned_guest_receiver",
    "test_owned_guest_rootful",
];
const MAX_BYTES: u64 = 512 * 1024;
const MAX_ROWS: usize = 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

fn invalid() -> io::Error {
    io::Error::other("self-test timing report invalid or incomplete")
}

struct Transport {
    directory: PathBuf,
    path: PathBuf,
}

impl Transport {
    fn new() -> io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "kubernetes-lens-selftest-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&directory)?;
        let transport = Self {
            path: directory.join("timings.json"),
            directory,
        };
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&transport.path)?;
        Ok(transport)
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }

    fn remove(&self) -> io::Result<()> {
        fs::remove_file(&self.path)?;
        fs::remove_dir(&self.directory)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Module {
    id: String,
    cases: u32,
    timed: u32,
    seconds: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema: u8,
    expected: u32,
    seen: u32,
    omitted: u32,
    untimed: u32,
    clock_errors: u32,
    elapsed: Option<f64>,
    complete: bool,
    modules: Vec<Module>,
    cases: Vec<(String, Option<f64>)>,
}

fn duration(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

fn identity(value: &str) -> bool {
    value.len() <= 192
        && value.split('.').count() >= 3
        && value.split('.').all(|part| {
            let mut chars = part.bytes();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

fn render(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if value.get("elapsed").is_none() {
        return Err(invalid());
    }
    let payload: Payload = serde_json::from_value(value).map_err(|_| invalid())?;
    if payload.schema != 1
        || payload.modules.len() != MODULES.len()
        || payload.cases.len() > MAX_ROWS
        || u64::from(payload.seen) != payload.cases.len() as u64 + u64::from(payload.omitted)
        || payload.untimed > payload.seen
        || payload.clock_errors > payload.untimed
        || payload.elapsed.is_some_and(|value| !duration(value))
        || payload.complete
            != (payload.omitted == 0
                && payload.clock_errors == 0
                && payload.seen == payload.expected
                && payload.elapsed.is_some())
    {
        return Err(invalid());
    }
    let mut counts = [0_u32; 6];
    let mut timed = [0_u32; 6];
    let mut sums = [0.0_f64; 6];
    let mut unique = BTreeSet::new();
    let mut output = String::new();
    for (id, seconds) in &payload.cases {
        if !identity(id) || !unique.insert(id) {
            return Err(invalid());
        }
        let index = MODULES
            .iter()
            .position(|module| id.starts_with(&format!("{module}.")))
            .ok_or_else(invalid)?;
        counts[index] += 1;
        let observed = if let Some(seconds) = seconds {
            if !duration(*seconds) {
                return Err(invalid());
            }
            timed[index] += 1;
            sums[index] += seconds;
            format!("{seconds:.6e}")
        } else {
            "untimed".to_owned()
        };
        writeln!(output, "timing case={id} seconds={observed}").map_err(|_| invalid())?;
    }
    let mut seen = 0_u64;
    let mut total_timed = 0_u64;
    for (index, module) in payload.modules.iter().enumerate() {
        if module.id != MODULES[index]
            || module.timed > module.cases
            || !duration(module.seconds)
            || counts[index] > module.cases
            || timed[index] > module.timed
            || (payload.omitted == 0
                && (counts[index] != module.cases
                    || timed[index] != module.timed
                    || (sums[index] - module.seconds).abs() > 0.000_001))
        {
            return Err(invalid());
        }
        seen += u64::from(module.cases);
        total_timed += u64::from(module.timed);
        writeln!(
            output,
            "timing module={} cases={} timed={} case_sum_seconds={:.6e}",
            module.id, module.cases, module.timed, module.seconds
        )
        .map_err(|_| invalid())?;
    }
    // Unsupported identity metadata can be omitted without inventing a module label.
    // Only omitted cases may be unattributed; complete reports retain exact equalities.
    let unattributed = u64::from(payload.seen).checked_sub(seen).ok_or_else(invalid)?;
    let observed_timed = u64::from(payload.seen - payload.untimed);
    if unattributed > u64::from(payload.omitted)
        || total_timed > observed_timed
        || observed_timed - total_timed > unattributed
    {
        return Err(invalid());
    }
    let elapsed = payload
        .elapsed
        .map_or_else(|| "unavailable".to_owned(), |v| format!("{v:.6e}"));
    writeln!(output,
        "timing overall elapsed_seconds={elapsed} seen={} expected={} omitted={} untimed={} clock_errors={} unattributed={unattributed} complete={}",
        payload.seen, payload.expected, payload.omitted, payload.untimed, payload.clock_errors, payload.complete
    ).map_err(|_| invalid())?;
    if output.len() > 320 * 1024 {
        return Err(invalid());
    }
    Ok(output)
}

pub(super) fn run(command: &mut Command) -> io::Result<()> {
    let transport = Transport::new()?;
    let outcome = command
        .env("KUBERNETES_LENS_SELFTEST_TIMINGS", &transport.path)
        .output()?;
    // Child stdout/stderr never leave this capture. Only validated timing records are relayed.
    let rendered = transport.read().and_then(|bytes| render(&bytes));
    let cleanup = transport.remove();
    // Direct Write survives ordinary successful libtest capture; no global --nocapture.
    let unavailable = "timing report=invalid-or-incomplete\n";
    io::stdout()
        .lock()
        .write_all(rendered.as_deref().unwrap_or(unavailable).as_bytes())?;
    if !outcome.status.success() {
        return Err(io::Error::other("external kind runtime pure contracts failed"));
    }
    cleanup.map_err(|_| invalid())?;
    rendered.map(|_| ()).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn sample() -> Value {
        json!({"schema":1,"expected":2,"seen":2,"omitted":0,"untimed":0,"clock_errors":0,
            "elapsed":1.0,"complete":true,
            "modules":MODULES.iter().enumerate().map(|(i,id)| json!({"id":id,
                "cases":if i==0 {2} else {0},"timed":if i==0 {2} else {0},
                "seconds":if i==0 {0.75} else {0.0}})).collect::<Vec<_>>(),
            "cases":[["test_kind_runtime.Fixture.test_first",0.25],
                     ["test_kind_runtime.Fixture.test_second",0.5]]})
    }

    #[test]
    fn authored_sums_and_private_transport_cleanup() -> io::Result<()> {
        let output = render(&serde_json::to_vec(&sample())?)?;
        assert!(output.contains("case_sum_seconds=7.500000e-1"));
        assert!(output.contains("seen=2 expected=2 omitted=0 untimed=0"));
        let mut omitted_identity = sample();
        omitted_identity["omitted"] = json!(1);
        omitted_identity["complete"] = json!(false);
        omitted_identity["cases"] = json!([["test_kind_runtime.Fixture.test_second", 0.5]]);
        omitted_identity["modules"][0]["cases"] = json!(1);
        omitted_identity["modules"][0]["timed"] = json!(1);
        omitted_identity["modules"][0]["seconds"] = json!(0.5);
        let incomplete = render(&serde_json::to_vec(&omitted_identity)?)?;
        assert!(incomplete.contains("unattributed=1 complete=false"));
        for clock_errors in [0, 1] {
            omitted_identity["untimed"] = json!(1);
            omitted_identity["clock_errors"] = json!(clock_errors);
            let untimed = render(&serde_json::to_vec(&omitted_identity)?)?;
            assert!(untimed.contains("untimed=1"));
            assert!(untimed.contains("unattributed=1 complete=false"));
        }
        omitted_identity["untimed"] = json!(2);
        assert!(render(&serde_json::to_vec(&omitted_identity)?).is_err());

        let transport = Transport::new()?;
        let directory = transport.directory.clone();
        fs::write(
            &transport.path,
            vec![b'x'; usize::try_from(MAX_BYTES + 1).map_err(|_| invalid())?],
        )?;
        assert!(transport.read().is_err());
        transport.remove()?;
        assert!(!directory.exists());
        Ok(())
    }

    #[test]
    fn malformed_records_and_bounds_refuse() -> io::Result<()> {
        let mut invalid_values = Vec::new();
        for (field, value) in [
            ("schema", json!(2)),
            ("seen", json!(true)),
            ("omitted", json!(1)),
            ("complete", json!(false)),
            ("elapsed", json!(-1)),
            ("unexpected", json!(1)),
        ] {
            let mut value_with_error = sample();
            value_with_error[field] = value;
            invalid_values.push(value_with_error);
        }
        let mut missing = sample();
        if let Some(object) = missing.as_object_mut() {
            object.remove("elapsed");
        }
        invalid_values.push(missing);
        let mut unsafe_id = sample();
        unsafe_id["cases"][0][0] = json!("test_kind_runtime.::error::private");
        invalid_values.push(unsafe_id);
        let mut duplicate = sample();
        duplicate["cases"][1] = duplicate["cases"][0].clone();
        invalid_values.push(duplicate);
        let mut over_rows = sample();
        over_rows["cases"] = json!(vec![json!(["test_kind_runtime.Example.test_case", 0.0]); MAX_ROWS + 1]);
        invalid_values.push(over_rows);
        let mut over_id = sample();
        over_id["cases"][0][0] = json!("a".repeat(193));
        invalid_values.push(over_id);
        let mut negative = sample();
        negative["cases"][0][1] = json!(-0.25);
        invalid_values.push(negative);
        let mut nonfinite = sample();
        nonfinite["elapsed"] = json!("NaN");
        invalid_values.push(nonfinite);
        let mut mismatch = sample();
        mismatch["modules"][0]["seconds"] = json!(0.9);
        invalid_values.push(mismatch);
        for value in invalid_values {
            assert!(render(&serde_json::to_vec(&value)?).is_err());
        }
        assert!(render(&vec![b' '; usize::try_from(MAX_BYTES + 1).map_err(|_| invalid())?]).is_err());
        Ok(())
    }

    const FIXTURE: &str = r"
import sys, unittest
sys.path.insert(0, sys.argv[1])
import selftest_timings
class Fixture(unittest.TestCase):
    def test_safe(self):
        print('::error::raw-timing-canary')
        self.assertEqual(sys.argv[2], 'pass')
Fixture.__module__ = 'test_kind_runtime'
raise SystemExit(selftest_timings.run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Fixture)))
";

    #[test]
    fn visibility_fixture() -> io::Result<()> {
        let mode = std::env::var("KUBERNETES_LENS_TIMING_FIXTURE").unwrap_or_else(|_| "pass".to_owned());
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg(FIXTURE)
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fixtures"))
            .arg(mode)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("PYTHONDONTWRITEBYTECODE", "1");
        let result = run(&mut command);
        let mut verified = false;
        for (key, value) in command.get_envs() {
            if key == "KUBERNETES_LENS_SELFTEST_TIMINGS" {
                let path = PathBuf::from(value.ok_or_else(invalid)?);
                assert!(!path.exists());
                assert!(!path.parent().ok_or_else(invalid)?.exists());
                verified = true;
            }
        }
        assert!(verified);
        io::stdout().lock().write_all(b"timing fixture_cleanup=complete\n")?;
        result
    }

    #[test]
    fn successful_and_failing_normal_capture_only_expose_timings() -> io::Result<()> {
        for mode in ["pass", "fail"] {
            let output = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "selftest_timings::tests::visibility_fixture",
                    "--test-threads=1",
                ])
                .env("KUBERNETES_LENS_TIMING_FIXTURE", mode)
                .output()?;
            assert_eq!(output.status.success(), mode == "pass");
            let logs = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(logs.contains("timing case=test_kind_runtime.Fixture.test_safe"));
            assert!(logs.contains("timing module=test_owned_guest_rootful"));
            assert!(!logs.contains("raw-timing-canary"));
            assert!(logs.contains("timing fixture_cleanup=complete"));
        }
        Ok(())
    }
}
