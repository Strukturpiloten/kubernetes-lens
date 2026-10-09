//! Cargo entry point for the repository's independently exercised Python policy suite.

use std::error::Error;
use std::process::Command;

#[test]
fn repository_policy() -> Result<(), Box<dyn Error>> {
    let status = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/test-repository-policy.py"
        ))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("repository policy suite failed with {status}").into())
    }
}
