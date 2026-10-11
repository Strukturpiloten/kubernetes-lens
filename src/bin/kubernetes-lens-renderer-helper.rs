//! Explicit system broker entry point; provisioning and runtime admission are external.
#![forbid(unsafe_code)]
fn main() {
    #[cfg(target_os = "linux")]
    if kubernetes_lens::formats::renderer_broker::run_helper(&std::env::args().take(8).collect::<Vec<_>>()).is_ok() {
        return;
    }
    eprintln!("renderer helper unavailable or failed");
    std::process::exit(75);
}
