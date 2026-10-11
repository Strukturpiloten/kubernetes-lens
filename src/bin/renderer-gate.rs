//! Single-threaded renderer gate; a root exec-stop audit remains mandatory.
#![forbid(unsafe_code)]
fn main() {
    #[cfg(target_os = "linux")]
    kubernetes_lens::formats::renderer_broker::run_gate();
    #[cfg(not(target_os = "linux"))]
    std::process::exit(75);
}
