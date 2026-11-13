//! Concurrency invariants against production SMTP and filesystem storage.

mod certificate;
#[path = "../common/mod.rs"]
#[allow(dead_code)]
mod common;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod crash;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod crash_trace;
mod credentials;
mod dkim_rotation;
mod quota;
mod removal;
mod submissions;
mod support;
#[path = "../smtp/hostile_smtp/harness.rs"]
#[allow(dead_code)]
mod wire;
