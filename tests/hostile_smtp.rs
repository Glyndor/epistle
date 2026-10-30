//! Hostile clients against the real in-process SMTP listener over loopback TCP.
//! No external server or environment variables are required.
//! Run locally with `cargo test --locked --test hostile_smtp -- --test-threads=2`.
//! GitHub Actions enables this target only in the path-filtered E2E step via
//! `HOSTILE_SMTP_RUN=1`; other workflows can still compile the target.

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

#[path = "hostile_smtp/abuse.rs"]
mod abuse;
#[path = "hostile_smtp/framing.rs"]
mod framing;
#[path = "hostile_smtp/harness.rs"]
mod harness;
#[path = "hostile_smtp/scram.rs"]
mod scram;
#[path = "hostile_smtp/tls.rs"]
mod tls;

fn enabled() -> bool {
	if std::env::var_os("GITHUB_ACTIONS").is_some()
		&& std::env::var("HOSTILE_SMTP_RUN").as_deref() != Ok("1")
	{
		eprintln!("skipping hostile SMTP: enabled by the path-filtered E2E step");
		return false;
	}
	true
}
