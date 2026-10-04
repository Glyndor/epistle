//! `epistle local` restart contract: a second run against a
//! directory that already has a `mail.toml` must advertise the
//! persisted ports, not the freshly-requested base. This pins
//! that `run` passes the loaded config to the banner
//! (`banner_endpoints(&prepared.config)`), not the requested
//! base: a future edit that pulls the port list from the
//! requested `--port-base Q` would make the banner lie about
//! what the runtime actually bound, and the SMTP greeting on
//! the Q-relative port would never arrive.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

mod common;
use common::{Child, is_eaddrinuse, pick_port_base, read_banner, redact_password, wait_for_bind};

/// Run the harness against a directory twice, with different
/// port bases, and assert the second run advertises the first
/// run's ports. The retry policy is gated on the child's
/// `EADDRINUSE` text and uses a fresh tempdir per attempt, same
/// as the primary test.
#[test]
fn local_mode_restart_keeps_the_persisted_ports() {
	let mut last_err: Option<String> = None;
	for attempt in 0..5 {
		match run_restart_pair() {
			Ok(()) => return,
			Err(message) => {
				if attempt == 4 || !is_eaddrinuse(&message) {
					panic!("{message}");
				}
				last_err = Some(message);
				std::thread::sleep(Duration::from_millis(100));
			}
		}
	}
	if let Some(err) = last_err {
		panic!("all retries failed: {err}");
	}
}

/// Run the first/second pair in a fresh dir. Returns the first
/// failure with the phase and redacted stderr attached.
fn run_restart_pair() -> Result<(), String> {
	let dir = tempfile::tempdir().expect("tempdir");
	let base_p = pick_port_base();
	let base_q = base_p.wrapping_add(1_000);
	// First run: lay out the directory and bind P. We do not
	// need its banner, only that the child reached the bind
	// step and left the marker on disk.
	run_until_listening_and_kill(dir.path(), base_p)?;
	// Second run: same directory, but the operator requested
	// base Q. The runtime must still bind P (the persisted
	// base) and the banner must name P's six ports.
	let port_base_q = base_q.to_string();
	let dir_str = dir.path().to_str().expect("utf-8").to_owned();
	let args = [
		"local",
		"--dir",
		dir_str.as_str(),
		"--port-base",
		port_base_q.as_str(),
	];
	let mut child = Child::spawn(&args, dir.path());
	let bind_deadline = Instant::now() + Duration::from_secs(10);
	// The persisted P-relative SMTP port is the one the
	// runtime will actually bind; wait for it.
	let smtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_p + 25);
	let mut smtp = wait_for_bind(
		smtp_addr,
		bind_deadline,
		"waiting for second-run SMTP port (the persisted P)",
		&mut child,
	)?;
	let banner = read_banner(
		&mut smtp,
		Instant::now() + Duration::from_secs(2),
		"reading the second-run SMTP banner",
	)?;
	drop(smtp);
	if !banner.starts_with(b"220 ") {
		let (_stdout, stderr) = child.kill_and_drain(
			Instant::now() + Duration::from_secs(2),
			"reading the second-run SMTP banner",
		)?;
		return Err(format!(
			"reading the second-run SMTP banner: greeting does not start with `220 `: {:?}\nstderr:\n{}",
			String::from_utf8_lossy(&banner),
			redact_password(&stderr)
		));
	}
	let (_stdout, stderr) = child.kill_and_drain(
		Instant::now() + Duration::from_secs(2),
		"killing second run",
	)?;
	let stderr_text = redact_password(&stderr);
	// Every endpoint line in the second run's banner must
	// name a P-relative port, never a Q-relative one. The
	// shape is `listening: 127.0.0.1:<port> (<kind>)`.
	for (kind, offset) in [
		("smtp", 25u16),
		("submission", 587),
		("submissions", 465),
		("imap", 143),
		("imaps", 993),
		("api", 8025),
	] {
		let port = base_p + offset;
		assert!(
			stderr_text.contains(&format!("listening: 127.0.0.1:{port} ({kind})")),
			"second-run banner must carry P's {kind} port {port}, got banner: {stderr_text}"
		);
	}
	for (_, offset) in [
		("smtp", 25u16),
		("submission", 587),
		("submissions", 465),
		("imap", 143),
		("imaps", 993),
		("api", 8025),
	] {
		let port_q = base_q + offset;
		assert!(
			!stderr_text.contains(&format!("listening: 127.0.0.1:{port_q}")),
			"second-run banner must NOT carry Q's port {port_q}, got banner: {stderr_text}"
		);
	}
	Ok(())
}

/// Run the harness once with `base_p`, wait until the SMTP
/// port is listening, then kill the child and reap it. The
/// directory is left on disk so a second run can pick up the
/// persisted port base from `mail.toml`.
fn run_until_listening_and_kill(dir: &Path, base_p: u16) -> Result<(), String> {
	let port_base_str = base_p.to_string();
	let dir_str = dir.to_str().expect("utf-8 tempdir path").to_owned();
	let args = [
		"local",
		"--dir",
		dir_str.as_str(),
		"--port-base",
		port_base_str.as_str(),
	];
	let mut child = Child::spawn(&args, dir);
	let bind_deadline = Instant::now() + Duration::from_secs(10);
	let smtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_p + 25);
	let _ = wait_for_bind(
		smtp_addr,
		bind_deadline,
		"waiting for first-run SMTP port",
		&mut child,
	)?;
	let (_stdout, _stderr) =
		child.kill_and_drain(Instant::now() + Duration::from_secs(2), "killing first run")?;
	Ok(())
}
