//! Waiting for Podman's API and retrying a podup step whose connection to it
//! dropped.
//!
//! The libpod socket is socket-activated: the unit listens before
//! `podman system service` is up, and the service exits when it has been idle
//! for a few seconds. A podup call that lands while the service is starting
//! or leaving fails with a connection error (`connection closed before
//! message completed`) although nothing is wrong with the stack. Every podup
//! step `stack update` runs converges on the compose file, so running it
//! again after the API answers is safe. Any other failure is returned at
//! once, and the last attempt's error is returned as it is.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Times a step is run before its connection error is reported.
pub(super) const ATTEMPTS: u32 = 4;
/// How long the API gets to answer before a step is run again.
pub(super) const API_WAIT: Duration = Duration::from_secs(30);
/// How much of podup's stderr is kept to tell a dropped connection from a
/// real failure.
const TAIL: usize = 4096;

/// Whether `stderr` is podup failing to talk to Podman, rather than Podman
/// refusing what podup asked.
pub(super) fn is_dropped_connection(stderr: &str) -> bool {
	let lower = stderr.to_ascii_lowercase();
	[
		"connection closed before message completed",
		"connection reset",
		"connection refused",
		"broken pipe",
		"error trying to connect",
		"incomplete message",
	]
	.iter()
	.any(|needle| lower.contains(needle))
}

/// Ask the libpod API at `socket` for `/libpod/_ping`; `true` on a 200.
pub(super) fn ping(socket: &Path, timeout: Duration) -> bool {
	let attempt = || -> std::io::Result<bool> {
		let mut stream = UnixStream::connect(socket)?;
		stream.set_read_timeout(Some(timeout))?;
		stream.set_write_timeout(Some(timeout))?;
		stream.write_all(b"GET /libpod/_ping HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n")?;
		let mut head = [0u8; 12];
		stream.read_exact(&mut head)?;
		Ok(&head == b"HTTP/1.1 200")
	};
	attempt().unwrap_or(false)
}

/// Poll `probe` every `interval` until it holds or `wait` has passed.
pub(super) fn wait_until(
	wait: Duration,
	interval: Duration,
	mut probe: impl FnMut() -> bool,
) -> bool {
	let deadline = Instant::now() + wait;
	loop {
		if probe() {
			return true;
		}
		if Instant::now() >= deadline {
			return false;
		}
		std::thread::sleep(interval);
	}
}

/// Wait for the libpod API behind `socket` to answer.
pub(super) fn wait_for_api(socket: &Path, wait: Duration) -> bool {
	wait_until(wait, Duration::from_millis(500), || {
		ping(socket, Duration::from_secs(5))
	})
}

/// How one run of a step ended.
pub(super) struct Run {
	pub(super) success: bool,
	/// The end of what the step wrote to stderr.
	pub(super) tail: String,
}

/// Run `command` with stderr copied to ours as it arrives and its end kept.
pub(super) fn run_tee(mut command: std::process::Command) -> std::io::Result<Run> {
	let mut child = command
		.stdin(Stdio::inherit())
		.stdout(super::json_out::child_stdout())
		.stderr(Stdio::piped())
		.spawn()?;
	let mut stderr = child
		.stderr
		.take()
		.ok_or_else(|| std::io::Error::other("no stderr"))?;
	let copier = std::thread::spawn(move || {
		let mut tail: Vec<u8> = Vec::new();
		let mut buf = [0u8; 1024];
		let mut ours = std::io::stderr();
		while let Ok(n) = stderr.read(&mut buf) {
			if n == 0 {
				break;
			}
			let _ = ours.write_all(&buf[..n]);
			tail.extend_from_slice(&buf[..n]);
			if tail.len() > TAIL {
				tail.drain(..tail.len() - TAIL);
			}
		}
		String::from_utf8_lossy(&tail).into_owned()
	});
	let status = child.wait()?;
	let tail = copier.join().unwrap_or_default();
	Ok(Run {
		success: status.success(),
		tail,
	})
}

/// Run a step up to [`ATTEMPTS`] times, waiting for the API between runs.
/// `run` performs one attempt, `wait` waits for the API and says whether it
/// answered, `note` tells the operator what is happening.
pub(super) fn with_retries(
	mut run: impl FnMut() -> std::io::Result<Run>,
	mut wait: impl FnMut() -> bool,
	mut note: impl FnMut(&str),
) -> Result<(), String> {
	for attempt in 1..=ATTEMPTS {
		let outcome = run().map_err(|error| format!("cannot run podup: {error}"))?;
		if outcome.success {
			return Ok(());
		}
		if !is_dropped_connection(&outcome.tail) {
			return Err("it exited with an error, shown above".to_string());
		}
		if attempt == ATTEMPTS {
			return Err(format!(
				"podup lost its connection to Podman {ATTEMPTS} times in a row"
			));
		}
		note(&format!(
			"Podman's API dropped the connection (attempt {attempt} of {ATTEMPTS}); waiting for it to answer before running the step again"
		));
		if !wait() {
			return Err(format!(
				"Podman's API did not answer within {} s after podup lost its connection",
				API_WAIT.as_secs()
			));
		}
	}
	Err("it exited with an error, shown above".to_string())
}

#[cfg(test)]
#[path = "stack_retry_tests.rs"]
mod tests;
