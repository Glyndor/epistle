//! Whether the host keeps its clock synchronised with a time source.
//!
//! DKIM signatures, certificate validity, token and key expiry, the
//! timestamp authority's seals and the evidence log all depend on the
//! wall clock. [`probe`] asks the kernel (`adjtimex`, read-only, no root
//! needed) whether a time daemon is disciplining it, and falls back to
//! `timedatectl` when the syscall is refused, as it is inside a container
//! whose seccomp profile blocks it.

use std::process::Command;

/// `STA_UNSYNC` from `<sys/timex.h>`: the kernel clock is not disciplined.
const STA_UNSYNC: i32 = 0x0040;

/// `TIME_ERROR` from `<sys/timex.h>`: `adjtimex` returns it while the clock
/// is unsynchronised.
const TIME_ERROR: i32 = 5;

/// What to do when the clock is not synchronised. Nothing runs these for the
/// operator. One provider per client: Cloudflare and Google must not be
/// mixed, because Google smears leap seconds and Cloudflare steps them, so a
/// client holding both sees the two disagree by up to half a second.
pub const FIX: &str = "run `sudo timedatectl set-ntp true`, or set NTP=time.cloudflare.com in \
	/etc/systemd/timesyncd.conf and restart systemd-timesyncd, or install chrony; \
	use servers of one provider only, never Cloudflare and Google together";

/// What the host says about its clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostClock {
	/// A time source disciplines the clock.
	Synced,
	/// Nothing disciplines the clock.
	Unsynced,
	/// Neither the syscall nor `timedatectl` gave an answer; the text says why.
	Unknown(String),
}

/// Ask the host. Never changes anything.
pub fn probe() -> HostClock {
	match kernel_state() {
		Ok(state) => state,
		Err(syscall) => match timedatectl() {
			Some(state) => state,
			None => HostClock::Unknown(format!(
				"the kernel refused adjtimex ({syscall}) and timedatectl gave no answer"
			)),
		},
	}
}

/// Read the kernel's clock state with `adjtimex` in read-only mode.
fn kernel_state() -> Result<HostClock, std::io::Error> {
	// SAFETY: `timex` is plain old data, all-zero is a valid value, and
	// `modes == 0` makes the call read-only.
	let mut buffer: libc::timex = unsafe { std::mem::zeroed() };
	let state = unsafe { libc::adjtimex(&mut buffer) };
	if state < 0 {
		return Err(std::io::Error::last_os_error());
	}
	Ok(classify(state, buffer.status))
}

/// Judge an `adjtimex` answer: the return value and the status word.
pub(crate) fn classify(state: i32, status: i32) -> HostClock {
	if state == TIME_ERROR || status & STA_UNSYNC != 0 {
		HostClock::Unsynced
	} else {
		HostClock::Synced
	}
}

/// `timedatectl show -p NTPSynchronized --value`, when it exists and answers.
fn timedatectl() -> Option<HostClock> {
	let mut command = Command::new("timedatectl");
	command.args(["show", "-p", "NTPSynchronized", "--value"]);
	let text = output_within(command, PROBE_TIMEOUT)?;
	parse_timedatectl(&text)
}

/// How long the host probe may take before it is given up and killed.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Run a command and return its standard output when it succeeds within
/// `timeout`. A command that is still running at the deadline is killed and
/// reaped, so a probe that never answers cannot hold `status` or `init`.
fn output_within(mut command: Command, timeout: std::time::Duration) -> Option<String> {
	use std::io::Read;
	use std::process::Stdio;
	let mut child = command
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.ok()?;
	let deadline = std::time::Instant::now() + timeout;
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if std::time::Instant::now() < deadline => {
				std::thread::sleep(std::time::Duration::from_millis(20));
			}
			_ => {
				let _ = child.kill();
				let _ = child.wait();
				return None;
			}
		}
	};
	if !status.success() {
		return None;
	}
	let mut text = String::new();
	child.stdout.take()?.read_to_string(&mut text).ok()?;
	Some(text)
}

/// Parse the `yes`/`no` that `timedatectl` prints.
pub(crate) fn parse_timedatectl(text: &str) -> Option<HostClock> {
	match text.trim() {
		"yes" => Some(HostClock::Synced),
		"no" => Some(HostClock::Unsynced),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
