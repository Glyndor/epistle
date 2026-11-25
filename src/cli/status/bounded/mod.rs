//! Running a program for a check, and no longer than the check may last.
//!
//! A check runs on a blocking thread that outlives the future that started
//! it, and the program it started outlives the thread unless something kills
//! it: so every program a check runs has a time at which it is killed.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How often a running program is looked at.
const POLL: Duration = Duration::from_millis(25);

/// The most of a program's output that is kept. A program with more to say is
/// read to its end all the same, so it is never stopped by a full pipe, and what
/// is past this is dropped.
pub(in crate::cli) const MAX_OUTPUT: u64 = 4 * 1024 * 1024;

const OVER: &str = "the time for the check is over";

/// Run `command` and collect its stdout, killing it at `until`. Its stdin and
/// stderr are closed. A program still running at `until`, or whose output is
/// still held open at `until` by something it started outside its group, is an
/// error, after the group was killed and the program waited for. The collection
/// of the output is held to the same time as the program is.
pub(in crate::cli) fn output_until(
	command: &mut Command,
	until: Instant,
) -> Result<(ExitStatus, Vec<u8>), String> {
	if Instant::now() >= until {
		return Err(OVER.to_string());
	}
	// Its own process group, so that what it starts dies with it.
	let mut child = command
		.process_group(0)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|error| error.to_string())?;
	// Read as it writes, so a program with more to say than a pipe holds is
	// not mistaken for one that hangs. The reader hands over what it kept as
	// soon as it has it, and goes on emptying the pipe so a talkative program
	// is never stopped by it; it is never waited for, only listened to.
	let mut pipe = child.stdout.take();
	let (sender, receiver) = mpsc::channel();
	std::thread::spawn(move || {
		let mut kept = Vec::new();
		if let Some(pipe) = pipe.as_mut() {
			let _ = pipe.by_ref().take(MAX_OUTPUT).read_to_end(&mut kept);
			let _ = sender.send(kept);
			let _ = std::io::copy(pipe, &mut std::io::sink());
		} else {
			let _ = sender.send(kept);
		}
	});
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if Instant::now() < until => std::thread::sleep(POLL),
			Ok(None) => {
				kill_group(&mut child);
				return Err(OVER.to_string());
			}
			Err(error) => {
				kill_group(&mut child);
				return Err(error.to_string());
			}
		}
	};
	// What the program left running in its group would hold the pipe open and
	// the output would never end: it goes with the program.
	signal_group(child.id());
	match receiver.recv_timeout(until.saturating_duration_since(Instant::now())) {
		Ok(stdout) => Ok((status, stdout)),
		Err(_) => {
			signal_group(child.id());
			Err(OVER.to_string())
		}
	}
}

/// SIGKILL to the process group the program led.
fn signal_group(pid: u32) {
	if let Ok(group) = i32::try_from(pid) {
		// SAFETY: killpg takes two integers and touches no memory; the group
		// is the one this program leads, made by `process_group(0)` above.
		unsafe {
			libc::killpg(group, libc::SIGKILL);
		}
	}
}

/// Kill the program and everything in its process group, and wait for it.
fn kill_group(child: &mut std::process::Child) {
	signal_group(child.id());
	let _ = child.kill();
	let _ = child.wait();
}

#[cfg(test)]
mod tests;
