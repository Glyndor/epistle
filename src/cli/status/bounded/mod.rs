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
	#[cfg(test)]
	let watched = probe::of(command);
	// Its own process group, so that what it starts dies with it.
	let mut child = command
		.process_group(0)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|error| error.to_string())?;
	#[cfg(test)]
	if let Some(watch) = &watched {
		watch.started(child.id());
	}
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
			#[cfg(test)]
			Ok(None) if watched.as_ref().is_some_and(|watch| watch.expired()) => {
				kill_group(&mut child);
				return Err(OVER.to_string());
			}
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

/// What a test needs to know of the programs a check runs, and the means to
/// end their time when it chooses: it registers a program by its path, is told
/// when each has started, and says when its time is over, so that no time is
/// waited for.
#[cfg(test)]
pub(crate) mod probe {
	use std::ffi::OsString;
	use std::path::Path;
	use std::process::Command;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::{Arc, Mutex};

	static WATCHED: Mutex<Vec<(OsString, Arc<Watch>)>> = Mutex::new(Vec::new());

	/// The programs started under one path.
	pub(crate) struct Watch {
		started: tokio::sync::Semaphore,
		pids: Mutex<Vec<u32>>,
		expired: AtomicBool,
	}

	/// Watch the programs run from `program`.
	pub(crate) fn watch(program: &Path) -> Arc<Watch> {
		let watch = Arc::new(Watch {
			started: tokio::sync::Semaphore::new(0),
			pids: Mutex::new(Vec::new()),
			expired: AtomicBool::new(false),
		});
		WATCHED
			.lock()
			.expect("watched")
			.push((program.as_os_str().to_os_string(), Arc::clone(&watch)));
		watch
	}

	pub(super) fn of(command: &Command) -> Option<Arc<Watch>> {
		WATCHED
			.lock()
			.expect("watched")
			.iter()
			.find(|(program, _)| program == command.get_program())
			.map(|(_, watch)| Arc::clone(watch))
	}

	impl Watch {
		pub(super) fn started(&self, pid: u32) {
			self.pids.lock().expect("pids").push(pid);
			self.started.add_permits(1);
		}

		pub(super) fn expired(&self) -> bool {
			self.expired.load(Ordering::SeqCst)
		}

		/// Wait until `count` programs have started. The limit is only there
		/// so that a lost signal fails the test and does not hang it.
		pub(crate) async fn started_count(&self, count: u32) {
			tokio::time::timeout(
				std::time::Duration::from_secs(120),
				self.started.acquire_many(count),
			)
			.await
			.expect("the programs started")
			.expect("open")
			.forget();
		}

		/// End the time of every program of the path: each is killed with
		/// what it started the next time it is looked at.
		pub(crate) fn expire(&self) {
			self.expired.store(true, Ordering::SeqCst);
		}

		/// The process ids of the programs that were started.
		pub(crate) fn pids(&self) -> Vec<u32> {
			self.pids.lock().expect("pids").clone()
		}
	}
}

#[cfg(test)]
mod tests;
