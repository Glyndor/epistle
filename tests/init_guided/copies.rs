//! Copies of this target, and what a launcher leaves behind when it gives up
//! with copies still running.

use super::*;

/// How many copies of this target run at once.
const COPIES: usize = 4;

/// The copies of this target a launcher still holds.
///
/// Dropping a `Child` neither stops nor reaps the process behind it, so a
/// launcher that asserts, panics or fails to spawn with copies still running
/// would leave them behind with nobody left to read them. Dropping this takes
/// down every copy still held, with everything each of them started, and waits
/// for each one.
#[derive(Default)]
struct PendingCopies(Vec<Option<Child>>);

impl PendingCopies {
	fn push(&mut self, copy: Child) {
		self.0.push(Some(copy));
	}

	/// The copy at `index`, given up so its output can be read. This launcher
	/// stops holding it from here on.
	fn take(&mut self, index: usize) -> Child {
		self.0[index].take().expect("a copy was already taken")
	}

	fn ids(&self) -> Vec<u32> {
		self.0.iter().flatten().map(Child::id).collect()
	}
}

impl Drop for PendingCopies {
	fn drop(&mut self) {
		for copy in self.0.iter_mut().flatten() {
			// The copy leads a group of its own, so this reaches the processes
			// it started as well as the copy. Signalling the copy alone would
			// leave them running, and a `Child` waiting on the copy collects no
			// one else.
			// SAFETY: the group of a copy is the copy, the copy is alive while
			// this launcher holds it, and the signal is valid.
			let _ = unsafe { libc::killpg(copy.id() as libc::pid_t, libc::SIGKILL) };
			let _ = copy.wait();
		}
	}
}

/// Start `command` as the leader of a process group of its own.
///
/// A copy of this target starts processes of its own, and a signal sent to the
/// copy alone leaves those running. The group is taken before the copy
/// executes and the spawn only returns once it has, so the group is there by
/// the time a launcher can hold the copy.
fn spawn_as_a_group_leader(command: &mut Command, what: &str) -> Child {
	command.process_group(0);
	command
		.spawn()
		.unwrap_or_else(|error| panic!("{what}: {error}"))
}

/// Whether `pid` is still running as the command this test started, so a
/// process that has taken the number over is not mistaken for one left behind.
fn still_running_as(pid: u32, command: &[u8]) -> bool {
	std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmd| cmd.starts_with(command))
}

/// Whether `pid` is `command` within `budget`, for a process nobody here waited
/// for: it takes a moment to get there from its fork.
fn running_within(pid: u32, command: &[u8], budget: Duration) -> bool {
	let until = Instant::now() + budget;
	while !still_running_as(pid, command) {
		if Instant::now() >= until {
			return false;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	true
}

/// Whether `pid` stops being `command` within `budget`. A process that takes a
/// signal but is nobody's to wait for reads as itself for a moment after it.
fn gone_within(pid: u32, command: &[u8], budget: Duration) -> bool {
	let until = Instant::now() + budget;
	while still_running_as(pid, command) {
		if Instant::now() >= until {
			return false;
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	true
}

/// The number written in `record`, which a copy fills in once it has started a
/// process of its own.
fn number_in(record: &Path) -> u32 {
	let until = Instant::now() + Duration::from_secs(10);
	loop {
		if let Some(number) = std::fs::read_to_string(record)
			.ok()
			.and_then(|text| text.trim().parse().ok())
		{
			return number;
		}
		assert!(
			Instant::now() < until,
			"no copy wrote the number of the process it started in {}",
			record.display()
		);
		std::thread::sleep(Duration::from_millis(10));
	}
}

/// A launcher that gives up with copies still running has to take them with
/// it. `Child` does neither, so this is what stops a copy left behind from
/// outliving the test that started it.
#[test]
fn a_launcher_that_gives_up_reaps_the_copies_it_still_holds() {
	let mut copies = PendingCopies::default();
	for _ in 0..2 {
		let mut command = Command::new("/bin/sleep");
		command
			.arg("600")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null());
		copies.push(spawn_as_a_group_leader(
			&mut command,
			"a copy that outlives its launcher",
		));
	}
	let ids = copies.ids();
	drop(copies);
	for id in ids {
		assert!(
			!still_running_as(id, b"/bin/sleep\0"),
			"copy {id} was still running after the launcher that started it gave up"
		);
	}
}

/// A launcher that gives up has to take down what its copies started, and not
/// only the copies it knows the number of.
///
/// Every copy of this target spawns `epistle init` of its own, and a launcher
/// that fails while an earlier copy is still running kills that copy without
/// touching anything below it. The descendant here is a plain sleep, so what is
/// checked is the group and nothing about the guided setup.
#[test]
fn a_launcher_that_gives_up_also_takes_the_processes_its_copies_started() {
	let dir = tempfile::tempdir().unwrap();
	let record = dir.path().join("descendant");
	let mut command = Command::new("/bin/sh");
	command
		.arg("-c")
		// The descendant is left in the group of the copy that started it, and
		// the number it runs under is written down because the copy itself is
		// gone by the time the check runs.
		.arg("/bin/sleep 600 & echo $! > \"$1\"; wait")
		.arg("sh")
		.arg(&record)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null());
	let mut copies = PendingCopies::default();
	copies.push(spawn_as_a_group_leader(
		&mut command,
		"a copy that starts a process of its own",
	));
	let descendant = number_in(&record);
	assert!(
		running_within(descendant, b"/bin/sleep\0", Duration::from_secs(10)),
		"the copy started no process of its own, so this run proves nothing about the ones it did"
	);
	drop(copies);
	assert!(
		gone_within(descendant, b"/bin/sleep\0", Duration::from_secs(10)),
		"process {descendant} outlived the launcher that gave up with the copy that started it running"
	);
}
/// Run this target against itself, several copies at once, and require every
/// copy to pass.
///
/// The copies stand for the rest of a test run, and the launcher that starts
/// each of them stands for the supervisor it runs under: a background job of a
/// shell, a service manager and a container runtime all start a process with
/// SIGINT ignored, and an ignored disposition survives `exec`, so a copy that
/// inherited it could not be interrupted at all. Between them, running several
/// copies at once also multiplies what each copy asks of the machine, which is
/// what turned a leaked pseudo-terminal into a run that never finished. A copy
/// runs the whole target with this test skipped, so nothing recurses.
///
/// Every output is collected before anything is asserted on, so a copy that
/// fails still leaves the rest to be read and reaped instead of stranding them.
#[test]
fn the_target_passes_with_several_copies_at_once() {
	let program = std::env::current_exe().expect("path of this test binary");
	let mut copies = PendingCopies::default();
	for _ in 0..COPIES {
		let mut command = Command::new("/bin/sh");
		command
			.arg("-c")
			.arg("trap '' INT; exec \"$0\" \"$@\"")
			.arg(&program)
			.arg("--skip")
			.arg(SELF)
			.env_remove("RUST_TEST_THREADS")
			.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		copies.push(spawn_as_a_group_leader(
			&mut command,
			"copy of this test binary",
		));
	}
	let mut outputs = Vec::new();
	for index in 0..COPIES {
		outputs.push(
			copies
				.take(index)
				.wait_with_output()
				.unwrap_or_else(|error| panic!("output of copy {index} of {COPIES}: {error}")),
		);
	}
	for (index, output) in outputs.iter().enumerate() {
		assert!(
			output.status.success(),
			"copy {index} of {COPIES} failed with {:?}: {}",
			output.status,
			String::from_utf8_lossy(&output.stdout)
		);
	}
}
