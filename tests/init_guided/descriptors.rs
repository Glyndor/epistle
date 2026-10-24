//! The pseudo-terminal of a run must not reach a process this test did not give
//! it to, and the check for that must see a descriptor the inspector itself
//! replaces.

use super::*;

use std::process::Output;

/// Print every descriptor this shell was given, its number and its target.
///
/// A descriptor the glob itself opens to walk `/proc` is closed again before
/// `readlink` reaches it, so one entry can read empty without meaning the
/// listing failed, and a shell with no `readlink`, or a machine with no `/proc`,
/// prints no target at all.
const INSPECT: &str = "for f in /proc/self/fd/*; do printf '%s %s\\n' \"$f\" \"$(readlink \"$f\" 2>/dev/null || true)\"; done";

/// The table of descriptors the shell was given, then the table it holds once
/// the marker has taken descriptor 9. `leak` is what the shell is handed on
/// descriptor 9 before any of it, when there is one.
fn inspect(leak: Option<&File>, marker: &Path) -> (String, String) {
	let mut command = Command::new("/bin/sh");
	command
		.arg("-c")
		.arg(format!(
			"printf 'before\\n'; {INSPECT}; exec 9<\"$1\" || exit 1; printf 'after\\n'; {INSPECT}"
		))
		.arg("sh")
		.arg(marker)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = match leak {
		Some(leak) => run_with_the_leak_on_nine(&mut command, leak),
		None => command.output().expect("inspect the descriptors"),
	};
	assert!(
		output.status.success(),
		"the inspection failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let printed = String::from_utf8_lossy(&output.stdout).into_owned();
	let (before, after) = printed
		.split_once("\nafter\n")
		.unwrap_or_else(|| panic!("the shell printed one table and not both: {printed}"));
	(
		before.strip_prefix("before\n").unwrap_or(before).to_owned(),
		after.to_owned(),
	)
}

/// Run `command` with `leak` on descriptor 9 of the child it starts.
///
/// The copy the child reads it from is a number of its own, taken high enough
/// that it cannot be the one the copy lands on: `dup2` onto the number a
/// descriptor already holds leaves its flag alone, and dropping that flag is
/// the whole point here.
fn run_with_the_leak_on_nine(command: &mut Command, leak: &File) -> Output {
	// SAFETY: `F_DUPFD_CLOEXEC` returns the lowest free number from 40 up and
	// leaves the copy set to close across an exec, so this descriptor reaches no
	// other child of this test process.
	let source = unsafe { libc::fcntl(leak.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 40) };
	assert!(
		source >= 0,
		"copy the leaked descriptor: {}",
		std::io::Error::last_os_error()
	);
	// SAFETY: the call above returned that number and nothing else has taken it,
	// so this `File` is its only owner. It stays owner until the child has been
	// spawned, because a number free again before the fork is a number the child
	// does not have.
	let _source = unsafe { File::from_raw_fd(source) };
	// SAFETY: the closure runs between `fork` and `exec`, where the only work
	// allowed is async-signal-safe, and `dup2` is one of them. It closes whatever
	// number 9 held in the child and leaves the copy without the flag that would
	// close it across the exec. A copy that never happened leaves nothing in the
	// table, which is what the check in the caller says out loud.
	unsafe {
		command.pre_exec(move || {
			libc::dup2(source, 9);
			Ok(())
		});
	}
	command.output().expect("inspect the descriptors")
}

/// A pseudo-terminal must not reach a process this test did not give it to.
///
/// The tests of this target run in parallel and each spawns `epistle init`
/// while the others still hold their own pair open, so a descriptor left
/// inheritable is inherited by whichever child the next test spawns. That
/// child then holds the slave of a terminal whose master is waiting for the end
/// of its stream: the end never arrives and the owning test waits out its
/// deadline for a child that already exited.
#[test]
fn a_pseudo_terminal_does_not_reach_another_process() {
	let dir = tempfile::tempdir().unwrap();
	let marker = dir.path().join("descriptor-nine");
	std::fs::write(&marker, b"nine").unwrap();
	let (_master, _slave) = pseudo_terminal();
	let (before, after) = inspect(None, &marker);
	// The table is taken before anything is substituted, so it is the table the
	// shell was handed. The marker going to descriptor 9 closes whatever that
	// number held on arrival, and nine is a plausible number for a leaked
	// terminal to arrive on.
	assert!(
		!before.contains("descriptor-nine"),
		"the marker was in place before the table was read, so the check never saw the descriptors this shell inherited: {before}"
	);
	// The shell was started with its output on a pipe, so a table that names
	// that pipe is one this shell really read. An empty one is then not read as
	// the absence of a leak: a shell with no `readlink`, or a machine with no
	// `/proc`, prints nothing either way.
	assert!(
		before.contains("/proc/self/fd/1 pipe:"),
		"the child was never inspected, so this run cannot tell that a pseudo-terminal stayed behind: {before}"
	);
	assert!(
		!before.contains("/dev/pts"),
		"a pseudo-terminal reached a process that was given none: {before}"
	);
	assert!(
		after.contains("descriptor-nine"),
		"descriptor 9 was never taken by the marker, so the second table proves nothing about the order the two were taken in: {after}"
	);
}

/// The check has to name a pseudo-terminal that sits on the descriptor the
/// inspection replaces.
///
/// This is the control that says the detection works: the leak is put on
/// descriptor 9 on purpose, between the fork and the exec of the inspector, and
/// the table taken before the marker runs has to report it. An inspection that
/// substituted 9 first would close the only terminal in the shell and pass.
#[test]
fn the_inspection_sees_a_pseudo_terminal_leaked_on_descriptor_nine() {
	let dir = tempfile::tempdir().unwrap();
	let marker = dir.path().join("descriptor-nine");
	std::fs::write(&marker, b"nine").unwrap();
	let (_master, slave) = pseudo_terminal();
	let (before, _after) = inspect(Some(&slave), &marker);
	assert!(
		before.contains("/proc/self/fd/9 /dev/pts/"),
		"a pseudo-terminal left on descriptor 9 was not seen, so the table says nothing about a leak on that descriptor: {before}"
	);
}
