//! The identity change and the descriptors, in a real child process.

use super::*;
use std::process::Stdio;

/// Whether this process is root. The change of identity itself needs it, so
/// the test that makes it is skipped otherwise and says so.
fn is_root() -> bool {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() == 0 }
}

#[test]
fn a_child_started_as_the_account_runs_with_its_ids_and_groups() {
	if !is_root() {
		eprintln!("SKIPPED: needs root to change identity");
		return;
	}
	// The `nobody` ids and a group list that no root process has.
	let identity = Identity::new(65534, 65534, vec![65534, 4, 24]);
	let mut command = Command::new("sh");
	command.args(["-c", "echo $(id -u) $(id -g) $(id -G)"]);
	run_as(&mut command, identity);
	let output = command.stdout(Stdio::piped()).output().unwrap();
	assert!(output.status.success(), "{output:?}");
	let said = String::from_utf8_lossy(&output.stdout);
	let mut words: Vec<_> = said.split_whitespace().collect();
	let groups = words.split_off(2);
	assert_eq!(words, ["65534", "65534"], "uid and gid");
	let mut groups: Vec<u32> = groups.iter().map(|g| g.parse().unwrap()).collect();
	groups.sort_unstable();
	assert_eq!(
		groups,
		[4, 24, 65534],
		"supplementary groups are the account's"
	);
}

#[test]
fn a_failed_change_is_a_spawn_error_and_the_command_never_runs() {
	if is_root() {
		eprintln!("SKIPPED: as root the change succeeds");
		return;
	}
	let dir = tempfile::tempdir().unwrap();
	let marker = dir.path().join("ran");
	let mut command = Command::new("sh");
	command.arg("-c").arg(format!("touch {}", marker.display()));
	run_as(&mut command, Identity::new(0, 0, vec![0]));
	let error = command
		.status()
		.expect_err("an ordinary user cannot become root");
	assert_eq!(error.raw_os_error(), Some(libc::EPERM), "{error}");
	assert!(
		!marker.exists(),
		"the command must not run with a half change"
	);
}

#[test]
fn descriptors_above_stderr_do_not_reach_the_command() {
	// A descriptor with no close-on-exec flag, the way a root caller started
	// from a shell with extra descriptors would leave one.
	let mut fds = [0 as libc::c_int; 2];
	// SAFETY: `fds` has room for the two descriptors pipe writes.
	assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
	let mut command = Command::new("sh");
	command.arg("-c").arg(format!(
		"if [ -e /proc/self/fd/{0} ]; then echo open; else echo closed; fi",
		fds[0]
	));
	// The identity change needs root, so this test only seals the descriptors.
	// SAFETY: same constraints as in `run_as`: a system call and nothing else.
	unsafe {
		std::os::unix::process::CommandExt::pre_exec(&mut command, || {
			seal_descriptors();
			Ok(())
		});
	}
	let output = command.stdout(Stdio::piped()).output().unwrap();
	// SAFETY: closing the two descriptors opened above.
	unsafe {
		libc::close(fds[0]);
		libc::close(fds[1]);
	}
	assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "closed");
}
