//! The identity change and the descriptors, in a real child process.

use super::*;
use std::process::Stdio;

/// Whether this process is root. The change of identity itself needs it.
fn is_root() -> bool {
	// SAFETY: geteuid takes no arguments and cannot fail.
	unsafe { libc::geteuid() == 0 }
}

/// The real change of identity, which only root can make. It is ignored in an
/// ordinary run so that it shows up as ignored, not as a pass it did not
/// earn; run it with
/// `sudo -E cargo test --lib identity::tests::process -- --ignored`.
#[test]
#[ignore = "needs root: sudo -E cargo test --lib identity::tests::process -- --ignored"]
fn a_child_started_as_the_account_runs_with_its_ids_and_groups() {
	assert!(is_root(), "this test must run as root");
	// The `nobody` ids and a group list that no root process has.
	let identity = Identity::new(65534, 65534, vec![65534, 4, 24]);
	let mut command = Command::new("sh");
	command.args(["-c", "grep -E '^(Uid|Gid|Groups):' /proc/self/status"]);
	run_as(&mut command, identity);
	// Runs after the change: the way back to root must be closed.
	// SAFETY: setuid is a system call and nothing else happens here.
	unsafe {
		std::os::unix::process::CommandExt::pre_exec(&mut command, || {
			if libc::setuid(0) == 0 {
				Err(io::Error::other("root could be regained"))
			} else {
				Ok(())
			}
		});
	}
	let output = command.stdout(Stdio::piped()).output().unwrap();
	assert!(output.status.success(), "{output:?}");
	let said = String::from_utf8_lossy(&output.stdout);
	let field = |name: &str| -> Vec<u32> {
		said.lines()
			.find_map(|line| line.strip_prefix(name))
			.unwrap_or_else(|| panic!("no {name} in {said}"))
			.split_whitespace()
			.map(|word| word.parse().unwrap())
			.collect()
	};
	// Uid and Gid list real, effective, saved and filesystem ids.
	assert_eq!(field("Uid:"), [65534; 4], "real, effective, saved, fs uid");
	assert_eq!(field("Gid:"), [65534; 4], "real, effective, saved, fs gid");
	let mut groups = field("Groups:");
	groups.sort_unstable();
	assert_eq!(
		groups,
		[4, 24, 65534],
		"supplementary groups are the account's"
	);
}

#[test]
fn the_command_sees_the_account_as_its_user() {
	let mut command = Command::new("true");
	run_as(&mut command, Identity::new(987, 986, vec![986]));
	let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
	for name in ["USER", "LOGNAME"] {
		assert_eq!(
			env.get(std::ffi::OsStr::new(name)).copied().flatten(),
			Some(std::ffi::OsStr::new("glyndor-epistle")),
			"{name} is still the caller's: podup reads it to find the account"
		);
	}
}

#[test]
fn a_failed_change_is_a_spawn_error_and_the_command_never_runs() {
	if is_root() {
		eprintln!("SKIPPED: as root the change succeeds; run this test as an ordinary user");
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

/// Whether a command started with `seal` in its `pre_exec` sees a descriptor
/// that has no close-on-exec flag, the way a root caller started from a shell
/// with extra descriptors would leave one.
fn descriptor_reaches_the_command(seal: fn() -> io::Result<()>) -> bool {
	let mut fds = [0 as libc::c_int; 2];
	// SAFETY: `fds` has room for the two descriptors pipe writes.
	assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
	let mut command = Command::new("sh");
	command.arg("-c").arg(format!(
		"if [ -e /proc/self/fd/{0} ]; then echo open; else echo closed; fi",
		fds[0]
	));
	// The identity change needs root, so these tests only seal the descriptors.
	// SAFETY: same constraints as in `run_as`: system calls and nothing else.
	unsafe {
		std::os::unix::process::CommandExt::pre_exec(&mut command, seal);
	}
	let output = command.stdout(Stdio::piped()).output().unwrap();
	// SAFETY: closing the two descriptors opened above.
	unsafe {
		libc::close(fds[0]);
		libc::close(fds[1]);
	}
	String::from_utf8_lossy(&output.stdout).trim() == "open"
}

#[test]
fn descriptors_above_stderr_do_not_reach_the_command() {
	assert!(!descriptor_reaches_the_command(seal_descriptors));
}

#[test]
fn a_kernel_that_refuses_close_range_still_seals_the_descriptors() {
	// The first attempt fails the way ENOSYS, EINVAL or a seccomp filter do.
	assert!(!descriptor_reaches_the_command(|| seal_with(|| -1)));
}

fn nofile() -> libc::rlimit {
	let mut limit = libc::rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	// SAFETY: valid storage for the answer.
	assert_eq!(
		unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
		0
	);
	limit
}

#[test]
fn a_descriptor_above_the_soft_limit_is_sealed_too() {
	let original = nofile();
	if original.rlim_max < 8192 {
		eprintln!("SKIPPED: the hard limit on descriptors is below 8192");
		return;
	}
	// Open a descriptor under a high limit, then lower the limit under it, as
	// a caller that was started with a larger one can leave things.
	let high = libc::rlimit {
		rlim_cur: 8192,
		rlim_max: original.rlim_max,
	};
	// SAFETY: setrlimit reads a valid struct.
	assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &high) }, 0);
	let mut fds = [0 as libc::c_int; 2];
	// SAFETY: room for the two descriptors pipe writes.
	assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
	const FAR: libc::c_int = 5000;
	// SAFETY: duplicating onto a free number below the limit just set.
	assert_eq!(unsafe { libc::dup2(fds[0], FAR) }, FAR);
	let low = libc::rlimit {
		rlim_cur: 1024,
		rlim_max: original.rlim_max,
	};
	// SAFETY: setrlimit reads a valid struct.
	assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
	let mut command = Command::new("sh");
	command.arg("-c").arg(format!(
		"if [ -e /proc/self/fd/{FAR} ]; then echo open; else echo closed; fi"
	));
	// SAFETY: same constraints as in `run_as`: system calls and nothing else.
	unsafe {
		std::os::unix::process::CommandExt::pre_exec(&mut command, || seal_with(|| -1));
	}
	let output = command.stdout(Stdio::piped()).output();
	// SAFETY: putting the limit back and closing what was opened above.
	unsafe {
		libc::setrlimit(libc::RLIMIT_NOFILE, &original);
		libc::close(FAR);
		libc::close(fds[0]);
		libc::close(fds[1]);
	}
	let output = output.unwrap();
	assert_eq!(
		String::from_utf8_lossy(&output.stdout).trim(),
		"closed",
		"a descriptor above the soft limit reached the command"
	);
}

#[test]
fn without_any_sealing_the_test_descriptor_does_reach_the_command() {
	// The control: the two tests above mean nothing if it never arrives.
	assert!(descriptor_reaches_the_command(|| Ok(())));
}
