//! Tests for the process probe's reading of `/proc/<pid>/status`.

use super::owned_by;

const STATUS: &str =
	"Name:\tcatatonit\nState:\tS (sleeping)\nUid:\t990\t991\t992\t993\nGid:\t990\t990\t990\t990\n";

#[test]
fn the_real_or_effective_uid_counts() {
	assert!(owned_by(STATUS, 990), "real uid");
	assert!(owned_by(STATUS, 991), "effective uid");
	assert!(
		!owned_by(STATUS, 992),
		"the saved uid does not make it the account's"
	);
	assert!(!owned_by(STATUS, 0));
	assert!(!owned_by("Name:\tx\n", 990), "no Uid line, no match");
}

#[test]
fn this_process_is_found_under_its_own_uid() {
	// SAFETY: getuid takes no arguments and cannot fail.
	let uid = unsafe { libc::getuid() };
	let me = std::process::id().to_string();
	assert!(
		super::account_processes(uid)
			.iter()
			.any(|(pid, _)| pid.to_string() == me)
	);
}
