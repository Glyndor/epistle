//! The common lock: who may take it, what a waiter is told, and when it stops
//! waiting.

use super::*;

use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

/// A configuration file next to nothing else, so the lock beside it is the
/// only one the test touches.
fn config(dir: &Path) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(&path, "hostname = 'mail.example.org'\n").unwrap();
	path
}

#[test]
fn a_lock_file_this_user_owns_is_taken_and_its_holder_is_recorded() {
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let held = acquire_within(&path, Duration::from_secs(1)).unwrap();
	assert!(
		held.metadata().unwrap().permissions().mode() & 0o777 == 0o600,
		"a lock file this command created is owner-only"
	);
	// A second command in this process reads the record the first one wrote,
	// which is what its wait message names.
	assert!(
		held_by(&held).is_some_and(|holder| holder.contains("pid ")),
		"the holder must name the process that owns the lock"
	);
}

/// The wait ends at its deadline. The second command runs in its own thread so
/// that a wait with no deadline at all is a failure here and not a hung test:
/// the assertion has to name the deadline, not time out silently.
#[test]
fn a_wait_times_out_naming_the_holder() {
	use std::sync::mpsc;
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let held = acquire_within(&path, Duration::from_secs(1)).unwrap();
	let (done, waited) = mpsc::channel();
	let waiting = path.clone();
	std::thread::spawn(move || {
		done.send(acquire_within(&waiting, Duration::from_millis(300)))
			.unwrap();
	});
	let error = waited
		.recv_timeout(Duration::from_secs(10))
		.expect("the wait must give up at its deadline instead of waiting forever")
		.unwrap_err();
	drop(held);
	assert!(
		error.contains("has held") && error.contains("retry once it has finished"),
		"the refusal must say what it waited for and what to do: {error}"
	);
	assert!(
		acquire_within(&path, Duration::from_secs(1)).is_ok(),
		"the lock is free again once the holder is gone"
	);
}

/// The lock belongs to the service user or to root, who creates it from
/// `postinst` and takes it from the commands an operator runs under sudo. It
/// carries no secret, so the only mode that is refused is one other users may
/// write, and the refusal names the command that fixes it.
#[test]
fn a_lock_file_is_taken_from_either_owner_and_refused_only_when_others_can_write() {
	let path = Path::new("/etc/epistle/.epistle-config.lock");
	let euid = unsafe { libc::geteuid() };
	for mode in [0o600, 0o640, 0o644, 0o660, 0o664] {
		assert_eq!(usable(path, mode, euid), Ok(()), "{mode:04o}");
	}
	assert_eq!(
		usable(path, 0o644, 0),
		Ok(()),
		"a lock root created is one the service user may take"
	);
	let error = usable(path, 0o666, euid).unwrap_err();
	assert!(
		error.contains("writable by other users")
			&& error.contains("0666")
			&& error.contains("chmod 600"),
		"{error}"
	);
	assert!(
		usable(path, 0o666, 0).unwrap_err().contains("0666"),
		"a lock root created wide open is refused too"
	);
	// A uid that is neither root nor the user running the test, whoever that is:
	// a fixed number is the runner's own uid on some machines.
	let stranger = euid + 1001;
	let error = usable(path, 0o600, stranger).unwrap_err();
	assert!(error.contains("another user"), "{error}");
}

#[test]
fn a_lock_file_left_wide_open_is_put_back_rather_than_refused() {
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let lock = dir.path().join(".epistle-config.lock");
	std::fs::write(&lock, b"").unwrap();
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
	}
	let held = acquire_within(&path, Duration::from_secs(1)).unwrap();
	assert_eq!(
		held.metadata().unwrap().permissions().mode() & 0o777,
		0o600,
		"a lock this command owns is put back to the mode it creates"
	);
	drop(held);
}

/// A symlink is never followed and a fifo is never read: the lock file has to
/// be a regular file this process owns, so neither can redirect the lock.
#[test]
fn a_lock_file_that_is_not_a_regular_file_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let lock = dir.path().join(".epistle-config.lock");
	std::os::unix::fs::symlink(dir.path().join("elsewhere"), &lock).unwrap();
	let error = acquire_within(&path, Duration::from_secs(1)).unwrap_err();
	assert!(error.contains("cannot lock"), "{error}");
	assert!(
		!dir.path().join("elsewhere").exists(),
		"the target stays untouched"
	);

	std::fs::remove_file(&lock).unwrap();
	let fifo = CString::new(lock.to_str().unwrap()).unwrap();
	assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
	let error = acquire_within(&path, Duration::from_secs(1)).unwrap_err();
	assert!(error.contains("regular lock file"), "{error}");
}

/// A lock this command can not write is still a lock: `flock` serialises
/// writers through the descriptor alone, so a lock root created at `0644` in
/// `/etc/epistle` keeps two commands apart instead of failing both of them.
#[test]
fn a_lock_file_this_user_can_not_write_still_excludes_a_second_writer() {
	use std::sync::mpsc;
	let dir = tempfile::tempdir().unwrap();
	let path = config(dir.path());
	let lock = dir.path().join(".epistle-config.lock");
	std::fs::write(&lock, b"").unwrap();
	std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
	let held = acquire_within(&path, Duration::from_secs(1)).unwrap();
	let (done, waited) = mpsc::channel();
	let waiting = path.clone();
	std::thread::spawn(move || {
		done.send(acquire_within(&waiting, Duration::from_millis(200)))
			.unwrap();
	});
	let error = waited
		.recv_timeout(Duration::from_secs(10))
		.expect("a read-only lock must still be waited for")
		.unwrap_err();
	assert!(error.contains("has held"), "{error}");
	drop(held);
}
