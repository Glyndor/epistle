//! The limit files read hostile: the compose file is read before the
//! server drops its privileges, from a directory the service account
//! writes, so a link or a FIFO planted there must not be followed or
//! block start-up.

use super::*;

const GIB: u64 = 1024 * 1024 * 1024;

fn mkfifo(path: &Path) {
	let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("nul-free");
	// SAFETY: `c_path` is a NUL-terminated string valid for the call.
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
}

#[test]
fn a_symlinked_compose_file_is_not_followed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let elsewhere = dir.path().join("elsewhere.json");
	std::fs::write(&elsewhere, r#"{"services":{"mail":{"mem_limit":"2g"}}}"#).expect("write");
	let compose = dir.path().join("compose.yaml");
	std::os::unix::fs::symlink(&elsewhere, &compose).expect("symlink");
	assert_eq!(read_compose_limit(&compose), None);
	assert_eq!(compose_or_fallback(&compose), ContainerLimit::fallback());
}

#[test]
fn a_fifo_at_the_compose_path_does_not_block_start_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	mkfifo(&compose);
	let (sender, receiver) = std::sync::mpsc::channel();
	let reading = compose.clone();
	std::thread::spawn(move || {
		let _ = sender.send(read_compose_limit(&reading));
	});
	let answer = receiver.recv_timeout(std::time::Duration::from_secs(5));
	if answer.is_err() {
		// Open a writer and close it so the blocked reader sees the end.
		drop(
			std::fs::OpenOptions::new()
				.write(true)
				.open(&compose)
				.expect("writer"),
		);
	}
	assert_eq!(answer, Ok(None), "the read blocked on a FIFO");
}

#[test]
fn a_symlinked_memory_max_is_not_followed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let proc = dir.path().join("cgroup");
	std::fs::write(&proc, "0::/\n").expect("proc");
	let root = dir.path().join("sys-fs-cgroup");
	std::fs::create_dir_all(&root).expect("root");
	let elsewhere = dir.path().join("elsewhere");
	std::fs::write(&elsewhere, "1024\n").expect("write");
	std::os::unix::fs::symlink(&elsewhere, root.join("memory.max")).expect("symlink");
	assert_eq!(read_cgroup_limit(&proc, &root), None);
}

#[test]
fn memory_max_values_at_the_edges() {
	let dir = tempfile::tempdir().expect("tempdir");
	let proc = dir.path().join("cgroup");
	std::fs::write(&proc, "0::/\n").expect("proc");
	let root = dir.path().join("sys-fs-cgroup");
	std::fs::create_dir_all(&root).expect("root");
	let read = |value: &str| {
		std::fs::write(root.join("memory.max"), value).expect("memory.max");
		read_cgroup_limit(&proc, &root)
	};
	assert_eq!(read("max\n"), None, "no limit");
	assert_eq!(
		read("  2147483648 \n\n"),
		Some(2 * GIB),
		"spaces and newlines"
	);
	assert_eq!(read("18446744073709551615\n"), Some(u64::MAX));
	assert_eq!(
		read("18446744073709551616\n"),
		None,
		"past u64 is no number"
	);
	assert_eq!(read("-1\n"), None);
	assert_eq!(read("2g\n"), None, "the kernel writes bytes only");
	assert_eq!(read("0\n"), Some(0));
	// A limit too large to mean anything still gives the 1 GiB ceiling, and
	// a zero limit one message of the largest size.
	assert_eq!(derive(u64::MAX, 25 << 20), GIB);
	assert_eq!(derive(0, 25 << 20), 25 << 20);
}

#[test]
fn a_device_is_not_read() {
	// Opening some devices has effects of its own (a watchdog arms on
	// open), and this read runs as root before the privilege drop.
	let refused = read_regular(Path::new("/dev/zero"), 16).map(|text| text.len());
	assert_eq!(
		refused.map_err(|error| error.kind()),
		Err(std::io::ErrorKind::InvalidInput)
	);
}
