//! The helper itself: a fifo, a link to one and a device are refused, a link
//! to a regular file is followed.

use super::*;

fn within(path: &Path) -> io::Result<Vec<u8>> {
	// The closure fixes the lifetime of the borrowed path; the bare function does not.
	#[allow(clippy::redundant_closure)]
	bounded(path, |p| read(p))
}

#[test]
fn a_fifo_and_a_link_to_one_are_refused_instead_of_waited_on() {
	let dir = tempfile::tempdir().unwrap();
	let pipe = dir.path().join("pipe");
	fifo_at(&pipe);
	let error = within(&pipe).expect_err("a fifo is not a file");
	assert!(is_not_regular(&error), "{error}");
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&pipe, &link).unwrap();
	assert!(is_not_regular(
		&within(&link).expect_err("a link to a fifo")
	));
}

#[test]
fn a_device_and_a_directory_are_refused() {
	assert!(is_not_regular(&within(Path::new("/dev/zero")).unwrap_err()));
	let dir = tempfile::tempdir().unwrap();
	assert!(is_not_regular(&within(dir.path()).unwrap_err()));
}

#[test]
fn a_link_to_a_regular_file_is_followed_and_a_missing_file_is_not_found() {
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("target");
	std::fs::write(&target, "hello").unwrap();
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&target, &link).unwrap();
	assert_eq!(within(&link).unwrap(), b"hello");
	assert_eq!(read_to_string(&link).unwrap(), "hello");
	let missing = within(&dir.path().join("none")).unwrap_err();
	assert_eq!(missing.kind(), io::ErrorKind::NotFound);
}
