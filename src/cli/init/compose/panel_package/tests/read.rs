//! Reading the pin file from disk: absent is "not installed", unusable is an
//! error that names the file, and a FIFO is never read from.

use super::*;

const GOOD: &str = "ghcr.io/glyndor/epistle-panel:0.3.1\n";

#[test]
fn a_missing_file_is_a_package_that_is_not_installed() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(installed(&dir.path().join("image")), Ok(None));
	assert_eq!(installed(&dir.path().join("no/such/dir/image")), Ok(None));
}

#[test]
fn the_file_the_package_installs_gives_its_reference() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("image");
	std::fs::write(&path, GOOD).expect("write");
	assert_eq!(
		installed(&path),
		Ok(Some("ghcr.io/glyndor/epistle-panel:0.3.1".to_string()))
	);
}

#[test]
fn an_unusable_file_is_an_error_that_names_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("image");
	std::fs::write(&path, "ghcr.io/glyndor/epistle:0.3.1\n").expect("write");
	let error = installed(&path).expect_err("wrong repository");
	assert!(
		error.starts_with(&format!("{} is not usable: ", path.display())),
		"{error}"
	);
	assert!(
		error.contains("is not ghcr.io/glyndor/epistle-panel:<tag>"),
		"{error}"
	);
}

#[test]
fn a_file_that_is_not_utf8_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("image");
	std::fs::write(&path, b"ghcr.io/glyndor/epistle-panel:\xff\n").expect("write");
	let error = installed(&path).expect_err("not utf-8");
	assert!(error.ends_with("is not valid UTF-8"), "{error}");
}

#[test]
fn a_directory_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let error = installed(dir.path()).expect_err("directory");
	assert!(error.contains("cannot read"), "{error}");
	assert!(
		error.contains(crate::cli::regular::read::NOT_REGULAR),
		"{error}"
	);
}

/// A FIFO without a writer blocks a plain `open` for reading. The update
/// holds the stack lock while it reads, so the refusal has to come at once.
#[test]
fn a_fifo_is_refused_without_blocking() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("image");
	let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("no NUL");
	// SAFETY: `c_path` is a NUL-terminated C string that outlives the call.
	let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
	assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
	let (sender, receiver) = std::sync::mpsc::channel();
	let probe = path.clone();
	std::thread::spawn(move || {
		let _ = sender.send(installed(&probe));
	});
	let result = receiver
		.recv_timeout(std::time::Duration::from_secs(10))
		.expect("the read must not wait for a writer");
	let error = result.expect_err("fifo");
	assert!(
		error.contains(crate::cli::regular::read::NOT_REGULAR),
		"{error}"
	);
}
