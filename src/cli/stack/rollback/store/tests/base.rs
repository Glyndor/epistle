//! Validate opened rollback sources and install from the verified descriptor.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn mode(path: &Path) -> u32 {
	std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";

#[test]
fn source_links_and_non_root_files_are_rejected() {
	let temp = tempfile::tempdir().unwrap();
	std::fs::write(temp.path().join("binary"), "abc").unwrap();
	std::fs::set_permissions(
		temp.path().join("binary"),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	symlink("binary", temp.path().join("link")).unwrap();
	let dir = File::open(temp.path()).unwrap();
	assert_eq!(
		checked_file(&dir, 0, "link").unwrap_err().raw_os_error(),
		Some(libc::ELOOP)
	);
	// A normal unprivileged test run must exercise the ownership refusal.
	if dir.metadata().unwrap().uid() != 0 {
		let error = checked_file(&dir, 0, "binary").unwrap_err();
		assert!(error.to_string().contains("root-owned"));
	}
	assert!(checked_file(&dir, 0, ".").is_err());
	assert!(checked_file(&dir, 0, "../binary").is_err());
	assert!(checked_file(&dir, 0, "missing").is_err());
}

#[test]
fn non_regular_sources_are_rejected_without_reading_them() {
	let temp = tempfile::tempdir().unwrap();
	std::fs::create_dir(temp.path().join("directory")).unwrap();
	let fifo = CString::new(temp.path().join("fifo").as_os_str().as_bytes()).unwrap();
	// SAFETY: fifo is a valid path C string throughout the call.
	assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
	let dir = File::open(temp.path()).unwrap();
	for name in ["directory", "fifo"] {
		assert!(
			checked_file(&dir, 0, name)
				.unwrap_err()
				.to_string()
				.contains("regular")
		);
	}
}

#[test]
fn digest_verification_rewinds_and_rejects_altered_or_missing_manifests() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("binary");
	std::fs::write(&path, "abc").unwrap();
	let mut file = File::open(&path).unwrap();
	verify_digest(&mut file, ABC_SHA256).unwrap();
	let mut bytes = String::new();
	file.read_to_string(&mut bytes).unwrap();
	assert_eq!(bytes, "abc");
	for manifest in ["", ABC_SHA256.trim(), "invalid\n"] {
		assert!(verify_digest(&mut File::open(&path).unwrap(), manifest).is_err());
	}
	std::fs::write(&path, "abd").unwrap();
	assert!(verify_digest(&mut File::open(path).unwrap(), ABC_SHA256).is_err());
}

#[test]
fn installation_uses_the_open_descriptor_and_an_atomic_private_copy() {
	let temp = tempfile::tempdir().unwrap();
	let source = temp.path().join("source");
	let installed = temp.path().join("installed");
	std::fs::write(&source, "abc").unwrap();
	std::fs::write(&installed, "current").unwrap();
	let mut binary = File::open(&source).unwrap();
	verify_digest(&mut binary, ABC_SHA256).unwrap();
	std::fs::rename(&source, temp.path().join("original")).unwrap();
	std::fs::write(source, "replacement").unwrap();
	install(&mut binary, &installed).unwrap();
	assert_eq!(std::fs::read_to_string(&installed).unwrap(), "abc");
	assert_eq!(
		installed.metadata().unwrap().permissions().mode() & 0o777,
		0o755
	);
	assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 3);
	let target_directory = temp.path().join("target-directory");
	std::fs::create_dir(&target_directory).unwrap();
	binary.rewind().unwrap();
	assert!(install(&mut binary, &target_directory).is_err());
	assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 4);
}

#[test]
fn directory_validation_requires_protected_root_parents_and_private_store() {
	let temp = tempfile::tempdir().unwrap();
	let file = File::open(temp.path()).unwrap();
	if file.metadata().unwrap().uid() != 0 {
		assert!(check_directory(&file, ROOT, true).is_err());
	}
	assert!(Store::open(Path::new("relative")).is_err());
	assert!(Store::open(Path::new("/usr/../usr")).is_err());
	let link = temp.path().join("linked");
	symlink("/usr", &link).unwrap();
	assert!(Store::open(&link).is_err());
	assert!(Store::open(&temp.path().join("missing")).is_err());
}

mod published;
mod sandbox;
