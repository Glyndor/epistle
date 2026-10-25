use super::*;

#[test]
fn descriptor_checks_reject_a_different_owner_and_wrong_type() {
	let dir = tempfile::tempdir().expect("dir");
	let file = File::create(dir.path().join("state")).expect("file");
	let uid = file.metadata().expect("metadata").uid();
	assert!(owned_by(&file, false, uid).is_ok());
	assert!(owned_by(&file, false, uid.wrapping_add(1)).is_err());
	assert!(owned_by(&file, true, uid).is_err());
	let directory = File::open(dir.path()).expect("dir");
	assert!(owned_by(&directory, true, uid).is_ok());
	assert!(owned_by(&directory, true, uid.wrapping_add(1)).is_err());
	assert!(owned_by(&directory, false, uid).is_err());
}

#[test]
fn an_existing_foreign_owned_directory_is_refused() {
	let path = Path::new("/etc");
	let metadata = std::fs::metadata(path).expect("system directory");
	// SAFETY: geteuid has no arguments or memory access requirements.
	if metadata.uid() != unsafe { libc::geteuid() } {
		assert!(root(path).is_err());
	}
}

#[test]
fn ownership_error_explains_the_data_directory_requirement() {
	let dir = tempfile::tempdir().expect("dir");
	let file = File::open(dir.path()).unwrap();
	let owner = file.metadata().unwrap().uid();
	let error = owned_by(&file, true, owner.wrapping_add(1))
		.unwrap_err()
		.to_string();
	assert!(
		error.contains("data_dir") && error.contains("effective user"),
		"operator guidance: {error}"
	);
}

#[test]
fn scratch_storage_is_private_unlinked_and_rejects_linked_roots() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let mut file = scratch(&root(dir.path()).unwrap()).unwrap();
	assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
	assert_eq!(file.metadata().unwrap().nlink(), 0);
	file.write_all(b"index data").unwrap();
	assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
	let link = dir.path().join("linked");
	std::os::unix::fs::symlink(dir.path(), &link).unwrap();
	assert!(root(&link).is_err());
}

#[test]
fn reading_state_for_a_dry_run_creates_nothing_but_still_checks_the_owner() {
	let dir = tempfile::tempdir().unwrap();
	let root = root(dir.path()).unwrap();
	let error = directory(&root, "alice", false).unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::NotFound);
	assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
	directory(&root, "alice", true).unwrap();
	let existing = directory(&root, "alice", false).unwrap();
	let owner = existing.metadata().unwrap().uid();
	assert!(owned_by(&existing, true, owner.wrapping_add(1)).is_err());
}
