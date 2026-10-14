use super::*;

fn state(last_uid: u32) -> FolderState {
	FolderState {
		folder: "INBOX".to_string(),
		uid_validity: 7,
		last_uid,
		in_progress: false,
		copied: 3,
	}
}

#[test]
fn saves_and_loads_per_source_and_folder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let states = StateDir::open(dir.path(), "alice", "a@old:993").expect("open");
	assert_eq!(states.load(b"INBOX").expect("load"), None);
	states.save(b"INBOX", &state(5)).expect("save");
	assert_eq!(states.load(b"INBOX").expect("load"), Some(state(5)));
	assert_eq!(
		states.load(b"inbox").expect("load"),
		None,
		"folder names keep their case"
	);
	let other = StateDir::open(dir.path(), "alice", "b@old:993").expect("open");
	assert_eq!(
		other.load(b"INBOX").expect("load"),
		None,
		"another source starts fresh"
	);
	states.save(b"INBOX", &state(9)).expect("save");
	assert_eq!(states.load(b"INBOX").expect("load"), Some(state(9)));
}

#[cfg(unix)]
#[test]
fn files_are_private() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let states = StateDir::open(dir.path(), "alice", "a@old:993").expect("open");
	states.save(b"INBOX", &state(1)).expect("save");
	let alice = dir.path().join("migrate/alice");
	assert_eq!(
		std::fs::metadata(&alice).expect("dir").permissions().mode() & 0o777,
		0o700
	);
	for entry in std::fs::read_dir(&alice).expect("list") {
		let mode = entry
			.expect("entry")
			.metadata()
			.expect("meta")
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600);
	}
}

#[test]
fn a_corrupt_file_is_an_error_not_a_fresh_start() {
	let dir = tempfile::tempdir().expect("tempdir");
	let states = StateDir::open(dir.path(), "alice", "a@old:993").expect("open");
	states.save(b"INBOX", &state(1)).expect("save");
	let file = std::fs::read_dir(dir.path().join("migrate/alice"))
		.expect("list")
		.next()
		.expect("one")
		.expect("entry")
		.path();
	std::fs::write(&file, b"{not json").expect("corrupt");
	assert!(states.load(b"INBOX").is_err());
}

#[test]
fn an_account_name_that_is_not_a_path_component_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	for bad in ["../x", "a/b", ".."] {
		assert!(StateDir::open(dir.path(), bad, "s").is_err(), "{bad}");
	}
}
