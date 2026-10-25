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

#[cfg(unix)]
#[test]
fn state_paths_refuse_links_and_special_files() {
	use std::os::unix::fs::symlink;
	for part in ["migrate", "migrate/alice", "final"] {
		let root = tempfile::tempdir().expect("root");
		let outside = tempfile::tempdir().expect("outside");
		let states = StateDir::open(root.path(), "alice", "source").expect("open");
		if part == "final" {
			states.save(b"INBOX", &state(1)).expect("save");
			let path = states.path(b"INBOX").expect("path");
			std::fs::remove_file(&path).expect("remove");
			let victim = outside.path().join("victim");
			std::fs::write(&victim, serde_json::to_vec(&state(9)).expect("json")).expect("write");
			symlink(&victim, &path).expect("link");
			assert!(states.load(b"INBOX").is_err(), "linked state must fail");
			assert!(
				states.save(b"INBOX", &state(2)).is_err(),
				"linked destination must fail"
			);
		} else {
			if part.contains('/') {
				std::fs::create_dir(root.path().join("migrate")).expect("parent");
			}
			symlink(outside.path(), root.path().join(part)).expect("link");
			assert!(
				states.save(b"INBOX", &state(2)).is_err(),
				"linked directory must fail: {part}"
			);
			assert!(
				std::fs::read_dir(outside.path())
					.expect("outside")
					.next()
					.is_none()
			);
		}
	}
}

#[cfg(unix)]
#[test]
fn a_preexisting_temporary_link_cannot_overwrite_another_file() {
	let root = tempfile::tempdir().expect("root");
	let states = StateDir::open(root.path(), "alice", "source").expect("open");
	states.save(b"INBOX", &state(1)).expect("save");
	let path = states.path(b"INBOX").expect("path");
	let victim = root.path().join("victim");
	std::fs::write(&victim, b"keep").expect("victim");
	std::os::unix::fs::symlink(&victim, path.with_extension("json.tmp")).expect("link");
	let _ = states.save(b"INBOX", &state(2));
	assert_eq!(std::fs::read(&victim).expect("victim"), b"keep");
	assert!(
		!std::fs::symlink_metadata(&path)
			.expect("state")
			.file_type()
			.is_symlink()
	);
}

#[cfg(unix)]
#[test]
fn state_files_must_be_regular_single_link_and_size_bounded() {
	let dir = tempfile::tempdir().expect("dir");
	let states = StateDir::open(dir.path(), "alice", "source").expect("open");
	states.save(b"INBOX", &state(1)).expect("save");
	let path = states.path(b"INBOX").expect("path");
	std::fs::remove_file(&path).expect("remove");
	assert!(
		std::process::Command::new("mkfifo")
			.arg(&path)
			.status()
			.expect("mkfifo")
			.success()
	);
	assert!(states.load(b"INBOX").is_err());
	assert!(states.save(b"INBOX", &state(2)).is_err());
	std::fs::remove_file(&path).expect("remove");
	std::fs::create_dir(&path).expect("directory");
	assert!(states.load(b"INBOX").is_err());
	assert!(states.save(b"INBOX", &state(2)).is_err());
	std::fs::remove_dir(&path).expect("remove");
	states.save(b"INBOX", &state(1)).expect("save");
	let alias = dir.path().join("alias");
	std::fs::hard_link(&path, &alias).expect("link");
	assert!(states.load(b"INBOX").is_err());
	assert!(states.save(b"INBOX", &state(2)).is_err());
	std::fs::remove_file(alias).expect("unlink");
	let mut body = serde_json::to_vec(&state(1)).expect("json");
	body.resize(MAX_STATE_BYTES as usize + 1, b' ');
	std::fs::write(&path, body).expect("large");
	assert!(
		states
			.load(b"INBOX")
			.expect_err("size")
			.to_string()
			.contains("size limit")
	);
}

#[test]
fn data_dir_itself_refuses_links_even_with_trailing_separators() {
	use std::os::unix::fs::symlink;
	let dir = tempfile::tempdir().expect("dir");
	let outside = tempfile::tempdir().expect("outside");
	let link = dir.path().join("link");
	symlink(outside.path(), &link).expect("link");
	std::fs::create_dir(outside.path().join("child")).expect("child");
	for suffix in ["", "/", "/."] {
		let root = PathBuf::from(format!("{}{suffix}", link.display()));
		assert!(
			StateDir::open(&root, "alice", "source").is_err(),
			"linked root: {root:?}"
		);
	}
	assert!(!outside.path().join("migrate").exists());
	assert!(
		StateDir::open(&dir.path().join(".."), "alice", "source").is_err(),
		"reject ambiguous parent traversal"
	);
	let normal = PathBuf::from(format!("{}/.", dir.path().display()));
	let states = StateDir::open(&normal, "alice", "source").expect("regular root");
	states.save(b"INBOX", &state(1)).expect("save");
}

#[test]
fn state_access_keeps_the_opened_root_after_its_name_is_replaced() {
	let dir = tempfile::tempdir().expect("dir");
	let root = dir.path().join("data");
	std::fs::create_dir(&root).expect("root");
	let states = StateDir::open(&root, "alice", "source").expect("open");
	let moved = dir.path().join("moved");
	std::fs::rename(&root, &moved).expect("move");
	std::fs::create_dir(&root).expect("replacement");
	states
		.save(b"INBOX", &state(1))
		.expect("save through descriptor");
	assert!(
		!root.join("migrate").exists(),
		"do not reopen the root by name"
	);
	let original = StateDir::open(&moved, "alice", "source").expect("original");
	assert_eq!(original.load(b"INBOX").expect("load"), Some(state(1)));
}

#[test]
fn a_linked_parent_of_data_dir_allows_state_and_scratch_access() {
	let dir = tempfile::tempdir().unwrap();
	let real = dir.path().join("real");
	std::fs::create_dir_all(real.join("data")).unwrap();
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&real, &link).unwrap();
	let data = link.join("data");
	let result = StateDir::open(&data, "alice", "source");
	assert!(result.is_ok(), "a linked parent is allowed");
	let states = result.unwrap();
	states.save(b"INBOX", &state(2)).unwrap();
	assert_eq!(states.load(b"INBOX").unwrap(), Some(state(2)));
	assert!(scratch(&data).is_ok(), "recovery uses the same root policy");
}

#[test]
fn a_rejected_data_dir_names_the_path_and_reason() {
	let dir = tempfile::tempdir().unwrap();
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(dir.path(), &link).unwrap();
	let error = StateDir::open(&link, "alice", "source")
		.unwrap_err()
		.to_string();
	assert!(
		error.contains(&link.display().to_string()) && error.contains("symbolic link"),
		"actionable root error: {error}"
	);
}
