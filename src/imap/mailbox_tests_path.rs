//! Account and mailbox names are path components: an account name that is not
//! one plain directory name must never reach the filesystem, whichever
//! mailbox operation it arrives through.

use super::*;
use crate::storage::MessageCrypto;

const BAD_ACCOUNTS: &[&str] = &["../evil", "..", ".", "", "a/b", "a\\b", "x\0y", "/abs"];

/// A data directory nested one level down, so a `..` escape lands in `root`
/// where the test can see it. `accounts/` exists, as on a live server, so a
/// `..` component resolves instead of failing on a missing parent.
fn nested() -> (tempfile::TempDir, PathBuf) {
	let root = tempfile::tempdir().expect("tempdir");
	let data = root.path().join("data");
	std::fs::create_dir_all(data.join("accounts")).expect("data dir");
	(root, data)
}

fn entries(dir: &Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir)
		.expect("read_dir")
		.flatten()
		.map(|entry| entry.file_name().to_string_lossy().into_owned())
		.collect();
	names.sort();
	names
}

#[test]
fn mailbox_dir_refuses_bad_accounts() {
	let (_root, data) = nested();
	for (case, account) in BAD_ACCOUNTS.iter().enumerate() {
		for mailbox in ["INBOX", "Work"] {
			assert_eq!(
				mailbox_dir(&data, account, mailbox),
				None,
				"bad account case {case} / mailbox {mailbox:?} must not resolve to a directory"
			);
		}
	}
}

#[test]
fn create_with_bad_account_leaves_nothing_behind() {
	let (root, data) = nested();
	for (case, account) in BAD_ACCOUNTS.iter().enumerate() {
		let result = create(&data, account, "Work");
		assert!(
			result.is_err(),
			"create for bad account case {case} must fail, got {result:?}"
		);
	}
	assert_eq!(
		entries(root.path()),
		vec!["data".to_string()],
		"no directory may appear next to the data dir"
	);
	assert_eq!(
		entries(&data),
		vec!["accounts".to_string()],
		"the data dir stays untouched"
	);
	assert!(entries(&data.join("accounts")).is_empty());
}

#[test]
fn append_with_bad_account_stores_nothing() {
	let (root, data) = nested();
	let crypto = MessageCrypto::disabled();
	for (case, account) in BAD_ACCOUNTS.iter().enumerate() {
		for mailbox in ["INBOX", "Work"] {
			let result = append(&data, account, mailbox, &[], b"x\r\n", &crypto);
			assert!(
				result.is_err(),
				"append for bad account case {case} must fail"
			);
		}
	}
	assert_eq!(entries(root.path()), vec!["data".to_string()]);
	assert_eq!(entries(&data), vec!["accounts".to_string()]);
	assert!(entries(&data.join("accounts")).is_empty());
}

#[test]
fn delete_and_rename_with_bad_account_leave_the_victim_alone() {
	let (root, data) = nested();
	// A folder that `../victim` would reach from `<data>/accounts/`.
	let victim = data.join("victim/folders/Work/new");
	std::fs::create_dir_all(&victim).expect("victim");
	assert!(delete(&data, "../victim", "Work").is_err());
	assert!(
		victim.is_dir(),
		"delete must not remove another account's folder"
	);
	let renamed = rename(&data, "../victim", "Work", "Moved");
	assert!(renamed.is_err(), "rename must refuse, got {renamed:?}");
	assert!(
		victim.is_dir(),
		"rename must not move another account's folder"
	);
	assert_eq!(entries(root.path()), vec!["data".to_string()]);
}

#[test]
fn exists_and_list_do_not_follow_a_bad_account() {
	let (_root, data) = nested();
	std::fs::create_dir_all(data.join("victim/folders/Work/new")).expect("victim");
	assert!(!exists(&data, "../victim", "Work"));
	assert_eq!(list(&data, "../victim"), vec!["INBOX".to_string()]);
}

#[test]
fn snapshot_open_refuses_a_bad_account() {
	let (_root, data) = nested();
	for (case, account) in BAD_ACCOUNTS.iter().enumerate() {
		let result = Snapshot::open(&data, account, "INBOX", &MessageCrypto::disabled());
		assert!(
			result.is_err(),
			"Snapshot::open for bad account case {case} must fail"
		);
	}
}

#[test]
fn account_usage_ignores_a_bad_account() {
	let (_root, data) = nested();
	let victim = data.join("victim/new");
	std::fs::create_dir_all(&victim).expect("victim");
	std::fs::write(
		victim.join(format!("{}.eml", Uuid::now_v7())),
		b"secret body",
	)
	.expect("write");
	assert_eq!(
		account_usage(&data, "../victim", &MessageCrypto::disabled()),
		0
	);
}

#[test]
fn legitimate_names_keep_their_layout() {
	let (_root, data) = nested();
	assert_eq!(
		mailbox_dir(&data, "alice", "INBOX"),
		Some(data.join("accounts/alice/new"))
	);
	assert_eq!(
		mailbox_dir(&data, "alice", "inbox"),
		Some(data.join("accounts/alice/new"))
	);
	assert_eq!(
		mailbox_dir(&data, "alice", "Sent Items"),
		Some(data.join("accounts/alice/folders/Sent Items/new"))
	);
	create(&data, "alice", "Archive.2024").expect("create");
	rename(&data, "alice", "Archive.2024", "Old-2024").expect("rename");
	assert_eq!(list(&data, "alice"), vec!["INBOX", "Old-2024"]);
	delete(&data, "alice", "Old-2024").expect("delete");
	assert_eq!(list(&data, "alice"), vec!["INBOX"]);
}

#[test]
fn traversals_and_empty_levels_are_refused() {
	let (_root, data) = nested();
	for mailbox in ["Archive//2024", "/Archive", "a\\b", "../x", "..", "a/.."] {
		let result = create(&data, "alice", mailbox);
		assert!(
			result.is_err(),
			"CREATE {mailbox:?} must fail, got {result:?}"
		);
		assert!(!exists(&data, "alice", mailbox));
	}
	assert!(
		entries(&data.join("accounts")).is_empty(),
		"a refused name creates nothing"
	);
}

#[test]
fn folder_names_with_dot_dot_inside_are_ordinary_names() {
	let (_root, data) = nested();
	for name in ["a..b", "Projects..2024"] {
		assert!(valid_name(name), "{name:?} is a valid folder name");
		create(&data, "alice", name).expect("create");
		assert!(exists(&data, "alice", name));
		assert_eq!(
			mailbox_dir(&data, "alice", name),
			Some(data.join(format!("accounts/alice/folders/{name}/new")))
		);
	}
	assert_eq!(
		list(&data, "alice"),
		vec!["INBOX", "Projects..2024", "a..b"]
	);
	let snapshot = Snapshot::open(&data, "alice", "a..b", &MessageCrypto::disabled());
	assert!(snapshot.is_ok(), "SELECT of a..b must open");
}

#[test]
fn an_existing_folder_with_dot_dot_inside_is_listed() {
	let (_root, data) = nested();
	std::fs::create_dir_all(data.join("accounts/alice/folders/a..b/new")).expect("folder");
	assert_eq!(list(&data, "alice"), vec!["INBOX", "a..b"]);
}

#[test]
fn single_and_double_dot_are_not_folder_names() {
	let (_root, data) = nested();
	for name in [".", ".."] {
		assert!(!valid_name(name));
		assert!(create(&data, "alice", name).is_err());
		assert!(!exists(&data, "alice", name));
	}
}

#[test]
fn ensure_defaults_refuses_bad_accounts() {
	let (root, data) = nested();
	for (case, account) in BAD_ACCOUNTS.iter().enumerate() {
		assert!(
			ensure_defaults(&data, account).is_err(),
			"defaults for bad account case {case} must fail"
		);
	}
	assert_eq!(entries(root.path()), vec!["data".to_string()]);
	assert_eq!(entries(&data), vec!["accounts".to_string()]);
	assert!(entries(&data.join("accounts")).is_empty());
}
