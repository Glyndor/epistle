//! Hierarchical folder names (`Work/Project`) reach the filesystem as one
//! directory under `folders/`, never as nested directories.

use super::*;

fn data_dir() -> (tempfile::TempDir, PathBuf) {
	let guard = tempfile::tempdir().expect("tempdir");
	let data = guard.path().canonicalize().expect("canonical").join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	(guard, data)
}

#[test]
fn a_hierarchical_name_is_a_folder() {
	for name in ["Work/Project", "INBOX/child", "a/b/c"] {
		assert_eq!(MailboxName::new(name), Ok(MailboxName::Folder(name)));
		assert_eq!(MailboxName::folder(name), Ok(MailboxName::Folder(name)));
	}
	for name in ["a//b", "/a", "a/", "a/.x", "a&AC8-b"] {
		assert_eq!(MailboxName::new(name), Err(InvalidComponent), "{name:?}");
	}
}

#[test]
fn a_hierarchical_folder_is_one_flat_directory() {
	let (_guard, data) = data_dir();
	let account = AccountName::new("alice").expect("account");
	let project = MailboxName::new("Work/Project").expect("folder");
	assert_eq!(
		project.messages_dir(&account, &data).expect("messages dir"),
		data.join("accounts/alice/folders/Work&AC8-Project/new")
	);
	assert_eq!(
		project.folder_dir(&account, &data).expect("folder dir"),
		Some(data.join("accounts/alice/folders/Work&AC8-Project"))
	);
	let child = MailboxName::new("inbox/child").expect("folder");
	assert_eq!(
		child.folder_dir(&account, &data).expect("folder dir"),
		Some(data.join("accounts/alice/folders/INBOX&AC8-child")),
		"the INBOX level is spelled one way on disk"
	);
}

#[test]
fn an_unchecked_traversal_stays_one_component_under_folders() {
	// The delimiter never reaches the filesystem as a separator, so even a
	// name that skipped validation names one directory inside `folders/`.
	let (_guard, data) = data_dir();
	let account = AccountName::new("alice").expect("account");
	std::fs::create_dir_all(data.join("accounts/alice/folders")).expect("tree");
	let folders = data.join("accounts/alice/folders");
	for name in ["../../bob", "../../../../outside", "a/../../x"] {
		let dir = MailboxName::Folder(name)
			.folder_dir(&account, &data)
			.expect("contained")
			.expect("a folder");
		assert_eq!(dir.parent(), Some(folders.as_path()), "{name:?}");
	}
}
