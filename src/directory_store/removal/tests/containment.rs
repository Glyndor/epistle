//! The account root that removal deletes must be one plain directory name
//! under `accounts/`, and a link there must stay visible to the caller.

use super::*;

#[test]
fn account_root_refuses_names_that_leave_accounts() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().join("data");
	std::fs::create_dir_all(data.join("accounts")).expect("accounts");
	for name in ["../evil", "..", ".", "a/b", ""] {
		let error = account_root(&data, name).expect_err(name);
		assert_eq!(error.kind(), ErrorKind::InvalidInput, "{name:?}");
	}
}

#[test]
fn account_root_names_the_account_directory() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().canonicalize().expect("canonical").join("data");
	std::fs::create_dir_all(data.join("accounts/alice")).expect("alice");
	assert_eq!(
		account_root(&data, "alice").expect("root"),
		data.join("accounts/alice")
	);
}

#[cfg(unix)]
#[test]
fn a_link_at_the_account_root_is_still_refused_by_the_removal() {
	let outer = tempfile::tempdir().expect("tempdir");
	let data = outer.path().canonicalize().expect("canonical").join("data");
	std::fs::create_dir_all(data.join("accounts/bob")).expect("bob");
	std::os::unix::fs::symlink(data.join("accounts/bob"), data.join("accounts/alice"))
		.expect("link");
	let root = account_root(&data, "alice").expect("root");
	let error = remove_mailbox_dir(&root).expect_err("link at the root");
	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	assert!(data.join("accounts/bob").is_dir());
}
