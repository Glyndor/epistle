//! A recorded role follows its folder through RENAME and dies with DELETE,
//! and a folder the account no longer has is never brought back by a role.

use super::*;
use crate::imap::mailbox;
use crate::imap::special_use::FolderPolicy;

const ACCOUNT: &str = "alice@example.org";

fn account() -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = dir.path().to_path_buf();
	mailbox::ensure_defaults(&data, ACCOUNT).expect("defaults");
	(dir, data)
}

#[test]
fn renaming_a_folder_moves_its_role() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Spam").expect("create");
	set(&data, ACCOUNT, Role::Junk, "Spam").expect("set");
	mailbox::rename(&data, ACCOUNT, "Spam", "Basura").expect("rename");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.recorded(Role::Junk), Some("Basura"));
	assert_eq!(roles.attribute("Basura"), "\\Junk");
	assert_eq!(
		roles.attribute("Spam"),
		"",
		"the old name lost the role with the rename"
	);
}

#[test]
fn renaming_a_parent_moves_the_role_of_a_child() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Old/Out").expect("create");
	set(&data, ACCOUNT, Role::Sent, "Old/Out").expect("set");
	mailbox::rename(&data, ACCOUNT, "Old", "New").expect("rename");
	assert_eq!(
		Roles::load(&data, ACCOUNT).recorded(Role::Sent),
		Some("New/Out")
	);
}

#[test]
fn deleting_a_folder_drops_its_role_and_a_delivery_does_not_bring_it_back() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Basura").expect("create");
	set(&data, ACCOUNT, Role::Junk, "Basura").expect("set");
	mailbox::delete(&data, ACCOUNT, "Basura").expect("delete");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.recorded(Role::Junk), None);
	let single = single_spam_policy();
	assert_eq!(single.delivery_target(&data, ACCOUNT, "Rejects"), "Junk");
	assert!(!mailbox::exists(&data, ACCOUNT, "Basura"));
}

#[test]
fn a_record_whose_folder_vanished_is_not_used() {
	let (_dir, data) = account();
	mailbox::create(&data, ACCOUNT, "Basura").expect("create");
	set(&data, ACCOUNT, Role::Junk, "Basura").expect("set");
	// The folder goes behind the account's back (a restore, an operator).
	std::fs::remove_dir_all(data.join("accounts/alice@example.org/folders/Basura")).expect("rm");
	let roles = Roles::load(&data, ACCOUNT);
	assert_eq!(roles.folder(&data, ACCOUNT, Role::Junk, "Junk"), "Junk");
	let two = FolderPolicy::default();
	assert_eq!(two.delivery_target(&data, ACCOUNT, "Rejects"), "Rejects");
}

fn single_spam_policy() -> FolderPolicy {
	let (_dir, config) = super::config("[storage.folders]\nsingle_spam_folder = true\n");
	FolderPolicy::from_config(&config)
}
