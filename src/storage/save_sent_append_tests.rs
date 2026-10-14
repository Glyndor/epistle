//! Tests for the IMAP APPEND side of the dedup: the path that the IMAP
//! session walks when a client appends its own copy of a message the
//! server just saved to `Sent`.

use super::*;
use crate::imap::mailbox;
use crate::storage::MessageCrypto;
use crate::util::path_component::{AccountName, FixedDir};
use crate::util::path_containment::contained_child;
use std::fs;

fn temp_data_dir() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

fn ensure_account(data_dir: &std::path::Path, account: &str) {
	let account_name = AccountName::new(account).expect("valid account");
	let root = account_name.root(data_dir).expect("root");
	fs::create_dir_all(root.child(FixedDir::New).unwrap()).unwrap();
	fs::create_dir_all(root.child(FixedDir::Tmp).unwrap()).unwrap();
	fs::create_dir_all(root.child(FixedDir::Folders).unwrap()).unwrap();
}

#[test]
fn store_copy_records_message_id_and_returns_uid() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let message = b"Message-ID: <a@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	let uid = store_copy(
		dir.path(),
		"alice",
		message,
		"<a@x>",
		&MessageCrypto::disabled(),
		None,
	)
	.expect("store");
	assert!(uid >= 1, "uid should be at least 1, got {uid}");
	let guard = Guard::open(dir.path(), "alice").expect("guard");
	assert!(
		guard.is_recent("<a@x>").expect("recent").is_some(),
		"the guard records the message id we just stored"
	);
}

#[test]
fn lookup_sent_uid_finds_the_message_we_just_stored() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let message = b"Message-ID: <b@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	let uid = store_copy(
		dir.path(),
		"alice",
		message,
		"<b@x>",
		&MessageCrypto::disabled(),
		None,
	)
	.expect("store");
	let found = lookup_sent_uid(dir.path(), "alice", "<b@x>").expect("lookup");
	assert_eq!(found, Some(uid), "lookup finds the message we just stored");
}

#[test]
fn lookup_sent_uid_returns_none_for_a_missing_message_id() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let found = lookup_sent_uid(dir.path(), "alice", "<missing@x>").expect("lookup");
	assert_eq!(found, None);
}

#[test]
fn store_copy_creates_the_sent_mailbox_when_missing() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	// `ensure_defaults` would have created `Sent`, but the test runs with
	// a manual setup; the saver's own call to `ensure_defaults` must
	// produce the folder.
	let message = b"Message-ID: <c@x>\r\n\r\nbody\r\n";
	store_copy(
		dir.path(),
		"alice",
		message,
		"<c@x>",
		&MessageCrypto::disabled(),
		None,
	)
	.expect("store");
	assert!(
		mailbox::exists(dir.path(), "alice", "Sent"),
		"saver created the Sent folder"
	);
}

#[test]
fn store_copy_appends_with_the_seen_flag_set() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let message = b"Message-ID: <d@x>\r\n\r\nbody\r\n";
	store_copy(
		dir.path(),
		"alice",
		message,
		"<d@x>",
		&MessageCrypto::disabled(),
		None,
	)
	.expect("store");
	// Open the snapshot for Sent and check the flag sidecar.
	let sent = mailbox_dir_for_test(dir.path(), "alice", "Sent");
	let flag_files: Vec<_> = sent
		.read_dir()
		.unwrap()
		.flatten()
		.filter(|entry| {
			entry
				.file_name()
				.to_str()
				.is_some_and(|name| name.ends_with(".flags"))
		})
		.collect();
	assert_eq!(flag_files.len(), 1, "exactly one flag sidecar");
	let text = fs::read_to_string(flag_files[0].path()).unwrap();
	assert!(
		text.contains("seen") || text.contains("\\Seen"),
		"flag sidecar carries \\Seen: {text}"
	);
}

fn mailbox_dir_for_test(
	data_dir: &std::path::Path,
	account: &str,
	mailbox: &str,
) -> std::path::PathBuf {
	let account_name = AccountName::new(account).expect("valid account");
	let account_root = account_name.root(data_dir).expect("root");
	let folders = account_root.child(FixedDir::Folders).expect("folders");
	contained_child(&folders, mailbox)
		.expect("mailbox dir")
		.join("new")
}

#[test]
fn a_copy_that_would_exceed_the_quota_is_not_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = b"From: a@example.org\r\nMessage-ID: <q@example.org>\r\n\r\nbody\r\n";
	let crypto = MessageCrypto::disabled();
	let result = store_copy(
		dir.path(),
		"alice",
		data,
		"<q@example.org>",
		&crypto,
		Some(data.len() as u64 - 1),
	);
	assert!(matches!(result, Err(SaveError::OverQuota)), "{result:?}");
	assert!(
		lookup_sent_uid(dir.path(), "alice", "<q@example.org>")
			.unwrap_or(None)
			.is_none(),
		"nothing may be stored over quota"
	);
	store_copy(
		dir.path(),
		"alice",
		data,
		"<q@example.org>",
		&crypto,
		Some(data.len() as u64),
	)
	.expect("a copy that fits exactly is stored");
}
