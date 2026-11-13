//! Archive sweep, listing and usage tests.

use super::*;

#[test]
fn sweep_with_injected_clock_purges_only_old_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let old_id = delivered(dir.path(), "alice", "INBOX", b"old\r\n");
	let young_id = delivered(dir.path(), "alice", "INBOX", b"young\r\n");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	// Expunge the second message 29 days later.
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000 + 29 * 86_400,
	)
	.expect("snapshot");
	// The first message is gone; the new seq 1 is `young_id`.
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	// Now sweep at "31 days after the first deletion": the old entry is 31
	// days old and must go; the young entry is 0 days old and must stay.
	let now = 1_000 + 31 * 86_400;
	let removed = archive::sweep(dir.path(), 30, now).expect("sweep");
	assert_eq!(removed, 1, "exactly the older entry must be purged");

	let entries = archive::list(&root(dir.path(), "alice")).expect("list");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].id, young_id);
	// The first deletion id is gone from disk.
	let archive = dir.path().join("accounts/alice/.archive");
	assert!(!archive.join(format!("{old_id}.eml")).exists());
	assert!(archive.join(format!("{young_id}.eml")).exists());
}

#[test]
fn sweep_with_zero_retention_is_a_noop() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"x\r\n");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	// Retention flipped to 0 — sweep must not touch the existing entry.
	let removed = archive::sweep(dir.path(), 0, 1_000 + 1_000 * 86_400).expect("sweep");
	assert_eq!(removed, 0);
	let entries = archive::list(&root(dir.path(), "alice")).expect("list");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].id, id);
}

#[test]
fn archived_bytes_are_identical_to_mailbox_when_encrypted() {
	let key = [7u8; 32];
	let crypto = MessageCrypto::for_test(&key);
	let dir = tempfile::tempdir().expect("tempdir");
	let body = b"Subject: secret\r\n\r\nbody\r\n";
	let id = mailbox::append(dir.path(), "alice", "INBOX", &[], body, &crypto).expect("append");
	let mailbox_path = dir
		.path()
		.join("accounts/alice/new")
		.join(format!("{id}.eml"));
	let bytes_in_mailbox = std::fs::read(&mailbox_path).expect("read mailbox");

	let mut snapshot =
		Snapshot::open_at(dir.path(), "alice", "INBOX", &crypto, 30, 1_000).expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	let archived_path = dir
		.path()
		.join("accounts/alice/.archive")
		.join(format!("{id}.eml"));
	let bytes_in_archive = std::fs::read(&archived_path).expect("read archive");
	assert_eq!(
		bytes_in_mailbox, bytes_in_archive,
		"archived bytes must be identical to the mailbox (encryption untouched)",
	);
	// And the body is still encrypted — it is not the plaintext.
	assert_ne!(
		bytes_in_archive, body,
		"archived bytes must remain ciphertext, not plaintext",
	);
}

#[test]
fn archive_listing_is_empty_when_archive_directory_is_missing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let entries = archive::list(&root(dir.path(), "alice")).expect("list");
	assert!(entries.is_empty());
}

#[test]
fn account_usage_includes_archived_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	delivered(dir.path(), "alice", "INBOX", b"hello\r\n");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	let used = mailbox::account_usage(dir.path(), "alice", &MessageCrypto::disabled());
	// 7 bytes ("hello\r\n") still count toward the quota while in the archive.
	assert_eq!(used, 7);
}

#[test]
fn archive_dir_helper_handles_folder_layout() {
	// The archive lives at the account root even when the mailbox is a folder.
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "Sent", b"x\r\n");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"Sent",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");
	let archive = dir.path().join("accounts/alice/.archive");
	assert!(archive.join(format!("{id}.eml")).exists());
}
