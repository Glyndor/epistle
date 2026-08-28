use super::*;
use crate::imap::archive;
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;
use uuid::Uuid;

fn delivered(dir: &Path, account: &str, mailbox: &str, body: &[u8]) -> Uuid {
	mailbox::append(dir, account, mailbox, &[], body, &MessageCrypto::disabled()).expect("append")
}

#[test]
fn expunge_with_zero_retention_deletes_in_the_act() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		0,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");

	// Files are gone, no archive was created.
	let inbox = dir.path().join("accounts/alice/new");
	assert!(!inbox.join(format!("{id}.eml")).exists());
	let archive = dir.path().join("accounts/alice/.archive");
	assert!(
		!archive.exists(),
		"zero retention must not create an archive directory",
	);
	assert!(
		archive::list(&dir.path().join("accounts/alice"))
			.expect("list")
			.is_empty()
	);
}

#[test]
fn expunge_with_retention_moves_to_archive_and_writes_sidecar() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
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

	// The .eml has been moved, not deleted.
	let inbox = dir.path().join("accounts/alice/new");
	assert!(
		!inbox.join(format!("{id}.eml")).exists(),
		"original mailbox must be empty after expunge",
	);
	let archive = dir.path().join("accounts/alice/.archive");
	let archived = archive.join(format!("{id}.eml"));
	assert!(archived.exists(), "archived .eml must exist");

	// Sidecar carries the unix time and the source mailbox name.
	let sidecar =
		std::fs::read_to_string(archive.join(format!("{id}.deleted"))).expect("read sidecar");
	let mut lines = sidecar.lines();
	assert_eq!(
		lines.next(),
		Some("1000"),
		"sidecar timestamp must match `now`"
	);
	assert_eq!(
		lines.next(),
		Some("INBOX"),
		"sidecar must record the source mailbox",
	);
}

#[test]
fn restore_roundtrips_message_back_to_mailbox_with_fresh_uid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
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

	let restored_to =
		archive::restore(dir.path(), "alice", id, &MessageCrypto::disabled()).expect("restore");
	assert_eq!(restored_to, "INBOX");

	// The restored message is a new entry, not the original UID.
	let snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"INBOX",
		&MessageCrypto::disabled(),
		0,
		2_000,
	)
	.expect("snapshot");
	assert_eq!(snapshot.len(), 1);
	// The archive is empty.
	let entries = archive::list(&dir.path().join("accounts/alice")).expect("list");
	assert!(
		entries.is_empty(),
		"restored entry must be gone from archive"
	);
}

#[test]
fn restore_falls_back_to_inbox_when_original_mailbox_was_deleted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(
		dir.path(),
		"alice",
		"Sent",
		b"Subject: sent\r\n\r\nbody\r\n",
	);
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
	// Drop the mailbox itself so the original is gone.
	mailbox::delete(dir.path(), "alice", "Sent").expect("delete Sent");

	let restored_to =
		archive::restore(dir.path(), "alice", id, &MessageCrypto::disabled()).expect("restore");
	assert_eq!(
		restored_to, "INBOX",
		"missing source mailbox must fall back to INBOX"
	);
}

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

	let entries = archive::list(&dir.path().join("accounts/alice")).expect("list");
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
	let entries = archive::list(&dir.path().join("accounts/alice")).expect("list");
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
	let entries = archive::list(&dir.path().join("accounts/alice")).expect("list");
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

#[test]
fn expunge_through_a_real_session_archives_rather_than_deletes() {
	// The unit tests drive `Snapshot::open_at` directly, so they keep passing
	// even if the session stops threading the retention through. That is not
	// hypothetical: a later refactor split the session into per-command files
	// and every new call site went back to `Snapshot::open`, which leaves
	// retention at zero — the feature would have been silently gone with the
	// whole suite green. This test goes in through SELECT and EXPUNGE.
	use crate::imap::session::tests::{logged_in, text};
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");

	let mut session = logged_in(dir.path()).with_retention_days(30);
	assert!(text(&session.command_line("a2 SELECT INBOX")).contains("a2 OK"));
	assert!(text(&session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)")).contains("a3 OK"));
	assert!(text(&session.command_line("a4 EXPUNGE")).contains("a4 OK"));

	let account = dir.path().join("accounts/alice");
	assert!(
		account.join(".archive").join(format!("{id}.eml")).exists(),
		"the session path must archive, not delete",
	);
	assert_eq!(archive::list(&account).expect("list").len(), 1);
}

#[test]
fn a_session_without_retention_still_deletes_in_the_act() {
	use crate::imap::session::tests::{logged_in, text};
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");

	let mut session = logged_in(dir.path());
	assert!(text(&session.command_line("a2 SELECT INBOX")).contains("a2 OK"));
	assert!(text(&session.command_line(r"a3 STORE 1 +FLAGS (\Deleted)")).contains("a3 OK"));
	assert!(text(&session.command_line("a4 EXPUNGE")).contains("a4 OK"));

	let account = dir.path().join("accounts/alice");
	assert!(!account.join("new").join(format!("{id}.eml")).exists());
	assert!(
		!account.join(".archive").exists(),
		"retention 0 must not start archiving on its own",
	);
}
