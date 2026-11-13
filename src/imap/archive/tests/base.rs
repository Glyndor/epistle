use super::*;
use crate::imap::archive;
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;
use crate::util::path_component::{AccountName, AccountRoot};
use uuid::Uuid;

fn root(data_dir: &Path, account: &str) -> AccountRoot {
	AccountName::new(account)
		.expect("valid account")
		.root(data_dir)
		.expect("account root")
}

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
		archive::list(&root(dir.path(), "alice"))
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
	let entries = archive::list(&root(dir.path(), "alice")).expect("list");
	assert!(
		entries.is_empty(),
		"restored entry must be gone from archive"
	);
}

#[test]
fn restore_returns_a_message_to_its_subfolder() {
	let dir = tempfile::tempdir().expect("tempdir");
	mailbox::create(dir.path(), "alice", "Work/Project").expect("create");
	let id = delivered(
		dir.path(),
		"alice",
		"Work/Project",
		b"Subject: hi\r\n\r\nbody\r\n",
	);
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"alice",
		"Work/Project",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");
	let restored_to =
		archive::restore(dir.path(), "alice", id, &MessageCrypto::disabled()).expect("restore");
	assert_eq!(restored_to, "Work/Project");
	let snapshot = Snapshot::open(
		dir.path(),
		"alice",
		"Work/Project",
		&MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(snapshot.len(), 1);
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

mod session;
mod sweep;
