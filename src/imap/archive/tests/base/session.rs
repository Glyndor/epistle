//! Archive behaviour through a real IMAP session.

use super::*;

#[test]
fn expunge_through_a_real_session_archives_rather_than_deletes() {
	// The unit tests drive `Snapshot::open_at` directly, so they keep passing
	// even if the session stops threading the retention through. That is not
	// hypothetical: a later refactor split the session into per-command files
	// and every new call site went back to `Snapshot::open`, which leaves
	// retention at zero — the feature would have been silently gone with the
	// whole suite green. This test goes in through SELECT and EXPUNGE.
	use crate::imap::session::tests::base::{logged_in, text};
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
	assert_eq!(
		archive::list(&root(dir.path(), "alice"))
			.expect("list")
			.len(),
		1
	);
}

#[test]
fn a_session_without_retention_still_deletes_in_the_act() {
	use crate::imap::session::tests::base::{logged_in, text};
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

#[test]
fn a_failed_archive_leaves_the_message_on_disk() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");

	// Occupy `.archive` with a plain file so `create_dir_all` cannot succeed.
	// This is the durable-storage failure the retention promise has to survive:
	// a full disk or a bad permission must not turn into deleted mail.
	let account = dir.path().join("accounts/alice");
	std::fs::create_dir_all(&account).expect("account dir");
	std::fs::write(account.join(".archive"), b"not a directory").expect("block archive");

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

	assert!(
		account.join("new").join(format!("{id}.eml")).exists(),
		"an unarchivable message must stay on disk, not be deleted",
	);
}

#[test]
fn purge_reclaims_a_sidecar_whose_body_never_arrived() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = dir.path().join("accounts/alice");
	let archive = account.join(".archive");
	std::fs::create_dir_all(&archive).expect("archive dir");

	// The shape a half-finished archive leaves behind: sidecar, no body.
	let id = Uuid::new_v4();
	let sidecar = archive.join(format!("{id}.deleted"));
	std::fs::write(&sidecar, b"1000\nINBOX\n").expect("sidecar");

	assert!(
		archive::list(&root(dir.path(), "alice"))
			.expect("list")
			.is_empty(),
		"a bodiless entry cannot be restored, so it must not be listed",
	);

	let removed = archive::purge(&root(dir.path(), "alice"), 86_400, 1_000_000).expect("purge");
	assert_eq!(removed, 0, "a bodiless entry is not a purged message");
	assert!(
		!sidecar.exists(),
		"purge must reclaim the orphaned sidecar; nothing else ever will",
	);
}

#[test]
fn the_body_is_the_last_thing_moved_into_the_archive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = delivered(dir.path(), "alice", "INBOX", b"Subject: hi\r\n\r\nbody\r\n");
	let account = dir.path().join("accounts/alice");
	let inbox = account.join("new");

	// Block only the body's destination, so the sidecar and the small
	// sidecars move but the `.eml` rename fails. What survives tells us the
	// order: a sidecar on disk here means it was written before the body was
	// moved, which is the invariant that keeps a half-finished archive
	// visible to `list` and `purge` instead of orphaning the message.
	let archive = account.join(".archive");
	std::fs::create_dir_all(archive.join(format!("{id}.eml"))).expect("block body");

	archive::archive_message(&root(dir.path(), "alice"), &inbox, "INBOX", id, 1_000)
		.expect_err("moving the body onto a directory must fail");

	assert!(
		archive.join(format!("{id}.deleted")).exists(),
		"the sidecar must already be written when the body move fails",
	);
	assert!(
		inbox.join(format!("{id}.eml")).exists(),
		"a failed move leaves the body in its mailbox",
	);
}
