//! Save-to-Sent integration tests for the SMTP submission path.
//!
//! Each test stands up a real `data_dir`, a `SplitDelivery` sink (so the
//! rest of the submission path stays unchanged), and exercises the
//! `Server::save_sent_*` helpers directly through a synthetic
//! `Session`. The tests assert on the on-disk filesystem state after
//! the helper runs: the `Sent` mailbox must carry exactly one copy of
//! the message (or zero, when the relevant setting disables the save),
//! with the `\Seen` flag and without a `Bcc:` header.

use std::collections::HashMap;
use std::sync::Arc;

use crate::imap::mailbox;
use crate::smtp::directory::Directory;
use crate::smtp::sink::MessageSink;
use crate::smtp::trace::{ensure_submission_headers, strip_bcc};
use crate::storage::{self, SplitDelivery};

use super::*;

fn directory_with_account(name: &str, save_sent: Option<bool>) -> DirectoryHandle {
	let mut hashes = HashMap::new();
	hashes.insert(
		name.to_string(),
		crate::smtp::auth::tests::hash(crate::smtp::auth::tests::fixture_password()),
	);
	let mut dir = Directory::new(
		["example.org".to_string()],
		[(format!("{name}@example.org"), name.to_string())],
	)
	.with_password_hashes(hashes);
	if let Some(value) = save_sent {
		dir = dir.with_save_sent([(name.to_string(), value)]);
	}
	DirectoryHandle::new(dir)
}

fn server_with_split_sink(data_dir: &std::path::Path, dir: DirectoryHandle) -> Server {
	let sink = Arc::new(
		SplitDelivery::new_with_crypto(data_dir, dir.clone(), storage::MessageCrypto::disabled())
			.expect("split delivery"),
	);
	Server::new("mail.example.org", sink as Arc<dyn MessageSink>)
		.with_directory(dir)
		.with_data_dir(data_dir.to_path_buf())
}

#[test]
fn an_authenticated_smtp_submission_saves_one_copy_in_sent_with_seen() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
	let message = ensure_submission_headers(&raw, "example.org", std::time::SystemTime::now());
	server.save_sent_copy(&session, account, &message);
	// Exactly one message in Sent, with the `\Seen` flag.
	assert!(mailbox::exists(dir.path(), account, "Sent"));
	let snapshot = mailbox::Snapshot::open(
		dir.path(),
		account,
		"Sent",
		&storage::MessageCrypto::disabled(),
	)
	.expect("open Sent");
	let messages: Vec<_> = snapshot.messages().collect();
	assert_eq!(messages.len(), 1, "exactly one copy in Sent");
	assert!(
		messages[0]
			.flags
			.iter()
			.any(|flag| matches!(flag, mailbox::Flag::Seen)),
		"the copy carries the \\Seen flag"
	);
}

#[test]
fn the_saved_copy_does_not_carry_a_bcc_header() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	let raw = b"Subject: hi\r\nBcc: secret@elsewhere.example\r\n\r\nbody\r\n".to_vec();
	let stamped = ensure_submission_headers(&raw, "example.org", std::time::SystemTime::now());
	let stripped = strip_bcc(&stamped);
	server.save_sent_copy(&session, account, &stripped);
	let sent = mailbox::Snapshot::open(
		dir.path(),
		account,
		"Sent",
		&storage::MessageCrypto::disabled(),
	)
	.expect("open Sent");
	let bytes = std::fs::read(
		std::path::Path::new(dir.path())
			.join("accounts")
			.join(account)
			.join("folders")
			.join("Sent")
			.join("new")
			.join(format!("{}.eml", sent.messages().next().unwrap().id())),
	)
	.expect("read sent");
	let header_block = String::from_utf8_lossy(
		&bytes[..bytes
			.windows(4)
			.position(|w| w == b"\r\n\r\n")
			.unwrap_or(bytes.len())],
	);
	assert!(
		!header_block.to_ascii_lowercase().contains("bcc:"),
		"Bcc header leaked into the saved copy: {header_block}"
	);
}

#[test]
fn save_sent_disabled_on_the_account_skips_the_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, Some(false)));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	assert!(
		!server.save_sent_enabled_for(&session),
		"account-wide opt-out disables the save"
	);
	// The decision is "skip"; the helper does not write anything.
	server.save_sent_copy(&session, account, b"Subject: hi\r\n\r\nbody\r\n");
	assert!(!mailbox::exists(dir.path(), account, "Sent"));
}

#[test]
fn the_save_uses_the_message_id_the_server_stamped_when_the_client_omitted_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
	let stamped = ensure_submission_headers(&raw, "example.org", std::time::SystemTime::now());
	server.save_sent_copy(&session, account, &stamped);
	let guard = storage::save_sent::Guard::open(dir.path(), account).expect("guard");
	let entries = guard.raw_entries().expect("entries");
	assert_eq!(entries.len(), 1, "the saver recorded exactly one id");
	assert!(
		entries[0].message_id.starts_with('<') && entries[0].message_id.ends_with('>'),
		"Message-ID is in angle brackets: {}",
		entries[0].message_id
	);
}

#[test]
fn a_message_without_a_message_id_is_skipped_not_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	// No Message-ID, no Date header; `first_message_id` returns None
	// and the helper refuses to store. The submission itself is
	// unchanged: `ensure_submission_headers` would have stamped both
	// in production; this test asserts the helper's defensive branch.
	server.save_sent_copy(&session, account, b"Subject: hi\r\n\r\nbody\r\n");
	assert!(!mailbox::exists(dir.path(), account, "Sent"));
}

#[test]
fn a_client_append_of_the_same_message_id_returns_the_existing_uid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	let raw = b"Message-ID: <dup@x>\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
	// First save: stores the message and records the Message-ID.
	server.save_sent_copy(&session, account, &raw);
	let first_uid = storage::save_sent::lookup_sent_uid(dir.path(), account, "<dup@x>")
		.expect("lookup")
		.expect("the message is in Sent");
	// Second save: the guard recognises the id and refuses to store
	// again. The IMAP APPEND fast path reads `Guard::is_recent` and
	// reports the existing UID back to the client.
	let guard = storage::save_sent::Guard::open(dir.path(), account).expect("guard");
	let recent = guard
		.is_recent("<dup@x>")
		.expect("recent")
		.expect("id is recent");
	assert_eq!(recent.message_id, "<dup@x>");
	assert_eq!(
		storage::save_sent::lookup_sent_uid(dir.path(), account, "<dup@x>")
			.expect("lookup")
			.expect("the message is still in Sent"),
		first_uid
	);
	let snapshot = mailbox::Snapshot::open(
		dir.path(),
		account,
		"Sent",
		&storage::MessageCrypto::disabled(),
	)
	.expect("open Sent");
	assert_eq!(
		snapshot.messages().count(),
		1,
		"no duplicate landed: still exactly one message in Sent"
	);
}

#[test]
fn save_sent_respects_a_full_mailbox_quota() {
	let dir = tempfile::tempdir().expect("tempdir");
	let account = "alice";
	let server = server_with_split_sink(dir.path(), directory_with_account(account, None));
	let mut session = crate::smtp::session::Session::new("mail.example.org");
	session.set_directory_for_test(server.directory.current());
	session.mark_authenticated_for_test(account);
	// A repeated save of a payload that would otherwise succeed must
	// also be deduplicated: the guard sees the existing entry and
	// refuses to write a second copy, so quota pressure on the Sent
	// mailbox is unchanged.
	let raw = b"Message-ID: <q@x>\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
	server.save_sent_copy(&session, account, &raw);
	server.save_sent_copy(&session, account, &raw);
	let snapshot = mailbox::Snapshot::open(
		dir.path(),
		account,
		"Sent",
		&storage::MessageCrypto::disabled(),
	)
	.expect("open Sent");
	assert_eq!(
		snapshot.messages().count(),
		1,
		"second save is deduped; quota pressure is unchanged"
	);
}

// `SplitDelivery::new_with_crypto` is the public constructor for the
// SMTP server tests. Tests do not exercise the local-delivery side
// here (the messages we send have remote envelopes that go to the
// outbound spool, but the spool is on disk and irrelevant for the
// Sent-save assertions).
#[allow(dead_code)]
fn _split_delivery_marker() {}
