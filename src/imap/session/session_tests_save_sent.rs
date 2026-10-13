//! Tests for the IMAP APPEND dedup path: when a client appends a
//! Message-ID the server already saved to `Sent` within the dedup
//! window, the server returns `OK [APPENDUID ...]` with the UID of
//! the copy it stored and does not produce a second copy.

use super::*;

fn ensure_account_dir(dir: &std::path::Path, account: &str) {
	let account_dir = dir.join("accounts").join(account);
	std::fs::create_dir_all(account_dir.join("new")).unwrap();
	std::fs::create_dir_all(account_dir.join("tmp")).unwrap();
	std::fs::create_dir_all(account_dir.join("folders")).unwrap();
}

#[test]
fn an_append_of_a_message_id_the_server_just_saved_returns_the_existing_uid() {
	let dir = tempfile::tempdir().expect("tempdir");
	ensure_account_dir(dir.path(), "alice");
	let message = b"Message-ID: <dup@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	// Pre-stage the server's save: a real entry on disk.
	let saved_uid = crate::imap::mailbox::append_dated(
		dir.path(),
		"alice",
		"Sent",
		&[crate::imap::mailbox::Flag::Seen],
		None,
		message,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("server-side save");
	let (_validity, expected_uid) =
		crate::imap::mailbox::appenduid(dir.path(), "alice", "Sent", saved_uid).expect("lookup");
	// Record the Message-ID in the guard so the IMAP dedup fast
	// path is satisfied.
	crate::storage::save_sent::Guard::open(dir.path(), "alice")
		.expect("guard")
		.record("<dup@x>")
		.expect("record");
	// Client now APPENDs the same Message-ID to Sent. The server
	// must answer `OK [APPENDUID ...]` with the existing UID and
	// must not write a second copy.
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND Sent {50}");
	assert_eq!(output.collect_literal, Some(50));
	assert!(text(&output).starts_with("+ "));
	let output = session.literal_done(message);
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	assert!(
		response.contains("[APPENDUID"),
		"APPENDUID present: {response}"
	);
	assert!(
		response.contains(&format!(" {}]", expected_uid)),
		"APPENDUID carries the existing UID {expected_uid}: {response}"
	);
	let snapshot = crate::imap::mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"Sent",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(
		snapshot.messages().count(),
		1,
		"no duplicate was appended; still exactly one message"
	);
}

#[test]
fn an_append_of_an_unrelated_message_id_still_stores() {
	let dir = tempfile::tempdir().expect("tempdir");
	ensure_account_dir(dir.path(), "alice");
	// Stage a server-side save under a different Message-ID, so the
	// guard has an entry that does not match the client's literal.
	let server_message = b"Message-ID: <server@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	crate::imap::mailbox::append_dated(
		dir.path(),
		"alice",
		"Sent",
		&[crate::imap::mailbox::Flag::Seen],
		None,
		server_message,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("server save");
	crate::storage::save_sent::Guard::open(dir.path(), "alice")
		.expect("guard")
		.record("<server@x>")
		.expect("record");
	// The client appends a different Message-ID; the dedup path
	// does not trigger, the literal lands normally.
	let client_message = b"Message-ID: <client@x>\r\nSubject: bye\r\n\r\nbye\r\n";
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND Sent {50}");
	assert_eq!(output.collect_literal, Some(50));
	let output = session.literal_done(client_message);
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	let snapshot = crate::imap::mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"Sent",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(
		snapshot.messages().count(),
		2,
		"both messages are present: the server-saved one and the client append"
	);
}

#[test]
fn an_append_to_a_mailbox_other_than_sent_ignores_the_guard() {
	let dir = tempfile::tempdir().expect("tempdir");
	ensure_account_dir(dir.path(), "alice");
	// Stage a server-side save to Sent so the guard has the id.
	let server_message = b"Message-ID: <copy@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	crate::imap::mailbox::append_dated(
		dir.path(),
		"alice",
		"Sent",
		&[crate::imap::mailbox::Flag::Seen],
		None,
		server_message,
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("server save");
	crate::storage::save_sent::Guard::open(dir.path(), "alice")
		.expect("guard")
		.record("<copy@x>")
		.expect("record");
	// The client APPENDs the same Message-ID to INBOX. The dedup
	// path only fires for Sent; INBOX must accept the literal.
	let client_message = b"Message-ID: <copy@x>\r\nSubject: hi\r\n\r\nbody\r\n";
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND INBOX {50}");
	assert_eq!(output.collect_literal, Some(50));
	let output = session.literal_done(client_message);
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	let snapshot = crate::imap::mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"INBOX",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(snapshot.messages().count(), 1, "INBOX now has the message");
	let sent = crate::imap::mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"Sent",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("sent snapshot");
	assert_eq!(
		sent.messages().count(),
		1,
		"Sent is unchanged: the guard is Sent-only"
	);
}

#[test]
fn an_append_without_a_message_id_is_unaffected_by_the_dedup() {
	let dir = tempfile::tempdir().expect("tempdir");
	ensure_account_dir(dir.path(), "alice");
	let client_message = b"Subject: hi\r\n\r\nbody\r\n";
	let mut session = logged_in(dir.path());
	let output = session.command_line("a2 APPEND Sent {30}");
	assert_eq!(output.collect_literal, Some(30));
	let output = session.literal_done(client_message);
	let response = text(&output);
	assert!(response.contains("a2 OK"), "{response}");
	let snapshot = crate::imap::mailbox::Snapshot::open(
		dir.path(),
		"alice",
		"Sent",
		&crate::storage::MessageCrypto::disabled(),
	)
	.expect("snapshot");
	assert_eq!(
		snapshot.messages().count(),
		1,
		"a literal without Message-ID lands normally"
	);
}
