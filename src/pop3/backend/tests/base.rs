use super::*;
use crate::test_fixtures as fixtures;
use std::collections::HashMap;

fn backend(dir: &std::path::Path) -> MailboxBackend {
	let directory = DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_password_hashes(HashMap::from([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixtures::password()),
		)])),
	);
	MailboxBackend::new(directory, dir.to_path_buf())
}

#[test]
fn verify_checks_credentials_without_oracle() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	assert_eq!(
		backend
			.verify("alice@example.org", fixtures::password(), None)
			.as_deref(),
		Some("alice")
	);
	// Wrong password and unknown user both fail the same way.
	assert!(
		backend
			.verify("alice@example.org", fixtures::second_password(), None)
			.is_none()
	);
	assert!(
		backend
			.verify("ghost@example.org", fixtures::password(), None)
			.is_none()
	);
}

#[test]
fn list_returns_messages_in_arrival_order() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	// No INBOX yet → empty.
	assert!(backend.list("alice").is_empty());

	crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: one\r\n\r\na\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append one");
	crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: two\r\n\r\nb\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append two");

	let messages = backend.list("alice");
	assert_eq!(messages.len(), 2);
	// UUIDv7 stems sort in arrival order, and the index carries the sizes.
	assert_eq!(messages[0].1, b"Subject: one\r\n\r\na\r\n".len());
	let first = backend.fetch("alice", &messages[0].0).expect("first");
	let second = backend.fetch("alice", &messages[1].0).expect("second");
	assert!(first.windows(3).any(|w| w == b"one"));
	assert!(second.windows(3).any(|w| w == b"two"));
}

#[test]
fn remove_deletes_named_messages() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"x\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let messages = backend.list("alice");
	assert_eq!(messages.len(), 1);
	let uid = messages[0].0.clone();

	backend.remove("alice", &[uid]);
	assert!(backend.list("alice").is_empty());
	// Removing from a missing account is a harmless no-op.
	backend.remove("nobody", &["whatever".to_string()]);
}

/// A POP3 delete is an expunge JMAP clients must learn about.
#[test]
fn remove_records_the_destroyed_message_for_jmap() {
	use crate::imap::changelog::{Change, Op};
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	let id = crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"x\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let root = dir.path().join("accounts").join("alice");
	let before = crate::imap::changelog::current(&root).expect("current");
	backend.remove("alice", &[id.to_string()]);
	let (_, entries) =
		crate::imap::changelog::since(&root, before.epoch, before.current).expect("since");
	let changes: Vec<Change> = entries.into_iter().map(|e| e.change).collect();
	assert_eq!(
		changes,
		vec![
			Change::email(Op::Destroyed, id),
			Change::mailbox(Op::Updated, "INBOX")
		]
	);
}

#[test]
fn the_index_of_an_encrypted_inbox_reports_the_plaintext_size() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");
	let backend = MailboxBackend::new_with_crypto(
		DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)),
		dir.path().to_path_buf(),
		crypto.clone(),
	);
	let raw = b"Subject: sealed\r\n\r\nbody\r\n";
	crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], raw, &crypto).expect("append");
	let index = backend.list("alice");
	assert_eq!(index.len(), 1);
	assert_eq!(index[0].1, raw.len());
	assert_eq!(
		backend.fetch("alice", &index[0].0).as_deref(),
		Some(&raw[..])
	);
}

#[test]
fn fetch_refuses_a_message_over_the_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	let id = crate::imap::mailbox::append(
		dir.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: x\r\n\r\n0123456789\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append")
	.to_string();
	assert!(backend.fetch_within("alice", &id, 8).is_none());
	assert!(backend.fetch_within("alice", &id, 1024).is_some());
}

#[test]
fn fetch_only_serves_ids_of_the_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	for uid in ["", ".", "..", "../x", "a/b", ".hidden", "a\\b"] {
		assert!(
			backend.fetch("alice", uid).is_none(),
			"an id outside the inbox is not served"
		);
	}
	assert!(backend.fetch("alice", "missing").is_none());
}

#[test]
fn list_keeps_the_newest_messages_in_arrival_order() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path());
	let ids: Vec<String> = (0..6)
		.map(|n| {
			crate::imap::mailbox::append(
				dir.path(),
				"alice",
				"INBOX",
				&[],
				format!("Subject: {n}\r\n\r\nb\r\n").as_bytes(),
				&MessageCrypto::disabled(),
			)
			.expect("append")
			.to_string()
		})
		.collect();
	let kept = backend.list_newest("alice", 3);
	let names: Vec<&str> = kept.iter().map(|(name, _)| name.as_str()).collect();
	let mut expected: Vec<&str> = ids.iter().map(String::as_str).collect();
	expected.sort_unstable();
	assert_eq!(names, expected[3..].to_vec());
	assert_eq!(backend.list_newest("alice", 100).len(), 6);
}

#[test]
fn list_returns_no_more_than_its_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let backend = backend(dir.path()).with_listed_limit(3);
	for n in 0..6 {
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			format!("Subject: {n}\r\n\r\nb\r\n").as_bytes(),
			&MessageCrypto::disabled(),
		)
		.expect("append");
	}
	assert_eq!(backend.list("alice").len(), 3);
}

#[test]
fn the_limit_of_a_backend_is_the_session_maximum() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(backend(dir.path()).listed_limit, MAX_SESSION_MESSAGES);
}
