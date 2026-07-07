//! End-to-end tests with at-rest encryption ENABLED, proving every stored-mail
//! read path decrypts transparently. Because encryption is opt-in, the ordinary
//! (encryption-off) tests cannot catch a read site that forgot to decode: each
//! test here writes an encrypted message and asserts the PLAINTEXT comes back
//! through a real read path, and that the on-disk bytes are ciphertext.

use super::crypto::{MAGIC, MessageCrypto};
use super::delivery::LocalDelivery;
use crate::directory_store::DirectoryHandle;
use crate::imap::mailbox::{self, Snapshot};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MessageSink;

const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const BODY: &[u8] = b"Subject: secret\r\n\r\nthe plaintext body\r\n";

fn directory() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	))
}

fn message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "sender@elsewhere.example".into(),
		recipients: vec!["alice@example.org".into()],
		data: BODY.to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	}
}

/// The on-disk `.eml` files in a mailbox directory.
fn on_disk_eml(dir: &std::path::Path) -> Vec<Vec<u8>> {
	std::fs::read_dir(dir)
		.map(|entries| {
			entries
				.flatten()
				.filter(|e| e.path().extension().is_some_and(|x| x == "eml"))
				.map(|e| std::fs::read(e.path()).expect("read eml"))
				.collect()
		})
		.unwrap_or_default()
}

#[test]
fn delivery_writes_ciphertext_and_imap_reads_plaintext() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(KEY);
	let delivery =
		LocalDelivery::new_with_crypto(dir.path(), directory(), crypto.clone()).expect("delivery");
	delivery.deliver(message()).expect("deliver");

	// On disk the message is the encrypted envelope, never the plaintext.
	let new_dir = dir.path().join("accounts").join("alice").join("new");
	let files = on_disk_eml(&new_dir);
	assert_eq!(files.len(), 1);
	assert!(
		files[0].starts_with(MAGIC),
		"on-disk file must be encrypted"
	);
	assert!(
		!files[0].windows(BODY.len()).any(|w| w == BODY),
		"plaintext must not appear on disk"
	);

	// Reading back through the IMAP mailbox API yields the plaintext.
	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX", &crypto).expect("snapshot");
	let msg = snapshot.messages().next().expect("one message");
	assert_eq!(snapshot.read(msg).expect("read"), BODY);
	// RFC822.SIZE reports the plaintext length, not the on-disk envelope length.
	assert_eq!(msg.size, BODY.len() as u64);
}

#[test]
fn imap_append_then_read_roundtrips_plaintext() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(KEY);
	mailbox::append(dir.path(), "alice", "INBOX", &[], BODY, &crypto).expect("append");

	let new_dir = dir.path().join("accounts").join("alice").join("new");
	assert!(on_disk_eml(&new_dir)[0].starts_with(MAGIC));

	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX", &crypto).expect("snapshot");
	let msg = snapshot.messages().next().expect("one message");
	assert_eq!(snapshot.read(msg).expect("read"), BODY);
}

#[test]
fn pop3_retr_returns_plaintext() {
	use crate::pop3::backend::MailboxBackend;
	use crate::pop3::session::Backend;

	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = MessageCrypto::for_test(KEY);
	mailbox::append(dir.path(), "alice", "INBOX", &[], BODY, &crypto).expect("append");

	let backend =
		MailboxBackend::new_with_crypto(directory(), dir.path().to_path_buf(), crypto.clone());
	let messages = backend.load("alice");
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].1, BODY, "POP3 RETR must return plaintext");
}

#[test]
fn imap_read_fails_closed_with_wrong_key() {
	// A message encrypted under one key must not be readable under another: the
	// read fails closed rather than returning ciphertext.
	let dir = tempfile::tempdir().expect("tempdir");
	let writer = MessageCrypto::for_test(KEY);
	mailbox::append(dir.path(), "alice", "INBOX", &[], BODY, &writer).expect("append");

	let wrong = MessageCrypto::for_test(b"ffffffffffffffffffffffffffffffff");
	let snapshot = Snapshot::open(dir.path(), "alice", "INBOX", &wrong).expect("snapshot");
	let msg = snapshot.messages().next().expect("one message");
	assert!(snapshot.read(msg).is_err());
}
