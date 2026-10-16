//! A submission never carries an attachment warning the sender wrote: only
//! the server's own inspection may speak in that header, and a local user
//! must not be able to forge one toward another local user (or anyone).

use super::*;
use crate::storage::FsSpool;

/// A forged warning in two spellings, one of them folded.
const FORGED: &[u8] = b"From: alice@example.org\r\n\
	X-Epistle-Attachment-Warning: none\r\n\
	Subject: hi\r\n\
	x-epistle-attachment-warning: checked,\r\n clean\r\n\
	\r\n\
	body\r\n";

const CLEAN: &str = "From: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n";

fn sink(dir: &std::path::Path) -> SplitDelivery {
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	));
	SplitDelivery::new(dir, directory).expect("sink")
}

fn submission(recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: FORGED.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

/// The one message in `account`'s INBOX.
fn delivered(root: &std::path::Path, account: &str) -> String {
	let mut files: Vec<_> = std::fs::read_dir(root.join("accounts").join(account).join("new"))
		.expect("inbox")
		.flatten()
		.map(|entry| entry.path())
		.collect();
	assert_eq!(files.len(), 1, "one message for {account}");
	String::from_utf8(std::fs::read(files.remove(0)).expect("read")).expect("utf-8")
}

/// The one queued message.
fn queued(root: &std::path::Path) -> String {
	let spool = FsSpool::open(root).expect("spool");
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), 1, "one queued message");
	String::from_utf8(spool.load(ids[0]).expect("entry").data).expect("utf-8")
}

/// No warning header is left, and the rest of the message is untouched.
fn assert_unforged(text: &str) {
	assert_eq!(
		crate::smtp::trace::header_values(text.as_bytes(), "X-Epistle-Attachment-Warning"),
		Vec::<String>::new()
	);
	assert!(text.ends_with(CLEAN), "the other headers and the body stay");
}

#[test]
fn a_forged_warning_never_reaches_a_local_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	sink(dir.path())
		.submit(
			submission(&["bob@example.org"]),
			uuid::Uuid::now_v7(),
			"alice",
			&BTreeMap::new(),
		)
		.expect("routed");
	assert_unforged(&delivered(dir.path(), "bob"));
}

#[test]
fn a_forged_warning_never_leaves_in_the_queue() {
	let dir = tempfile::tempdir().expect("tempdir");
	sink(dir.path())
		.submit(
			submission(&["carol@elsewhere.example"]),
			uuid::Uuid::now_v7(),
			"alice",
			&BTreeMap::new(),
		)
		.expect("routed");
	assert_unforged(&queued(dir.path()));
}
