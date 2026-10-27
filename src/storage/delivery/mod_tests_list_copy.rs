//! The copy a list member receives, read off the stored `.eml`. A third
//! review (2026-10-15) found that local delivery prepended the `List-*` block
//! again to a message the submission path had already written one to, so the
//! members got two of each field from a message whose client wrote none. The
//! assertions below read the file the mailbox actually holds and count the
//! fields the way a Sieve `header` test counts them, not the bytes the
//! submission path produced.

use super::*;
use crate::sieve::interp::{Message, evaluate};
use crate::sieve::lexer::tokenize;
use crate::sieve::parser::parse;

/// The single copy the member's mailbox holds.
fn stored(root: &std::path::Path, account: &str) -> Vec<u8> {
	let files = fs::read_dir(root.join("accounts").join(account).join("new"))
		.expect("inbox")
		.map(|entry| entry.expect("entry").path())
		.collect::<Vec<_>>();
	assert_eq!(files.len(), 1, "the member must receive one copy");
	std::fs::read(&files[0]).expect("read the stored copy")
}

/// Whether a Sieve `header` count test of `name` against `count` matches,
/// read through the interpreter a user's filter runs at delivery.
fn sieve_sees(raw: &[u8], name: &str, count: &str) -> bool {
	let script = format!(
		"require \"relational\";\nif header :count \"eq\" :comparator \
		 \"i;ascii-numeric\" \"{name}\" \"{count}\" {{ discard; }}\n"
	);
	let commands = parse(&tokenize(&script).expect("lex")).expect("parse");
	evaluate(&commands, &Message::parse(raw)).discarded
}

/// Exactly one field of each name, both as the bytes read and as a filter
/// counts them.
fn one_field_each(raw: &[u8], names: &[&str]) {
	let text = String::from_utf8_lossy(raw);
	for name in names {
		let field = format!("{}:", name.to_ascii_lowercase());
		let count = text
			.lines()
			.filter(|line| line.to_ascii_lowercase().starts_with(&field))
			.count();
		assert_eq!(count, 1, "not one {name} in the stored copy:\n{text}");
		assert!(
			sieve_sees(raw, name, "1"),
			"a filter finds no single {name}"
		);
		assert!(!sieve_sees(raw, name, "2"), "a filter finds two {name}");
	}
}

fn directory_handle() -> crate::directory_store::DirectoryHandle {
	crate::directory_store::DirectoryHandle::new(
		crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		)
		.with_aliases([(
			"team@example.org".to_string(),
			crate::smtp::directory::AliasSpec {
				members: vec!["alice@example.org".to_string()],
				senders: Vec::new(),
				hidden: true,
				list_id: Some("team.example.org".to_string()),
			},
		)]),
	)
}

/// A personal message from the list address to itself, through the same
/// [`crate::smtp::identification::apply`] the submission path runs, with
/// `client_headers` whatever the client wrote before it.
fn submitted_to_the_list(client_headers: &str) -> AcceptedMessage {
	let mut message = AcceptedMessage {
		reverse_path: "team@example.org".into(),
		recipients: vec!["team@example.org".to_string()],
		data: format!(
			"From: Someone <someone@example.org>\r\n{client_headers}Subject: hi\r\n\r\nbody\r\n"
		)
		.into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	};
	let policy = crate::smtp::identification::Policy::default();
	crate::smtp::identification::apply(
		&mut message,
		crate::evidence::MailClass::Personal,
		&policy,
		Some(&directory_handle().current()),
	)
	.expect("ordinary submission");
	message
}

/// Mail to the list address from a sender outside it, delivered without the
/// submission pass: the path unauthenticated inbound mail takes, where
/// nothing has deduplicated the fields a sender wrote twice.
fn inbound_to_the_list(client_headers: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "someone@remote.example".into(),
		recipients: vec!["team@example.org".to_string()],
		data: format!(
			"From: Someone <someone@remote.example>\r\n{client_headers}Subject: hi\r\n\r\nbody\r\n"
		)
		.into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[test]
fn a_member_receives_one_copy_of_each_list_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_handle()).expect("delivery");
	delivery
		.deliver(submitted_to_the_list(""))
		.expect("deliver to the list");
	let raw = stored(dir.path(), "alice");
	one_field_each(&raw, &["List-Id", "List-Post", "List-Unsubscribe"]);
	let text = String::from_utf8_lossy(&raw);
	assert!(
		text.contains("List-Id: <team.example.org>\r\n"),
		"the surviving copy does not name the list:\n{text}"
	);
	assert!(
		text.contains("List-Unsubscribe: <mailto:team@example.org?subject=unsubscribe>\r\n"),
		"the surviving unsubscribe is not the list's:\n{text}"
	);
}

#[test]
fn a_one_click_unsubscribe_the_sender_published_is_the_one_that_stays() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_handle()).expect("delivery");
	delivery
		.deliver(submitted_to_the_list(
			"List-Unsubscribe: <https://example.org/u/team>\r\n\
			 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
		))
		.expect("deliver to the list");
	let raw = stored(dir.path(), "alice");
	one_field_each(
		&raw,
		&[
			"List-Id",
			"List-Post",
			"List-Unsubscribe",
			"List-Unsubscribe-Post",
		],
	);
	let text = String::from_utf8_lossy(&raw);
	assert!(
		text.contains("List-Unsubscribe: <https://example.org/u/team>\r\n"),
		"the list's mailto went in front of the URL RFC 8058 posts to:\n{text}"
	);
	assert!(
		text.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"),
		"the post lost the URL it names:\n{text}"
	);
}

/// Inbound mail carries no submission pass, so a sender that published the
/// unsubscribe fields twice reached the member twice. The stored copy keeps
/// one of each: the first, which is the pair RFC 8058 posts to when the sender
/// published it first.
#[test]
fn an_inbound_message_with_two_unsubscribes_leaves_one_in_the_copy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let delivery = LocalDelivery::new(dir.path(), directory_handle()).expect("delivery");
	delivery
		.deliver(inbound_to_the_list(
			"List-Unsubscribe: <https://remote.example/u/one>\r\n\
			 List-Unsubscribe: <https://remote.example/u/two>\r\n\
			 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
			 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
		))
		.expect("deliver to the list");
	let raw = stored(dir.path(), "alice");
	one_field_each(
		&raw,
		&[
			"List-Id",
			"List-Post",
			"List-Unsubscribe",
			"List-Unsubscribe-Post",
		],
	);
	let text = String::from_utf8_lossy(&raw);
	assert!(
		text.contains("List-Unsubscribe: <https://remote.example/u/one>\r\n"),
		"the second copy is not the one that went:\n{text}"
	);
	assert!(
		!text.contains("List-Unsubscribe: <https://remote.example/u/two>\r\n"),
		"the member received the sender's second claim:\n{text}"
	);
}
