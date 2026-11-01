//! An authenticated submission may only carry a From field the account
//! owns, and only one of it: that is the field the DKIM signer signs and
//! the field DMARC judges at the receiver.

use super::*;
use crate::smtp::auth::tests::base::fixture_password;
use crate::smtp::session::tests::mods::auth::tests_auth::{plain, reply_text};

fn session() -> Session {
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
			],
		)
		.with_password_hashes([(
			"alice".to_string(),
			crate::smtp::auth::tests::base::hash(fixture_password()),
		)]),
	);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(session.authenticated(), Some("alice"));
	session
}

/// Submit `headers` as alice to a remote recipient; return the final action.
fn submit(headers: &str) -> Action {
	let mut session = session();
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<carol@remote.example>");
	session.command_line("DATA");
	for line in headers.split("\r\n").chain(["", "hello", "."]) {
		if let Some(action) = session.data_line(line.as_bytes()) {
			return action;
		}
	}
	panic!("DATA never finished");
}

#[track_caller]
fn assert_refused(headers: &str) {
	let action = submit(headers);
	assert!(
		!matches!(action, Action::Deliver(..)),
		"accepted: {headers:?}"
	);
	assert_eq!(
		reply_text(&action),
		"550 5.7.1 From header not owned by the authenticated account\r\n",
		"{headers:?}"
	);
}

#[test]
fn own_from_is_accepted() {
	for headers in [
		"From: alice@example.org\r\nSubject: hi",
		"From: \"Alice\" <Alice@Example.ORG>\r\nSubject: hi",
	] {
		assert!(
			matches!(submit(headers), Action::Deliver(..)),
			"{headers:?}"
		);
	}
}

#[test]
fn another_accounts_from_is_refused() {
	assert_refused("From: bob@example.org\r\nSubject: hi");
	assert_refused("From: \"alice@example.org\" <bob@example.org>\r\nSubject: hi");
}

#[test]
fn a_second_from_field_is_refused() {
	assert_refused("From: alice@example.org\r\nFrom: bob@example.org\r\nSubject: hi");
	assert_refused("From : bob@example.org\r\nFrom: alice@example.org\r\nSubject: hi");
}

#[test]
fn a_from_with_two_mailboxes_is_refused() {
	assert_refused("From: alice@example.org, bob@example.org\r\nSubject: hi");
}

#[test]
fn a_message_without_from_is_refused() {
	assert_refused("Subject: hi");
}

#[track_caller]
fn assert_malformed_refused(headers: &str) {
	let action = submit(headers);
	assert!(
		!matches!(action, Action::Deliver(..)),
		"accepted: {headers:?}"
	);
	assert_eq!(
		reply_text(&action),
		"550 5.7.1 submission header lines must follow RFC 5322 field and folding syntax\r\n",
		"{headers:?}"
	);
}

#[test]
fn malformed_header_lines_are_refused_before_the_author_check() {
	for headers in [
		" From: victim@example.org\r\nFrom: alice@example.org",
		"From: alice@example.org\r\n:From: victim@example.org",
		"From: alice@example.org\r\nGarbage\r\n Fr om: victim@example.org",
	] {
		assert_malformed_refused(headers);
	}
}

#[test]
fn a_body_after_a_leading_blank_line_is_not_a_header_block() {
	let action = submit("\r\nHello world: x\r\n");
	assert!(
		!matches!(action, Action::Deliver(..)),
		"accepted a body as a header block"
	);
	assert_eq!(
		reply_text(&action),
		"550 5.7.1 From header not owned by the authenticated account\r\n"
	);
}
