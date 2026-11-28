//! An authenticated submission may only name in its `Sender` field an
//! address the account may send as, the rule `POST /api/v1/send` and JMAP
//! `EmailSubmission/set` apply. Mail from a peer that did not log in is not
//! a submission and keeps whatever it carries.

use super::*;
use crate::smtp::auth::tests::base::{fixture_password, hash};
use crate::smtp::directory::send_as_fixture::{CASES, directory};
use crate::smtp::session::tests::mods::auth::tests_auth::{plain, reply_text};

const REFUSED: &str = "550 5.7.1 Sender header not owned by the authenticated account\r\n";

/// The shared send-as directory, with one enabled mask for `alice`, one for
/// `bob` and one that is switched off.
fn masked_directory() -> Directory {
	directory()
		.with_masked([
			("quiet.fox@example.org".to_string(), "alice".to_string()),
			("loud.owl@example.org".to_string(), "bob".to_string()),
		])
		.with_masked_paused(["old.hare@example.org".to_string()])
}

fn session_as(account: &str) -> Session {
	let directory = Arc::new(masked_directory().with_password_hashes(
		["alice", "bob", "carol"].map(|name| (name.to_string(), hash(fixture_password()))),
	));
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain(account, fixture_password())
	));
	assert_eq!(session.authenticated(), Some(account));
	session
}

/// Send `headers` from `envelope` to `recipient`; return the final action.
fn send(session: &mut Session, envelope: &str, recipient: &str, headers: &str) -> Action {
	session.command_line(&format!("MAIL FROM:<{envelope}>"));
	session.command_line(&format!("RCPT TO:<{recipient}>"));
	session.command_line("DATA");
	for line in headers.split("\r\n").chain(["", "hello", "."]) {
		if let Some(action) = session.data_line(line.as_bytes()) {
			return action;
		}
	}
	panic!("DATA never finished");
}

/// Submit as the owner of `session`, with its own envelope and `From`, and
/// `sender_lines` after them.
fn submit(session: &mut Session, sender_lines: &str) -> Action {
	let account = session
		.authenticated()
		.expect("an authenticated session")
		.to_string();
	let own = format!("{account}@example.org");
	let headers = format!("From: {own}\r\n{sender_lines}\r\nSubject: hi");
	send(session, &own, "dest@remote.example", &headers)
}

#[track_caller]
fn assert_accepted(session: &mut Session, sender_lines: &str) {
	let action = submit(session, sender_lines);
	assert!(
		matches!(action, Action::Deliver(..)),
		"{sender_lines:?} was refused: {}",
		reply_text(&action)
	);
}

#[track_caller]
fn assert_refused(session: &mut Session, sender_lines: &str) {
	let action = submit(session, sender_lines);
	assert!(
		!matches!(action, Action::Deliver(..)),
		"accepted: {sender_lines:?}"
	);
	assert_eq!(reply_text(&action), REFUSED, "{sender_lines:?}");
}

#[test]
fn the_sender_header_follows_the_table() {
	for account in ["alice", "bob", "carol"] {
		let mut session = session_as(account);
		for (_, address, allowed) in CASES.iter().filter(|case| case.0 == account) {
			let line = format!("Sender: {address}");
			if *allowed {
				assert_accepted(&mut session, &line);
			} else {
				assert_refused(&mut session, &line);
			}
		}
	}
}

#[test]
fn a_mask_is_a_sender_only_for_its_owner_while_enabled() {
	let mut session = session_as("alice");
	assert_accepted(&mut session, "Sender: Quiet.Fox@Example.org");
	assert_refused(&mut session, "Sender: loud.owl@example.org");
	assert_refused(&mut session, "Sender: old.hare@example.org");
}

#[test]
fn every_spelling_of_the_field_is_read() {
	let mut session = session_as("alice");
	for (own, other) in [
		(
			"Sender: \"Alice\" <Alice@Example.ORG>",
			"Sender: \"alice@example.org\" <bob@example.org>",
		),
		("sEnDeR: alice@example.org", "sEnDeR: bob@example.org"),
		("Sender : alice@example.org", "Sender : bob@example.org"),
		(
			"Sender:\r\n <alice@example.org>",
			"Sender:\r\n <bob@example.org>",
		),
		(
			"Sender: Desk: alice@example.org;",
			"Sender: Desk: bob@example.org;",
		),
	] {
		assert_accepted(&mut session, own);
		assert_refused(&mut session, other);
	}
}

#[test]
fn every_field_and_every_address_is_held_to_the_rule() {
	let mut session = session_as("alice");
	for owned in [
		"Sender: alice@example.org\r\nSender: team@example.org",
		"Sender: alice@example.org, team@example.org",
	] {
		assert_accepted(&mut session, owned);
	}
	for mixed in [
		"Sender: alice@example.org\r\nSender: bob@example.org",
		"Sender: bob@example.org\r\nSender: alice@example.org",
		"Sender: alice@example.org, bob@example.org",
		"Sender: bob@example.org, alice@example.org",
	] {
		assert_refused(&mut session, mixed);
	}
}

#[test]
fn a_sender_field_that_cannot_be_checked_is_refused() {
	let mut session = session_as("alice");
	assert_accepted(&mut session, "Sender: alice@example.org");
	for lines in [
		"Sender:",
		"Sender: ,,,",
		"Sender: ()",
		"Sender: <>",
		"Sender: undisclosed-recipients:;",
		"Sender: alice",
		"Sender: alice@example.org\r\nSender: <>",
	] {
		assert_refused(&mut session, lines);
	}
}

/// These field values do not parse as an address.
#[test]
fn a_sender_field_that_does_not_parse_as_an_address_is_refused() {
	let mut session = session_as("alice");
	for lines in [
		"Sender: <alice@example.org> <alice@example.org>",
		"Sender: alice@example.org alice@example.org",
		"Sender: .alice@example.org",
	] {
		assert_refused(&mut session, lines);
	}
}

#[test]
fn a_refused_author_is_reported_before_the_sender() {
	let mut session = session_as("alice");
	let action = send(
		&mut session,
		"alice@example.org",
		"dest@remote.example",
		"From: bob@example.org\r\nSender: bob@example.org",
	);
	assert_eq!(
		reply_text(&action),
		"550 5.7.1 From header not owned by the authenticated account\r\n"
	);
}

/// A list manager, a forwarder or another server delivering here names
/// whoever it names: nobody logged in, so there is nothing to own.
#[test]
fn mail_from_a_peer_that_did_not_log_in_keeps_its_sender() {
	let mut session = Session::new("mail.example.org")
		.with_directory(Arc::new(masked_directory()))
		.with_tls_active();
	session.command_line("EHLO mx.elsewhere.example");
	for sender in ["Sender: list-bounces@elsewhere.example", "Sender: <>"] {
		let headers = format!("From: someone@elsewhere.example\r\n{sender}");
		let action = send(
			&mut session,
			"list-bounces@elsewhere.example",
			"alice@example.org",
			&headers,
		);
		assert!(
			matches!(action, Action::Deliver(..)),
			"{sender}: {}",
			reply_text(&action)
		);
	}
}
