//! The limit on commands that bring a session no closer to a delivered
//! message: past it the client gets the exact 421 line and the session
//! ends, whatever mix of junk it sent and whether it is logged in.

use super::tests_auth::tls_session;
use super::tests_basic::{greeted, reply_code};
use super::*;

/// The line a session past its junk-command limit is closed with.
const TOO_MANY: &str = "421 4.7.0 too many commands without progress, closing connection\r\n";

/// The reply of a step that closes the connection; `None` otherwise.
fn closing(action: &Action) -> Option<String> {
	match action {
		Action::Close(reply) => Some(reply.to_string()),
		_ => None,
	}
}

/// Send `command` `times` times and assert none of them closes the session.
fn send_kept(session: &mut Session, command: &str, times: usize) {
	for sent in 1..=times {
		let action = session.command_line(command);
		assert_eq!(
			closing(&action),
			None,
			"{command} number {sent} must not close the session"
		);
	}
}

#[test]
fn the_101st_noop_closes_the_session_with_the_exact_line() {
	let mut session = greeted();
	for _ in 0..DEFAULT_JUNK_COMMAND_LIMIT {
		assert_eq!(reply_code(&session.command_line("NOOP")), 250);
	}
	assert_eq!(
		closing(&session.command_line("NOOP")).as_deref(),
		Some(TOO_MANY),
		"the 101st NOOP is answered 421 and the connection closed"
	);
}

#[test]
fn every_kind_of_command_without_progress_counts() {
	let mut session = greeted();
	let junk = [
		"RSET",
		"VRFY bob",
		"EXPN staff",
		"HELP",
		"FROB",
		"MAIL FROM:<not an address",
		"RCPT TO:<bob@example.org>",
		"MAIL FROM:<a@example.org> BOGUS=1",
		"NOOP",
		"DATA",
	];
	for round in 0..10 {
		for command in junk {
			let action = session.command_line(command);
			assert_eq!(
				closing(&action),
				None,
				"{command} in round {round} is still under the limit"
			);
		}
	}
	// A refused RCPT is junk too, inside a transaction that was opened.
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		250
	);
	assert_eq!(
		closing(&session.command_line("RCPT TO:<someone@elsewhere.example>")).as_deref(),
		Some(TOO_MANY),
		"the 101st command without progress is a refused relay"
	);
}

#[test]
fn a_delivered_message_does_not_reset_the_count() {
	let mut session = greeted();
	send_kept(&mut session, "NOOP", 60);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	assert_eq!(reply_code(&session.command_line("DATA")), 354);
	assert!(session.data_line(b"Subject: hi").is_none());
	assert_eq!(reply_code(&session.data_line(b".").expect("end")), 250);
	send_kept(&mut session, "NOOP", 40);
	assert_eq!(
		closing(&session.command_line("NOOP")).as_deref(),
		Some(TOO_MANY),
		"60 before the message and 41 after it make 101"
	);
}

#[test]
fn a_logged_in_session_has_the_same_limit() {
	let mut session = greeted();
	session.mark_authenticated_for_test("bob");
	send_kept(&mut session, "RSET", 100);
	assert_eq!(
		closing(&session.command_line("RSET")).as_deref(),
		Some(TOO_MANY)
	);
}

#[test]
fn cancelled_auth_exchanges_count() {
	let mut session = tls_session();
	for round in 0..100 {
		assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
		let action = session.auth_line("*");
		assert_eq!(reply_code(&action), 501, "cancel number {round}");
		assert_eq!(closing(&action), None);
	}
	assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
	assert_eq!(
		closing(&session.auth_line("*")).as_deref(),
		Some(TOO_MANY),
		"the 101st cancelled exchange closes the session"
	);
}

#[test]
fn a_limit_of_zero_turns_the_count_off() {
	let mut session = greeted().with_junk_command_limit(0);
	send_kept(&mut session, "NOOP", 1000);
	send_kept(&mut session, "FROB", 10);
}

#[test]
fn a_lower_limit_is_honoured() {
	let mut session = greeted().with_junk_command_limit(3);
	send_kept(&mut session, "VRFY bob", 3);
	assert_eq!(
		closing(&session.command_line("VRFY bob")).as_deref(),
		Some(TOO_MANY)
	);
}

#[test]
fn every_auth_continuation_line_counts() {
	// A LOGIN exchange that is answered one line at a time and then
	// cancelled costs two: the username line and the cancellation.
	let mut session = tls_session();
	for round in 0..50 {
		assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
		let username = session.auth_line("YWxpY2U=");
		assert_eq!(reply_code(&username), 334, "username in round {round}");
		assert_eq!(reply_code(&session.auth_line("*")), 501);
	}
	assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
	assert_eq!(
		closing(&session.auth_line("YWxpY2U=")).as_deref(),
		Some(TOO_MANY),
		"the 101st continuation line closes the session"
	);
}

#[test]
fn a_successful_auth_does_not_reset_the_count() {
	let mut session = tls_session();
	send_kept(&mut session, "NOOP", 99);
	assert_eq!(reply_code(&session.command_line("AUTH PLAIN")), 334);
	let password = crate::smtp::auth::tests::fixture_password();
	let action = session.auth_line(&super::tests_auth::plain("alice", password));
	assert_eq!(reply_code(&action), 235, "the login itself is answered");
	assert_eq!(session.authenticated(), Some("alice"));
	assert_eq!(
		closing(&session.command_line("NOOP")).as_deref(),
		Some(TOO_MANY),
		"99 NOOP, the credentials line and one more NOOP make 101"
	);
}
