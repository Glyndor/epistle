//! What a submission listener answers a client that has not authenticated
//! (RFC 6409 section 4.3, RFC 4954 section 6, RFC 3207 section 4), and that
//! the receiving listener keeps its own answers.

use super::tests_auth::*;
use super::*;
use crate::smtp::auth::tests::base::fixture_password;

fn submission(tls_available: bool, tls_active: bool) -> Session {
	let mut session = Session::new("mail.example.org")
		.with_directory(auth_directory())
		.with_submission_listener(true);
	if tls_available {
		session = session.with_tls_available();
	}
	if tls_active {
		session = session.with_tls_active();
	}
	session.command_line("EHLO client.example.org");
	session
}

#[test]
pub(in crate::smtp::session::tests::mods) fn submission_before_starttls_is_told_to_start_tls() {
	let mut session = submission(true, false);
	let action = session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(
		reply_text(&action),
		"530 5.7.0 Must issue a STARTTLS command first\r\n"
	);
	// Nothing was taken: the envelope is still closed.
	let action = session.command_line("RCPT TO:<alice@example.org>");
	assert_eq!(reply_code(&action), 503);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn submission_inside_tls_is_told_to_authenticate() {
	let mut session = submission(true, true);
	let action = session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(reply_text(&action), "530 5.7.0 Authentication required\r\n");
	let action = session.command_line("RCPT TO:<alice@example.org>");
	assert_eq!(reply_code(&action), 503);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn submission_without_tls_to_offer_is_told_to_authenticate()
 {
	let mut session = submission(false, false);
	let action = session.command_line("MAIL FROM:<>");
	assert_eq!(reply_text(&action), "530 5.7.0 Authentication required\r\n");
}

#[test]
pub(in crate::smtp::session::tests::mods) fn submission_after_authenticating_is_taken() {
	let mut session = submission(true, true);
	session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(session.authenticated(), Some("alice"));
	let action = session.command_line("MAIL FROM:<alice@example.org>");
	assert_eq!(reply_code(&action), 250);
	let action = session.command_line("RCPT TO:<carol@elsewhere.example>");
	assert_eq!(reply_code(&action), 250);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn the_receiving_listener_keeps_its_answers() {
	// Same session, not a submission listener: inbound mail is taken, and a
	// recipient outside the hosted domains is a relay.
	for tls_active in [false, true] {
		let mut session = Session::new("mail.example.org")
			.with_directory(auth_directory())
			.with_tls_available();
		if tls_active {
			session = session.with_tls_active();
		}
		session.command_line("EHLO client.example.org");
		let action = session.command_line("MAIL FROM:<eve@sender.example>");
		assert_eq!(reply_code(&action), 250);
		let action = session.command_line("RCPT TO:<someone@elsewhere.example>");
		assert_eq!(reply_text(&action), "550 5.7.1 relaying denied\r\n");
	}
}
