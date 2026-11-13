//! Relay and sender ownership for an authenticated submission.

use super::tests_auth::*;

#[test]
pub(in crate::smtp::session::tests::mods) fn authenticated_user_may_relay_to_foreign_domains() {
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 250);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn unauthenticated_relay_stays_denied() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<someone@elsewhere.example>");
	let action = session.command_line("RCPT TO:<bob@elsewhere.example>");
	assert_eq!(reply_code(&action), 550);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn authenticated_sender_must_own_the_address() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<other@elsewhere.example>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn authenticated_sender_cannot_use_null_path() {
	let mut session = authenticated_session();
	let action = session.command_line("MAIL FROM:<>");
	assert_eq!(reply_code(&action), 553);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn authenticated_relay_still_rejects_unknown_local_users()
{
	let mut session = authenticated_session();
	session.command_line("MAIL FROM:<alice@example.org>");
	let action = session.command_line("RCPT TO:<stranger@example.org>");
	assert_eq!(reply_code(&action), 550);
}

// TLS / STARTTLS tests
