//! STARTTLS availability, upgrade and session reset.

use super::tests_auth::*;
use super::*;

#[test]
pub(in crate::smtp::session::tests::mods) fn starttls_without_tls_configured_is_unavailable() {
	let mut session = greeted_plain();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn ehlo_advertises_starttls_when_available() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("250 STARTTLS\r\n"));
}

#[test]
pub(in crate::smtp::session::tests::mods) fn ehlo_advertises_dsn() {
	let mut session = Session::new("mail.example.org");
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(reply.to_string().contains("250-DSN\r\n"));
}

#[test]
pub(in crate::smtp::session::tests::mods) fn ehlo_does_not_advertise_starttls_when_unavailable() {
	let mut session = greeted_plain();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
}

#[test]
pub(in crate::smtp::session::tests::mods) fn starttls_upgrades_after_greeting() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	let action = session.command_line("STARTTLS");
	assert!(matches!(action, Action::UpgradeTls(_)));
	assert_eq!(reply_code(&action), 220);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn starttls_before_greeting_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn starttls_inside_transaction_is_bad_sequence() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<a@example.org>");
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn tls_started_resets_session() {
	let mut session = Session::new("mail.example.org").with_tls_available();
	session.command_line("EHLO client.example.org");
	session.tls_started();
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		503
	);
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("STARTTLS"));
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 454);
}
