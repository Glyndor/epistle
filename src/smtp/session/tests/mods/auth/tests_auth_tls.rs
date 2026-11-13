//! SMTP AUTH is refused outside TLS, and the capabilities advertised inside it.

use super::tests_auth::*;
use super::*;
use crate::smtp::auth::tests::base::fixture_password;

#[test]
pub(in crate::smtp::session::tests::mods) fn auth_rejected_outside_tls() {
	let mut session = greeted_plain();
	let action = session.command_line(&format!(
		"AUTH PLAIN {}",
		plain("alice", fixture_password())
	));
	assert_eq!(reply_code(&action), 538);
	assert_eq!(session.authenticated(), None);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn ehlo_advertises_auth_only_inside_tls() {
	let mut plain_session = greeted_plain();
	let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(!reply.to_string().contains("AUTH "));

	let mut tls = tls_session();
	let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(
		reply.to_string().contains("AUTH SCRAM-SHA-256 PLAIN"),
		"EHLO inside TLS must offer the SCRAM and PLAIN mechanisms"
	);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn ehlo_advertises_requiretls_only_inside_tls() {
	let mut plain_session = greeted_plain();
	let Action::Continue(reply) = plain_session.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(
		!reply.to_string().contains("REQUIRETLS"),
		"EHLO outside TLS must not offer REQUIRETLS"
	);

	let mut tls = tls_session();
	let Action::Continue(reply) = tls.command_line("EHLO c.example.org") else {
		panic!("expected continue");
	};
	assert!(
		reply.to_string().contains("REQUIRETLS"),
		"EHLO inside TLS must offer REQUIRETLS"
	);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn requiretls_rejected_without_tls() {
	let mut session = greeted_plain();
	let action = session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	assert_eq!(reply_code(&action), 530);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn requiretls_accepted_inside_tls() {
	let mut session = tls_session();
	let action = session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	assert_eq!(reply_code(&action), 250);
}

#[test]
pub(in crate::smtp::session::tests::mods) fn requiretls_flows_to_accepted_message() {
	let mut session = tls_session();
	session.command_line("MAIL FROM:<eve@sender.example> REQUIRETLS");
	session.command_line("RCPT TO:<alice@example.org>");
	session.command_line("DATA");
	session.data_line(b"Subject: hi");
	session.data_line(b"");
	session.data_line(b"body");
	let Some(Action::Deliver(_, message)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert!(
		message.require_tls,
		"REQUIRETLS must reach the accepted message"
	);
}
