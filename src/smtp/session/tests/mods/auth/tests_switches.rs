//! The send and receive switches over SMTP: a sender whose sending is off
//! signs in and is refused at `MAIL FROM`, and a recipient whose receiving is
//! off is refused at `RCPT TO` exactly like an address that does not exist.

use super::*;
use crate::smtp::auth::tests::base::{fixture_password, hash};
use crate::smtp::directory::send_as_fixture::directory;
use crate::smtp::session::tests::mods::auth::tests_auth::{plain, reply_text};

fn directory_with(send_off: &[&str], receive_off: &[&str]) -> Arc<Directory> {
	Arc::new(
		directory()
			.with_password_hashes(
				["alice", "bob", "carol"].map(|name| (name.to_string(), hash(fixture_password()))),
			)
			.with_switches(
				send_off.iter().map(|name| (*name).to_string()),
				receive_off.iter().map(|name| (*name).to_string()),
			),
	)
}

fn authenticated(directory: Arc<Directory>, account: &str) -> Session {
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

#[test]
fn an_account_whose_sending_is_off_still_authenticates() {
	// Reaching `authenticated` is the assertion: the login succeeded.
	authenticated(directory_with(&["alice"], &[]), "alice");
}

#[test]
fn it_is_refused_at_mail_from_with_a_permanent_reply() {
	let mut session = authenticated(directory_with(&["alice"], &[]), "alice");
	let reply = reply_text(&session.command_line("MAIL FROM:<alice@example.org>"));
	assert_eq!(
		reply,
		"550 5.7.1 sending is turned off for this account\r\n"
	);
}

#[test]
fn the_null_sender_does_not_get_around_it() {
	let mut session = authenticated(directory_with(&["alice"], &[]), "alice");
	let reply = reply_text(&session.command_line("MAIL FROM:<>"));
	assert!(
		reply.starts_with("550 5.7.1 sending is turned off"),
		"unexpected reply to the command"
	);
}

#[test]
fn sending_as_a_list_it_belongs_to_is_refused_too() {
	let mut session = authenticated(directory_with(&["alice"], &[]), "alice");
	let reply = reply_text(&session.command_line("MAIL FROM:<team@example.org>"));
	assert!(
		reply.starts_with("550 5.7.1 sending is turned off"),
		"unexpected reply to the command"
	);
}

#[test]
fn another_account_still_sends_while_one_is_off() {
	let mut session = authenticated(directory_with(&["alice"], &[]), "bob");
	let reply = reply_text(&session.command_line("MAIL FROM:<bob@example.org>"));
	assert!(reply.starts_with("250"), "unexpected reply to the command");
}

#[test]
fn an_account_that_receives_nothing_still_sends() {
	let mut session = authenticated(directory_with(&[], &["alice"]), "alice");
	let reply = reply_text(&session.command_line("MAIL FROM:<alice@example.org>"));
	assert!(reply.starts_with("250"), "unexpected reply to the command");
}

fn inbound(directory: Arc<Directory>) -> Session {
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<someone@remote.example>");
	session
}

#[test]
fn mail_for_an_account_that_does_not_receive_is_refused_like_an_unknown_user() {
	let mut session = inbound(directory_with(&[], &["alice"]));
	let refused = reply_text(&session.command_line("RCPT TO:<alice@example.org>"));
	let unknown = reply_text(&session.command_line("RCPT TO:<nobody-here@other.example>"));
	assert_eq!(refused, "550 5.1.1 no such user\r\n");
	assert_eq!(unknown, refused);
}

#[test]
fn a_sub_address_of_it_is_refused_and_does_not_reach_the_catch_all() {
	// `carol` catches `example.org`; `alice+tag` names alice, not an unknown user.
	let mut session = inbound(directory_with(&[], &["alice"]));
	let reply = reply_text(&session.command_line("RCPT TO:<alice+tag@example.org>"));
	assert_eq!(reply, "550 5.1.1 no such user\r\n");
}

#[test]
fn an_account_that_sends_nothing_still_receives() {
	let mut session = inbound(directory_with(&["alice"], &[]));
	let reply = reply_text(&session.command_line("RCPT TO:<alice@example.org>"));
	assert!(reply.starts_with("250"), "unexpected reply to the command");
}

#[test]
fn a_list_still_takes_mail_while_a_member_receives() {
	let mut session = inbound(directory_with(&[], &["alice"]));
	let reply = reply_text(&session.command_line("RCPT TO:<team@example.org>"));
	assert!(reply.starts_with("250"), "unexpected reply to the command");
}

#[test]
fn a_list_whose_members_all_stopped_receiving_is_refused() {
	let mut session = inbound(directory_with(&[], &["alice", "bob"]));
	let reply = reply_text(&session.command_line("RCPT TO:<team@example.org>"));
	assert_eq!(reply, "550 5.1.1 no such user\r\n");
}
