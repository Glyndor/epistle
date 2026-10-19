//! Send-as over SMTP submission, for the shared table in
//! `directory_send_as_fixture.rs`: `MAIL FROM` and the From header are both
//! held to `Directory::owns_address`, for dotted addresses, any case, lists
//! and the addresses that merely deliver to the account.

use super::*;
use crate::smtp::auth::tests::{fixture_password, hash};
use crate::smtp::directory::send_as_fixture::{CASES, directory};
use crate::smtp::session::tests_mods::tests_auth::{plain, reply_text};

fn session_as(account: &str) -> Session {
	let directory = Arc::new(directory().with_password_hashes(
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

/// The reply to `MAIL FROM:<from>`; the transaction is dropped after it so
/// the session (and its one slow login) serves the next case.
fn mail_from(session: &mut Session, from: &str) -> String {
	let reply = reply_text(&session.command_line(&format!("MAIL FROM:<{from}>")));
	session.command_line("RSET");
	reply
}

/// The final action of a submission whose envelope sender is `envelope`
/// and whose From header is `from`.
fn submit(session: &mut Session, envelope: &str, from: &str) -> Action {
	session.command_line(&format!("MAIL FROM:<{envelope}>"));
	session.command_line("RCPT TO:<dest@remote.example>");
	session.command_line("DATA");
	let from_line = format!("From: {from}");
	for line in [from_line.as_str(), "Subject: hi", "", "hello", "."] {
		if let Some(action) = session.data_line(line.as_bytes()) {
			return action;
		}
	}
	panic!("DATA never finished");
}

/// The account's own envelope address, to isolate the From header check.
fn own_envelope(account: &str) -> &'static str {
	match account {
		"alice" => "alice@example.org",
		"bob" => "bob@example.org",
		_ => "carol@example.org",
	}
}

#[test]
fn mail_from_follows_the_table() {
	for account in ["alice", "bob", "carol"] {
		let mut session = session_as(account);
		for (_, from, allowed) in CASES.iter().filter(|case| case.0 == account) {
			let reply = mail_from(&mut session, from);
			let code = if *allowed { "250" } else { "553" };
			assert!(
				reply.starts_with(code),
				"MAIL FROM {from} got an unexpected reply: {reply}"
			);
		}
	}
}

#[test]
fn the_from_header_follows_the_table() {
	for account in ["alice", "bob", "carol"] {
		let mut session = session_as(account);
		for (_, from, allowed) in CASES.iter().filter(|case| case.0 == account) {
			let action = submit(&mut session, own_envelope(account), from);
			if *allowed {
				assert!(
					matches!(action, Action::Deliver(..)),
					"From {from} got an unexpected action: {}",
					reply_text(&action)
				);
			} else {
				assert_eq!(
					reply_text(&action),
					"550 5.7.1 From header not owned by the authenticated account\r\n",
					"From {from} was not refused as not owned"
				);
			}
		}
	}
}
