//! RFC 5321 section 4.5.1 at the server's own name: the reports the server
//! sends itself, to `postmaster@<its hostname>`, are accepted although the
//! hostname is not a hosted domain.

use super::tests_basic::reply_code;
use super::*;

fn session(server_name: Option<&str>) -> Session {
	let mut directory = Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("postmaster@example.org".to_string(), "ops".to_string()),
		],
	);
	if let Some(name) = server_name {
		directory = directory.with_server_name(name);
	}
	let mut session = Session::new("mail.example.org").with_directory(Arc::new(directory));
	session.command_line("EHLO client.example.net");
	session.command_line("MAIL FROM:<reporter@example.net>");
	session
}

#[test]
fn postmaster_at_the_hostname_is_accepted() {
	let mut session = session(Some("mail.example.org"));
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<postmaster@mail.example.org>")),
		250
	);
}

#[test]
fn another_mailbox_at_the_hostname_is_still_a_relay_attempt() {
	let mut session = session(Some("mail.example.org"));
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<alice@mail.example.org>")),
		550
	);
}

#[test]
fn without_the_server_name_the_hostname_is_refused() {
	let mut session = session(None);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<postmaster@mail.example.org>")),
		550
	);
}
