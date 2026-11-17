//! The message-size caps below the server's: the sender's at `MAIL FROM` and
//! at the end of the data, a recipient's at `RCPT TO` and at the end of the
//! data, and BDAT.

use super::tests_basic::reply_code;
use super::*;
use crate::limits::test_support::shared;

const SERVER: &str = "[[limit_scope]]\ndomain = \"example.org\"\nmax_message_size = 100000\n\
	[[limit_scope]]\naccount = \"alice\"\nmax_message_size = 70000\n\
	[[limit_scope]]\naccount = \"carol\"\nmax_message_size = 65536\n";

fn session(extra: &str, authenticated: Option<&str>) -> Session {
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string(), "example.net".to_string()],
			[
				("alice@example.org".to_string(), "alice".to_string()),
				("bob@example.org".to_string(), "bob".to_string()),
				("carol@example.net".to_string(), "carol".to_string()),
				("dave@example.net".to_string(), "dave".to_string()),
			],
		)
		.with_limits(shared(extra)),
	);
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_max_message_size(10_485_760);
	if let Some(account) = authenticated {
		session.mark_authenticated_for_test(account);
	}
	session.command_line("EHLO client.example.org");
	session
}

fn text(action: Action) -> String {
	match action {
		Action::Continue(reply) | Action::Deliver(reply, _) => reply.to_string(),
		_ => panic!("answered, not collected"),
	}
}

fn send_body(session: &mut Session, bytes: usize) -> String {
	assert!(matches!(
		session.command_line("DATA"),
		Action::CollectData(_)
	));
	let line = [b'x'; 70];
	let mut sent = 0;
	while sent < bytes {
		session.data_line(&line);
		sent += line.len() + 2;
	}
	text(session.data_line(b".").expect("end of data"))
}

#[test]
fn no_limits_changes_nothing() {
	let mut session = session("", Some("alice"));
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org> SIZE=9000000")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
}

#[test]
fn a_sender_is_held_to_its_own_cap_when_it_declares_a_size() {
	let mut session = session(SERVER, Some("alice"));
	let refused = text(session.command_line("MAIL FROM:<alice@example.org> SIZE=70001"));
	for part in [
		"552 5.3.4",
		"70001 bytes",
		"70000 bytes",
		"account alice",
		"set by account alice",
	] {
		assert!(refused.contains(part), "{refused:?} lacks {part:?}");
	}
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<alice@example.org> SIZE=70000")),
		250
	);
}

#[test]
fn the_domain_cap_applies_to_an_account_without_its_own_and_the_server_to_others() {
	let mut session = session(SERVER, Some("bob"));
	let refused = text(session.command_line("MAIL FROM:<bob@example.org> SIZE=100001"));
	assert!(
		refused.contains("552 5.3.4") && refused.contains("set by domain example.org"),
		"{refused}"
	);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<bob@example.org> SIZE=100000")),
		250
	);
	let mut other = self::session(SERVER, Some("dave"));
	assert_eq!(
		reply_code(&other.command_line("MAIL FROM:<dave@example.net> SIZE=5000000")),
		250
	);
}

#[test]
fn a_declared_size_over_a_recipients_cap_refuses_that_recipient_only() {
	let mut session = session(SERVER, None);
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<x@example.com> SIZE=80000")),
		250
	);
	let refused = text(session.command_line("RCPT TO:<alice@example.org>"));
	assert!(refused.starts_with("552 5.3.4"), "{refused}");
	assert!(
		!refused.contains("70000"),
		"a stranger is not told the cap of the recipient: {refused}"
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<bob@example.org>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<dave@example.net>")),
		250
	);
}

#[test]
fn a_message_larger_than_it_declared_is_refused_whole_at_the_end_of_the_data() {
	let mut session = session(SERVER, None);
	session.command_line("MAIL FROM:<x@example.com> SIZE=1000");
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<carol@example.net>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<dave@example.net>")),
		250
	);
	let reply = send_body(&mut session, 70_000);
	assert!(reply.starts_with("552 5.3.4"), "{reply}");
	let mut ok = self::session(SERVER, None);
	ok.command_line("MAIL FROM:<x@example.com>");
	ok.command_line("RCPT TO:<dave@example.net>");
	let reply = send_body(&mut ok, 70_000);
	assert!(
		reply.starts_with("250"),
		"dave has no cap of his own: {reply}"
	);
}

#[test]
fn an_authenticated_sender_is_told_its_own_cap_at_the_end_of_the_data() {
	let mut session = session(SERVER, Some("alice"));
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<dave@example.net>");
	let reply = send_body(&mut session, 75_000);
	for part in ["552 5.3.4", "70000 bytes", "account alice"] {
		assert!(reply.contains(part), "{reply:?} lacks {part:?}");
	}
}

#[test]
fn an_alias_is_refused_when_any_member_cannot_take_the_message() {
	let directory = Arc::new(
		Directory::new(
			["example.org".to_string(), "example.net".to_string()],
			[
				("carol@example.net".to_string(), "carol".to_string()),
				("dave@example.net".to_string(), "dave".to_string()),
			],
		)
		.with_aliases([(
			"team@example.net".to_string(),
			crate::smtp::directory::AliasSpec {
				members: vec!["carol@example.net".into(), "dave@example.net".into()],
				senders: Vec::new(),
				hidden: true,
				list_id: None,
			},
		)])
		.with_limits(shared(SERVER)),
	);
	let mut session = Session::new("mail.example.org").with_directory(directory);
	session.command_line("EHLO client.example.org");
	session.command_line("MAIL FROM:<x@example.com> SIZE=70000");
	let refused = text(session.command_line("RCPT TO:<team@example.net>"));
	assert!(refused.starts_with("552 5.3.4"), "{refused}");
}

#[test]
fn bdat_is_held_to_the_same_caps() {
	let mut chunk = Vec::new();
	while chunk.len() < 80_000 {
		chunk.extend_from_slice(&[b'x'; 70]);
		chunk.extend_from_slice(b"\r\n");
	}
	let mut session = session(SERVER, Some("alice"));
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<dave@example.net>");
	let Action::CollectChunk { .. } = session.command_line(&format!("BDAT {} LAST", chunk.len()))
	else {
		panic!("expected CollectChunk");
	};
	let reply = text(session.bdat_chunk(&chunk, true));
	assert!(
		reply.starts_with("552 5.3.4") && reply.contains("account alice"),
		"{reply}"
	);
}
