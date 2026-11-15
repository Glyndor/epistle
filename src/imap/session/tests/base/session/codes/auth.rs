//! RFC 5530 response codes on the authentication and state failures: bad
//! credentials, TLS required first, and a command sent in the wrong state.
//! Each case sends the command in the state it describes and compares the
//! tagged reply byte for byte.

use super::*;
use crate::test_support::fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn unauth(dir: &std::path::Path) -> Session {
	Session::new("mail.example.org", dir.to_path_buf(), directory())
}

fn plain_command(user: &str, password: &str) -> String {
	format!(
		"a AUTHENTICATE PLAIN {}",
		B64.encode(format!("\0{user}\0{password}"))
	)
}

#[test]
fn login_with_an_unknown_user_and_a_wrong_password_are_the_same_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = unauth(dir.path())
		.command_line(&format!("a LOGIN missing@example.org {}", "wrong"))
		.bytes;
	let wrong = unauth(dir.path())
		.command_line("a LOGIN alice@example.org wrong")
		.bytes;
	assert_eq!(missing, wrong);
	assert_eq!(
		String::from_utf8_lossy(&wrong),
		"a NO [AUTHENTICATIONFAILED] LOGIN failed\r\n"
	);
}

#[test]
fn authenticate_plain_with_bad_credentials_is_the_same_for_user_and_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = unauth(dir.path())
		.command_line(&plain_command("missing", "wrong"))
		.bytes;
	let wrong = unauth(dir.path())
		.command_line(&plain_command("alice", "wrong"))
		.bytes;
	assert_eq!(missing, wrong);
	assert_eq!(
		String::from_utf8_lossy(&wrong),
		"a NO [AUTHENTICATIONFAILED] authentication failed\r\n"
	);
}

#[test]
fn authenticate_login_and_a_garbled_plain_answer_use_the_same_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(dir.path());
	session.command_line("a AUTHENTICATE LOGIN");
	session.auth_response(&B64.encode("alice"));
	let reply = text(&session.auth_response(&B64.encode("wrong")));
	assert_eq!(
		reply,
		"a NO [AUTHENTICATIONFAILED] authentication failed\r\n"
	);

	let mut session = unauth(dir.path());
	session.command_line("a AUTHENTICATE PLAIN");
	let reply = text(&session.auth_response("not base64 !!"));
	assert_eq!(
		reply,
		"a NO [AUTHENTICATIONFAILED] authentication failed\r\n"
	);
}

#[test]
fn the_third_failed_login_still_carries_the_code_before_the_goodbye() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = unauth(dir.path());
	for _ in 0..2 {
		session.command_line("a LOGIN alice wrong");
	}
	let reply = text(&session.command_line("a LOGIN alice wrong"));
	assert_eq!(
		reply,
		"* BYE too many failures\r\na NO [AUTHENTICATIONFAILED] LOGIN failed\r\n"
	);
}

#[test]
fn a_correct_login_is_not_given_a_failure_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let reply =
		text(&unauth(dir.path()).command_line(&format!("a LOGIN alice {}", fixtures::password())));
	assert!(reply.contains("a OK"), "{reply}");
	assert!(!reply.contains("AUTHENTICATIONFAILED"), "{reply}");
}

#[test]
fn login_and_authenticate_over_plain_text_ask_for_starttls_first() {
	let dir = tempfile::tempdir().expect("tempdir");
	for command in [
		format!("a LOGIN alice {}", fixtures::password()),
		"a AUTHENTICATE PLAIN".to_string(),
		plain_command("alice", fixtures::password()),
	] {
		let mut session =
			Session::new("mail.example.org", dir.path().to_path_buf(), directory()).with_starttls();
		assert_eq!(
			text(&session.command_line(&command)),
			"a NO [PRIVACYREQUIRED] STARTTLS first\r\n",
			"{command}"
		);
	}
}

#[test]
fn an_unsupported_sasl_mechanism_cannot_be_used() {
	let dir = tempfile::tempdir().expect("tempdir");
	let reply = text(&unauth(dir.path()).command_line("a AUTHENTICATE UNKNOWN"));
	assert_eq!(reply, "a NO [CANNOT] unsupported SASL mechanism\r\n");
}

#[test]
fn an_unsupported_compress_algorithm_cannot_be_used() {
	let dir = tempfile::tempdir().expect("tempdir");
	let reply = text(&unauth(dir.path()).command_line("a COMPRESS GZIP"));
	assert_eq!(reply, "a BAD [CANNOT] unsupported COMPRESS algorithm\r\n");
}

#[test]
fn a_second_login_is_a_bad_state_without_a_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let reply = text(&session.command_line(&format!("a LOGIN alice {}", fixtures::password())));
	assert_eq!(reply, "a BAD already authenticated\r\n");
	let reply = text(&session.command_line("a AUTHENTICATE PLAIN"));
	assert_eq!(reply, "a BAD already authenticated\r\n");
}

#[test]
fn commands_that_need_authentication_are_bad_before_login() {
	let dir = tempfile::tempdir().expect("tempdir");
	for command in [
		"LIST \"\" *",
		"LSUB \"\" *",
		"STATUS INBOX (MESSAGES)",
		"SELECT INBOX",
		"EXAMINE INBOX",
		"CREATE Work",
		"DELETE Work",
		"RENAME Work Other",
		"SUBSCRIBE Work",
		"UNSUBSCRIBE Work",
		"NAMESPACE",
		"IDLE",
		"GETQUOTAROOT INBOX",
		"GETQUOTA \"\"",
		"GETACL INBOX",
		"MYRIGHTS INBOX",
		"GETMETADATA INBOX (/private/comment)",
		"SETMETADATA INBOX (/private/comment \"x\")",
		"NOTIFY NONE",
		"ENABLE UTF8=ACCEPT",
		"APPEND INBOX {1+}",
	] {
		let mut session = unauth(dir.path());
		let reply = text(&session.command_line(&format!("a {command}")));
		let tagged = reply.lines().next().unwrap_or_default();
		assert!(tagged.starts_with("a BAD "), "{command}: {reply}");
		assert!(tagged.contains("authenticat"), "{command}: {reply}");
		assert!(!tagged.contains(" NO "), "{command}: {reply}");
	}
	let reply = text(&unauth(dir.path()).command_line("a LIST \"\" *"));
	assert_eq!(reply, "a BAD not authenticated\r\n");
}

#[test]
fn commands_that_need_a_mailbox_are_bad_when_none_is_selected() {
	let dir = tempfile::tempdir().expect("tempdir");
	for command in [
		"SEARCH ALL",
		"UID SEARCH ALL",
		"FETCH 1 FLAGS",
		"UID FETCH 1 FLAGS",
		"STORE 1 +FLAGS (\\Seen)",
		"UID STORE 1 +FLAGS (\\Seen)",
		"COPY 1 INBOX",
		"UID COPY 1 INBOX",
		"MOVE 1 INBOX",
		"EXPUNGE",
		"UID EXPUNGE 1",
		"CHECK",
		"CLOSE",
		"UNSELECT",
		"SORT (DATE) UTF-8 ALL",
		"THREAD REFERENCES UTF-8 ALL",
	] {
		let mut session = logged_in(dir.path());
		let reply = text(&session.command_line(&format!("a {command}")));
		assert_eq!(reply, "a BAD no mailbox selected\r\n", "{command}");
	}
}

#[test]
fn replace_without_a_selected_mailbox_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let reply = text(&session.command_line("a REPLACE 1 INBOX {5}"));
	assert_eq!(reply, "a BAD no mailbox selected\r\n");
}

#[test]
fn append_before_login_is_bad_and_a_late_literal_is_bad() {
	let dir = tempfile::tempdir().expect("tempdir");
	let reply = text(&unauth(dir.path()).command_line("a APPEND INBOX {5}"));
	assert_eq!(reply, "a BAD not authenticated\r\n");
	let mut session = unauth(dir.path());
	let reply = text(&session.literal_done(b"hello"));
	assert_eq!(reply, "* BAD [CLIENTBUG] unexpected literal\r\n");
}

#[test]
fn a_busy_password_gate_is_unavailable_not_a_failed_login() {
	use crate::smtp::directory::gate_fixture::*;
	use crate::smtp::directory::hash_gate::tests::base::full_gate;
	let dir = tempfile::tempdir().expect("tempdir");
	let (gate, _occupied) = full_gate();
	let directory = Arc::new(gate_directory().with_hash_gate(gate));
	let mut session = Session::new("mail.example.org", dir.path().to_path_buf(), directory);
	assert_eq!(
		text(&session.command_line("a LOGIN someone secret")),
		"a NO [UNAVAILABLE] Try again later\r\n"
	);
	assert_eq!(
		text(&session.command_line(&plain_command("someone", "secret"))),
		"a NO [UNAVAILABLE] Try again later\r\n"
	);
}
