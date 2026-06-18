//! Behavioural tests for the POP3 session state machine.

use super::command::Command;
use super::session::{Backend, Response, Session};
use std::cell::RefCell;

/// In-memory backend: one fixed credential, a fixed inbox, and a record of
/// which unique-ids were removed at QUIT.
struct FakeBackend {
	user: String,
	pass: String,
	inbox: Vec<(String, Vec<u8>)>,
	removed: RefCell<Vec<String>>,
}

impl FakeBackend {
	fn new(inbox: Vec<(String, Vec<u8>)>) -> Self {
		Self {
			user: "alice".to_string(),
			pass: "secret".to_string(),
			inbox,
			removed: RefCell::new(Vec::new()),
		}
	}
}

impl Backend for FakeBackend {
	fn verify(&self, user: &str, pass: &str) -> Option<String> {
		(user == self.user && pass == self.pass).then(|| self.user.clone())
	}
	fn load(&self, _account: &str) -> Vec<(String, Vec<u8>)> {
		self.inbox.clone()
	}
	fn remove(&self, _account: &str, uids: &[String]) {
		self.removed.borrow_mut().extend_from_slice(uids);
	}
}

fn inbox() -> Vec<(String, Vec<u8>)> {
	vec![
		(
			"uid-1".to_string(),
			b"Subject: one\r\n\r\nbody one\r\n".to_vec(),
		),
		(
			"uid-2".to_string(),
			b"Subject: two\r\n\r\nbody two\r\n".to_vec(),
		),
	]
}

fn login(session: &mut Session<FakeBackend>) {
	assert!(matches!(
		session.handle(Command::User("alice".into())),
		Response::Ok(_)
	));
	assert!(matches!(
		session.handle(Command::Pass("secret".into())),
		Response::Ok(_)
	));
}

#[test]
fn sasl_auth_plain_logs_in() {
	use base64::Engine;
	let mut session = Session::new(FakeBackend::new(inbox()));
	// AUTH with no mechanism lists PLAIN.
	let Response::Multiline { body, .. } = session.handle(Command::Auth {
		mechanism: None,
		initial: None,
	}) else {
		panic!("expected mechanism list");
	};
	assert!(String::from_utf8_lossy(&body).contains("PLAIN"));

	// AUTH PLAIN with the initial response authenticates.
	let ir = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
	assert!(matches!(
		session.handle(Command::Auth {
			mechanism: Some("PLAIN".into()),
			initial: Some(ir),
		}),
		Response::Ok(_)
	));
	assert!(matches!(session.handle(Command::Stat), Response::Ok(_)));

	// A wrong password fails.
	let mut session = Session::new(FakeBackend::new(inbox()));
	let bad = base64::engine::general_purpose::STANDARD.encode("\0alice\0wrong");
	assert!(matches!(
		session.handle(Command::Auth {
			mechanism: Some("PLAIN".into()),
			initial: Some(bad),
		}),
		Response::Err(_)
	));
}

#[test]
fn rejects_commands_before_authentication() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	assert!(matches!(session.handle(Command::Stat), Response::Err(_)));
}

#[test]
fn bad_password_fails_without_oracle() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	session.handle(Command::User("alice".into()));
	let r = session.handle(Command::Pass("wrong".into()));
	assert_eq!(r, Response::Err("authentication failed".to_string()));
	// Still in AUTHORIZATION: message commands stay rejected.
	assert!(matches!(session.handle(Command::Stat), Response::Err(_)));
}

#[test]
fn stat_and_list_report_counts_and_sizes() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	assert_eq!(
		session.handle(Command::Stat),
		Response::Ok("2 52".to_string())
	);
	let Response::Multiline { body, .. } = session.handle(Command::List(None)) else {
		panic!("expected multiline");
	};
	assert_eq!(body, b"1 26\r\n2 26\r\n");
}

#[test]
fn retr_returns_message_body() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	let Response::Multiline { body, status } = session.handle(Command::Retr(1)) else {
		panic!("expected multiline");
	};
	assert_eq!(status, "26 octets");
	assert_eq!(body, b"Subject: one\r\n\r\nbody one\r\n");
	assert!(matches!(session.handle(Command::Retr(9)), Response::Err(_)));
}

#[test]
fn uidl_lists_unique_ids() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	let Response::Multiline { body, .. } = session.handle(Command::Uidl(None)) else {
		panic!("expected multiline");
	};
	assert_eq!(body, b"1 uid-1\r\n2 uid-2\r\n");
	assert_eq!(
		session.handle(Command::Uidl(Some(2))),
		Response::Ok("2 uid-2".to_string())
	);
}

#[test]
fn top_returns_headers_plus_n_body_lines() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	let Response::Multiline { body, .. } = session.handle(Command::Top(1, 0)) else {
		panic!("expected multiline");
	};
	// Zero body lines: headers and the blank separator only.
	assert_eq!(body, b"Subject: one\r\n\r\n");
}

#[test]
fn dele_hides_message_and_quit_commits() {
	let backend = FakeBackend::new(inbox());
	let mut session = Session::new(backend);
	login(&mut session);
	assert!(matches!(session.handle(Command::Dele(1)), Response::Ok(_)));
	// Deleted message no longer appears or is retrievable.
	assert_eq!(
		session.handle(Command::Stat),
		Response::Ok("1 26".to_string())
	);
	assert!(matches!(session.handle(Command::Retr(1)), Response::Err(_)));
	assert!(matches!(session.handle(Command::Quit), Response::Bye(_)));
}

#[test]
fn rset_restores_deleted_messages() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	session.handle(Command::Dele(1));
	assert!(matches!(session.handle(Command::Rset), Response::Ok(_)));
	assert_eq!(
		session.handle(Command::Stat),
		Response::Ok("2 52".to_string())
	);
}

#[test]
fn encode_dot_stuffs_and_terminates() {
	let response = Response::Multiline {
		status: "1 octets".to_string(),
		body: b".hidden\r\nplain\r\n".to_vec(),
	};
	let encoded = response.encode();
	assert_eq!(encoded, b"+OK 1 octets\r\n..hidden\r\nplain\r\n.\r\n");
}

#[test]
fn quit_in_authorization_closes() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	let r = session.handle(Command::Quit);
	assert!(r.is_final());
}

#[test]
fn pass_without_user_errors() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	assert!(matches!(
		session.handle(Command::Pass("x".into())),
		Response::Err(_)
	));
}

#[test]
fn capa_available_in_both_states() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	// Before login.
	assert!(matches!(
		session.handle(Command::Capa),
		Response::Multiline { .. }
	));
	login(&mut session);
	// And after.
	let Response::Multiline { body, .. } = session.handle(Command::Capa) else {
		panic!("expected multiline");
	};
	assert!(body.windows(4).any(|w| w == b"UIDL"));
}

#[test]
fn list_single_and_out_of_range() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	assert_eq!(
		session.handle(Command::List(Some(1))),
		Response::Ok("1 26".to_string())
	);
	assert!(matches!(
		session.handle(Command::List(Some(99))),
		Response::Err(_)
	));
}

#[test]
fn noop_and_user_pass_after_login() {
	let mut session = Session::new(FakeBackend::new(inbox()));
	login(&mut session);
	assert_eq!(session.handle(Command::Noop), Response::Ok(String::new()));
	// USER/PASS are meaningless once authenticated.
	assert!(matches!(
		session.handle(Command::User("bob".into())),
		Response::Err(_)
	));
	assert!(matches!(
		session.handle(Command::Pass("x".into())),
		Response::Err(_)
	));
}

#[test]
fn greeting_is_positive() {
	let session = Session::new(FakeBackend::new(inbox()));
	assert!(matches!(session.greeting(), Response::Ok(_)));
}
