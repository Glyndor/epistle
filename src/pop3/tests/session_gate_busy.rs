//! With the password-check gate full, POP3 USER/PASS and AUTH PLAIN answer
//! `-ERR [SYS/TEMP]` (RFC 3206) instead of `authentication failed`, whatever
//! the login and the password.

use super::super::session::{Response, Session};
use super::backend::MailboxBackend;
use super::command::Command;
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::directory::hash_gate::tests::base::full_gate;
use crate::test_fixtures as fixtures;
use base64::Engine;

const TEMP: &str = "[SYS/TEMP] try again later";

fn plain_initial(user: &str, password: &str) -> Option<String> {
	Some(base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}")))
}

#[test]
fn a_full_gate_answers_a_temporary_failure_to_every_password_login() {
	let tmp = tempfile::tempdir().expect("tempdir");
	let (gate, occupied) = full_gate();
	let directory = gate_directory().with_hash_gate(gate);
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), tmp.path().to_path_buf());
	let mut session = Session::new(backend);
	for (user, secret) in [
		(OPEN, fixtures::password()),
		(OPEN, fixtures::wrong_password()),
		("nobody-here", fixtures::wrong_password()),
	] {
		session.handle(Command::User(user.into()));
		let reply = session.handle(Command::Pass(secret.into()));
		assert_eq!(reply, Response::Err(TEMP.to_string()), "USER/PASS {user}");
		let reply = session.handle(Command::Auth {
			mechanism: Some("PLAIN".into()),
			initial: plain_initial(user, secret),
		});
		assert_eq!(reply, Response::Err(TEMP.to_string()), "AUTH PLAIN {user}");
	}
	drop(occupied);
	session.handle(Command::User(OPEN.into()));
	let reply = session.handle(Command::Pass(fixtures::wrong_password().into()));
	assert_eq!(
		reply,
		Response::Err("authentication failed".to_string()),
		"a wrong password is refused again once a place is free"
	);
	session.handle(Command::User(OPEN.into()));
	let reply = session.handle(Command::Pass(fixtures::password().into()));
	assert!(matches!(reply, Response::Ok(_)), "{reply:?}");
}

#[allow(unused_imports)]
use super::super::session;
