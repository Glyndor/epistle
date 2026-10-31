//! With the password-check gate full, SMTP AUTH PLAIN and LOGIN answer
//! `454 4.7.0` instead of `535`, whatever the login and the password, and the
//! attempt does not count toward the failures that close the connection.

use super::super::scram::tests_scram::{b64, reply_code};
use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::directory::hash_gate::HashGate;
use crate::smtp::directory::hash_gate::tests::base::full_gate;
use crate::test_fixtures as fixtures;

fn session(gate: &Arc<HashGate>) -> Session {
	let directory = Arc::new(gate_directory().with_hash_gate(gate.clone()));
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session
}

fn plain(session: &mut Session, login: &str, password: &str) -> u16 {
	let response = b64(&format!("\0{login}\0{password}"));
	reply_code(&session.command_line(&format!("AUTH PLAIN {response}")))
}

fn login(session: &mut Session, user: &str, password: &str) -> u16 {
	assert_eq!(reply_code(&session.command_line("AUTH LOGIN")), 334);
	assert_eq!(reply_code(&session.auth_line(&b64(user))), 334);
	reply_code(&session.auth_line(&b64(password)))
}

#[test]
fn a_full_gate_answers_a_temporary_failure_to_every_password_auth() {
	type Attempt = fn(&mut Session, &str, &str) -> u16;
	let attempts: [(&str, Attempt); 2] = [("PLAIN", plain), ("LOGIN", login)];
	for (what, attempt) in attempts {
		let (gate, occupied) = full_gate();
		let mut session = session(&gate);
		// More than the three failures that close a connection.
		for round in 0..4 {
			for (user, secret) in [
				(OPEN, fixtures::password()),
				(OPEN, fixtures::wrong_password()),
				("nobody-here", fixtures::wrong_password()),
			] {
				assert_eq!(
					attempt(&mut session, user, secret),
					454,
					"{what} {round} {user}"
				);
			}
		}
		assert_eq!(session.authenticated(), None);
		drop(occupied);
		assert_eq!(
			attempt(&mut session, OPEN, fixtures::wrong_password()),
			535,
			"{what}: a wrong password is refused again once a place is free"
		);
		assert_eq!(
			attempt(&mut session, OPEN, fixtures::password()),
			235,
			"{what}"
		);
		assert_eq!(session.authenticated(), Some(OPEN));
	}
}
