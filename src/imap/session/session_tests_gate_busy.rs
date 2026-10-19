//! With the password-check gate full, every IMAP password login is told to
//! try again later instead of being refused as a wrong credential, and the
//! attempt does not count toward the three failures that close the session.
//! What a wrong password, a right one and an unknown login get is the same.

use super::*;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::directory::hash_gate::tests::full_gate;
use crate::test_fixtures as fixtures;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn session(
	dir: &std::path::Path,
	gate: &Arc<crate::smtp::directory::hash_gate::HashGate>,
) -> Session {
	let directory = Arc::new(gate_directory().with_hash_gate(gate.clone()));
	Session::new("mail.example.org", dir.to_path_buf(), directory)
}

fn login(session: &mut Session, user: &str, password: &str) -> String {
	text(&session.command_line(&format!("a LOGIN {user} {password}")))
}

fn plain(session: &mut Session, user: &str, password: &str) -> String {
	let response = B64.encode(format!("\0{user}\0{password}"));
	text(&session.command_line(&format!("a AUTHENTICATE PLAIN {response}")))
}

fn auth_login(session: &mut Session, user: &str, password: &str) -> String {
	session.command_line("a AUTHENTICATE LOGIN");
	session.auth_response(&B64.encode(user));
	text(&session.auth_response(&B64.encode(password)))
}

#[test]
fn a_full_gate_asks_every_password_login_to_try_again() {
	type Attempt = fn(&mut Session, &str, &str) -> String;
	let attempts: [(&str, Attempt); 3] = [
		("LOGIN", login),
		("AUTHENTICATE PLAIN", plain),
		("AUTHENTICATE LOGIN", auth_login),
	];
	for (what, attempt) in attempts {
		let dir = tempfile::tempdir().expect("tempdir");
		let (gate, occupied) = full_gate();
		let mut session = session(dir.path(), &gate);
		// More than the three failures that close a session.
		for round in 0..4 {
			for (user, secret) in [
				(OPEN, fixtures::password()),
				(OPEN, fixtures::wrong_password()),
				("nobody-here", fixtures::wrong_password()),
			] {
				let reply = attempt(&mut session, user, secret);
				assert!(
					reply.contains("NO [UNAVAILABLE]"),
					"{what}, round {round}, {user}: {reply}"
				);
				assert!(!reply.contains("BYE"), "{what}: busy is not a failure");
			}
		}
		assert_eq!(session.account(), None);
		drop(occupied);
		let wrong = attempt(&mut session, OPEN, fixtures::wrong_password());
		assert!(
			wrong.contains("NO ") && !wrong.contains("UNAVAILABLE"),
			"{what}: a wrong password is refused again once a place is free: {wrong}"
		);
		let right = attempt(&mut session, OPEN, fixtures::password());
		assert!(right.contains(" OK "), "{what}: {right}");
		assert_eq!(session.account(), Some(OPEN));
	}
}
