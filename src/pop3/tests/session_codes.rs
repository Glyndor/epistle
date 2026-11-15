//! The response codes of RFC 3206 on the lines a POP3 client reads to tell a
//! permanent failure from one worth retrying: `[AUTH]` on a refused login and
//! `[SYS/TEMP]` when the server had no room to check. No wait is ever
//! announced with `[LOGIN-DELAY]`: the server enforces no minimum interval
//! between logins, and a ban must stay indistinguishable from a wrong
//! password.

use super::super::session::{Response, Session};
use super::backend::MailboxBackend;
use super::command::Command;
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::gate_fixture::*;
use crate::smtp::directory::hash_gate::tests::base::full_gate;
use crate::test_support::fixtures;

fn wire(response: Response) -> String {
	String::from_utf8(response.encode()).expect("utf8")
}

fn session_with(gate_full: bool) -> (Session<MailboxBackend>, tempfile::TempDir) {
	let tmp = tempfile::tempdir().expect("tempdir");
	let mut directory = gate_directory();
	let held = gate_full.then(|| {
		let (gate, occupied) = full_gate();
		directory = gate_directory().with_hash_gate(gate);
		occupied
	});
	std::mem::forget(held);
	let backend = MailboxBackend::new(DirectoryHandle::new(directory), tmp.path().to_path_buf());
	(Session::new(backend), tmp)
}

#[test]
fn a_refused_login_is_told_auth_whoever_it_was() {
	let (mut session, _tmp) = session_with(false);
	for (user, secret) in [
		(OPEN, fixtures::wrong_password()),
		("nobody-here", fixtures::wrong_password()),
	] {
		session.handle(Command::User(user.into()));
		let reply = wire(session.handle(Command::Pass(secret.into())));
		assert_eq!(reply, "-ERR [AUTH] authentication failed\r\n", "{user}");
	}
}

#[test]
fn a_login_the_server_had_no_room_to_check_is_told_temporary_and_never_a_delay() {
	let (mut session, _tmp) = session_with(true);
	session.handle(Command::User(OPEN.into()));
	let reply = wire(session.handle(Command::Pass(fixtures::wrong_password().into())));
	assert_eq!(reply, "-ERR [SYS/TEMP] try again later\r\n");
	assert!(!reply.contains("LOGIN-DELAY"), "{reply}");
}

#[test]
fn a_successful_login_carries_no_failure_code() {
	let (mut session, _tmp) = session_with(false);
	session.handle(Command::User(OPEN.into()));
	let reply = wire(session.handle(Command::Pass(fixtures::password().into())));
	assert!(reply.starts_with("+OK "), "{reply}");
	assert!(!reply.contains('['), "{reply}");
}
