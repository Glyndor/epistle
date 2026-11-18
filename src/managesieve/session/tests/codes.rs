//! The response codes of RFC 5804 section 1.3 a client reads to tell a failure
//! that can pass from one that cannot.
//!
//! `(AUTH-TOO-WEAK)` and `(WARNINGS)` are never sent: only PLAIN over TLS is
//! offered, and no policy calls it too weak for an account, and the script
//! check either accepts a script or refuses it, with no warning in between.

use super::super::super::store::ScriptStore;
use super::{Backend, Response, Session};
use crate::managesieve::command::Command;

/// A backend whose account directory cannot be opened, so every store
/// operation fails with an I/O error.
struct Unopenable(std::path::PathBuf);

impl Backend for Unopenable {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		None
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.0, account)
	}
}

fn wire(response: &Response) -> String {
	String::from_utf8(response.encode()).expect("utf8")
}

fn broken_session(dir: &tempfile::TempDir) -> Session<Unopenable> {
	// The accounts root is a regular file, so no account directory can be
	// created under it.
	let root = dir.path().join("accounts");
	std::fs::write(&root, b"not a directory").expect("write");
	let mut session = Session::new(Unopenable(root), true);
	session.adopt_account_for_test("alice");
	session
}

#[test]
fn a_storage_error_that_can_pass_is_told_trylater() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = broken_session(&dir);
	let put = session.handle(Command::PutScript {
		name: "a".to_string(),
		content: "keep;\r\n".to_string(),
	});
	assert_eq!(wire(&put), "NO (TRYLATER) \"Storage error.\"\r\n");
	let get = session.handle(Command::GetScript("a".to_string()));
	assert_eq!(wire(&get), "NO (TRYLATER) \"Storage error.\"\r\n");
}

#[test]
fn a_refusal_that_cannot_pass_is_not_told_trylater() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(Unopenable(dir.path().to_path_buf()), true);
	session.adopt_account_for_test("alice");
	let missing = session.handle(Command::GetScript("nothing".to_string()));
	assert_eq!(wire(&missing), "NO (NONEXISTENT) \"No such script.\"\r\n");
	let bad = session.handle(Command::CheckScript {
		content: "if if if".to_string(),
	});
	assert!(!wire(&bad).contains("TRYLATER"), "{}", wire(&bad));
}

#[test]
fn authenticate_before_tls_is_told_encrypt_needed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(Unopenable(dir.path().to_path_buf()), false);
	let response = session.handle(Command::Authenticate {
		mechanism: "PLAIN".to_string(),
		initial: None,
	});
	assert_eq!(
		wire(&response),
		"NO (ENCRYPT-NEEDED) \"TLS is required first.\"\r\n"
	);
}

#[test]
fn a_wrong_password_and_an_unknown_mechanism_carry_no_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(Unopenable(dir.path().to_path_buf()), true);
	let other = session.handle(Command::Authenticate {
		mechanism: "CRAM-MD5".to_string(),
		initial: None,
	});
	assert_eq!(wire(&other), "NO \"Only SASL PLAIN is supported.\"\r\n");
}
