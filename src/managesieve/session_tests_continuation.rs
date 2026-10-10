use super::super::store::ScriptStore;
use super::{Backend, Session};
use crate::smtp::auth::tests::fixture_password;
use base64::Engine;

struct Login(std::path::PathBuf);
impl Backend for Login {
	fn verify(&self, user: &str, pass: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		(user == "alice" && pass == fixture_password()).then(|| "alice".into())
	}
	fn store(&self, account: &str) -> ScriptStore {
		ScriptStore::new(&self.0, account)
	}
}

#[test]
fn sieve_plain_continuation_login_and_cancel_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = Session::new(Login(dir.path().into()), true);
	assert!(
		session.handle_line("AUTHENTICATE \"PLAIN\"", None).encode() == b"\"\"\r\n",
		"ManageSieve AUTHENTICATE PLAIN must send an empty continuation"
	);
	let encoded = base64::engine::general_purpose::STANDARD
		.encode(format!("\0alice\0{}", fixture_password()));
	let response = format!("\"{encoded}\"");
	assert!(
		session.handle_line(&response, None).encode() == b"OK \"Authenticated.\"\r\n",
		"ManageSieve continuation must authenticate the quoted client response"
	);
	assert!(
		session.handle_line("UNAUTHENTICATE", None).encode() == b"OK\r\n",
		"ManageSieve continuation login must enter authenticated state"
	);
	for cancel in ["*", "\"*\"", "*", "\"*\""] {
		assert!(
			session.handle_line("AUTHENTICATE \"PLAIN\"", None).encode() == b"\"\"\r\n",
			"ManageSieve AUTHENTICATE PLAIN must send an empty continuation"
		);
		assert!(
			session.handle_line(cancel, None).encode() == b"NO \"Authentication cancelled.\"\r\n",
			"ManageSieve asterisk must cancel without counting a failed login"
		);
	}
	assert!(
		session.handle_line("UNAUTHENTICATE", None).encode() == b"NO \"Not authenticated.\"\r\n",
		"ManageSieve cancellation must leave the session unauthenticated"
	);
	session.handle_line("AUTHENTICATE \"PLAIN\"", None);
	assert!(
		session.handle_line(&response, None).encode() == b"OK \"Authenticated.\"\r\n",
		"ManageSieve must allow another login after cancellation"
	);
	session.handle_line("UNAUTHENTICATE", None);
	session.handle_line("AUTHENTICATE \"PLAIN\"", None);
	assert!(
		session
			.handle_line(
				&format!("{{{}+}}", encoded.len()),
				Some(encoded.as_bytes().to_vec())
			)
			.encode() == b"OK \"Authenticated.\"\r\n",
		"ManageSieve continuation must accept a literal client response"
	);
	let mut cleartext = Session::new(Login(dir.path().into()), false);
	assert!(
		cleartext
			.handle_line("AUTHENTICATE \"PLAIN\"", None)
			.encode() == b"NO (ENCRYPT-NEEDED) \"TLS is required first.\"\r\n",
		"ManageSieve must require TLS before sending a SASL challenge"
	);
}
