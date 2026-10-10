use super::{Backend, Session};
use crate::smtp::auth::tests::fixture_password;
use base64::Engine;

struct Login;
impl Backend for Login {
	fn verify(&self, user: &str, pass: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		(user == "alice" && pass == fixture_password()).then(|| "alice".into())
	}
	fn load(&self, _: &str) -> Vec<(String, Vec<u8>)> {
		Vec::new()
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

#[test]
fn pop3_plain_continuation_login_and_cancel_wire() {
	let mut session = Session::new(Login);
	assert!(
		session.handle_line("AUTH PLAIN").encode() == b"+ \r\n",
		"POP3 AUTH PLAIN must send an empty continuation"
	);
	let encoded = base64::engine::general_purpose::STANDARD
		.encode(format!("\0alice\0{}", fixture_password()));
	assert!(
		session.handle_line(&encoded).encode() == b"+OK mailbox ready, 0 messages\r\n",
		"POP3 continuation must authenticate the client response"
	);
	assert!(
		session.handle_line("STAT").encode() == b"+OK 0 0\r\n",
		"POP3 continuation login must enter transaction state"
	);
	let mut session = Session::new(Login);
	assert!(
		session.handle_line("AUTH PLAIN").encode() == b"+ \r\n",
		"POP3 AUTH PLAIN must send an empty continuation"
	);
	assert!(
		session.handle_line("*").encode() == b"-ERR authentication cancelled\r\n",
		"POP3 asterisk must cancel authentication"
	);
	assert!(
		session.handle_line("STAT").encode() == b"-ERR authenticate first\r\n",
		"POP3 cancellation must leave authorization state"
	);
	session.handle_line("AUTH PLAIN");
	assert!(
		session.handle_line(&encoded).encode() == b"+OK mailbox ready, 0 messages\r\n",
		"POP3 must allow another login after cancellation"
	);
}
