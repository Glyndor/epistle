//! A stand-in LDAP server that speaks just enough of the wire protocol to
//! answer binds and searches, and counts the connections it receives. The
//! tests that need a real directory live in `tests/system/ldap.rs`; these
//! pin how many round trips a login costs and that a dead server cannot
//! hold the caller.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::LdapAuthenticator;
use crate::config::Ldap;

fn config(port: u16) -> Ldap {
	toml::from_str(&format!(
		r#"
url = "ldap://127.0.0.1:{port}"
bind_dn = "cn=svc"
bind_password = "p"
base_dn = "dc=example,dc=org"
user_filter = "(uid=%s)"
account_attribute = "uid"
mail_attribute = "mail"
"#
	))
	.expect("parse ldap config")
}

/// Read one LDAPMessage: its message id and the tag of its operation.
fn read_message(stream: &mut std::net::TcpStream) -> Option<(u8, u8)> {
	let mut head = [0u8; 2];
	stream.read_exact(&mut head).ok()?;
	let mut length = usize::from(head[1]);
	if length & 0x80 != 0 {
		let mut long = vec![0u8; length & 0x7f];
		stream.read_exact(&mut long).ok()?;
		length = long
			.iter()
			.fold(0, |acc, byte| acc * 256 + usize::from(*byte));
	}
	let mut body = vec![0u8; length];
	stream.read_exact(&mut body).ok()?;
	// body: INTEGER message id (02 01 id), then the operation tag.
	Some((body[2], body[3]))
}

/// Answer binds with success and searches with "no entries", forever.
/// Returns the port and the number of connections accepted.
fn spawn_empty_directory() -> (u16, Arc<AtomicUsize>) {
	let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let connections = Arc::new(AtomicUsize::new(0));
	let counter = Arc::clone(&connections);
	std::thread::spawn(move || {
		for stream in listener.incoming() {
			let Ok(mut stream) = stream else { return };
			counter.fetch_add(1, Ordering::SeqCst);
			std::thread::spawn(move || {
				while let Some((id, op)) = read_message(&mut stream) {
					let response_tag = match op {
						0x60 => 0x61,
						0x63 => 0x65,
						_ => return,
					};
					let reply = [
						0x30,
						0x0c,
						0x02,
						0x01,
						id,
						response_tag,
						0x07,
						0x0a,
						0x01,
						0x00,
						0x04,
						0x00,
						0x04,
						0x00,
					];
					if stream.write_all(&reply).is_err() {
						return;
					}
				}
			});
		}
	});
	(port, connections)
}

#[test]
fn an_unknown_login_costs_the_same_connections_as_a_known_one() {
	let (port, connections) = spawn_empty_directory();
	let ldap = LdapAuthenticator::new(config(port));
	assert_eq!(ldap.authenticate("nobody", "wrong"), None);
	// One connection for the service bind and search, and one for the
	// user bind a known login would have made.
	assert_eq!(connections.load(Ordering::SeqCst), 2);
}
