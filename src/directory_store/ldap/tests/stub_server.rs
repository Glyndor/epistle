//! A stand-in LDAP server that speaks just enough of the wire protocol to
//! answer binds and searches, and counts the connections it receives. The
//! tests that need a real directory live in `tests/system/ldap.rs`; these
//! pin how many round trips a login costs and that a dead server cannot
//! hold the caller.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::super::limits::Limits;
use super::super::{LdapAuthenticator, LdapBusy, time_left};
use crate::config::Ldap;
use crate::test_support::fixtures;

/// A login budget with the given wait and a generous entry cap.
fn budget(timeout: Duration) -> Limits {
	Limits {
		timeout,
		entries: 1000,
	}
}

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
	assert_eq!(
		ldap.authenticate("nobody", fixtures::wrong_password()),
		Ok(None)
	);
	// One connection for the service bind and search, and one for the
	// user bind a known login would have made.
	assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// A server that accepts connections and never answers, and the number of
/// connections it has accepted.
fn spawn_silent_server() -> (u16, Arc<AtomicUsize>) {
	let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	let accepted = Arc::new(AtomicUsize::new(0));
	let counter = Arc::clone(&accepted);
	std::thread::spawn(move || {
		let mut held = Vec::new();
		for stream in listener.incoming() {
			counter.fetch_add(1, Ordering::SeqCst);
			held.push(stream);
		}
	});
	(port, accepted)
}

#[test]
fn a_server_that_never_answers_is_busy_and_does_not_hold_the_caller() {
	let (port, _) = spawn_silent_server();
	let ldap = LdapAuthenticator::with_queue(config(port), budget(Duration::from_millis(300)), 4);
	let (done_tx, done_rx) = std::sync::mpsc::channel();
	std::thread::spawn(move || {
		let started = Instant::now();
		let outcome = ldap.authenticate("alice", fixtures::password());
		let _ = done_tx.send((outcome, started.elapsed()));
	});
	let (outcome, elapsed) = done_rx
		.recv_timeout(Duration::from_secs(5))
		.expect("authenticate returned within the deadline");
	// Not `Ok(None)`: a server that did not answer is not a wrong password.
	assert_eq!(outcome, Err(LdapBusy::Reached));
	assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
}

#[test]
fn a_server_that_cannot_be_reached_is_busy_not_a_wrong_password() {
	// A port nothing listens on: bind, note the port, close.
	let port = TcpListener::bind("127.0.0.1:0")
		.expect("bind")
		.local_addr()
		.expect("addr")
		.port();
	let ldap = LdapAuthenticator::new(config(port));
	assert_eq!(
		ldap.authenticate("alice", fixtures::password()),
		Err(LdapBusy::NotSent)
	);
}

#[test]
fn a_full_queue_turns_the_login_away_at_once() {
	let (port, _) = spawn_silent_server();
	let ldap = Arc::new(LdapAuthenticator::with_queue(
		config(port),
		budget(Duration::from_secs(3)),
		1,
	));
	// One request in the worker, one waiting in the queue.
	for _ in 0..2 {
		let ldap = Arc::clone(&ldap);
		std::thread::spawn(move || {
			let _ = ldap.authenticate("alice", fixtures::password());
		});
		std::thread::sleep(Duration::from_millis(150));
	}
	let started = Instant::now();
	assert_eq!(
		ldap.authenticate("alice", fixtures::password()),
		Err(LdapBusy::NotSent)
	);
	assert!(
		started.elapsed() < Duration::from_millis(1500),
		"a full queue made the login wait {:?}",
		started.elapsed()
	);
}

#[test]
fn a_request_past_its_deadline_is_not_worked_on() {
	let now = Instant::now();
	assert_eq!(time_left(now, now + Duration::from_millis(1)), None);
	assert_eq!(time_left(now, now), None);
	assert!(time_left(now + Duration::from_secs(1), now).is_some());
}

#[test]
fn an_unknown_login_is_classified_like_a_known_one_when_the_user_bind_cannot_be_made() {
	// The first connection is answered like an empty directory; every later
	// one is closed at once, so the user bind of step (4) gets no answer.
	let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	std::thread::spawn(move || {
		for (index, stream) in listener.incoming().enumerate() {
			let Ok(mut stream) = stream else { return };
			if index > 0 {
				continue;
			}
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
	let ldap = LdapAuthenticator::with_queue(config(port), budget(Duration::from_secs(3)), 4);
	// A known login whose user bind fails in transport is unavailable; an
	// unknown one must be too, not a refusal.
	assert_eq!(
		ldap.authenticate("nobody", fixtures::wrong_password()),
		Err(LdapBusy::Reached)
	);
}
