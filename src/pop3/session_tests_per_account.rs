//! `[server] max_connections_per_account`: POP3 rejects an eleventh
//! connection from the same (account, IP) with `-ERR [IN-USE]` and
//! releases the slot on every disconnect path.

use std::sync::Arc;

use crate::net::per_account_conn::PerAccountCounter;

use super::command::Command;
use super::session::{Backend, Session};

struct Inbox;

impl Backend for Inbox {
	fn verify(&self, _: &str, _: &str, _: Option<std::net::IpAddr>) -> Option<String> {
		Some("alice".into())
	}
	fn load(&self, _: &str) -> Vec<(String, Vec<u8>)> {
		Vec::new()
	}
	fn remove(&self, _: &str, _: &[String]) {}
}

fn session_in(peer: std::net::IpAddr, counter: Arc<PerAccountCounter>) -> Session<Inbox> {
	let mut session = Session::new(Inbox);
	session.set_peer_ip(Some(peer));
	session.with_per_account_counter(counter)
}

#[test]
fn the_eleventh_authentication_from_one_account_and_ip_is_refused_with_in_use() {
	let peer: std::net::IpAddr = "203.0.113.7".parse().unwrap();
	let counter = Arc::new(PerAccountCounter::new(10, 50));
	let mut sessions = Vec::new();
	for _ in 0..10 {
		let mut session = session_in(peer, Arc::clone(&counter));
		session.handle(Command::User("alice".into()));
		let response = session.handle(Command::Pass(String::new()));
		let text = match response {
			super::session::Response::Ok(text) => text,
			other => panic!("expected Ok, got {other:?}"),
		};
		assert!(text.contains("mailbox ready"), "got {text}");
		sessions.push(session);
	}
	// The eleventh connection is refused.
	let mut eleventh = session_in(peer, Arc::clone(&counter));
	session_in(peer, Arc::clone(&counter));
	eleventh.handle(Command::User("alice".into()));
	let response = eleventh.handle(Command::Pass(String::new()));
	let text = match response {
		super::session::Response::Err(text) => text,
		other => panic!("expected Err, got {other:?}"),
	};
	assert!(
		text.contains("[IN-USE]"),
		"the eleventh POP3 connection must carry the IN-USE refusal: {text}"
	);
	// Disconnect the first; the eleventh must now fit.
	drop(sessions.remove(0));
	let mut fresh = session_in(peer, Arc::clone(&counter));
	fresh.handle(Command::User("alice".into()));
	let response = fresh.handle(Command::Pass(String::new()));
	let text = match response {
		super::session::Response::Ok(text) => text,
		other => panic!("expected Ok, got {other:?}"),
	};
	assert!(text.contains("mailbox ready"), "got {text}");
}

#[test]
fn the_per_account_total_cap_holds_across_distinct_ip_addresses() {
	let counter = Arc::new(PerAccountCounter::new(50, 2));
	let mut sessions = Vec::new();
	for index in 0..2 {
		let peer: std::net::IpAddr = format!("203.0.113.{}", index + 1).parse().unwrap();
		let mut session = session_in(peer, Arc::clone(&counter));
		session.handle(Command::User("alice".into()));
		let response = session.handle(Command::Pass(String::new()));
		let text = match response {
			super::session::Response::Ok(text) => text,
			other => panic!("expected Ok, got {other:?}"),
		};
		assert!(text.contains("mailbox ready"), "{text}");
		sessions.push(session);
	}
	let peer: std::net::IpAddr = "203.0.113.42".parse().unwrap();
	let mut third = session_in(peer, Arc::clone(&counter));
	third.handle(Command::User("alice".into()));
	let response = third.handle(Command::Pass(String::new()));
	let text = match response {
		super::session::Response::Err(text) => text,
		other => panic!("expected Err, got {other:?}"),
	};
	assert!(
		text.contains("[IN-USE]"),
		"the per-account total cap refuses the third connection: {text}"
	);
	// Drop one connection: the third must now fit.
	drop(sessions.remove(0));
	let mut fresh = session_in(peer, Arc::clone(&counter));
	fresh.handle(Command::User("alice".into()));
	let response = fresh.handle(Command::Pass(String::new()));
	let text = match response {
		super::session::Response::Ok(text) => text,
		other => panic!("expected Ok, got {other:?}"),
	};
	assert!(text.contains("mailbox ready"), "{text}");
}
