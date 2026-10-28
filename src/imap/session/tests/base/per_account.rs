//! `[server] max_connections_per_account`: after authentication, IMAP
//! rejects an eleventh connection from the same (account, IP) pair with
//! `NO [LIMIT]` and releases the slot on every disconnect path.

use std::sync::Arc;

use crate::imap::session::Session;
use crate::net::per_account_conn::PerAccountCounter;
use crate::test_fixtures as fixtures;

use super::{directory, text as rendered};

fn session_in(
	dir: &std::path::Path,
	peer: std::net::IpAddr,
	shared: &Arc<PerAccountCounter>,
) -> Session {
	let mut session = Session::new("mail.example.org", dir.to_path_buf(), directory());
	session.set_peer_ip(Some(peer));
	session = session.with_per_account_counter(Arc::clone(shared));
	session
}

#[test]
fn the_eleventh_authentication_from_one_account_and_ip_is_refused_with_no_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let peer: std::net::IpAddr = "203.0.113.7".parse().unwrap();
	let shared = Arc::new(PerAccountCounter::new(10, 50));
	let mut sessions = Vec::new();
	for index in 0..10 {
		let mut session = session_in(dir.path(), peer, &shared);
		let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
		assert!(
			rendered(&output).contains("a1 OK"),
			"connection {index} must succeed: {}",
			rendered(&output)
		);
		sessions.push(session);
	}
	// The eleventh must be refused with NO [LIMIT] and not leave a slot.
	let mut eleventh = session_in(dir.path(), peer, &shared);
	let output = eleventh.command_line(&format!("a11 LOGIN alice {}", fixtures::password()));
	assert_eq!(
		rendered(&output),
		"a11 NO [LIMIT] Too many concurrent connections for this account\r\n",
		"the eleventh IMAP connection must answer with the standard LIMIT refusal"
	);
	// A different IP gets a fresh per-IP slot.
	let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
	let mut other_session = session_in(dir.path(), other, &shared);
	let output = other_session.command_line(&format!("b1 LOGIN alice {}", fixtures::password()));
	assert!(
		rendered(&output).contains("b1 OK"),
		"the per-IP cap is independent; {}",
		rendered(&output)
	);
	// Disconnect the first connection; the eleventh must now fit.
	drop(sessions.remove(0));
	let output = eleventh.command_line(&format!("a11 LOGIN alice {}", fixtures::password()));
	assert!(
		rendered(&output).contains("a11 OK"),
		"after one disconnect the per-(account, IP) cap releases its slot: {}",
		rendered(&output)
	);
}

#[test]
fn the_per_account_total_cap_holds_across_distinct_ip_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let shared = Arc::new(PerAccountCounter::new(50, 2));
	let mut sessions = Vec::new();
	for index in 0..2 {
		let peer: std::net::IpAddr = format!("203.0.113.{}", index + 1).parse().unwrap();
		let mut session = session_in(dir.path(), peer, &shared);
		let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
		assert!(
			rendered(&output).contains("a1 OK"),
			"connection {index} must succeed: {}",
			rendered(&output)
		);
		sessions.push(session);
	}
	// The third connection from a third IP is over the per-account total.
	let peer: std::net::IpAddr = "203.0.113.42".parse().unwrap();
	let mut third = session_in(dir.path(), peer, &shared);
	let output = third.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert_eq!(
		rendered(&output),
		"a1 NO [LIMIT] Too many concurrent connections for this account\r\n",
		"the per-account total cap refuses the third connection"
	);
	// Drop one connection: the third must now fit.
	drop(sessions.remove(0));
	let output = third.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
	assert!(
		rendered(&output).contains("a1 OK"),
		"after one disconnect the total cap releases its slot: {}",
		rendered(&output)
	);
}

#[test]
fn dropping_a_session_releases_its_slot() {
	let dir = tempfile::tempdir().expect("tempdir");
	let peer: std::net::IpAddr = "203.0.113.5".parse().unwrap();
	let shared = Arc::new(PerAccountCounter::new(1, 1));
	{
		let mut session = session_in(dir.path(), peer, &shared);
		let output = session.command_line(&format!("a1 LOGIN alice {}", fixtures::password()));
		assert!(rendered(&output).contains("a1 OK"), "{}", rendered(&output));
		// The session holds one slot; the next is refused.
		let mut again = session_in(dir.path(), peer, &shared);
		let output = again.command_line(&format!("a2 LOGIN alice {}", fixtures::password()));
		assert_eq!(
			rendered(&output),
			"a2 NO [LIMIT] Too many concurrent connections for this account\r\n",
		);
	}
	// The session went out of scope; the slot is back.
	let mut fresh = session_in(dir.path(), peer, &shared);
	let output = fresh.command_line(&format!("a3 LOGIN alice {}", fixtures::password()));
	assert!(
		rendered(&output).contains("a3 OK"),
		"after the previous session dropped the cap is fresh again: {}",
		rendered(&output)
	);
}
