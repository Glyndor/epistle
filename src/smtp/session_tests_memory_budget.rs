//! The shared byte budget every DATA / BDAT reservation draws from. The
//! budget keeps the worst case for in-flight message bytes bounded:
//! once the sum of reservations reaches the cap, further reservations
//! are rejected with `452 4.3.1`, and the bytes already reserved are
//! released on every path that drops the in-flight body (success,
//! error, RSET, disconnect).

use std::sync::Arc;

use super::tests_basic::{greeted, reply_code};
use super::*;
use crate::smtp::memory_budget::MemoryBudget;

/// Build a greeted session wired to a fresh `MemoryBudget` of `cap` bytes.
fn session_with_budget(cap: u64) -> (Session, Arc<MemoryBudget>) {
	let budget = Arc::new(MemoryBudget::with_cap(cap));
	let session = greeted().with_memory_budget(Arc::clone(&budget));
	(session, budget)
}

fn line_reply(action: Option<Action>) -> String {
	let Some(action) = action else {
		return String::new();
	};
	match action {
		Action::Continue(reply)
		| Action::Deliver(reply, _)
		| Action::DiscardChunk { reply, .. } => reply.to_string(),
		_ => String::new(),
	}
}

#[test]
fn ehlo_advertises_size_with_no_budget_change() {
	let mut session = greeted();
	let Action::Continue(reply) = session.command_line("EHLO client.example.org") else {
		panic!("expected continue");
	};
	let rendered = reply.to_string();
	assert!(
		rendered.contains(&format!("SIZE {MAX_MESSAGE_SIZE}")),
		"EHLO must advertise the configured size cap"
	);
}

#[test]
fn data_respects_the_budget_at_end_of_message() {
	let (mut session, budget) = session_with_budget(10);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	// The first two-byte line is admitted; the reservation is the
	// line's content plus the CRLF terminator the session writes back.
	assert_eq!(session.data_line(b"ab"), None);
	assert_eq!(budget.used(), 4);
	// A second four-byte line still fits: 4 + 6 = 10, at the cap.
	assert_eq!(session.data_line(b"abcd"), None);
	assert_eq!(budget.used(), 10);
	// The next line cannot reserve anything; the body stops growing
	// and the budget is held at the cap.
	assert_eq!(session.data_line(b"more"), None);
	assert_eq!(budget.used(), 10);
	let action = session.data_line(b".").expect("final action");
	let Action::Continue(reply) = action else {
		panic!("expected 452 continue");
	};
	assert_eq!(
		reply.to_string(),
		"452 4.3.1 insufficient system resources; try again later\r\n"
	);
	assert_eq!(
		budget.used(),
		0,
		"the rejection at end-of-DATA must release the held reservation"
	);
}

#[test]
fn successful_data_delivery_releases_the_reservation() {
	let (mut session, budget) = session_with_budget(1024);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	session.data_line(b"hello");
	// "hello" (5) + CRLF (2) = 7 octets reserved against the budget.
	assert_eq!(budget.used(), 7);
	let Some(Action::Deliver(_, _)) = session.data_line(b".") else {
		panic!("expected delivery");
	};
	assert_eq!(budget.used(), 7, "the body is held while it is delivered");
	drop(session.take_delivery_reservation());
	assert_eq!(budget.used(), 0, "the end of the delivery releases it");
}

#[test]
fn rset_releases_the_in_flight_reservation() {
	let (mut session, budget) = session_with_budget(1024);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	session.data_line(b"hello world");
	// "hello world" (11) + CRLF (2) = 13 octets reserved.
	assert_eq!(budget.used(), 13);
	let action = session.command_line("RSET");
	assert_eq!(reply_code(&action), 250);
	assert_eq!(
		budget.used(),
		0,
		"RSET must release the in-flight reservation"
	);
}

#[test]
fn bdat_chunk_over_the_budget_is_refused_with_452() {
	let (mut session, budget) = session_with_budget(8);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	// The first 8-byte chunk fills the budget.
	let Action::CollectChunk { size, .. } = session.command_line("BDAT 8") else {
		panic!("expected CollectChunk");
	};
	assert_eq!(size, 8);
	assert_eq!(reply_code(&session.bdat_chunk(b"12345678", false)), 250);
	assert_eq!(budget.used(), 8);
	// The next chunk would push the running total past the cap.
	let action = session.command_line("BDAT 1 LAST");
	assert_eq!(reply_code(&action), 452);
	assert_eq!(
		line_reply(Some(action)),
		"452 4.3.1 insufficient system resources; try again later\r\n"
	);
	// The refused chunk's reservation (and any earlier one) is released.
	assert_eq!(budget.used(), 0);
}

#[test]
fn bdat_delivery_releases_the_reservation() {
	let (mut session, budget) = session_with_budget(64);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	let Action::CollectChunk { .. } = session.command_line("BDAT 11") else {
		panic!("expected CollectChunk");
	};
	let action = session.bdat_chunk(b"hello world\n", true);
	assert!(matches!(action, Action::Deliver(..)));
	drop(session.take_delivery_reservation());
	assert_eq!(
		budget.used(),
		0,
		"BDAT LAST delivery releases the reservation"
	);
}

#[test]
fn many_concurrent_sessions_share_the_budget() {
	let budget = Arc::new(MemoryBudget::with_cap(40));
	let mut sessions: Vec<Session> = (0..8)
		.map(|_| greeted().with_memory_budget(Arc::clone(&budget)))
		.collect();
	// Open four concurrent transfers of "abababab" (8) + CRLF (2) = 10
	// octets each. The budget holds 40 octets exactly.
	for session in sessions.iter_mut().take(4) {
		session.command_line("MAIL FROM:<a@example.org>");
		session.command_line("RCPT TO:<b@example.org>");
		session.command_line("DATA");
		session.data_line(b"abababab");
	}
	assert_eq!(
		budget.used(),
		40,
		"4 sessions of 10 octets fill the 40-octet cap"
	);
	// The fifth cannot fit; the body's data_line returns None and the
	// running total stays at the cap, but the final `.` returns 452.
	let fifth = &mut sessions[4];
	let _ = fifth.command_line("MAIL FROM:<a@example.org>");
	let _ = fifth.command_line("RCPT TO:<b@example.org>");
	let _ = fifth.command_line("DATA");
	assert_eq!(fifth.data_line(b"x"), None);
	assert_eq!(
		budget.used(),
		40,
		"over-budget line does not grow the reservation"
	);
	let action = fifth.data_line(b".").expect("final action");
	assert_eq!(reply_code(&action), 452);
	// Finishing one of the four releases its 10 bytes; the next session
	// in the queue can resume.
	let first = &mut sessions[0];
	let Some(Action::Deliver(_, _)) = first.data_line(b".") else {
		panic!("expected delivery");
	};
	drop(first.take_delivery_reservation());
	assert_eq!(budget.used(), 30);
	// Reset the others, so the held bytes return to the budget.
	for session in sessions.iter_mut().skip(1).take(4) {
		session.command_line("RSET");
	}
	assert_eq!(budget.used(), 0);
}

#[test]
fn one_client_cannot_hold_more_than_its_share_of_the_budget() {
	// A client trickling bodies slowly over many connections would hold
	// the whole budget and every other sender would get 452. Its share
	// is counted per IPv4 address or IPv6 /64.
	let budget = Arc::new(MemoryBudget::with_cap(1000).with_client_share(400));
	let open = |peer: &str| {
		let mut session = greeted().with_memory_budget(Arc::clone(&budget));
		session.set_peer_ip(Some(peer.parse().expect("peer")));
		session.command_line("MAIL FROM:<a@example.org>");
		session.command_line("RCPT TO:<b@example.org>");
		session.command_line("DATA");
		session
	};
	let mut first = open("2001:db8::1");
	let mut second = open("2001:db8::2");
	assert_eq!(first.data_line(&[b'x'; 198]), None);
	assert_eq!(second.data_line(&[b'x'; 198]), None);
	assert_eq!(budget.used(), 400, "the client's share is full");
	let mut third = open("2001:db8::3");
	assert_eq!(third.data_line(&[b'x'; 198]), None);
	assert_eq!(
		budget.used(),
		400,
		"a third body from the same /64 claims nothing"
	);
	assert_eq!(reply_code(&third.data_line(b".").expect("end")), 452);
	let mut other = open("198.51.100.7");
	assert_eq!(other.data_line(&[b'x'; 198]), None);
	assert_eq!(reply_code(&other.data_line(b".").expect("end")), 250);
	drop(first);
	assert_eq!(budget.used(), 400, "the other client's body is still held");
}

#[test]
fn bdat_last_hands_over_the_body_without_copying_it() {
	// The body is moved into the accepted message: a copy would hold the
	// message twice at the end of the transfer.
	let (mut session, _budget) = session_with_budget(1 << 20);
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("BDAT 4096");
	assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 4096], false)), 250);
	let State::ReceivingData { body, .. } = &session.state else {
		panic!("expected an open transaction");
	};
	let held = body.as_ptr();
	session.command_line("BDAT 0 LAST");
	let Action::Deliver(_, message) = session.bdat_chunk(&[], true) else {
		panic!("expected delivery");
	};
	assert_eq!(message.data.len(), 4096);
	assert!(
		std::ptr::eq(message.data.as_ptr(), held),
		"the delivered body is the buffer the session held"
	);
}
