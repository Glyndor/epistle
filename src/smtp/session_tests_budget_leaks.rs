//! Paths that must hand the memory-budget reservation back. A path that
//! forgets shrinks the shared budget for good, so each test drives the
//! leaking path many times against one budget and then shows that a
//! legitimate message still fits.

use std::sync::Arc;

use super::tests_basic::{greeted, reply_code};
use super::*;
use crate::smtp::memory_budget::MemoryBudget;

/// How many times each path is repeated against the same budget.
const ROUNDS: usize = 10;

fn session_on(budget: &Arc<MemoryBudget>) -> Session {
	greeted().with_memory_budget(Arc::clone(budget))
}

fn open_transaction(session: &mut Session) {
	assert_eq!(
		reply_code(&session.command_line("MAIL FROM:<a@example.org>")),
		250
	);
	assert_eq!(
		reply_code(&session.command_line("RCPT TO:<b@example.org>")),
		250
	);
}

/// A full DATA transaction of `lines` lines of 98 octets each.
fn deliver_by_data(session: &mut Session, lines: usize) -> u16 {
	open_transaction(session);
	assert_eq!(reply_code(&session.command_line("DATA")), 354);
	for _ in 0..lines {
		assert!(session.data_line(&[b'x'; 98]).is_none());
	}
	reply_code(&session.data_line(b".").expect("end of data"))
}

#[test]
fn a_bdat_chunk_never_read_is_released_when_the_session_goes_away() {
	// A client that announces a chunk, sends part of it and disconnects
	// (or times out) drops the session before `bdat_chunk` runs, with the
	// octets charged so far still on the budget.
	let budget = Arc::new(MemoryBudget::with_cap(1000));
	for _ in 0..ROUNDS {
		let mut session = session_on(&budget);
		open_transaction(&mut session);
		let action = session.command_line("BDAT 600");
		assert!(matches!(action, Action::CollectChunk { size: 600, .. }));
		assert!(session.reserve_chunk(400), "the part that arrived fits");
		drop(session);
	}
	assert_eq!(budget.used(), 0, "every unread chunk is released");
	let mut session = session_on(&budget);
	open_transaction(&mut session);
	assert!(matches!(
		session.command_line("BDAT 600 LAST"),
		Action::CollectChunk { size: 600, .. }
	));
	assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 600], true)), 250);
}

#[test]
fn a_bdat_chunk_outside_a_transaction_is_discarded_without_a_claim() {
	let budget = Arc::new(MemoryBudget::with_cap(1000));
	let mut session = session_on(&budget);
	let action = session.command_line("BDAT 600");
	assert!(matches!(action, Action::DiscardChunk { size: 600, .. }));
	assert_eq!(reply_code(&action), 503);
	assert_eq!(
		budget.used(),
		0,
		"a chunk that is thrown away claims nothing"
	);
}

#[test]
fn a_data_body_cut_short_is_released_when_the_session_goes_away() {
	let budget = Arc::new(MemoryBudget::with_cap(2000));
	for _ in 0..ROUNDS {
		let mut session = session_on(&budget);
		open_transaction(&mut session);
		assert_eq!(reply_code(&session.command_line("DATA")), 354);
		for _ in 0..10 {
			assert!(session.data_line(&[b'x'; 98]).is_none());
		}
		assert_eq!(budget.used(), 1000);
		drop(session);
	}
	assert_eq!(budget.used(), 0, "every abandoned body is released");
	assert_eq!(deliver_by_data(&mut session_on(&budget), 10), 250);
}

#[test]
fn a_panic_in_the_session_task_releases_the_body() {
	let budget = Arc::new(MemoryBudget::with_cap(2000));
	for _ in 0..ROUNDS {
		let mut session = session_on(&budget);
		let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
			open_transaction(&mut session);
			session.command_line("DATA");
			session.data_line(&[b'x'; 998]);
			panic!("the session task dies with the body held");
		}));
		assert!(outcome.is_err());
	}
	assert_eq!(budget.used(), 0, "unwinding releases the held body");
	assert_eq!(deliver_by_data(&mut session_on(&budget), 10), 250);
}

#[test]
fn ehlo_between_bdat_chunks_releases_the_chunks_already_held() {
	// RFC 5321 section 4.1.4: EHLO clears the transaction in progress.
	let budget = Arc::new(MemoryBudget::with_cap(1000));
	let mut session = session_on(&budget);
	for _ in 0..ROUNDS {
		open_transaction(&mut session);
		session.command_line("BDAT 600");
		assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 600], false)), 250);
		assert_eq!(
			reply_code(&session.command_line("EHLO again.example.org")),
			250
		);
	}
	assert_eq!(budget.used(), 0, "EHLO drops the held chunks");
	open_transaction(&mut session);
	session.command_line("BDAT 600 LAST");
	assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 600], true)), 250);
}

#[test]
fn a_bdat_chunk_that_crosses_the_size_cap_releases_its_own_reservation() {
	// Each chunk fits the per-chunk cap, but the second one takes the
	// running total past it: the transaction is refused with 552 and the
	// chunk that was reserved before it was read must go back too.
	let budget = Arc::new(MemoryBudget::with_cap(1000));
	for _ in 0..ROUNDS {
		let mut session = session_on(&budget).with_max_message_size(500);
		open_transaction(&mut session);
		session.command_line("BDAT 300");
		assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 300], false)), 250);
		session.command_line("BDAT 300");
		assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 300], false)), 552);
		assert_eq!(budget.used(), 0, "the refused transaction holds nothing");
	}
	let mut session = session_on(&budget).with_max_message_size(500);
	open_transaction(&mut session);
	session.command_line("BDAT 500 LAST");
	assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 500], true)), 250);
}

#[test]
fn starttls_inside_a_transaction_is_refused_and_keeps_the_count_exact() {
	// STARTTLS is only accepted from the greeted state (RFC 3207), so it
	// can never discard a held body; the count stays what the body holds.
	let budget = Arc::new(MemoryBudget::with_cap(1000));
	let mut session = session_on(&budget).with_tls_available();
	open_transaction(&mut session);
	session.command_line("BDAT 100");
	assert_eq!(reply_code(&session.bdat_chunk(&[b'x'; 100], false)), 250);
	assert_eq!(reply_code(&session.command_line("STARTTLS")), 503);
	assert_eq!(budget.used(), 100);
	assert_eq!(reply_code(&session.command_line("RSET")), 250);
	assert_eq!(budget.used(), 0);
}
