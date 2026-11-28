//! Listing the queue a page at a time, and reading envelopes under a budget.

use super::*;

fn message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@example.org".into()],
		data: b"Subject: hi\r\n\r\nhello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// A spool with `count` entries, and their ids oldest first.
fn spool_with(count: usize) -> (tempfile::TempDir, FsSpool, Vec<Uuid>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("open spool");
	for _ in 0..count {
		spool
			.store(&message(), None, &BTreeMap::new())
			.expect("store");
	}
	let ids = spool.list().expect("list");
	assert_eq!(ids.len(), count);
	(dir, spool, ids)
}

#[test]
fn pages_cover_the_queue_once_and_in_order() {
	let (_dir, spool, ids) = spool_with(7);
	let mut after = None;
	let mut seen = Vec::new();
	let mut pages = Vec::new();
	loop {
		let page = spool.list_after(after, 3).expect("page");
		after = page.ids.last().copied();
		pages.push((page.ids.len(), page.more));
		seen.extend(page.ids);
		if !page.more {
			break;
		}
	}
	assert_eq!(pages, [(3, true), (3, true), (1, false)]);
	assert_eq!(seen, ids);
}

#[test]
fn a_page_that_ends_on_the_last_entry_says_there_is_no_more() {
	let (_dir, spool, ids) = spool_with(6);
	let page = spool.list_after(Some(ids[2]), 3).expect("page");
	assert_eq!(page.ids, ids[3..]);
	assert!(!page.more);
}

#[test]
fn an_envelope_read_spends_one_entry_and_its_bytes() {
	let (dir, spool, ids) = spool_with(1);
	let file = dir.path().join(format!("spool/new/{}.json", ids[0]));
	let length = std::fs::metadata(file).expect("envelope").len() as usize;

	let mut budget = Budget::new(2, length + 1);
	spool
		.load_envelope_within(ids[0], &mut budget)
		.expect("read");
	assert_eq!(budget.entries(), 1);
	assert!(!budget.is_spent(), "one byte and one entry are left");

	let mut budget = Budget::new(2, length);
	spool
		.load_envelope_within(ids[0], &mut budget)
		.expect("read");
	assert!(budget.is_spent(), "the bytes are gone");
}

/// An entry that cannot be read still counts, so a queue of them cannot be
/// walked without end.
#[test]
fn an_entry_that_cannot_be_read_spends_one_entry() {
	let (_dir, spool, _) = spool_with(0);
	let mut budget = Budget::new(1, 1);
	spool
		.load_envelope_within(Uuid::now_v7(), &mut budget)
		.expect_err("no such entry");
	assert_eq!(budget.entries(), 0);
	assert!(budget.is_spent());
}
