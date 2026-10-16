use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::Record;
use crate::evidence::record::{Abandoned, Outcome, OutcomeKind};
use crate::evidence::test_support::{accepted_for, delivered};
use std::time::{Duration, Instant};

pub(super) const TODAY: Day = Day(20_740);

pub(super) fn limits() -> Limits {
	Limits {
		account_records: 12,
		account_kept_bytes: 100,
		day_records: 48,
	}
}

pub(super) fn id(n: u128) -> Uuid {
	Uuid::from_u128(n)
}

fn quota(dir: &Path) -> Quota {
	Quota::start_at(dir, limits(), TODAY)
}

/// Reserve a message to `recipients` (so `1 + recipients` records).
fn reserve(
	quota: &Quota,
	account: &str,
	n: u128,
	recipients: u64,
	kept: u64,
) -> std::io::Result<Reservation> {
	quota.reserve(account, id(n), (recipients, kept), TODAY)
}

/// Writes the records a book is rebuilt from.
pub(super) struct Log {
	pub(super) chain: Chain,
	at: u64,
}

impl Log {
	pub(super) fn new(dir: &Path, day: Day) -> Log {
		Log {
			chain: Chain::open(dir).expect("chain"),
			at: day.start_epoch(),
		}
	}

	pub(super) fn write(&mut self, entry: Entry) {
		self.at += 1;
		self.chain.append_at(self.at, entry).expect("record");
	}

	pub(super) fn accepted(
		&mut self,
		account: &str,
		n: u128,
		recipients: usize,
		full: Option<u64>,
	) {
		let Entry::Accepted(mut accepted) = accepted_for(0, 365) else {
			unreachable!()
		};
		accepted.spool_id = id(n);
		accepted.account = account.into();
		accepted.recipients = (0..recipients)
			.map(|r| format!("r{r}@example.net"))
			.collect();
		if let Some(size) = full {
			accepted.size = size;
			accepted.retention.mode = RetentionMode::Full;
		}
		self.write(Entry::Accepted(accepted));
	}

	pub(super) fn outcome(&mut self, n: u128) {
		let Entry::Outcome(outcome) = delivered(0) else {
			unreachable!()
		};
		self.write(Entry::Outcome(Outcome {
			spool_id: id(n),
			result: OutcomeKind::Delivered,
			..outcome
		}));
	}

	pub(super) fn abandoned(&mut self, n: u128) {
		self.write(Entry::Abandoned(Abandoned {
			spool_id: id(n),
			reason: "test".into(),
			retain_days: 365,
		}));
	}
}

#[test]
fn an_account_is_refused_past_its_share_and_the_others_are_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for n in 0..6 {
		let _ = reserve(&quota, "noisy", n, 1, 0).expect("within the share");
	}
	let refused = reserve(&quota, "noisy", 9, 1, 0).expect_err("past it");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	let _ = reserve(&quota, "quiet", 10, 1, 0).expect("another account");
}

#[test]
fn kept_bytes_are_counted_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 0, 90).expect("within");
	let _ = reserve(&quota, "a", 2, 0, 10).expect("exactly the limit");
	reserve(&quota, "a", 3, 0, 1).expect_err("one byte over");
	let _ = reserve(&quota, "b", 4, 0, 100).expect("another account");
}

#[test]
fn the_day_takes_no_more_than_its_limit_whoever_asks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for (n, account) in ["a", "b", "c", "d"].iter().enumerate() {
		let _ = reserve(&quota, account, n as u128, 11, 0).expect("a whole share");
	}
	let refused = reserve(&quota, "e", 9, 0, 0).expect_err("the day is full");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
}

#[test]
fn a_reservation_given_back_leaves_exactly_what_was_there() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 2, 10).expect("first");
	let before = quota.state();
	let held = reserve(&quota, "a", 2, 3, 20).expect("second");
	assert_ne!(quota.state(), before);
	quota.release(held);
	assert_eq!(quota.state(), before);
}

#[test]
fn the_clock_going_back_does_not_clear_the_counts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 11, 0).expect("a whole share");
	quota
		.reserve("a", id(2), (0, 0), Day(TODAY.0 - 1))
		.expect_err("the share is still used");
	assert_eq!(quota.state().day, TODAY.0);
	assert_eq!(quota.state().accounts["a"].records, 12);
}

#[test]
fn a_new_day_starts_the_counts_again_and_remembers_what_was_prepaid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 4, 0).expect("5 records");
	quota.fact(None, id(1), Day(TODAY.0 + 1));
	let state = quota.state();
	assert_eq!(
		state.total, 0,
		"an outcome prepaid yesterday is not paid again"
	);
	assert!(state.accounts.is_empty());
}

#[test]
fn a_fact_nobody_paid_for_is_counted_once_and_never_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for n in 0..40 {
		quota.fact(Some("a"), id(n), TODAY);
	}
	let state = quota.state();
	assert_eq!(state.accounts["a"].records, 40);
	assert!(state.within <= limits().account_records);
	reserve(&quota, "a", 100, 0, 0).expect_err("the account waits at its next acceptance");
	let _ = reserve(&quota, "b", 101, 11, 0).expect("and takes nothing from another");
}

#[test]
fn what_cannot_be_traced_has_an_account_of_its_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	quota.fact(None, id(1), TODAY);
	assert_eq!(quota.state().accounts[UNATTRIBUTED].records, 1);
}

#[test]
fn the_share_is_cut_to_fit_the_days_limit() {
	let fitted = Limits {
		account_records: 1_000,
		account_kept_bytes: 1,
		day_records: 100,
	}
	.fitted();
	assert_eq!(fitted.account_records * MIN_SHARES, 100);
}

#[test]
fn the_status_warns_before_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = Quota::start_at(
		dir.path(),
		Limits {
			account_records: 10,
			account_kept_bytes: u64::MAX,
			day_records: 1000,
		},
		TODAY,
	);
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 1, 6, 0).expect("70 percent");
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 2, 0, 0).expect("80 percent");
	assert!(
		quota
			.warning(TODAY)
			.expect("warning")
			.contains("near its evidence limits")
	);
}

#[test]
fn a_restart_rebuilds_the_book_from_the_days_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut log = Log::new(dir.path(), TODAY);
	log.accepted("a", 1, 2, Some(40));
	log.accepted("b", 2, 1, None);
	log.outcome(1);
	log.outcome(1);
	log.abandoned(2);
	// An outcome of a message accepted another day, and a record of no message.
	log.outcome(77);
	log.write(Entry::Setting(crate::evidence::record::Setting {
		name: "timestamp".into(),
		value: "enabled".into(),
	}));
	let state = quota(dir.path()).state();
	// "a": the acceptance and two outcomes it paid for; "b": the same, one.
	assert_eq!(state.accounts["a"].records, 3);
	assert_eq!(state.accounts["a"].bytes, 40);
	assert_eq!(state.accounts["b"].records, 2);
	assert_eq!(
		state.accounts[UNATTRIBUTED].records, 2,
		"the fact nobody paid for, and the setting"
	);
	assert_eq!(state.total, 7);
	assert_eq!(
		state.total,
		state
			.accounts
			.values()
			.map(|held| held.records)
			.sum::<u64>()
	);
}

#[test]
fn a_log_that_cannot_be_read_admits_no_acceptance_and_counts_facts_until_it_can() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut log = Log::new(dir.path(), TODAY);
	log.accepted("a", 1, 1, None);
	// Start with today's file unreadable: a directory in its place.
	let path = log.chain.day_file(TODAY);
	let kept = std::fs::read(&path).expect("read");
	std::fs::remove_file(&path).expect("remove");
	std::fs::create_dir(&path).expect("block");
	let quota = quota(dir.path());
	assert!(quota.unavailable());
	assert!(
		quota
			.warning(TODAY)
			.expect("alarm")
			.contains("no new acceptances")
	);
	let refused = reserve(&quota, "b", 2, 0, 0).expect_err("never from a book at nothing");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	// Facts are still taken, and counted.
	quota.fact(None, id(1), TODAY);
	quota.fact(None, id(9), TODAY);
	assert_eq!(quota.state().accounts[UNATTRIBUTED].records, 2);
	// The log can be read again: the book is rebuilt from it, and mail flows.
	std::fs::remove_dir(&path).expect("unblock");
	std::fs::write(&path, kept).expect("restore");
	quota.retry_now(TODAY);
	assert!(!quota.unavailable());
	let state = quota.state();
	assert_eq!(
		state.accounts["a"].records, 2,
		"rebuilt from the log, not added to"
	);
	assert!(!state.accounts.contains_key(UNATTRIBUTED));
	let _ = reserve(&quota, "b", 3, 0, 0).expect("mail flows again");
}

/// A quota whose limits are out of the way of the memory of outcomes.
fn roomy(dir: &Path) -> Quota {
	Quota::start_at(
		dir,
		Limits {
			account_records: 100_000_000,
			account_kept_bytes: u64::MAX,
			day_records: 800_000_000,
		},
		TODAY,
	)
}

#[test]
fn an_account_with_too_many_messages_waiting_is_refused_and_the_others_are_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = roomy(dir.path());
	for n in 0..MAX_OWED_PER_ACCOUNT as u128 {
		let _ = quota
			.reserve("noisy", id(n), (2, 0), TODAY)
			.expect("reserved");
	}
	let full = quota.state();
	let refused = quota
		.reserve("noisy", id(1 << 40), (2, 0), TODAY)
		.expect_err("no room for another message to wait");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	let _ = quota
		.reserve("quiet", id(1 << 41), (2, 0), TODAY)
		.expect("another account");
	// Nothing was reserved short, and nothing of anybody's was forgotten.
	let state = quota.state();
	assert_eq!(state.owed.len(), full.owed.len() + 1);
	assert_eq!(state.accounts["noisy"], full.accounts["noisy"]);
	assert_eq!(state.owed_per["noisy"], MAX_OWED_PER_ACCOUNT);
	// Facts are still taken, and counted to the account.
	let before = state.accounts["noisy"].records;
	quota.fact(Some("noisy"), id(1 << 50), TODAY);
	assert_eq!(quota.state().accounts["noisy"].records, before + 1);
	// A message that gets its outcomes leaves room for the next.
	quota.fact(Some("noisy"), id(0), TODAY);
	quota.fact(Some("noisy"), id(0), TODAY);
	let _ = quota
		.reserve("noisy", id(1 << 40), (2, 0), TODAY)
		.expect("room again");
}

#[test]
fn a_full_memory_refuses_only_the_accounts_above_their_fair_share_and_forgets_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = roomy(dir.path());
	let mut n = 0u128;
	let mut fill = |account: String, count: usize| {
		for _ in 0..count {
			let _ = quota
				.reserve(&account, id(n), (1, 0), TODAY)
				.expect("reserved");
			n += 1;
		}
	};
	// Eight accounts with 4 096 entries and thirty-two with 1 024: full.
	for account in 0..8 {
		fill(format!("big{account}"), 4096);
	}
	for account in 0..32 {
		fill(format!("small{account}"), 1024);
	}
	let full = quota.state();
	assert_eq!(full.owed.len(), MAX_OWED);
	assert!(quota.warning(TODAY).expect("alarm").contains("fair share"));
	// The average is 1 638: a big account is turned away, a small one is not.
	let refused = quota
		.reserve("big0", id(u128::MAX), (1, 0), TODAY)
		.expect_err("above its share");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	assert_eq!(quota.state(), full, "a refusal touched the book");
	let _ = quota
		.reserve("small0", id(u128::MAX - 1), (1, 0), TODAY)
		.expect("below its share");
	let _ = quota
		.reserve("newcomer", id(u128::MAX - 2), (1, 0), TODAY)
		.expect("a new account");
	// Nothing anybody had was changed.
	let after = quota.state();
	assert_eq!(after.owed.len(), MAX_OWED + 2);
	assert_eq!(after.owed_per["big0"], 4096);
	assert_eq!(after.owed_per["small1"], 1024);
	// The ceiling holds even for the accounts below their share.
	let mut admitted = 0;
	for k in 0..(MAX_OWED_CEILING as u128) {
		if quota
			.reserve(&format!("tiny{k}"), id(1 << 60 | k), (1, 0), TODAY)
			.is_ok()
		{
			admitted += 1;
		}
	}
	assert_eq!(quota.state().owed.len(), MAX_OWED_CEILING);
	assert!(admitted > 0);
	// A message with no recipients waits for nothing.
	let _ = quota
		.reserve("big0", id(u128::MAX - 3), (0, 0), TODAY)
		.expect("owes no outcome");
	// Outcomes coming frees room, for anybody.
	quota.fact(None, id(0), TODAY);
	assert!(quota.state().owed.len() < MAX_OWED_CEILING);
}

#[test]
fn an_abandonment_ends_the_message_and_gives_its_room_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = roomy(dir.path());
	for n in 0..MAX_OWED_PER_ACCOUNT as u128 {
		let _ = quota.reserve("a", id(n), (3, 0), TODAY).expect("reserved");
	}
	quota
		.reserve("a", id(1 << 40), (3, 0), TODAY)
		.expect_err("the account is full");
	let before = quota.state().accounts["a"].records;
	// One abandonment stands for the three outcomes the message owed.
	quota.ended(Some("a"), id(0), TODAY);
	let state = quota.state();
	assert_eq!(state.owed_per["a"], MAX_OWED_PER_ACCOUNT - 1);
	assert!(!state.owed.contains_key(&id(0)));
	assert_eq!(state.accounts["a"].records, before, "it was prepaid");
	let _ = quota
		.reserve("a", id(1 << 40), (3, 0), TODAY)
		.expect("room again");
}

#[test]
fn the_count_of_messages_waiting_follows_the_table_through_any_number_of_cycles() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = roomy(dir.path());
	for round in 0..50u128 {
		// The same id reserved twice replaces its entry; it is not two.
		let first = quota.reserve("a", id(round), (2, 0), TODAY).expect("first");
		let second = quota.reserve("a", id(round), (2, 0), TODAY).expect("again");
		assert_eq!(quota.state().owed_per["a"], 1, "round {round}");
		quota.release(second);
		quota.release(first);
		match round % 3 {
			0 => {
				let _ = quota.reserve("a", id(round), (2, 0), TODAY).expect("kept");
				quota.fact(Some("a"), id(round), TODAY);
				quota.fact(Some("a"), id(round), TODAY);
			}
			1 => {
				let _ = quota.reserve("a", id(round), (2, 0), TODAY).expect("kept");
				quota.ended(Some("a"), id(round), TODAY);
			}
			_ => {}
		}
		let state = quota.state();
		assert!(state.owed.is_empty(), "round {round}: {:?}", state.owed);
		assert!(
			state.owed_per.is_empty(),
			"round {round}: the count drifted"
		);
	}
}

#[test]
fn a_message_forgotten_with_the_days_leaves_the_count_with_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = roomy(dir.path());
	let _ = quota.reserve("a", id(1), (2, 0), TODAY).expect("reserved");
	quota.fact(None, id(999), Day(TODAY.0 + OWED_DAYS + 1));
	let state = quota.state();
	assert!(state.owed.is_empty());
	assert!(state.owed_per.is_empty());
}

#[test]
fn an_outcome_is_counted_to_the_account_that_was_accepted_for_it_after_a_restart() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Yesterday: an acceptance. Today: its outcomes, which nothing paid for
	// any more, and an outcome of a message nobody knows.
	let mut yesterday = Log::new(dir.path(), Day(TODAY.0 - 1));
	yesterday.accepted("a", 1, 1, None);
	let mut log = Log::new(dir.path(), TODAY);
	log.outcome(1);
	log.outcome(77);
	let state = quota(dir.path()).state();
	assert_eq!(state.accounts["a"].records, 1);
	assert_eq!(state.accounts[UNATTRIBUTED].records, 1);
}

#[test]
fn rebuilding_a_day_of_many_records_is_linear() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path();
	let chain = Chain::open(root).expect("chain");
	let path = chain.day_file(TODAY);
	// A day of 150 000 acceptances by three accounts, written straight to the
	// file: the book must not look through a table for each of them.
	let mut bytes = Vec::new();
	for n in 0..150_000u64 {
		let Entry::Accepted(mut accepted) = accepted_for(0, 365) else {
			unreachable!()
		};
		accepted.spool_id = id(u128::from(n) + 1);
		accepted.account = ["a", "b", "c"][(n % 3) as usize].into();
		let line = Record {
			v: crate::evidence::record::FORMAT_VERSION,
			seq: n + 1,
			prev: "0".repeat(64),
			time: TODAY.start_epoch() + n / 10,
			entry: Entry::Accepted(accepted),
		}
		.to_line()
		.expect("line");
		bytes.extend_from_slice(&line);
		bytes.push(b'\n');
	}
	std::fs::write(&path, bytes).expect("write");
	let started = Instant::now();
	let quota = Quota::start_at(
		root,
		Limits {
			account_records: u64::MAX / 8,
			account_kept_bytes: u64::MAX,
			day_records: u64::MAX / 2,
		},
		TODAY,
	);
	let took = started.elapsed();
	// 50 000 acceptances by "a", an outcome paid for only where the memory had room.
	assert_eq!(
		quota.state().accounts["a"].records,
		50_000 + MAX_OWED_PER_ACCOUNT as u64
	);
	assert!(
		took < Duration::from_secs(30),
		"rebuilding 150 000 records took {took:?}: the cost is not linear"
	);
}

use std::path::Path;
