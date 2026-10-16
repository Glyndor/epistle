use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::record::Record;
use crate::evidence::record::{Abandoned, Outcome, OutcomeKind};
use crate::evidence::test_support::{accepted_for, delivered};
use std::time::{Duration, Instant};

const TODAY: Day = Day(20_740);

fn limits() -> Limits {
	Limits {
		account_records: 12,
		account_kept_bytes: 100,
		day_records: 48,
	}
}

fn id(n: u128) -> Uuid {
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
struct Log {
	chain: Chain,
	at: u64,
}

impl Log {
	fn new(dir: &Path, day: Day) -> Log {
		Log {
			chain: Chain::open(dir).expect("chain"),
			at: day.start_epoch(),
		}
	}

	fn write(&mut self, entry: Entry) {
		self.at += 1;
		self.chain.append_at(self.at, entry).expect("record");
	}

	fn accepted(&mut self, account: &str, n: u128, recipients: usize, full: Option<u64>) {
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

	fn outcome(&mut self, n: u128) {
		let Entry::Outcome(outcome) = delivered(0) else {
			unreachable!()
		};
		self.write(Entry::Outcome(Outcome {
			spool_id: id(n),
			result: OutcomeKind::Delivered,
			..outcome
		}));
	}

	fn abandoned(&mut self, n: u128) {
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

#[test]
fn an_acceptance_always_reserves_its_outcomes_and_a_full_memory_forgets_the_biggest_accounts_oldest()
 {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = Quota::start_at(
		dir.path(),
		Limits {
			account_records: 10_000_000,
			account_kept_bytes: u64::MAX,
			day_records: 40_000_000,
		},
		TODAY,
	);
	let extra = 5;
	for n in 0..(MAX_OWED_PER_ACCOUNT as u128 + extra) {
		let _ = quota
			.reserve("noisy", id(n), (2, 0), TODAY)
			.expect("reserved");
	}
	let state = quota.state();
	// Nothing was reserved short: three records for every message.
	assert_eq!(
		state.accounts["noisy"].records,
		3 * (MAX_OWED_PER_ACCOUNT as u64 + extra as u64)
	);
	assert_eq!(state.owed.len(), MAX_OWED_PER_ACCOUNT);
	assert_eq!(state.owed_by["noisy"].len(), MAX_OWED_PER_ACCOUNT);
	// Another tenant keeps its place whatever the first sent.
	let _ = quota
		.reserve("quiet", id(1 << 40), (2, 0), TODAY)
		.expect("reserved");
	assert_eq!(quota.state().owed.len(), MAX_OWED_PER_ACCOUNT + 1);
	// The oldest of the noisy account were forgotten: their outcomes are
	// counted when they come, as facts. The newest were not.
	let before = quota.state().accounts["noisy"].records;
	quota.fact(Some("noisy"), id(0), TODAY);
	assert_eq!(quota.state().accounts["noisy"].records, before + 1);
	let before = quota.state().accounts["noisy"].records;
	quota.fact(
		Some("noisy"),
		id(MAX_OWED_PER_ACCOUNT as u128 + extra - 1),
		TODAY,
	);
	assert_eq!(quota.state().accounts["noisy"].records, before, "paid for");
}

#[test]
fn a_few_accounts_cannot_fill_the_whole_memory_of_outcomes_against_the_rest() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = Quota::start_at(
		dir.path(),
		Limits {
			account_records: 100_000_000,
			account_kept_bytes: u64::MAX,
			day_records: 800_000_000,
		},
		TODAY,
	);
	// Seven accounts at the most one may hold, and two with half of that.
	let mut n = 0u128;
	let mut fill = |account: String, count: usize| {
		for _ in 0..count {
			let _ = quota
				.reserve(&account, id(n), (1, 0), TODAY)
				.expect("reserved");
			n += 1;
		}
	};
	for account in 0..7 {
		fill(format!("big{account}"), MAX_OWED_PER_ACCOUNT);
	}
	fill("half1".into(), MAX_OWED_PER_ACCOUNT / 2);
	fill("half2".into(), MAX_OWED_PER_ACCOUNT / 2);
	assert_eq!(quota.state().owed.len(), MAX_OWED);
	// A small account still gets its place: the biggest gives one up.
	let _ = quota
		.reserve("small", id(u128::MAX), (1, 0), TODAY)
		.expect("reserved");
	let state = quota.state();
	assert_eq!(state.owed.len(), MAX_OWED);
	assert!(state.owed.contains_key(&id(u128::MAX)));
	assert_eq!(state.owed_by["small"].len(), 1);
	// It was the biggest that gave up one, not the smaller ones.
	assert_eq!(state.owed_by["half1"].len(), MAX_OWED_PER_ACCOUNT / 2);
	assert_eq!(state.owed_by["half2"].len(), MAX_OWED_PER_ACCOUNT / 2);
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
	assert_eq!(quota.state().accounts["a"].records, 100_000);
	assert!(
		took < Duration::from_secs(30),
		"rebuilding 150 000 records took {took:?}: the cost is not linear"
	);
}

/// A small deterministic generator, so a failing sequence can be replayed.
struct Dice(u64);

impl Dice {
	fn next(&mut self, below: u64) -> u64 {
		self.0 ^= self.0 << 13;
		self.0 ^= self.0 >> 7;
		self.0 ^= self.0 << 17;
		self.0 % below
	}
}

const ACCOUNTS: [&str; 5] = ["a", "b", "c", "d", "e"];

/// The invariants of the module, checked on `state`.
fn check(state: &State, limits: Limits, step: &str) {
	// 1. One account per record: the total is the sum of the accounts'.
	let sum: u64 = state.accounts.values().map(|held| held.records).sum();
	assert_eq!(
		state.total, sum,
		"{step}: a record belongs to no account, or to two"
	);
	// 2 and 6. What is set aside is at most each account's share summed, and
	// never more than the day's limit.
	let shares: u64 = state
		.accounts
		.values()
		.map(|held| held.records.min(limits.account_records))
		.sum();
	assert!(
		state.within <= shares,
		"{step}: an account set aside more than its share"
	);
	assert!(
		state.within <= limits.day_records,
		"{step}: the day set aside more than its limit"
	);
	for (account, held) in &state.accounts {
		assert!(
			held.bytes <= limits.account_kept_bytes,
			"{step}: {account} kept too much"
		);
	}
}

#[test]
fn random_sequences_keep_every_invariant_after_every_step() {
	for seed in 1..=40u64 {
		let dir = tempfile::tempdir().expect("tempdir");
		let limits = limits();
		let mut day = TODAY;
		let mut log = Log::new(dir.path(), day);
		let mut quota = Quota::start_at(dir.path(), limits, day);
		let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
		let mut next_id = 1u128;
		let mut known: Vec<(u128, &str)> = Vec::new();
		// Whether the book remembers outcomes prepaid on an earlier day, which a
		// restart does not: it counts them as facts, never fewer.
		let mut carried = false;
		for step_number in 0..70u32 {
			let before = quota.state();
			let account = ACCOUNTS[dice.next(ACCOUNTS.len() as u64) as usize];
			let step = format!("seed {seed} step {step_number}");
			match dice.next(10) {
				// An acceptance, which may fail for certain or maybe.
				0..=3 => {
					let recipients = dice.next(5);
					let kept = dice.next(40);
					let message = next_id;
					next_id += 1;
					match quota.reserve(account, id(message), (recipients, kept), day) {
						Ok(held) => match dice.next(4) {
							// Nothing was written: exactly what was reserved goes back.
							0 => {
								quota.release(held);
								let mut expected = before.clone();
								expected.roll(day);
								assert_eq!(
									quota.state(),
									expected,
									"{step}: the rollback was not exact"
								);
							}
							// Written, or maybe: it keeps its room, and is in the log.
							_ => {
								let full = (kept > 0).then_some(kept);
								log.accepted(account, message, recipients as usize, full);
								drop(held);
								known.push((message, account));
								assert!(
									quota.state().accounts[account].records
										<= limits.account_records,
									"{step}: past the share"
								);
							}
						},
						Err(refused) => {
							assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded, "{step}");
							let mut rolled = before.clone();
							rolled.roll(day);
							assert_eq!(
								quota.state(),
								rolled,
								"{step}: a refusal changed the counts"
							);
						}
					}
				}
				// An outcome or an abandonment: a fact, in the log and the book.
				4..=7 => {
					let (message, owner) = match known.len() {
						0 => (next_id, None),
						n => {
							let (message, owner) = known[dice.next(n as u64) as usize];
							(message, Some(owner))
						}
					};
					next_id += 1;
					if dice.next(3) == 0 {
						log.abandoned(message);
					} else {
						log.outcome(message);
					}
					quota.fact(owner, id(message), day);
				}
				// The process restarts: the book is rebuilt from the log.
				8 => {
					let before_restart = quota.state();
					quota = Quota::start_at(dir.path(), limits, day);
					let after = quota.state();
					if carried {
						assert!(
							after.total >= before_restart.total,
							"{step}: a restart granted what the book had counted"
						);
					} else {
						assert_eq!(
							after.total, before_restart.total,
							"{step}: a restart lost the counts"
						);
						assert_eq!(after.within, before_restart.within, "{step}");
						assert_eq!(after.accounts, before_restart.accounts, "{step}");
					}
					carried = false;
				}
				// A new day: the counts start again, the prepaid outcomes stay.
				_ => {
					day = Day(day.0 + 1);
					log = Log::new(dir.path(), day);
					// What is older than the last two days is not named at a restart.
					carried = true;
					known.clear();
					let message = next_id;
					next_id += 1;
					log.outcome(message);
					quota.fact(None, id(message), day);
					let state = quota.state();
					assert_eq!(state.day, day.0, "{step}");
					assert_eq!(
						state.total, 1,
						"{step}: yesterday's counts came into the new day"
					);
				}
			}
			let state = quota.state();
			check(&state, limits, &step);
			// 2. A fresh account is held up by the day's limit only: probing it
			// sets aside exactly what an acceptance of that size needs, and
			// giving it back leaves the book as it was.
			let room = limits.day_records.saturating_sub(state.within);
			let granted = quota.reserve(
				"probe",
				id(u128::MAX - u128::from(step_number)),
				(limits.account_records - 1, 0),
				day,
			);
			assert_eq!(
				granted.is_ok(),
				room >= limits.account_records,
				"{step}: an account's share is not what the day has left ({room} left)"
			);
			if let Ok(held) = granted {
				quota.release(held);
			}
			let mut expected = state.clone();
			expected.roll(day);
			assert_eq!(quota.state(), expected, "{step}: probing left a trace");
		}
	}
}

use std::path::Path;
