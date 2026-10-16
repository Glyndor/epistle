use super::*;

const TODAY: Day = Day(20_740);

fn limits() -> Limits {
	Limits {
		account_records: 12,
		account_kept_bytes: 100,
		day_records: 48,
	}
}

fn quota(dir: &Path) -> Quota {
	Quota::open(dir, limits())
}

fn id(n: u128) -> Uuid {
	Uuid::from_u128(n)
}

fn reserve(
	quota: &Quota,
	account: &str,
	n: u128,
	records: u64,
	kept: u64,
) -> std::io::Result<Reservation> {
	quota.reserve(account, id(n), (records, kept), TODAY)
}

#[test]
fn an_account_is_refused_past_its_share_and_the_others_are_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for n in 0..6 {
		let _ = reserve(&quota, "noisy", n, 2, 0).expect("within the share");
	}
	let refused = reserve(&quota, "noisy", 9, 2, 0).expect_err("past it");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
	let _ = reserve(&quota, "quiet", 10, 2, 0).expect("another account");
}

#[test]
fn kept_bytes_are_counted_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 1, 90).expect("within");
	let _ = reserve(&quota, "a", 2, 1, 10).expect("exactly the limit");
	reserve(&quota, "a", 3, 1, 1).expect_err("one byte over");
	let _ = reserve(&quota, "b", 4, 1, 100).expect("another account");
}

#[test]
fn the_day_takes_no_more_than_its_limit_whoever_asks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for (n, account) in ["a", "b", "c", "d"].iter().enumerate() {
		let _ = reserve(&quota, account, n as u128, 12, 0).expect("a whole share");
	}
	let refused = reserve(&quota, "e", 9, 1, 0).expect_err("the day is full");
	assert_eq!(refused.kind(), std::io::ErrorKind::QuotaExceeded);
}

#[test]
fn a_reservation_given_back_leaves_exactly_what_was_there() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 3, 10).expect("first");
	let before = quota.state();
	let held = reserve(&quota, "a", 2, 4, 20).expect("second");
	assert_ne!(quota.state(), before);
	quota.release(held).expect("release");
	assert_eq!(quota.state(), before);
}

#[test]
fn a_new_day_starts_the_counts_again_and_remembers_what_was_prepaid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	let _ = reserve(&quota, "a", 1, 5, 0).expect("5 records");
	let tomorrow = Day(TODAY.0 + 1);
	quota.fact(Some("a"), id(1), tomorrow).expect("an outcome");
	let state = quota.state();
	assert_eq!(
		state.total, 0,
		"an outcome prepaid yesterday is not paid again"
	);
	assert!(state.accounts.is_empty());
}

#[test]
fn a_fact_with_no_prepayment_is_counted_to_its_account_and_never_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	for n in 0..40 {
		quota.fact(Some("a"), id(n), TODAY).expect("a fact");
	}
	let state = quota.state();
	assert_eq!(state.accounts["a"].records, 40);
	assert!(
		state.within <= limits().account_records,
		"past its share it sets nothing aside"
	);
	reserve(&quota, "a", 100, 1, 0).expect_err("the account waits at its next acceptance");
	let _ = reserve(&quota, "b", 101, 12, 0).expect("and takes nothing from another");
}

#[test]
fn what_cannot_be_traced_has_an_account_of_its_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	quota.fact(None, id(1), TODAY).expect("a fact");
	assert_eq!(quota.state().accounts[UNATTRIBUTED].records, 1);
}

#[test]
fn the_counts_survive_a_restart_and_are_shared_between_processes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = quota(dir.path());
	let _ = reserve(&first, "a", 1, 12, 0).expect("a whole share");
	// Another process, or the same one after a restart.
	let second = quota(dir.path());
	reserve(&second, "a", 2, 1, 0).expect_err("the share is already used");
	assert_eq!(second.state(), first.state());
}

#[test]
fn a_state_that_cannot_be_read_refuses_acceptances_and_not_facts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let quota = quota(dir.path());
	crate::storage::write_secret(&dir.path().join(FILE), b"not json").expect("corrupt");
	assert!(
		reserve(&quota, "a", 1, 1, 0).is_err(),
		"granted on a state nobody read"
	);
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
	let quota = Quota::open(
		dir.path(),
		Limits {
			account_records: 10,
			account_kept_bytes: u64::MAX,
			day_records: 1000,
		},
	);
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 1, 7, 0).expect("70 percent");
	assert_eq!(quota.warning(TODAY), None);
	let _ = reserve(&quota, "a", 2, 1, 0).expect("80 percent");
	assert!(
		quota
			.warning(TODAY)
			.expect("warning")
			.contains("near its evidence limits")
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
	// Bytes never pass the limit: an acceptance that would is refused.
	for (account, held) in &state.accounts {
		assert!(
			held.bytes <= limits.account_kept_bytes,
			"{step}: {account} kept too much"
		);
	}
}

#[test]
fn random_sequences_keep_every_invariant_after_every_step() {
	for seed in 1..=60u64 {
		let dir = tempfile::tempdir().expect("tempdir");
		let limits = limits();
		let mut quota = Quota::open(dir.path(), limits);
		let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
		let mut day = TODAY;
		let mut next_id = 1u128;
		let mut known: Vec<(Uuid, &str)> = Vec::new();
		for step_number in 0..80 {
			let before = quota.state();
			let account = ACCOUNTS[dice.next(ACCOUNTS.len() as u64) as usize];
			let step = format!("seed {seed} step {step_number}");
			match dice.next(10) {
				// An acceptance, which may fail for certain or maybe.
				0..=3 => {
					let records = 1 + dice.next(6);
					let kept = dice.next(40);
					let message = id(next_id);
					next_id += 1;
					match quota.reserve(account, message, (records, kept), day) {
						Ok(held) => match dice.next(4) {
							// Nothing was written: exactly what was reserved goes back.
							0 => {
								let reserved = quota.state();
								quota.release(held).expect("release");
								let mut expected = before.clone();
								expected.roll(day);
								assert_eq!(
									quota.state(),
									expected,
									"{step}: the rollback was not exact"
								);
								assert_ne!(
									reserved, expected,
									"{step}: the reservation did nothing"
								);
							}
							// Written, or maybe: it keeps its room.
							_ => {
								let held_before =
									before.accounts.get(account).map_or(0, |held| held.records);
								let after = quota.state();
								assert!(
									after.accounts[account].records <= limits.account_records,
									"{step}: past the share ({held_before} before)"
								);
								drop(held);
								known.push((message, account));
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
				// An outcome or an abandonment or a cancellation: a fact.
				4..=7 => {
					let traced = dice.next(3) != 0;
					let (message, owner) = match known.len() {
						0 => (id(next_id), account),
						n => known[dice.next(n as u64) as usize],
					};
					next_id += 1;
					let counted = quota.fact(traced.then_some(owner), message, day);
					assert!(counted.is_ok(), "{step}: a fact was refused");
				}
				// The process restarts: the counts are the same.
				8 => {
					let before_restart = quota.state();
					quota = Quota::open(dir.path(), limits);
					assert_eq!(
						quota.state(),
						before_restart,
						"{step}: a restart lost the counts"
					);
				}
				// A new day: the counts start again, the prepaid outcomes stay.
				_ => {
					day = Day(day.0 + 1);
					let owed_before = quota.state().owed.len();
					quota.fact(None, id(next_id), day).expect("a fact");
					next_id += 1;
					let state = quota.state();
					assert_eq!(state.day, day.0, "{step}");
					assert!(
						state.owed.len() <= owed_before,
						"{step}: an owed entry appeared from nowhere"
					);
					assert_eq!(
						state.total, 1,
						"{step}: yesterday's counts came into the new day"
					);
				}
			}
			let state = quota.state();
			check(&state, limits, &step);
			// 2. A fresh account is held up by the day's limit only: probing
			// it sets aside exactly what an acceptance of that size needs, and
			// giving it back leaves the state as it was.
			if state.day == day.0 {
				let probe = id(u128::MAX - u128::from(step_number as u64));
				let room = limits.day_records.saturating_sub(state.within);
				let granted = quota.reserve("probe", probe, (limits.account_records, 0), day);
				assert_eq!(
					granted.is_ok(),
					room >= limits.account_records,
					"{step}: an account's share is not what the day has left ({room} left)"
				);
				if let Ok(held) = granted {
					quota.release(held).expect("release");
				}
				// (Forgetting the outcomes that have all come is not a trace.)
				let mut expected = state.clone();
				expected.roll(day);
				assert_eq!(quota.state(), expected, "{step}: probing left a trace");
			}
		}
	}
}

use std::path::Path;
