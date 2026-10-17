//! The invariants of the quota hold after every step of random sequences.

use super::tests::{Log, TODAY, id, limits};
use super::*;

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
	for held in state.accounts.values() {
		assert!(
			held.bytes <= limits.account_kept_bytes,
			"{step}: an account kept too much"
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
		// An oracle for invariant 3 that shares nothing with the book: how many
		// outcomes each accepted message was paid for and has not had yet.
		let mut paid: std::collections::HashMap<u128, u64> = std::collections::HashMap::new();
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
								paid.insert(message, recipients);
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
					let ends = dice.next(3) == 0;
					if ends {
						log.abandoned(message);
						quota.ended(owner, id(message), day);
					} else {
						log.outcome(message);
						quota.fact(owner, id(message), day);
					}
					// Invariant 3, from the oracle: a fact the acceptance paid for
					// adds nothing; any other adds exactly one record, to the
					// account of its acceptance (or to the unattributed ones).
					let prepaid = paid.get(&message).is_some_and(|left| *left > 0);
					let owner = owner.unwrap_or(UNATTRIBUTED);
					let records =
						|state: &State| state.accounts.get(owner).map_or(0, |h| h.records);
					let counted = u64::from(!prepaid);
					let after = quota.state();
					assert_eq!(
						after.total - before.total,
						counted,
						"{step}: a fact was counted {} times",
						after.total - before.total
					);
					assert_eq!(
						records(&after) - records(&before),
						counted,
						"{step}: a fact was counted to another account"
					);
					match (prepaid, ends) {
						(true, false) => *paid.entry(message).or_default() -= 1,
						(_, true) => {
							paid.remove(&message);
						}
						_ => {}
					}
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
					paid.clear();
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
