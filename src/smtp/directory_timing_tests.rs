//! A login nobody holds costs the server the same work as a wrong password on
//! a real account, so the time a refusal takes does not say which logins exist.

use std::time::{Duration, Instant};

use super::gate_fixture::*;
use crate::config::Protocol;
use crate::test_fixtures as fixtures;

/// The median of `rounds` timings of one failed password check for `login`.
fn failed_check(directory: &super::Directory, login: &str, rounds: usize) -> Duration {
	let mut samples: Vec<Duration> = (0..rounds)
		.map(|_| {
			let started = Instant::now();
			let outcome =
				directory.authenticate(login, fixtures::wrong_password(), Protocol::Imaps);
			let elapsed = started.elapsed();
			assert_eq!(outcome, None);
			elapsed
		})
		.collect();
	samples.sort();
	samples[rounds / 2]
}

#[test]
fn an_unknown_login_takes_as_long_to_refuse_as_a_wrong_password() {
	let directory = gate_directory();
	// Warm the hashing code so the first sample is not the odd one.
	failed_check(&directory, OPEN, 1);
	let known = failed_check(&directory, OPEN, 5);
	let unknown = failed_check(&directory, "nobody-here", 5);
	let ratio = unknown.as_secs_f64() / known.as_secs_f64();
	assert!(
		(0.4..2.5).contains(&ratio),
		"unknown {unknown:?} against known {known:?}: ratio {ratio:.3} says the login does not exist"
	);
}

#[test]
fn a_disabled_account_takes_as_long_to_refuse_as_a_wrong_password() {
	let directory = gate_directory();
	failed_check(&directory, OPEN, 1);
	let known = failed_check(&directory, OPEN, 5);
	let disabled = failed_check(&directory, DISABLED, 5);
	let ratio = disabled.as_secs_f64() / known.as_secs_f64();
	assert!(
		(0.4..2.5).contains(&ratio),
		"disabled {disabled:?} against known {known:?}: ratio {ratio:.3} says the account is disabled"
	);
}
