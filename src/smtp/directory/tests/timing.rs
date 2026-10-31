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

/// How many password hashes one refused attempt for `login` ran.
fn hashes_for_a_refusal(login: &str) -> usize {
	use super::bans::decoy_counters::DecoyCounters;
	let counters = std::sync::Arc::new(DecoyCounters::default());
	let (directory, _, _) = gate_directory_with_app_passwords();
	let directory = directory.with_decoy_counters(counters.clone());
	let outcome = directory.authenticate(login, fixtures::wrong_password(), Protocol::Imaps);
	assert_eq!(outcome, None);
	counters.hashes()
}

#[test]
fn a_refusal_runs_the_same_hashing_whatever_the_login_holds() {
	// alice has two app passwords, the rest none, and a refusal that ran fewer
	// hashes for them than for alice would say which logins have app passwords.
	let with_apps = hashes_for_a_refusal(OPEN);
	assert_eq!(with_apps, 3, "the primary and the two app passwords");
	assert_eq!(hashes_for_a_refusal("nobody-here"), with_apps, "unknown");
	assert_eq!(hashes_for_a_refusal(DISABLED), with_apps, "disabled");
	assert_eq!(
		hashes_for_a_refusal(TWO_FACTOR),
		with_apps,
		"an account with no app passwords"
	);
}
