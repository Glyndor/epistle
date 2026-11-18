//! The iteration count of a new verifier follows `[auth] scram_iterations`,
//! and a verifier keeps the count it was derived with.

use super::*;
use crate::test_support::fixtures;

#[test]
fn the_default_count_is_the_owasp_minimum() {
	assert_eq!(iterations::current(), 600_000);
	let stored = ScramStored::with_fresh_salt(fixtures::password()).expect("derive");
	assert_eq!(stored.iterations, 600_000);
}

#[test]
fn a_new_verifier_carries_the_count_in_force() {
	let stored = iterations::scoped(700_000, || {
		ScramStored::with_fresh_salt(fixtures::password()).expect("derive")
	});
	assert_eq!(stored.iterations, 700_000);
	assert_eq!(iterations::current(), 600_000, "restored");
}

#[test]
fn a_verifier_below_the_count_in_force_is_the_one_that_gets_upgraded() {
	let old = ScramStored::with_fresh_salt(fixtures::password()).expect("derive");
	let below_default = old.iterations < iterations::current();
	let below_raised = iterations::scoped(700_000, || old.iterations < iterations::current());
	assert!(!below_default);
	assert!(
		below_raised,
		"raising the count reaches the verifiers that already exist"
	);
}

#[test]
fn the_count_cannot_go_below_the_floor_or_above_the_ceiling() {
	assert!(iterations::validate(600_000).is_ok());
	assert!(iterations::validate(10_000_000).is_ok());
	let error = iterations::validate(599_999).expect_err("below");
	assert!(error.contains("must be at least 600000"), "{error}");
	let error = iterations::validate(10_000_001).expect_err("above");
	assert!(error.contains("must be at most 10000000"), "{error}");
}
