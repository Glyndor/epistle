//! Length limits and the operator's list, against explicit values: nothing
//! here installs process-wide settings, so the other tests keep 12 and 64.

use super::*;
use crate::password::limits::{Limits, MAX_CEILING, MAX_FLOOR, MIN_FLOOR};
use crate::password::policy::check_lists;
use crate::test_support::fixtures;

const SHORT_LIMITS: Limits = Limits { min: 8, max: 64 };
const LONG_LIMITS: Limits = Limits { min: 12, max: 200 };

#[test]
fn the_defaults_are_the_historical_limits() {
	assert_eq!(Limits::default(), Limits { min: 12, max: 64 });
	assert_eq!(limits::current(), Limits::default());
	assert_eq!(
		limits::message(),
		"Password must be between 12 and 64 characters."
	);
}

#[test]
fn the_floors_are_what_the_loader_enforces() {
	assert_eq!((MIN_FLOOR, MAX_FLOOR, MAX_CEILING), (8, 64, 1024));
	Limits { min: 8, max: 64 }.validate().expect("floors");
	assert!(Limits { min: 7, max: 64 }.validate().is_err());
	assert!(Limits { min: 12, max: 63 }.validate().is_err());
	assert!(Limits { min: 12, max: 1025 }.validate().is_err());
	assert!(Limits { min: 70, max: 64 }.validate().is_err());
}

#[test]
fn a_lower_minimum_accepts_what_the_default_refuses() {
	let eight = fixtures::printable_ascii(8);
	let policy = Policy::ASCII_ONLY;
	assert_eq!(
		policy.prepare_with(Limits::default(), &eight),
		Err(Rejection::TooShort)
	);
	assert!(policy.prepare_with(SHORT_LIMITS, &eight).is_ok());
	let seven = fixtures::printable_ascii(7);
	assert_eq!(
		policy.prepare_with(SHORT_LIMITS, &seven),
		Err(Rejection::TooShort)
	);
}

#[test]
fn a_higher_maximum_accepts_what_the_default_refuses() {
	let long = fixtures::printable_ascii(150);
	let policy = Policy::ASCII_ONLY;
	assert_eq!(
		policy.prepare_with(Limits::default(), &long),
		Err(Rejection::TooLong)
	);
	assert!(policy.prepare_with(LONG_LIMITS, &long).is_ok());
	let over = fixtures::printable_ascii(201);
	assert_eq!(
		policy.prepare_with(LONG_LIMITS, &over),
		Err(Rejection::TooLong)
	);
	let exact = fixtures::printable_ascii(200);
	assert!(policy.prepare_with(LONG_LIMITS, &exact).is_ok());
}

#[test]
fn the_unicode_policy_counts_against_the_same_limits() {
	let policy = Policy::unicode();
	let eight: String = std::iter::repeat_n(fixtures::non_ascii_char(), 8).collect();
	assert_eq!(
		policy.prepare_with(Limits::default(), &eight),
		Err(Rejection::TooShort)
	);
	assert!(policy.prepare_with(SHORT_LIMITS, &eight).is_ok());
	let long: String = std::iter::repeat_n(fixtures::non_ascii_char(), 100).collect();
	assert_eq!(
		policy.prepare_with(Limits::default(), &long),
		Err(Rejection::TooLong)
	);
	assert!(policy.prepare_with(LONG_LIMITS, &long).is_ok());
}

#[test]
fn installing_the_limits_in_force_changes_nothing() {
	limits::install(Limits::default());
	assert_eq!(limits::current(), Limits::default());
}

#[test]
fn the_message_names_the_limits_it_was_built_for() {
	assert_eq!(
		SHORT_LIMITS.message(),
		"Password must be between 8 and 64 characters."
	);
}

#[test]
fn the_operator_list_refuses_what_the_bundle_does_not_know() {
	let operator = forbidden::parse("# our own\nExample Company 2026\n\n  spaced entry here  \n");
	let ask = |password: &str| check_lists(password, |lowered| operator.contains(lowered));
	assert_eq!(ask("example company 2026"), Err(Rejection::Forbidden));
	assert_eq!(
		ask("EXAMPLE COMPANY 2026"),
		Err(Rejection::Forbidden),
		"case is ignored"
	);
	assert_eq!(
		ask("spaced entry here"),
		Err(Rejection::Forbidden),
		"entries are trimmed"
	);
	assert_eq!(ask("# our own"), Ok(()), "comments are not entries");
	assert_eq!(ask(fixtures::password()), Ok(()));
}

#[test]
fn the_bundled_list_still_refuses_with_an_operator_list_in_force() {
	let breached = breached_set().iter().next().copied().expect("bundle");
	assert_eq!(check_lists(breached, |_| false), Err(Rejection::Breached));
}

#[test]
fn an_empty_or_commented_list_forbids_nothing() {
	assert!(forbidden::parse("").is_empty());
	assert!(forbidden::parse("# only a comment\n\n").is_empty());
}

#[test]
fn the_list_file_is_read_and_a_directory_or_oversized_file_is_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("list.txt");
	std::fs::write(&path, "first entry here\nSecond Entry Here\n").expect("write");
	let set = forbidden::load(&path).expect("load");
	assert!(set.contains("first entry here") && set.contains("second entry here"));
	assert!(forbidden::load(dir.path()).is_err(), "a directory");
	let big = dir.path().join("big.txt");
	std::fs::File::create(&big)
		.and_then(|file| file.set_len(forbidden::MAX_FILE_BYTES + 1))
		.expect("sparse file");
	assert!(forbidden::load(&big).is_err(), "over the size limit");
	assert!(forbidden::load(&dir.path().join("missing.txt")).is_err());
}

#[test]
fn the_bundled_set_is_built_against_the_widest_limits() {
	assert!(survives_filter("abcd1234efgh")); // 12
	assert!(survives_filter("abcd1234")); // 8: still protects a server that lowers the minimum
	assert!(!survives_filter("abcd123")); // 7
	assert!(!survives_filter(&"a".repeat(MAX_CEILING + 1)));
}

#[test]
fn the_rejection_for_the_operator_list_has_its_own_message() {
	assert_ne!(
		Rejection::Forbidden.message(),
		Rejection::Breached.message()
	);
	assert!(Rejection::Forbidden.message().contains("not allowed"));
}

#[test]
fn the_policy_in_force_uses_the_installed_limits_end_to_end() {
	let eight = fixtures::printable_ascii(8);
	assert_eq!(validate(&eight), Err(Rejection::TooShort));
	limits::scoped(SHORT_LIMITS, || {
		assert_eq!(validate(&eight), Ok(()));
		assert_eq!(
			Rejection::TooShort.message(),
			"Password must be between 8 and 64 characters."
		);
	});
	assert_eq!(validate(&eight), Err(Rejection::TooShort), "restored");
	let long = fixtures::printable_ascii(150);
	assert_eq!(validate(&long), Err(Rejection::TooLong));
	limits::scoped(LONG_LIMITS, || assert_eq!(validate(&long), Ok(())));
}

#[test]
fn the_policy_in_force_refuses_what_the_operator_list_names() {
	let password = fixtures::password();
	assert_eq!(validate(password), Ok(()));
	let list = forbidden::parse(password);
	forbidden::scoped(list.clone(), || {
		assert_eq!(validate(password), Err(Rejection::Forbidden));
		assert_eq!(
			Policy::unicode().validate(password),
			Err(Rejection::Forbidden),
			"both policies read the list"
		);
	});
	assert_eq!(validate(password), Ok(()), "restored");
}
