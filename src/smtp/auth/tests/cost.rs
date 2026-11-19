//! The argon2id cost of a new hash follows the setting, and a hash of any
//! cost keeps verifying.

use super::base::{fixture_password, wrong_password};
use super::*;
use crate::smtp::auth::cost::{self, Argon2Cost};

const STRONGER: Argon2Cost = Argon2Cost {
	memory_kib: 32_768,
	iterations: 3,
	parallelism: 2,
};

fn parameters_of(hash: &str) -> &str {
	hash.split('$').nth(3).expect("parameters")
}

#[test]
fn the_default_cost_is_the_owasp_minimum() {
	let hash = hash_password(fixture_password()).expect("hash");
	assert_eq!(parameters_of(&hash), "m=19456,t=2,p=1");
	assert!(verify_password(&hash, fixture_password()));
}

#[test]
fn a_new_hash_carries_the_cost_in_force() {
	let hash = cost::scoped(STRONGER, || {
		hash_password(fixture_password()).expect("hash")
	});
	assert_eq!(parameters_of(&hash), "m=32768,t=3,p=2");
	assert!(verify_password(&hash, fixture_password()));
	assert!(!verify_password(&hash, wrong_password()));
}

#[test]
fn hashes_of_every_cost_verify_whatever_the_cost_in_force() {
	let old = hash_password(fixture_password()).expect("hash");
	let strong = cost::scoped(STRONGER, || {
		hash_password(fixture_password()).expect("hash")
	});
	cost::scoped(STRONGER, || {
		assert!(verify_password(&old, fixture_password()))
	});
	assert!(
		verify_password(&strong, fixture_password()),
		"after the cost went back"
	);
}

#[test]
fn a_cost_the_hasher_cannot_use_is_an_error_not_a_weak_hash() {
	let salt = crate::test_support::fixtures::salt();
	let broken = Argon2Cost {
		memory_kib: 1,
		iterations: 2,
		parallelism: 1,
	};
	assert!(hash_password_with_cost(fixture_password(), broken, salt).is_err());
}

fn stored(cost: Argon2Cost) -> String {
	hash_password_with_cost(
		fixture_password(),
		cost,
		&crate::smtp::auth::fresh_salt().expect("salt"),
	)
	.expect("hash")
}

#[test]
fn a_hash_at_or_above_the_cost_in_force_needs_no_rewrite() {
	let default = Argon2Cost::default();
	assert_eq!(cost::rewrite_cost(&stored(default), default), None);
	assert_eq!(cost::rewrite_cost(&stored(STRONGER), default), None);
}

#[test]
fn a_hash_below_the_cost_in_force_in_any_respect_is_rewritten_at_the_larger_of_each() {
	let default = Argon2Cost::default();
	assert_eq!(
		cost::rewrite_cost(&stored(default), STRONGER),
		Some(STRONGER)
	);
	let lanes = Argon2Cost {
		parallelism: 2,
		..default
	};
	assert_eq!(cost::rewrite_cost(&stored(lanes), default), None);
	let wide = Argon2Cost {
		memory_kib: 65_536,
		..default
	};
	assert_eq!(
		cost::rewrite_cost(&stored(wide), STRONGER),
		Some(Argon2Cost {
			memory_kib: 65_536,
			iterations: 3,
			parallelism: 2,
		})
	);
}

#[test]
fn an_unreadable_string_is_left_alone() {
	for text in [
		"",
		"plain",
		"$2b$12$abcdefghijklmnopqrstuv",
		"$argon2id$v=19$m=x",
	] {
		assert_eq!(cost::rewrite_cost(text, STRONGER), None, "{text:?}");
	}
}
