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
