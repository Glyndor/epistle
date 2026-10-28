use super::base::{fixture_password, hash};

#[test]
fn fixture_hashes_use_independent_salts() {
	let password = fixture_password();
	let first = hash(password);
	let second = hash(password);
	assert!(
		first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
		"fixture PHC encoding must retain Argon2 parameters"
	);
	assert!(
		first.split('$').nth(4) != second.split('$').nth(4),
		"fixture hashes must use independent salts"
	);
	assert!(
		super::verify_password(&first, password),
		"first hash must verify"
	);
	assert!(
		super::verify_password(&second, password),
		"second hash must verify"
	);
}

#[test]
fn runtime_credentials_have_distinct_roles_and_valid_passwords() {
	use crate::test_fixtures as fixtures;
	let values = [
		fixtures::password(),
		fixtures::second_password(),
		fixtures::wrong_password(),
		fixtures::api_token(),
		fixtures::api_key(),
		fixtures::nonce(),
	];
	for (i, value) in values.iter().enumerate() {
		assert_eq!(
			crate::password::validate(value),
			Ok(()),
			"runtime credential must pass password policy"
		);
		assert!(
			values[..i].iter().all(|previous| previous != value),
			"credential roles must be distinct"
		);
	}
	assert!(
		fixtures::fresh_secret() != fixtures::fresh_secret(),
		"fresh credentials must differ between calls"
	);
	assert!(
		fixtures::bytes::<32>() != fixtures::bytes::<32>(),
		"fresh key material must differ between calls"
	);
}
