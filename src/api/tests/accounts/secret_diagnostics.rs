use crate::test_fixtures as fixtures;

pub(in super::super) fn assert_totp_secret(secret: &str) {
	assert!(
		crate::totp::decode_base32_secret(secret).is_some(),
		"TOTP secret must decode as base32"
	);
}

#[test]
fn totp_assertion_diagnostics_omit_secret() {
	let candidate = format!("!{}", fixtures::password());
	let failure = std::panic::catch_unwind(|| assert_totp_secret(&candidate))
		.expect_err("malformed base32 must fail the assertion");
	let message = failure
		.downcast_ref::<String>()
		.map(String::as_str)
		.or_else(|| failure.downcast_ref::<&str>().copied())
		.expect("assertion must have a text diagnostic");
	assert!(
		message == "TOTP secret must decode as base32",
		"TOTP assertion diagnostics must omit the secret"
	);
}
