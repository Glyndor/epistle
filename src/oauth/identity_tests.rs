use super::*;
use serde_json::json;

fn claims(raw: serde_json::Value) -> Claims {
	Claims { raw }
}

fn strict() -> IdentityPolicy {
	IdentityPolicy::default()
}

fn lenient() -> IdentityPolicy {
	IdentityPolicy {
		allow_unverified_email: true,
		..IdentityPolicy::default()
	}
}

fn own() -> IdentityPolicy {
	IdentityPolicy {
		own_tokens: true,
		..IdentityPolicy::default()
	}
}

fn address(text: &str) -> Result<Verified, Refusal> {
	Ok(Verified::Address(text.to_string()))
}

#[test]
fn a_verified_email_is_the_identity() {
	let token = claims(json!({"email": "a@example.org", "email_verified": true}));
	assert_eq!(strict().identity(&token), address("a@example.org"));
	let text = claims(json!({"email": "a@example.org", "email_verified": "True"}));
	assert_eq!(strict().identity(&text), address("a@example.org"));
}

#[test]
fn an_unverified_or_unstated_email_is_refused_by_default() {
	for (raw, why) in [
		(
			json!({"email": "a@example.org", "email_verified": false}),
			Refusal::EmailNotVerified,
		),
		(
			json!({"email": "a@example.org", "email_verified": "false"}),
			Refusal::EmailNotVerified,
		),
		(
			json!({"email": "a@example.org", "email_verified": 1}),
			Refusal::EmailNotVerified,
		),
		(
			json!({"email": "a@example.org", "email_verified": null}),
			Refusal::EmailNotVerified,
		),
		(
			json!({"email": "a@example.org"}),
			Refusal::EmailVerifiedMissing,
		),
		(json!({"email_verified": true}), Refusal::NoEmail),
	] {
		assert_eq!(strict().identity(&claims(raw.clone())), Err(why), "{raw}");
	}
}

#[test]
fn the_operator_can_accept_a_claim_the_provider_never_states() {
	let absent = claims(json!({"email": "a@example.org"}));
	assert_eq!(lenient().identity(&absent), address("a@example.org"));
	// A provider that says it did not verify the address is still refused.
	let denied = claims(json!({"email": "a@example.org", "email_verified": false}));
	assert_eq!(lenient().identity(&denied), Err(Refusal::EmailNotVerified));
}

#[test]
fn the_subject_of_an_external_provider_is_never_an_identity() {
	for policy in [strict(), lenient()] {
		let token = claims(json!({"sub": "a@example.org", "email_verified": true}));
		assert_eq!(policy.identity(&token), Err(Refusal::NoEmail));
	}
}

#[test]
fn a_token_of_the_built_in_server_names_the_account_in_its_subject() {
	let token = claims(json!({"sub": "alice"}));
	assert_eq!(
		own().identity(&token),
		Ok(Verified::Account("alice".to_string()))
	);
	assert_eq!(
		own().identity(&claims(json!({"email": "a@example.org"}))),
		Err(Refusal::NoSubject)
	);
}

#[test]
fn only_the_built_in_server_or_a_declared_provider_stands_for_the_second_factor() {
	assert!(!strict().second_factor_met());
	assert!(own().second_factor_met());
	let declared = IdentityPolicy {
		second_factor_attested: true,
		..IdentityPolicy::default()
	};
	assert!(declared.second_factor_met());
}

#[test]
fn the_reasons_name_no_value_of_the_token() {
	for why in [
		Refusal::NoEmail,
		Refusal::EmailVerifiedMissing,
		Refusal::EmailNotVerified,
		Refusal::NoSubject,
	] {
		assert!(!why.reason().contains('@'));
	}
}
