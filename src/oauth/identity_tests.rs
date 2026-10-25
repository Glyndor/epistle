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
		second_factor_attested: false,
	}
}

#[test]
fn a_verified_email_is_the_identity() {
	let token = claims(json!({"email": "a@example.org", "email_verified": true}));
	assert_eq!(strict().identity(&token).as_deref(), Some("a@example.org"));
	let text = claims(json!({"email": "a@example.org", "email_verified": "True"}));
	assert_eq!(strict().identity(&text).as_deref(), Some("a@example.org"));
}

#[test]
fn an_unverified_or_unstated_email_is_refused_by_default() {
	for raw in [
		json!({"email": "a@example.org", "email_verified": false}),
		json!({"email": "a@example.org", "email_verified": "false"}),
		json!({"email": "a@example.org", "email_verified": 1}),
		json!({"email": "a@example.org", "email_verified": null}),
		json!({"email": "a@example.org"}),
	] {
		assert_eq!(strict().identity(&claims(raw.clone())), None, "{raw}");
	}
}

#[test]
fn the_operator_can_accept_a_claim_the_provider_never_states() {
	let absent = claims(json!({"email": "a@example.org"}));
	assert_eq!(
		lenient().identity(&absent).as_deref(),
		Some("a@example.org")
	);
	// A provider that says it did not verify the address is still refused.
	let denied = claims(json!({"email": "a@example.org", "email_verified": false}));
	assert_eq!(lenient().identity(&denied), None);
}

#[test]
fn the_subject_is_never_an_identity() {
	for policy in [strict(), lenient()] {
		let token = claims(json!({"sub": "a@example.org", "email_verified": true}));
		assert_eq!(policy.identity(&token), None);
	}
}
