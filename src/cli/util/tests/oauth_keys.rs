use super::*;

#[test]
fn oauth_keypair_round_trips_through_jwt() {
	// The generated private/public pair must be matched: a token signed with the
	// private key verifies against the public point.
	use base64::Engine;
	let (private_b64, public_b64) = generate_oauth_keypair().expect("keypair");
	let private = base64::engine::general_purpose::STANDARD
		.decode(&private_b64)
		.expect("private b64");
	let public = base64::engine::general_purpose::STANDARD
		.decode(&public_b64)
		.expect("public b64");
	let claims = serde_json::json!({"sub": "x", "exp": 9999999999u64});
	let token = crate::jwt::sign(&claims, crate::jwt::Algorithm::Es256, &private).expect("sign");
	let validation = crate::jwt::Validation {
		now: 1000,
		issuer: None,
		audience: None,
	};
	assert!(
		crate::jwt::validate(&token, crate::jwt::Algorithm::Es256, &public, &validation).is_ok()
	);
}
