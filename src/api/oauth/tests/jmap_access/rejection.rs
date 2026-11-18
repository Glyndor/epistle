use super::*;
use base64::Engine;

#[tokio::test]
async fn invalid_signed_claims_are_401_with_an_identical_generic_body() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let valid = claims(&state);
	let app = router(state.clone());
	let (_, expected) = request(&app, "GET", "/jmap/session", "invalid-bearer", Value::Null).await;
	for (field, replacement) in [
		("sub", Value::Null),
		("sub", json!("")),
		("sub", json!("unknown-account")),
		("sub", json!("alice@example.org")),
		("iss", json!("another-issuer")),
		("aud", json!("another-audience")),
		("exp", json!(now())),
		("exp", Value::Null),
		("exp", json!("tomorrow")),
		("iat", json!(now() + 7200)),
		("scope", Value::Null),
		("scope", json!("")),
		("scope", json!("read scim")),
		("jti", Value::Null),
		("nbf", json!(now() + 7200)),
		("nbf", json!("invalid")),
	] {
		let mut invalid = valid.clone();
		invalid[field] = replacement;
		let token = signed(&state, &invalid);
		let (status, body) = request(&app, "GET", "/jmap/session", &token, Value::Null).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
		assert_eq!(body, expected);
		assert!(!body.to_string().contains(&token));
	}
	assert_eq!(
		request(
			&app,
			"GET",
			"/jmap/session",
			&signed(&state, &valid),
			Value::Null
		)
		.await
		.0,
		StatusCode::OK
	);
}

#[tokio::test]
async fn another_key_tampering_and_algorithm_downgrades_fail_closed() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let foreign_dir = tempfile::tempdir().unwrap();
	let foreign = world(foreign_dir.path());
	let claims = claims(&state);
	let good = signed(&state, &claims);
	let foreign_key = signed(&foreign, &claims);
	let parts: Vec<_> = good.split('.').collect();
	let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
	let mut changed = claims.clone();
	changed["sub"] = json!("bob");
	let tampered = format!(
		"{}.{}.{}",
		parts[0],
		b64.encode(changed.to_string()),
		parts[2]
	);
	let none = format!("{}.{}.", b64.encode(br#"{"alg":"none"}"#), parts[1]);
	let hs256 = format!(
		"{}.{}.{}",
		b64.encode(br#"{"alg":"HS256"}"#),
		parts[1],
		parts[2]
	);
	let app = router(state);
	for token in [
		foreign_key,
		tampered,
		none,
		hs256,
		format!("{good}.extra"),
		"x".repeat(1025),
	] {
		assert_eq!(
			request(&app, "GET", "/jmap/session", &token, Value::Null)
				.await
				.0,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request(&app, "GET", "/jmap/session", &good, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
}

#[tokio::test]
async fn oauth_failures_share_the_bearer_limiter_and_success_does_not_reset_it() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let good = issued(&state, "alice", "read");
	let mut expired = claims(&state);
	expired["exp"] = json!(now());
	let bad = signed(&state, &expired);
	let app = router(state);
	for _ in 0..19 {
		assert_eq!(
			request(&app, "GET", "/jmap/session", &bad, Value::Null)
				.await
				.0,
			StatusCode::UNAUTHORIZED
		);
		assert_eq!(
			request(&app, "GET", "/jmap/session", &good, Value::Null)
				.await
				.0,
			StatusCode::OK
		);
	}
	assert_eq!(
		request(
			&app,
			"GET",
			"/api/v1/accounts",
			"other-wrong-bearer",
			Value::Null
		)
		.await
		.0,
		StatusCode::UNAUTHORIZED
	);
	let response = response(
		&app,
		"GET",
		"/jmap/session",
		Some(&good),
		"application/json",
		String::new(),
	)
	.await;
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
	assert!(response.headers().contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn disabled_and_deleted_subjects_cannot_authenticate() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let token = issued(&state, "bob", "read");
	let app = router(state.clone());
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
	state.store().set_disabled("bob", true).unwrap();
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
	state.store().set_disabled("bob", false).unwrap();
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
	state.store().remove("bob").unwrap();
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
}

#[test]
fn oauth_principal_diagnostics_do_not_print_token_or_claim_contents() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let claims = claims(&state);
	let token = signed(&state, &claims);
	let principal = state.oauth_principal(&token, None).unwrap();
	let diagnostic = format!("{principal:?}");
	for secret in [
		token.as_str(),
		"alice",
		"read",
		"write",
		"send",
		claims["jti"].as_str().unwrap(),
	] {
		assert!(!diagnostic.contains(secret));
	}
}
