use super::*;

#[tokio::test]
async fn revocation_is_per_token_id_idempotent_and_survives_restart() {
	let dir = tempfile::tempdir().unwrap();
	let keys = keys();
	let state = state_with_authz(dir.path(), &keys);
	let first = issued(&state, "alice", "read");
	let second = issued(&state, "alice", "read");
	assert!(first != second);
	let app = router(state.clone());
	assert_eq!(
		request(&app, "GET", "/jmap/session", &first, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
	for token in [first.as_str(), first.as_str(), "invalid-token"] {
		let response = response(
			&app,
			"POST",
			"/oauth/revoke",
			None,
			"application/x-www-form-urlencoded",
			format!("token={token}"),
		)
		.await;
		assert_eq!(response.status(), StatusCode::OK);
		assert!(
			axum::body::to_bytes(response.into_body(), usize::MAX)
				.await
				.unwrap()
				.is_empty()
		);
	}
	let persisted = std::fs::read_to_string(dir.path().join("oauth_revocations.json")).unwrap();
	assert!(!persisted.contains(&first));
	assert!(!persisted.contains("alice"));
	// The same signed claims with a fresh randomized ECDSA signature stay revoked.
	let first_claims = state.authz().unwrap().access_claims(&first, now()).unwrap();
	let resigned = signed(&state, &first_claims.raw);
	for token in [&first, &resigned] {
		assert_eq!(
			request(&app, "GET", "/jmap/session", token, Value::Null)
				.await
				.0,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request(&app, "GET", "/jmap/session", &second, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
	drop(app);
	drop(state);
	let restarted = router(state_with_authz(dir.path(), &keys));
	assert_eq!(
		request(&restarted, "GET", "/jmap/session", &first, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		request(&restarted, "GET", "/jmap/session", &second, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
}

#[tokio::test]
async fn unreadable_or_corrupt_revocations_fail_closed_and_cannot_report_success() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let token = issued(&state, "alice", "read");
	let app = router(state);
	let path = dir.path().join("oauth_revocations.json");
	std::fs::write(&path, b"invalid json").unwrap();
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		form(&app, "/oauth/revoke", &format!("token={token}"))
			.await
			.0,
		StatusCode::SERVICE_UNAVAILABLE
	);
	std::fs::remove_file(&path).unwrap();
	std::fs::create_dir(&path).unwrap();
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
	assert_eq!(
		form(&app, "/oauth/revoke", &format!("token={token}"))
			.await
			.0,
		StatusCode::SERVICE_UNAVAILABLE
	);
}

#[tokio::test]
async fn revoked_tokens_count_toward_the_existing_bearer_limit() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let token = issued(&state, "alice", "read");
	let app = router(state);
	assert_eq!(
		form(&app, "/oauth/revoke", &format!("token={token}"))
			.await
			.0,
		StatusCode::OK
	);
	for _ in 0..20 {
		assert_eq!(
			request(&app, "GET", "/jmap/session", &token, Value::Null)
				.await
				.0,
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request(
			&app,
			"GET",
			"/api/v1/accounts",
			"wrong-static-token",
			Value::Null
		)
		.await
		.0,
		StatusCode::TOO_MANY_REQUESTS
	);
}
