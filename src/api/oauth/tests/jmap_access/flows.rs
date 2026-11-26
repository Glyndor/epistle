use super::*;

#[tokio::test]
async fn both_grants_read_only_the_issued_account() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let app = router(state);
	for token in [pkce(&app, Some("read")).await, device(&app, "read").await] {
		for path in ["/jmap/session", "/.well-known/jmap"] {
			let (status, body) = request(&app, "GET", path, &token, Value::Null).await;
			assert_eq!(status, StatusCode::OK);
			assert_eq!(body["accounts"].as_object().unwrap().len(), 1);
			assert!(body["accounts"].get("alice").is_some());
			assert!(body["accounts"].get("bob").is_none());
		}
		let own = call(&app, &token, "Mailbox/get", json!({"accountId": "alice"})).await;
		assert_eq!(own[0], "Mailbox/get");
		let foreign = call(&app, &token, "Mailbox/get", json!({"accountId": "bob"})).await;
		assert_eq!(foreign[1]["type"], "accountNotFound");
	}
}

#[tokio::test]
async fn oauth_never_authenticates_rest_admin_or_scim_even_with_all_mail_scopes() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let token = issued(&state, "alice", "read write send");
	let app = router(state);
	for (method, path) in [
		("GET", "/api/v1/accounts"),
		("GET", "/api/v1/domains"),
		("POST", "/api/v1/send"),
		("GET", "/api/v1/deliveries"),
		("GET", "/scim/v2/Users"),
	] {
		let (status, _) = request(&app, method, path, &token, json!({})).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED);
	}
}

#[tokio::test]
async fn uploads_downloads_and_writes_keep_the_subject_binding() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let alice = issued(&state, "alice", "read write");
	let bob = issued(&state, "bob", "read write");
	let app = router(state);
	let (status, blob) = request(
		&app,
		"POST",
		"/jmap/upload/bob",
		&bob,
		json!({"payload": true}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let path = format!(
		"/jmap/download/bob/{}/file.json",
		blob["blobId"].as_str().unwrap()
	);
	assert_eq!(
		request(&app, "GET", &path, &alice, Value::Null).await.0,
		StatusCode::NOT_FOUND
	);
	assert_eq!(
		response(
			&app,
			"GET",
			&path,
			Some(&bob),
			"application/json",
			String::new()
		)
		.await
		.status(),
		StatusCode::OK
	);
	assert_eq!(
		request(&app, "POST", "/jmap/upload/bob", &alice, json!({}))
			.await
			.0,
		StatusCode::NOT_FOUND
	);
	let foreign = call(
		&app,
		&alice,
		"Mailbox/set",
		json!({"accountId": "bob", "create": {"m": {"name": "private"}}}),
	)
	.await;
	assert_eq!(foreign[1]["type"], "accountNotFound");
	let own = call(
		&app,
		&alice,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {"m": {"name": "private"}}}),
	)
	.await;
	assert!(own[1]["created"]["m"]["id"].is_string());
}

#[tokio::test]
async fn static_and_api_key_authentication_keep_working_with_oauth_enabled() {
	let dir = tempfile::tempdir().unwrap();
	let oauth_state = world(dir.path());
	let token = issued(&oauth_state, "alice", "read");
	let secret = crate::test_support::fixtures::api_key();
	crate::api::ApiKeyStore::open(dir.path())
		.unwrap()
		.add(crate::api::ApiKey {
			grants: Vec::new(),
			label: "operator".into(),
			hash: crate::api::api_keys::sha256_hash(secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".into()],
			domains: Vec::new(),
			account: None,
			auto_submitted: false,
		})
		.unwrap();
	use base64::Engine;
	let authz = crate::api::oauth::AuthzServer::new(
		&base64::engine::general_purpose::STANDARD
			.encode(&oauth_state.authz().unwrap().signing_key),
		&oauth_state.authz().unwrap().issuer,
		&oauth_state.authz().unwrap().audience,
	)
	.unwrap();
	let base = crate::api::tests::base::test_state(dir.path(), 0);
	let without_oauth = router(base);
	assert_eq!(
		request(&without_oauth, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::UNAUTHORIZED
	);
	let app = router(crate::api::tests::base::test_state(dir.path(), 0).with_authz(authz));
	for credential in [crate::test_support::fixtures::api_token(), secret] {
		assert_eq!(
			request(&app, "GET", "/api/v1/accounts", credential, Value::Null)
				.await
				.0,
			StatusCode::OK
		);
	}
	assert_eq!(
		request(&app, "GET", "/jmap/session", &token, Value::Null)
			.await
			.0,
		StatusCode::OK
	);
}
