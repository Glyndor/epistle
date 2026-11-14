use super::*;

#[tokio::test]
async fn both_grants_preserve_scopes_and_redemption_cannot_widen_them() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let app = router(state.clone());
	for token in [
		pkce(&app, Some("read")).await,
		device(&app, "read").await,
		pkce(&app, None).await,
	] {
		let principal = state.oauth_principal(&token, None).unwrap();
		assert!(principal.admits_scope(crate::api::api_keys::Scope::Read));
		assert!(!principal.admits_scope(crate::api::api_keys::Scope::Write));
		assert!(!principal.admits_scope(crate::api::api_keys::Scope::Send));
		for method in ["Mailbox/set", "Email/set", "EmailSubmission/set"] {
			let reply = call(
				&app,
				&token,
				method,
				json!({"accountId": "alice", "create": {}}),
			)
			.await;
			assert_eq!(reply, json!(["error", {"type": "forbidden"}, "c"]));
		}
		assert_eq!(
			request(&app, "POST", "/jmap/upload/alice", &token, json!({}))
				.await
				.0,
			StatusCode::FORBIDDEN
		);
	}
}

#[tokio::test]
async fn invalid_or_admin_scopes_are_never_granted() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(world(dir.path()));
	for scope in [
		"",
		"scim",
		"admin",
		"read+unknown",
		"READ",
		"read++write",
		"read%09write",
	] {
		for (path, prefix) in [
			("/oauth/device_authorization", "client_id=panel".to_owned()),
			(
				"/oauth/authorize",
				format!(
					"client_id=panel&code_challenge_method=S256&code_challenge={}",
					super::super::base::CHALLENGE
				),
			),
		] {
			let (status, body) = form(&app, path, &format!("{prefix}&scope={scope}")).await;
			assert_eq!(status, StatusCode::BAD_REQUEST);
			assert_eq!(body, json!({"error": "invalid_scope"}));
		}
	}
}

#[tokio::test]
async fn write_and_send_do_not_imply_read() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let app = router(state);
	let writer = pkce(&app, Some("write")).await;
	let write = call(
		&app,
		&writer,
		"Mailbox/set",
		json!({"accountId": "alice", "create": {"m": {"name": "Writer"}}}),
	)
	.await;
	assert!(write[1]["created"]["m"]["id"].is_string());
	for token in [writer, device(&app, "send").await] {
		assert_eq!(
			request(&app, "GET", "/jmap/session", &token, Value::Null)
				.await
				.0,
			StatusCode::FORBIDDEN
		);
		let reply = call(
			&app,
			&token,
			"Email/get",
			json!({"accountId": "alice", "ids": []}),
		)
		.await;
		assert_eq!(reply[1]["type"], "forbidden");
	}
}

#[tokio::test]
async fn send_scope_submits_only_as_the_issued_account() {
	let dir = tempfile::tempdir().unwrap();
	let state = world(dir.path());
	let id = uuid::Uuid::now_v7().to_string();
	std::fs::write(dir.path().join("accounts/alice/new").join(format!("{id}.eml")), b"From: alice@example.org\r\nTo: recipient@elsewhere.example\r\nSubject: hello\r\n\r\nbody\r\n").unwrap();
	let app = router(state);
	let args = json!({"accountId": "alice", "create": {"s": {
		"emailId": id, "identityId": "alice@example.org",
		"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": [{"email": "recipient@elsewhere.example"}]}
	}}});
	let reader = pkce(&app, Some("read+write")).await;
	let refused = call(&app, &reader, "EmailSubmission/set", args.clone()).await;
	assert_eq!(refused[1]["type"], "forbidden");
	assert_eq!(state_spool_count(dir.path()), 0);
	let sender = device(&app, "send").await;
	let mut foreign = args.clone();
	foreign["accountId"] = json!("bob");
	assert_eq!(
		call(&app, &sender, "EmailSubmission/set", foreign).await[1]["type"],
		"accountNotFound"
	);
	let sent = call(&app, &sender, "EmailSubmission/set", args).await;
	assert!(sent[1]["created"]["s"]["id"].is_string());
	assert_eq!(state_spool_count(dir.path()), 1);
}

fn state_spool_count(dir: &std::path::Path) -> usize {
	// One message is a `.eml` file and a `.json` envelope beside it.
	std::fs::read_dir(dir.join("spool/new"))
		.map(|entries| {
			entries
				.flatten()
				.filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
				.count()
		})
		.unwrap_or(0)
}

#[tokio::test]
async fn non_string_json_scopes_do_not_fall_back_to_read() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(world(dir.path()));
	for scope in [
		Value::Null,
		json!(123),
		json!(["send"]),
		json!({"read": true}),
	] {
		for path in ["/oauth/authorize", "/oauth/device_authorization"] {
			let (status, body) = request(
				&app,
				"POST",
				path,
				"",
				json!({"client_id": "panel", "scope": scope}),
			)
			.await;
			assert_eq!(status, StatusCode::BAD_REQUEST);
			assert_eq!(body, json!({"error": "invalid_scope"}));
		}
	}
}

#[tokio::test]
async fn a_device_gets_beyond_read_only_what_the_approval_names() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(world(dir.path()));
	let (status, grant) = form(
		&app,
		"/oauth/device_authorization",
		"client_id=panel&scope=read+send",
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(grant["scope"], "read send", "the response names the scopes");
	let approve = |scope: &'static str| {
		let app = app.clone();
		let code = grant["user_code"].as_str().unwrap().to_owned();
		async move {
			let tail = if scope.is_empty() { String::new() } else { format!("&scope={scope}") };
			form(
				&app,
				"/oauth/device/approve",
				&format!(
					"user_code={code}&login=alice@example.org&password={}{tail}",
					crate::test_support::fixtures::password()
				),
			)
			.await
		}
	};
	for wrong in ["", "read", "read+write+send", "send"] {
		let (status, body) = approve(wrong).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "scope {wrong:?}: {body}");
		assert_eq!(body["error"], "invalid_grant");
	}
	let (status, _) = approve("send+read").await;
	assert_eq!(status, StatusCode::OK, "the same set in any order is the approval");
}

#[tokio::test]
async fn a_read_only_device_needs_no_scope_in_the_approval() {
	let dir = tempfile::tempdir().unwrap();
	let app = router(world(dir.path()));
	let (_, grant) = form(&app, "/oauth/device_authorization", "client_id=panel").await;
	assert_eq!(grant["scope"], "read");
	let (status, _) = form(
		&app,
		"/oauth/device/approve",
		&format!(
			"user_code={}&login=alice@example.org&password={}",
			grant["user_code"].as_str().unwrap(),
			crate::test_support::fixtures::password()
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}
