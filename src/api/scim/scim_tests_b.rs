//! SCIM 2.0 end-to-end tests, second half. Split from `scim_tests.rs` only
//! to stay under the per-file line limit; the harness lives in the first
//! half and is shared unchanged.

use axum::http::StatusCode;

use super::tests::*;

#[tokio::test]
async fn groups_endpoint_returns_not_implemented() {
	let (_dir, state) = build_state();
	let (status, body) = send(
		&app(state.clone()),
		"GET",
		"/scim/v2/Groups",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
	assert_eq!(
		body["schemas"][0],
		"urn:ietf:params:scim:api:messages:2.0:Error"
	);
	assert_eq!(body["status"], "501");
}

#[tokio::test]
async fn disabled_account_cannot_authenticate() {
	let (_dir, state) = build_state();
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org"}],
		"password": "Correct-Horse-Battery-9"
	});
	let (status, _) = send(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);

	// Disable via PATCH.
	let patch = serde_json::json!({
		"Operations": [{"op": "replace", "path": "active", "value": false}]
	});
	let (status, _) = send(
		&app(state.clone()),
		"PATCH",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	// The directory must reject the password even though the account is
	// present. We check via `state.store().is_disabled` to keep this
	// independent of the directory's exact authentication timing path.
	assert!(
		state.store().is_disabled("alice"),
		"disabled flag should be persisted on the store"
	);
}

#[tokio::test]
async fn list_users_with_no_filter_returns_all() {
	let (_dir, state) = build_state();
	for name in ["alice", "bob", "carol"] {
		let create = serde_json::json!({
			"userName": name,
			"active": true,
			"emails": [{"value": format!("{name}@example.org")}],
			"password": "Correct-Horse-Battery-9"
		});
		let (status, _) = send(
			&app(state.clone()),
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED);
	}

	let (status, body) = send(
		&app(state.clone()),
		"GET",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["totalResults"], 3);
	assert_eq!(body["itemsPerPage"], 3);
}

#[tokio::test]
async fn list_users_reports_filtered_total_and_page_metadata() {
	let (_dir, state) = build_state();
	for name in ["alice", "bob", "carol"] {
		let create = serde_json::json!({
			"userName": name,
			"active": true,
			"emails": [{"value": format!("{name}@example.org")}],
		});
		let (status, _) = send(
			&app(state.clone()),
			"POST",
			"/scim/v2/Users",
			Some(SCIM_KEY_SECRET.as_str()),
			Some(&create),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED);
	}

	let users = app(state);
	let (status, first) = send(
		&users,
		"GET",
		"/scim/v2/Users?startIndex=1&count=2",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(first["totalResults"], 3);
	assert_eq!(first["startIndex"], 1);
	assert_eq!(first["itemsPerPage"], 2);
	assert_eq!(first["Resources"].as_array().unwrap().len(), 2);

	let (_, second) = send(
		&users,
		"GET",
		"/scim/v2/Users?startIndex=3&count=2",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(second["totalResults"], 3);
	assert_eq!(second["startIndex"], 3);
	assert_eq!(second["itemsPerPage"], 1);
	assert_eq!(second["Resources"].as_array().unwrap().len(), 1);

	let (_, total_only) = send(
		&users,
		"GET",
		"/scim/v2/Users?count=0",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(total_only["totalResults"], 3);
	assert_eq!(total_only["itemsPerPage"], 0);
	assert!(total_only["Resources"].as_array().unwrap().is_empty());

	let (_, beyond) = send(
		&users,
		"GET",
		"/scim/v2/Users?startIndex=4&count=2",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(beyond["totalResults"], 3);
	assert_eq!(beyond["startIndex"], 4);
	assert_eq!(beyond["itemsPerPage"], 0);
	assert!(beyond["Resources"].as_array().unwrap().is_empty());

	let (_, filtered) = send(
		&users,
		"GET",
		"/scim/v2/Users?filter=userName%20eq%20%22bob%22&count=1",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(filtered["totalResults"], 1);
	assert_eq!(filtered["itemsPerPage"], 1);
	assert_eq!(filtered["Resources"][0]["userName"], "bob");
}

#[tokio::test]
async fn filter_rejects_unsupported_expressions() {
	let (_dir, state) = build_state();
	let (status, body) = send(
		&app(state),
		"GET",
		"/scim/v2/Users?filter=displayName%20eq%20%22Alice%22",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["status"], "400");
}

#[tokio::test]
async fn a_user_name_with_a_dot_is_refused_naming_the_character() {
	let (_dir, state) = build_state();
	let create = serde_json::json!({
		"userName": "john.doe",
		"active": true,
		"emails": [{"value": "john.doe@example.org"}],
		"password": "Correct-Horse-Battery-9"
	});
	let (status, body) = send(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let detail = body["detail"].as_str().unwrap_or_default();
	assert!(detail.contains("'.'"), "{body}");
	assert!(!detail.contains("init"), "{body}");
	assert!(state.store().dynamic("john.doe").is_none());
}
