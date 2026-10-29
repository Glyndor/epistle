//! SCIM `displayName` is the account's display name: stored on create,
//! replaced by PUT and PATCH, returned as given, and never the identifier.

use axum::http::StatusCode;

use super::base::*;

async fn call(
	state: &crate::api::state::ApiState,
	method: &str,
	path: &str,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	send(
		&app(state.clone()),
		method,
		path,
		Some(SCIM_KEY_SECRET.as_str()),
		body.as_ref(),
	)
	.await
}

#[tokio::test]
async fn display_name_round_trips_through_create_put_and_patch() {
	let (_dir, state) = build_state();
	let user = |display: &str| {
		serde_json::json!({
			"userName": "dana",
			"displayName": display,
			"active": true,
			"emails": [{"value": "dana@example.org"}],
		})
	};
	let (status, body) = call(&state, "POST", "/scim/v2/Users", Some(user("Dana ÖZTÜRK"))).await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["displayName"], "Dana ÖZTÜRK");
	let (_, body) = call(&state, "GET", "/scim/v2/Users/dana", None).await;
	assert_eq!(body["displayName"], "Dana ÖZTÜRK");
	assert_eq!(
		state.store().display_name("dana").as_deref(),
		Some("Dana ÖZTÜRK")
	);

	let (status, body) = call(&state, "PUT", "/scim/v2/Users/dana", Some(user("Dana Ö."))).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["displayName"], "Dana Ö.");

	let patch = serde_json::json!({
		"Operations": [{"op": "replace", "path": "displayName", "value": "D. Öztürk"}]
	});
	let (status, body) = call(&state, "PATCH", "/scim/v2/Users/dana", Some(patch)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["displayName"], "D. Öztürk");
	assert_eq!(
		state.store().display_name("dana").as_deref(),
		Some("D. Öztürk")
	);
}

#[tokio::test]
async fn without_a_display_name_the_identifier_is_not_shown_as_one() {
	let (_dir, state) = build_state();
	let user = serde_json::json!({
		"userName": "erin",
		"active": true,
		"emails": [{"value": "erin@example.org"}],
	});
	let (status, body) = call(&state, "POST", "/scim/v2/Users", Some(user)).await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body.get("displayName"), None, "{body}");
}
