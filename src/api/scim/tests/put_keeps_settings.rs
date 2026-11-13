//! `PUT /Users/{id}` replaces the attributes SCIM models. The settings it
//! does not model (quota, forwards, catch-all, the `Sent` copy and the send
//! and receive switches) stay as they were.

use axum::http::StatusCode;

use super::base::*;
use crate::directory_store::Switch;

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

fn user(active: bool) -> serde_json::Value {
	serde_json::json!({
		"userName": "frank",
		"active": active,
		"emails": [{"value": "frank@example.org"}],
		"password": crate::smtp::auth::tests::base::fixture_password(),
	})
}

#[tokio::test]
async fn put_keeps_the_settings_it_does_not_name() {
	let (_dir, state) = build_state();
	let (status, body) = call(&state, "POST", "/scim/v2/Users", Some(user(true))).await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let store = state.store();
	store
		.set_quota_bytes("frank", Some(5_000_000))
		.expect("quota");
	store
		.add_forward("frank", "away@elsewhere.example")
		.expect("forward");
	store
		.add_catch_all("frank", "example.org")
		.expect("catch-all");
	store.set_save_sent("frank", false).expect("save_sent");
	store
		.set_switch("frank", Switch::Send, false)
		.expect("send");
	store
		.set_switch("frank", Switch::Receive, false)
		.expect("receive");

	let (status, body) = call(&state, "PUT", "/scim/v2/Users/frank", Some(user(false))).await;
	assert_eq!(status, StatusCode::OK, "{body}");

	let kept = store.dynamic_account("frank").expect("account");
	assert!(kept.disabled, "the PUT still applies what it names");
	assert_eq!(kept.quota_bytes, Some(5_000_000));
	assert_eq!(kept.forward, vec!["away@elsewhere.example".to_string()]);
	assert_eq!(kept.catch_all, vec!["example.org".to_string()]);
	assert_eq!(kept.save_sent, Some(false));
	assert_eq!(kept.send, Some(false));
	assert_eq!(kept.receive, Some(false));
}

/// The password a PUT carries is the one stored afterwards.
#[tokio::test]
async fn put_stores_the_password_it_carries() {
	let (_dir, state) = build_state();
	let (status, body) = call(&state, "POST", "/scim/v2/Users", Some(user(true))).await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	let next = format!("{}-next", uuid::Uuid::now_v7());
	let mut replacement = user(true);
	replacement["password"] = serde_json::json!(next);
	let (status, body) = call(&state, "PUT", "/scim/v2/Users/frank", Some(replacement)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let stored = state.store().dynamic_account("frank").expect("account");
	assert!(crate::smtp::auth::verify_password(
		&stored.password_hash,
		&next
	));
}
