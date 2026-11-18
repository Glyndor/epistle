//! `/api/v1/auth/verify` (the panel's sign-in) refuses an account whose
//! credentials were reset exactly as it refuses a wrong password, admin or
//! not, until the account is given a new password.

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::directory_store::ResetTarget;
use crate::directory_store::credential_reset::hash_digest;
use crate::test_support::fixtures;

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::state::ApiState;

async fn verify(app: &axum::Router, password: &str) -> Value {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		Some(json!({"name": "ops@example.org", "password": password})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body
}

fn reset(state: &ApiState) {
	let store = state.store();
	let digest = hash_digest(&store.dynamic_account("ops").unwrap().password_hash);
	let secret = crate::queue::srs::generate_secret().expect("random bytes");
	let placeholder = crate::smtp::auth::hash_password(&secret).unwrap();
	let targets = [ResetTarget {
		name: "ops".to_string(),
		digest,
	}];
	assert_eq!(
		store.reset_credentials(&targets, &placeholder).unwrap(),
		["ops"]
	);
}

#[tokio::test]
async fn a_reset_admin_is_refused_like_a_wrong_password_until_it_has_a_new_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0).with_admins(vec!["ops".to_string()]);
	let app = router(state.clone());
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TOKEN.as_str()),
		Some(json!({
			"name": "ops",
			"addresses": ["ops@example.org"],
			"password": fixtures::password(),
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(verify(&app, fixtures::password()).await["valid"], true);

	reset(&state);
	let wrong = verify(&app, fixtures::wrong_password()).await;
	assert_eq!(wrong["valid"], false);
	assert_eq!(verify(&app, fixtures::password()).await, wrong);

	let (status, body) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/ops/password",
		Some(TOKEN.as_str()),
		Some(json!({ "password": fixtures::second_password() })),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let admitted = verify(&app, fixtures::second_password()).await;
	assert_eq!(admitted["valid"], true);
	assert_eq!(admitted["admin"], true);
	assert_eq!(verify(&app, fixtures::password()).await, wrong);
}
