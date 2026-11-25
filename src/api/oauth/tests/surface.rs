//! The OAuth routes are a surface of their own: mounted where it is asked for,
//! and only with a signing key.

use super::base::{keys, state_with_authz};
use crate::api::{Surface, Surfaces, router_for};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn token_status(app: &axum::Router) -> StatusCode {
	let request = Request::builder()
		.method("POST")
		.uri("/oauth/token")
		.header("content-type", "application/x-www-form-urlencoded")
		.body(Body::from("grant_type=authorization_code"))
		.expect("request");
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

#[tokio::test]
async fn oauth_listener_takes_oauth_off_jmap_and_api() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let off = router_for(
		state.clone(),
		&Surfaces::only(&[Surface::Manage, Surface::Jmap, Surface::Scim]),
	);
	// Not mounted, so the bearer check answers, as for any path nobody serves.
	assert_eq!(token_status(&off).await, StatusCode::UNAUTHORIZED);
	let on = router_for(state, &Surfaces::only(&[Surface::Oauth]));
	let status = token_status(&on).await;
	assert!(
		status.is_client_error()
			&& status != StatusCode::UNAUTHORIZED
			&& status != StatusCode::NOT_FOUND,
		"the grant endpoint answers a bad grant itself: {status}"
	);
}

#[tokio::test]
async fn no_signing_key_no_oauth_routes_on_any_listener() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = crate::api::tests::base::test_state(dir.path(), 0);
	let app = router_for(state, &Surfaces::only(&[Surface::Oauth]));
	assert_eq!(
		token_status(&app).await,
		StatusCode::UNAUTHORIZED,
		"not mounted"
	);
}
