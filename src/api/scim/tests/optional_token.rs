//! Every SCIM route remains reachable by a scoped key without a static token.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn scim_routes_accept_a_labelled_key_without_a_static_token() {
	let dir = tempfile::tempdir().unwrap();
	let secret = crate::test_fixtures::api_key();
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).unwrap();
	keys.add(crate::api::ApiKey {
		label: "provisioner".into(),
		hash: crate::api::api_keys::sha256_hash(secret),
		scopes: vec!["scim".into()],
		expires_at: None,
		ip_cidr: None,
		domains: Vec::new(),
		account: None,
	})
	.unwrap();
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir.path(),
			vec!["example.org".into()],
			Default::default(),
			Vec::new(),
		)
		.unwrap(),
	);
	let app = crate::api::router(crate::api::ApiState::new_with_optional_token(
		None,
		dir.path().into(),
		vec!["example.org".into()],
		store,
		crate::storage::FsSpool::open(dir.path()).unwrap(),
	));
	for (method, path, expected) in [
		("GET", "ServiceProviderConfig", StatusCode::OK),
		("GET", "Schemas", StatusCode::OK),
		("GET", "ResourceTypes", StatusCode::OK),
		("GET", "Users", StatusCode::OK),
		("POST", "Users", StatusCode::CREATED),
		("GET", "Users/missing", StatusCode::NOT_FOUND),
		("PUT", "Users/missing", StatusCode::NOT_FOUND),
		("PATCH", "Users/missing", StatusCode::NOT_FOUND),
		("DELETE", "Users/missing", StatusCode::NOT_FOUND),
		("GET", "Groups", StatusCode::NOT_IMPLEMENTED),
		("POST", "Groups", StatusCode::NOT_IMPLEMENTED),
		("GET", "Groups/missing", StatusCode::NOT_IMPLEMENTED),
		("PUT", "Groups/missing", StatusCode::NOT_IMPLEMENTED),
		("PATCH", "Groups/missing", StatusCode::NOT_IMPLEMENTED),
		("DELETE", "Groups/missing", StatusCode::NOT_IMPLEMENTED),
	] {
		for token in [None, Some(secret)] {
			let mut request = Request::builder()
				.method(method)
				.uri(format!("/scim/v2/{path}"))
				.header("Content-Type", "application/scim+json");
			if let Some(token) = token {
				request = request.header("Authorization", format!("Bearer {token}"));
			}
			let response = app
				.clone()
				.oneshot(
					request
						.body(Body::from(
							r#"{"userName":"probe","active":true,"emails":[{"value":"probe@example.org"}],"Operations":[]}"#,
						))
						.unwrap(),
				)
				.await
				.unwrap();
			assert_eq!(
				response.status(),
				if token.is_some() {
					expected
				} else {
					StatusCode::UNAUTHORIZED
				},
				"{method} {path}"
			);
		}
	}
}
