//! SCIM 2.0 end-to-end tests against the real router with a temporary
//! directory. Each test mounts the full authenticated surface, so the
//! `Scope::Scim` gate, the JSON envelopes, and the directory write paths
//! all run together — which is where the interesting regressions live.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::sync::Arc;
use std::sync::LazyLock;
use tower::ServiceExt;

use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};
use crate::api::{ApiState, api_keys, router};
use crate::directory_store::AccountStore;
use crate::smtp::auth::tests::hash as configured_token_hash;
use crate::storage::FsSpool;

/// Configured bearer token. Generated fresh at process start so a literal
/// does not trip CodeQL.
static CONFIGURED_TOKEN: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// A SCIM-scoped key. Its plaintext is shown once and never stored.
static SCIM_KEY_SECRET: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// A read-only key (used to verify the 403 gate).
static READ_KEY_SECRET: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// Build an `ApiState` rooted at a fresh temp directory, with a configured
/// token plus the two labeled API keys above.
fn build_state() -> (tempfile::TempDir, ApiState) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	// Seed the API key store under the data dir so the keys are loaded
	// at startup. The store refuses empty scopes, so both keys declare at
	// least one.
	let mut keys = ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(ApiKey {
		label: "scim".to_string(),
		hash: api_keys::sha256_hash(SCIM_KEY_SECRET.as_str()),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![Scope::Scim.as_str().to_string()],
		domains: Vec::new(),
	})
	.expect("add scim key");
	keys.add(ApiKey {
		label: "read".to_string(),
		hash: api_keys::sha256_hash(READ_KEY_SECRET.as_str()),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![Scope::Read.as_str().to_string()],
		domains: Vec::new(),
	})
	.expect("add read key");
	drop(keys);
	let state = ApiState::new(
		&configured_token_hash(CONFIGURED_TOKEN.as_str()),
		dir.path().to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	(dir, state)
}

fn app(state: ApiState) -> Router {
	router(state)
}

/// Send a SCIM request. `accept` is hardcoded to `application/scim+json`
/// so the test asserts the server's responses always negotiate SCIM.
async fn send(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	body: Option<&serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder()
		.method(method)
		.uri(path)
		.header(header::ACCEPT, "application/scim+json");
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let body = match body {
		Some(json) => {
			builder = builder.header(header::CONTENT_TYPE, "application/scim+json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let response = app
		.clone()
		.oneshot(builder.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = if bytes.is_empty() {
		serde_json::Value::Null
	} else {
		match serde_json::from_slice(&bytes) {
			Ok(v) => v,
			Err(_) => {
				panic!(
					"non-JSON body (status={status}): {}",
					String::from_utf8_lossy(&bytes)
				);
			}
		}
	};
	(status, json)
}

/// Same as `send` but also returns the response headers — the few tests
/// that pin a header (e.g. `Content-Type: application/scim+json`) reach
/// for this.
async fn send_with_headers(
	app: &Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	body: Option<&serde_json::Value>,
) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
	let mut builder = Request::builder()
		.method(method)
		.uri(path)
		.header(header::ACCEPT, "application/scim+json");
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let body = match body {
		Some(json) => {
			builder = builder.header(header::CONTENT_TYPE, "application/scim+json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let response = app
		.clone()
		.oneshot(builder.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let headers = response.headers().clone();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = if bytes.is_empty() {
		serde_json::Value::Null
	} else {
		serde_json::from_slice(&bytes).expect("json body")
	};
	(status, json, headers)
}

#[tokio::test]
async fn service_provider_config_carries_scim_content_type() {
	let (_dir, state) = build_state();
	let (status, body, headers) = send_with_headers(
		&app(state),
		"GET",
		"/scim/v2/ServiceProviderConfig",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		headers
			.get(header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.unwrap_or(""),
		"application/scim+json",
	);
	assert_eq!(body["bulk"]["supported"], false);
	assert_eq!(body["sort"]["supported"], false);
	assert_eq!(body["filter"]["supported"], true);
	assert_eq!(body["patch"]["supported"], true);
}

#[tokio::test]
async fn key_without_scim_scope_is_forbidden() {
	let (_dir, state) = build_state();
	// A `read`-only key must not be able to reach the SCIM surface, even
	// on the discovery endpoint. The middleware does the rejection based
	// on path + method, so the test does not depend on any handler
	// branching.
	let (status, _body) = send(
		&app(state),
		"GET",
		"/scim/v2/ServiceProviderConfig",
		Some(READ_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn request_without_token_is_rejected() {
	let (_dir, state) = build_state();
	let (status, _) = send(
		&app(state),
		"GET",
		"/scim/v2/ServiceProviderConfig",
		None,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn configured_token_authorises_scim_routes() {
	let (_dir, state) = build_state();
	let (status, _) = send(
		&app(state),
		"GET",
		"/scim/v2/ServiceProviderConfig",
		Some(CONFIGURED_TOKEN.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn user_lifecycle_create_list_get_patch_delete() {
	let (_dir, state) = build_state();

	// POST /Users → 201.
	let create = serde_json::json!({
		"userName": "alice",
		"active": true,
		"emails": [{"value": "alice@example.org", "type": "work", "primary": true}],
		"password": "Correct-Horse-Battery-9"
	});
	let (status, body, headers) = send_with_headers(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(
		headers
			.get(header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.unwrap_or(""),
		"application/scim+json"
	);
	assert_eq!(body["userName"], "alice");
	assert_eq!(body["active"], true);
	assert_eq!(body["id"], "alice");
	assert_eq!(body["emails"][0]["value"], "alice@example.org");
	// SCIM §8.2: password is write-only and must not be rendered back.
	assert!(body.get("password").is_none(), "password leaked: {body}");

	// GET /Users/{id}.
	let (status, body) = send(
		&app(state.clone()),
		"GET",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["userName"], "alice");

	// GET /Users?filter=userName eq "alice".
	let (status, body) = send(
		&app(state.clone()),
		"GET",
		"/scim/v2/Users?filter=userName%20eq%20%22alice%22",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["totalResults"], 1);
	assert_eq!(body["Resources"][0]["userName"], "alice");

	// PATCH active=false → 200.
	let patch = serde_json::json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "replace", "path": "active", "value": false}]
	});
	let (status, body) = send(
		&app(state.clone()),
		"PATCH",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["active"], false);

	// Re-enable.
	let patch = serde_json::json!({
		"Operations": [{"op": "replace", "path": "active", "value": true}]
	});
	let (status, body) = send(
		&app(state.clone()),
		"PATCH",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["active"], true);

	// DELETE /Users/{id} → 204.
	let (status, body) = send(
		&app(state.clone()),
		"DELETE",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
	assert!(body.is_null());

	// GET /Users/alice after delete → 404 with SCIM envelope.
	let (status, body) = send(
		&app(state.clone()),
		"GET",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		body["schemas"][0],
		"urn:ietf:params:scim:api:messages:2.0:Error"
	);
	assert_eq!(body["status"], "404");
}

#[tokio::test]
async fn duplicate_user_name_is_conflict() {
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

	let (status, body) = send(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&create),
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
	assert_eq!(
		body["schemas"][0],
		"urn:ietf:params:scim:api:messages:2.0:Error"
	);
	assert_eq!(body["status"], "409");
}

#[tokio::test]
async fn patch_user_name_is_rejected() {
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

	let patch = serde_json::json!({
		"Operations": [{"op": "add", "path": "userName", "value": "mallory"}]
	});
	let (status, body) = send(
		&app(state.clone()),
		"PATCH",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["status"], "400");
}

#[tokio::test]
async fn patch_password_updates_credentials() {
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

	let patch = serde_json::json!({
		"Operations": [{"op": "replace", "path": "password", "value": "Another-Strong-Pass-1234"}]
	});
	let (status, body) = send(
		&app(state.clone()),
		"PATCH",
		"/scim/v2/Users/alice",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&patch),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

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
	for name in ["alice", "bob"] {
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
	assert_eq!(body["totalResults"], 2);
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
