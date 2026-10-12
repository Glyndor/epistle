//! A key bound to one account stops reaching anything over HTTP once that
//! account is disabled or removed: every JMAP endpoint and `/api/v1/send`
//! answer it with the same 403 `forbidden` the WebSocket gives a frame sent
//! after the account went away. Re-enabling the account restores it.

use super::tests::{request, request_with_body, test_state};
use super::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

const CAROL: &str = "carol-http-secret";

/// `test_state` plus `carol`, a dynamic account (so she can be disabled or
/// removed) with a key bound to her holding every account scope.
fn state_with_carol(dir: &std::path::Path) -> ApiState {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "carol-key".to_string(),
			hash: crate::api::api_keys::sha256_hash(CAROL),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".into(), "write".into(), "send".into()],
			domains: Vec::new(),
			account: Some("carol".to_string()),
		})
		.expect("add key");
	drop(key_store);
	let state = test_state(dir, 0);
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "carol".to_string(),
			addresses: vec!["carol@example.org".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
		})
		.expect("add carol");
	state
}

/// Upload a small JSON blob as carol while she is enabled, for the download
/// checks.
async fn upload_blob(app: &axum::Router) -> String {
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/upload/carol",
		Some(CAROL),
		Some(json!({ "blob": true })),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "upload while enabled");
	body["blobId"].as_str().expect("blobId").to_string()
}

/// The status and error code of every account-scoped route carol's key uses.
async fn reach(app: &axum::Router, blob: &str) -> Vec<(String, StatusCode, Value)> {
	let mut seen = Vec::new();
	for path in ["/jmap/session", "/.well-known/jmap"] {
		let (status, body) = request(app, "GET", path, Some(CAROL)).await;
		seen.push((path.to_string(), status, body["error"]["code"].clone()));
	}
	let download = format!("/jmap/download/carol/{blob}/b.json");
	let (status, body) = request(app, "GET", &download, Some(CAROL)).await;
	seen.push((download, status, body["error"]["code"].clone()));
	let calls = [
		(
			"/jmap/api",
			json!({
				"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
				"methodCalls": [["Mailbox/get", { "accountId": "carol" }, "c1"]],
			}),
		),
		("/jmap/upload/carol", json!({ "blob": true })),
		(
			"/api/v1/send",
			json!({
				"from": "carol@example.org",
				"to": ["someone@elsewhere.example"],
				"subject": "hi",
				"text": "hello",
			}),
		),
	];
	for (path, payload) in calls {
		let (status, body) = request_with_body(app, "POST", path, Some(CAROL), Some(payload)).await;
		seen.push((path.to_string(), status, body["error"]["code"].clone()));
	}
	seen
}

fn assert_all_served(seen: &[(String, StatusCode, Value)], when: &str) {
	for (path, status, _) in seen {
		assert_eq!(*status, StatusCode::OK, "{when}: {path} must be served");
	}
}

fn assert_all_refused(seen: &[(String, StatusCode, Value)], when: &str) {
	for (path, status, code) in seen {
		assert_eq!(
			*status,
			StatusCode::FORBIDDEN,
			"{when}: {path} must refuse the key"
		);
		assert_eq!(code, "forbidden", "{when}: {path} error code");
	}
}

#[tokio::test]
async fn disabling_the_account_refuses_its_key_on_every_http_route() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let blob = upload_blob(&app).await;
	assert_all_served(&reach(&app, &blob).await, "enabled");

	state
		.store()
		.set_disabled("carol", true)
		.expect("disable carol");
	assert_all_refused(&reach(&app, &blob).await, "disabled");

	state
		.store()
		.set_disabled("carol", false)
		.expect("enable carol");
	assert_all_served(&reach(&app, &blob).await, "re-enabled");
}

#[tokio::test]
async fn removing_the_account_refuses_its_key_on_every_http_route() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let blob = upload_blob(&app).await;
	assert_all_served(&reach(&app, &blob).await, "present");

	state.store().remove("carol").expect("remove carol");
	assert_all_refused(&reach(&app, &blob).await, "removed");
}
