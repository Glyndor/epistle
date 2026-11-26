//! A key bound to one account stops reaching anything over HTTP once that
//! account is disabled or removed: every JMAP endpoint and `/api/v1/send`
//! answer it with the same 403 `forbidden` the WebSocket gives a frame sent
//! after the account went away. Re-enabling the account restores it. A reset
//! of its credentials refuses the key the same way until it has a new password.

use super::base::{request, request_with_body, test_state};
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
			grants: Vec::new(),
			label: "carol-key".to_string(),
			hash: crate::api::api_keys::sha256_hash(CAROL),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".into(), "write".into(), "send".into()],
			domains: Vec::new(),
			account: Some("carol".to_string()),
			auto_submitted: false,
		})
		.expect("add key");
	drop(key_store);
	let state = test_state(dir, 0);
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			send: None,
			receive: None,
			display_name: None,
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
			save_sent: None,
			reset: None,
			rehashed: None,
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

#[tokio::test]
async fn resetting_the_account_refuses_its_key_until_it_has_a_new_password() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let blob = upload_blob(&app).await;
	assert_all_served(&reach(&app, &blob).await, "before the reset");

	let store = state.store();
	let digest = crate::directory_store::credential_reset::hash_digest(
		&store.dynamic_account("carol").unwrap().password_hash,
	);
	let targets = [crate::directory_store::ResetTarget {
		name: "carol".to_string(),
		digest,
	}];
	store
		.reset_credentials(&targets, "$argon2id$placeholder")
		.expect("reset carol");
	assert_all_refused(&reach(&app, &blob).await, "reset");

	store
		.set_password_hash("carol", "$argon2id$new".to_string(), None)
		.expect("new password");
	assert_all_served(&reach(&app, &blob).await, "given a new password");
}

/// A request body the test hands over in pieces: the server has started to
/// read it once `started` fires, and it stays pending until a piece is sent
/// and complete when the sender is dropped.
struct Pending {
	started: Option<tokio::sync::oneshot::Sender<()>>,
	pieces: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl futures_core::Stream for Pending {
	type Item = Result<axum::body::Bytes, std::io::Error>;

	fn poll_next(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Self::Item>> {
		let this = self.get_mut();
		if let Some(started) = this.started.take() {
			let _ = started.send(());
		}
		this.pieces
			.poll_recv(cx)
			.map(|piece| piece.map(|bytes| Ok(axum::body::Bytes::from(bytes))))
	}
}

/// POST `payload` to `path` as carol with the body held back until `change`
/// has run, once the server is reading it; the answer.
async fn post_while(
	app: &axum::Router,
	path: &str,
	payload: Value,
	change: impl FnOnce(),
) -> (StatusCode, Value) {
	use tower::ServiceExt;
	let (started, reading) = tokio::sync::oneshot::channel();
	let (send_piece, pieces) = tokio::sync::mpsc::channel(1);
	let request = axum::http::Request::builder()
		.method("POST")
		.uri(path)
		.header(axum::http::header::AUTHORIZATION, format!("Bearer {CAROL}"))
		.header(axum::http::header::CONTENT_TYPE, "application/json")
		.body(axum::body::Body::from_stream(Pending {
			started: Some(started),
			pieces,
		}))
		.expect("request");
	let app = app.clone();
	let answer = tokio::spawn(async move { app.oneshot(request).await.expect("response") });
	reading
		.await
		.expect("the server never started reading the body");
	change();
	send_piece
		.send(payload.to_string().into_bytes())
		.await
		.expect("send the body");
	drop(send_piece);
	let response = answer.await.expect("the request task");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, serde_json::from_slice(&bytes).expect("json body"))
}

fn create_email() -> Value {
	json!({
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {
			"accountId": "carol",
			"create": {"e": {
				"mailboxIds": {"INBOX": true},
				"from": [{"email": "carol@example.org"}],
				"to": [{"email": "someone@elsewhere.example"}],
				"subject": "held",
			}},
		}, "c1"]],
	})
}

fn send_body() -> Value {
	json!({
		"from": "carol@example.org",
		"to": ["someone@elsewhere.example"],
		"subject": "hi",
		"text": "hello",
	})
}

/// How many messages `carol` holds, asked as the configured token.
async fn mails_of(app: &axum::Router, account: &str) -> usize {
	let request = json!({
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/query", {"accountId": account}, "q"]],
	});
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(super::base::TOKEN.as_str()),
		Some(request),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1]["ids"]
		.as_array()
		.unwrap_or_else(|| panic!("no ids: {body}"))
		.len()
}

fn assert_refused(answer: &(StatusCode, Value), what: &str) {
	assert_eq!(answer.0, StatusCode::FORBIDDEN, "{what}: {}", answer.1);
	assert_eq!(answer.1["error"]["code"], "forbidden", "{what}");
}

#[tokio::test]
async fn a_body_that_is_still_arriving_is_served_when_nothing_changed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_carol(dir.path()));
	let (status, body) = post_while(&app, "/jmap/api", create_email(), || {}).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(body["methodResponses"][0][1]["created"]["e"]["id"].is_string());
	assert_eq!(mails_of(&app, "carol").await, 1);
	let (status, body) = post_while(&app, "/api/v1/send", send_body(), || {}).await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn suspending_the_account_while_its_body_arrives_refuses_the_jmap_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let suspend = || {
		state.store().set_disabled("carol", true).expect("disable");
	};
	let answer = post_while(&app, "/jmap/api", create_email(), suspend).await;
	assert_refused(&answer, "JMAP");
	assert_eq!(mails_of(&app, "carol").await, 0, "nothing was written");
}

#[tokio::test]
async fn suspending_the_account_while_its_body_arrives_refuses_the_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let suspend = || {
		state.store().set_disabled("carol", true).expect("disable");
	};
	let answer = post_while(&app, "/api/v1/send", send_body(), suspend).await;
	assert_refused(&answer, "send");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "nothing was queued");
}

/// The key leaves `api_keys.toml` and the set is reloaded, as the watcher does.
fn revoke_key(state: &ApiState, dir: &std::path::Path) {
	let mut key_store = crate::api::ApiKeyStore::open(dir).expect("key store");
	key_store.remove("carol-key").expect("remove key");
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
}

#[tokio::test]
async fn losing_the_send_scope_while_the_body_arrives_refuses_the_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let answer = post_while(&app, "/api/v1/send", send_body(), || {
		// The key comes back with the scopes it had, less `send`.
		let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
		key_store.remove("carol-key").expect("remove key");
		key_store
			.add(crate::api::api_keys::ApiKey {
				grants: Vec::new(),
				label: "carol-key".to_string(),
				hash: crate::api::api_keys::sha256_hash(CAROL),
				expires_at: None,
				ip_cidr: None,
				scopes: vec!["read".into(), "write".into()],
				domains: Vec::new(),
				account: Some("carol".to_string()),
				auto_submitted: false,
			})
			.expect("add key");
		let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("key file");
		state.api_keys().reload_from(&text).expect("reload keys");
	})
	.await;
	assert_refused(&answer, "send");
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "nothing was queued");
}

#[tokio::test]
async fn revoking_the_key_while_its_body_arrives_refuses_the_request() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let answer = post_while(&app, "/jmap/api", create_email(), || {
		revoke_key(&state, dir.path());
	})
	.await;
	assert_refused(&answer, "JMAP");
	assert_eq!(mails_of(&app, "carol").await, 0, "nothing was written");
}

#[tokio::test]
async fn an_account_replaced_while_the_body_arrives_is_not_written_to() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_carol(dir.path());
	let app = router(state.clone());
	let replace = || {
		// What removing the account does: its keys go, and the name is free
		// for someone else, here with an address of their own.
		revoke_key(&state, dir.path());
		state.store().remove("carol").expect("remove carol");
		state
			.store()
			.add(crate::directory_store::DynamicAccount {
				send: None,
				receive: None,
				display_name: None,
				name: "carol".to_string(),
				addresses: vec!["carol.two@example.org".to_string()],
				password_hash: "$argon2id$secret".to_string(),
				scram: None,
				totp_secret: None,
				disabled: false,
				quota_bytes: None,
				allowed_protocols: None,
				forward: Vec::new(),
				catch_all: Vec::new(),
				save_sent: None,
				reset: None,
				rehashed: None,
			})
			.expect("recreate carol");
	};
	let answer = post_while(&app, "/jmap/api", create_email(), replace).await;
	assert_refused(&answer, "JMAP");
	assert_eq!(
		mails_of(&app, "carol").await,
		0,
		"the new account is untouched"
	);
}
