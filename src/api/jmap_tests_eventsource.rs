//! JMAP push over an event source (RFC 8620 §7.3): the Session advertises a
//! URL template with `types`, `closeafter` and `ping`, and the route behind it
//! streams `state` events for the caller's own accounts, `ping` events when
//! idle, and ends once the credential stops being valid.

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::body::{Body, BodyDataStream};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use std::pin::Pin;
use std::time::Duration;
use tower::ServiceExt;

const ALICE: &str = "alice-es-secret";
const CAROL: &str = "carol-es-secret";
const SENDER: &str = "sender-es-secret";

fn key(label: &str, secret: &str, scopes: &[&str], account: &str) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|s| s.to_string()).collect(),
		domains: Vec::new(),
		account: Some(account.to_string()),
	}
}

/// `alice` (static) and `carol` (dynamic), a read/write key bound to each and
/// a send-only key bound to alice.
fn es_state(dir: &std::path::Path) -> crate::api::ApiState {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	keys.add(key("alice", ALICE, &["read", "write"], "alice"))
		.expect("add key");
	keys.add(key("carol", CAROL, &["read", "write"], "carol"))
		.expect("add key");
	keys.add(key("sender", SENDER, &["send"], "alice"))
		.expect("add key");
	drop(keys);
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
		})
		.expect("add carol");
	for account in ["alice", "carol"] {
		std::fs::create_dir_all(dir.join("accounts").join(account)).expect("mkdir");
	}
	state
}

async fn open(app: &axum::Router, token: &str, query: &str) -> (StatusCode, Body) {
	let request = Request::builder()
		.uri(format!("/jmap/eventsource?{query}"))
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.body(Body::empty())
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	(response.status(), response.into_body())
}

/// The next event as (name, data), `None` once the stream ended.
async fn next_event(stream: &mut BodyDataStream) -> Option<(String, Value)> {
	use futures_core::Stream;
	let chunk = tokio::time::timeout(
		Duration::from_secs(5),
		std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)),
	)
	.await
	.expect("nothing within 5s")?
	.expect("body chunk");
	let text = String::from_utf8(chunk.to_vec()).expect("utf-8");
	let field = |name: &str| {
		text.lines()
			.find_map(|line| line.strip_prefix(name))
			.map(str::to_string)
	};
	let data = field("data: ").expect("data line");
	Some((
		field("event: ").expect("event line"),
		serde_json::from_str(&data).expect("data is JSON"),
	))
}

async fn create_mailbox(app: &axum::Router, account: &str) {
	let body = json!({ "methodCalls": [[
		"Mailbox/set", { "accountId": account, "create": { "n": { "name": "Work" } } }, "c"
	]] });
	let (_, reply) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(body)).await;
	assert!(
		reply["methodResponses"][0][1]["created"]["n"].is_object(),
		"{reply}"
	);
}

/// What `Email/get`, `Mailbox/get` and `Thread/get` report as alice's state.
async fn alice_states(app: &axum::Router) -> Value {
	let body = json!({ "methodCalls": [
		["Email/get", { "accountId": "alice", "ids": [] }, "e"],
		["Mailbox/get", { "accountId": "alice", "ids": [] }, "m"],
		["Thread/get", { "accountId": "alice", "ids": [] }, "t"],
	] });
	let (_, reply) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(body)).await;
	let state = |i: usize| reply["methodResponses"][i][1]["state"].clone();
	json!({ "Email": state(0), "Mailbox": state(1), "Thread": state(2) })
}

#[tokio::test]
async fn the_session_advertises_the_event_source_template() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(ALICE)).await;
	assert_eq!(
		session["eventSourceUrl"],
		"/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}"
	);
}

#[tokio::test]
async fn a_change_is_pushed_for_the_callers_own_account_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let (status, body) = open(&app, ALICE, "types=*&closeafter=state&ping=0").await;
	assert_eq!(status, StatusCode::OK);
	let mut stream = body.into_data_stream();
	create_mailbox(&app, "carol").await;
	create_mailbox(&app, "alice").await;
	let (name, data) = next_event(&mut stream).await.expect("a state event");
	assert_eq!(name, "state");
	assert_eq!(
		data,
		json!({ "@type": "StateChange", "changed": { "alice": alice_states(&app).await } })
	);
	assert!(
		next_event(&mut stream).await.is_none(),
		"closeafter=state ends the response after the state event"
	);
}

#[tokio::test]
async fn only_the_types_asked_for_are_pushed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let (_, body) = open(
		&app,
		ALICE,
		"types=Mailbox,CalendarEvent&closeafter=state&ping=0",
	)
	.await;
	let mut stream = body.into_data_stream();
	create_mailbox(&app, "alice").await;
	let (_, data) = next_event(&mut stream).await.expect("a state event");
	let states = alice_states(&app).await;
	assert_eq!(
		data["changed"],
		json!({ "alice": { "Mailbox": states["Mailbox"] } })
	);
}

#[tokio::test]
async fn an_idle_stream_pings_at_the_interval_asked_for() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let (_, body) = open(&app, ALICE, "types=*&closeafter=no&ping=1").await;
	let mut stream = body.into_data_stream();
	let event = next_event(&mut stream).await.expect("a ping");
	assert_eq!(event, ("ping".to_string(), json!({ "interval": 1 })));
}

#[tokio::test]
async fn disabling_the_account_ends_its_stream() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = es_state(dir.path());
	let app = router(state.clone());
	let (_, body) = open(&app, CAROL, "types=*&closeafter=no&ping=1").await;
	let mut stream = body.into_data_stream();
	assert_eq!(next_event(&mut stream).await.expect("a ping").0, "ping");
	state
		.store()
		.set_disabled("carol", true)
		.expect("disable carol");
	let mut after = Vec::new();
	while let Some((name, _)) = next_event(&mut stream).await {
		after.push(name);
		assert!(after.len() < 3, "still streaming after disable: {after:?}");
	}
}

#[tokio::test]
async fn losing_the_read_scope_ends_the_stream() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = es_state(dir.path());
	let app = router(state.clone());
	let (_, body) = open(&app, ALICE, "types=*&closeafter=no&ping=1").await;
	let mut stream = body.into_data_stream();
	assert_eq!(next_event(&mut stream).await.expect("a ping").0, "ping");
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.remove("alice").expect("remove key");
	keys.add(key("alice", ALICE, &["write"], "alice"))
		.expect("re-add key");
	let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
	let mut after = Vec::new();
	while let Some((name, _)) = next_event(&mut stream).await {
		after.push(name);
		assert!(after.len() < 3, "still streaming without read: {after:?}");
	}
}

#[tokio::test]
async fn the_event_source_needs_read_and_valid_arguments() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let (status, _) = open(&app, SENDER, "types=*&closeafter=no&ping=0").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED, "a send-only key");
	for query in [
		"types=*&closeafter=maybe&ping=0",
		"types=*&closeafter=no&ping=soon",
		"types=Email,,Mailbox&closeafter=no&ping=0",
	] {
		let (status, _) = open(&app, ALICE, query).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
	}
}

#[tokio::test]
async fn one_caller_holds_a_bounded_number_of_streams() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(es_state(dir.path()));
	let max = crate::api::jmap::event_source::MAX_STREAMS_PER_CALLER;
	let mut held = Vec::new();
	for _ in 0..max {
		let (status, body) = open(&app, ALICE, "types=*&closeafter=no&ping=0").await;
		assert_eq!(status, StatusCode::OK);
		held.push(body);
	}
	let (status, _) = open(&app, ALICE, "types=*&closeafter=no&ping=0").await;
	assert_eq!(
		status,
		StatusCode::TOO_MANY_REQUESTS,
		"a caller past the cap must be refused"
	);
	let (status, _carol) = open(&app, CAROL, "types=*&closeafter=no&ping=0").await;
	assert_eq!(status, StatusCode::OK, "the cap is per caller");
	held.pop();
	let (status, _) = open(&app, ALICE, "types=*&closeafter=no&ping=0").await;
	assert_eq!(status, StatusCode::OK, "a closed stream frees its slot");
}
