//! A quota is written only if the key, read again under the account store's
//! lock, is still one that may write it: still there, still holding the scope,
//! still confined to nothing, not expired and still admitting the network the
//! client is in. Each case holds the lock, waits until the request is stopped
//! at it, changes the key and lets go.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::super::base::{TOKEN, test_state};
use super::held_commit::{held_at_the_lock, until_waiting};
use super::*;
use crate::api::api_keys::ApiKey;
use crate::directory_store::DynamicAccount;

const SECRET: &str = "held-quota-secret";
const PRIOR_QUOTA: u64 = 4096;
const NEW_QUOTA: u64 = 2 << 30;
/// The client the requests come from.
const PEER: &str = "10.1.2.3:40000";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.0.insert(field.name().into(), format!("{value:?}"));
	}
	fn record_str(&mut self, field: &Field, value: &str) {
		self.0.insert(field.name().into(), value.into());
	}
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
		if event.metadata().target() == "epistle::api::audit" {
			let mut fields = Fields::default();
			event.record(&mut fields);
			self.0.lock().unwrap().push(fields.0);
		}
	}
}

impl Capture {
	fn events(&self) -> Vec<BTreeMap<String, String>> {
		self.0.lock().unwrap().clone()
	}
}

/// The key `k` as the requests are admitted with it: `manage:write`, confined
/// to nothing, limited to a network the client is in.
fn admitted() -> ApiKey {
	ApiKey {
		label: "k".to_string(),
		hash: crate::api::api_keys::sha256_hash(SECRET),
		expires_at: None,
		ip_cidr: Some("10.0.0.0/8".to_string()),
		scopes: vec!["manage:write".to_string()],
		grants: Vec::new(),
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	}
}

/// Write `k` as `key` and reload the key set as the watcher does.
fn put_key(state: &crate::api::ApiState, dir: &Path, key: ApiKey) {
	let mut store = crate::api::ApiKeyStore::open(dir).expect("key store");
	let _ = store.remove("k");
	store.add(key).expect("add key");
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
}

fn world(dir: &Path) -> crate::api::ApiState {
	let state = test_state(dir, 0);
	state
		.store()
		.add(DynamicAccount {
			name: "dyna".to_string(),
			addresses: vec!["dyna@example.org".to_string()],
			password_hash: "$argon2id$prior".to_string(),
			quota_bytes: Some(PRIOR_QUOTA),
			..DynamicAccount::default()
		})
		.expect("add dyna");
	put_key(&state, dir, admitted());
	state
}

/// `PUT` (a new quota) or `DELETE` of the quota of `dyna`, from [`PEER`].
fn request(method: &str, bearer: &str) -> Request<Body> {
	let body = match method {
		"PUT" => Body::from(r#"{"quota":"2G"}"#),
		_ => Body::empty(),
	};
	let mut request = Request::builder()
		.method(method)
		.uri("/api/v1/accounts/dyna/quota")
		.header(header::AUTHORIZATION, format!("Bearer {bearer}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(body)
		.expect("request");
	let peer: SocketAddr = PEER.parse().expect("peer");
	request.extensions_mut().insert(ConnectInfo(peer));
	request
}

fn quota(state: &crate::api::ApiState) -> Option<u64> {
	state.store().dynamic("dyna").expect("dyna").quota_bytes
}

/// What the key may have become by the time the write is made, none of which
/// may write a quota.
fn changed() -> Vec<(&'static str, ApiKey)> {
	let mut confined = admitted();
	confined.domains = vec!["example.org".to_string()];
	let mut bound = admitted();
	bound.account = Some("dyna".to_string());
	bound.scopes = vec!["mail:write".to_string()];
	let mut narrowed = admitted();
	narrowed.scopes = vec!["manage:read".to_string()];
	let mut expired = admitted();
	expired.expires_at = Some(1);
	let mut moved = admitted();
	moved.ip_cidr = Some("192.0.2.0/24".to_string());
	let mut replaced = admitted();
	replaced.hash = crate::api::api_keys::sha256_hash("another secret");
	vec![
		("confined to a domain", confined),
		("bound to an account", bound),
		("without the scope", narrowed),
		("expired", expired),
		("limited to another network", moved),
		("replaced", replaced),
	]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_changed_before_the_write_sets_no_quota_and_writes_no_line() {
	crate::cli::trace::capture::keep_callsites_live();
	// Every case is tried before judging, so a failure names all that went on.
	let mut went_on = Vec::new();
	for method in ["PUT", "DELETE"] {
		for (what, key) in changed() {
			let dir = tempfile::tempdir().expect("tempdir");
			let state = world(dir.path());
			let capture = Capture::default();
			let status = held_at_the_lock(&state, request(method, SECRET), || {
				put_key(&state, dir.path(), key);
			})
			.with_subscriber(Registry::default().with(capture.clone()))
			.await;
			if status != StatusCode::NOT_FOUND
				|| quota(&state) != Some(PRIOR_QUOTA)
				|| !capture.events().is_empty()
			{
				went_on.push(format!("{method}, {what}: {status}"));
			}
		}
	}
	assert!(went_on.is_empty(), "writes that went on: {went_on:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_may_still_write_sets_the_quota_after_waiting() {
	crate::cli::trace::capture::keep_callsites_live();
	// A network that still holds the client, an expiry still to come, and the
	// key as it was.
	let mut smaller = admitted();
	smaller.ip_cidr = Some("10.1.0.0/16".to_string());
	let mut expiring = admitted();
	expiring.expires_at = Some(u64::MAX >> 1);
	for method in ["PUT", "DELETE"] {
		for key in [admitted(), smaller.clone(), expiring.clone()] {
			let dir = tempfile::tempdir().expect("tempdir");
			let state = world(dir.path());
			let capture = Capture::default();
			let status = held_at_the_lock(&state, request(method, SECRET), || {
				put_key(&state, dir.path(), key);
			})
			.with_subscriber(Registry::default().with(capture.clone()))
			.await;
			assert_eq!(status, StatusCode::OK, "{method}");
			assert_eq!(capture.events().len(), 1, "{method}");
			assert_eq!(
				quota(&state),
				(method == "PUT").then_some(NEW_QUOTA),
				"{method}"
			);
		}
		// The configured token asks no key file.
		let dir = tempfile::tempdir().expect("tempdir");
		let state = world(dir.path());
		let status = held_at_the_lock(&state, request(method, TOKEN.as_str()), || {}).await;
		assert_eq!(status, StatusCode::OK, "{method} with the token");
	}
}

/// The write and its line are made together even when the client goes away
/// while the write waits for the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_goes_away_leaves_the_quota_written_and_recorded() {
	crate::cli::trace::capture::keep_callsites_live();
	let dir = tempfile::tempdir().expect("tempdir");
	let state = world(dir.path());
	let capture = Capture::default();
	let lock = crate::storage::locked::lock_path(state.store().store_path());
	let held = crate::storage::lock::FileLock::acquire(&lock).expect("hold the lock");
	let app = router(state.clone());
	let answer = tokio::spawn(
		app.oneshot(request("PUT", SECRET))
			.with_subscriber(Registry::default().with(capture.clone())),
	);
	until_waiting(&lock).await;
	answer.abort();
	assert!(answer.await.expect_err("aborted").is_cancelled());
	drop(held);
	for _ in 0..3000 {
		if !capture.events().is_empty() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let events = capture.events();
	assert_eq!(events.len(), 1, "{events:?}");
	assert_eq!(events[0]["event"], "account.quota_set");
	assert_eq!(events[0]["key"], "k");
	assert_eq!(events[0]["client_ip"], "10.1.2.3");
	assert_eq!(quota(&state), Some(NEW_QUOTA));
}
