//! Shared setup for the hostile event-source tests: two accounts, three
//! credentials, and a client that reads an event stream with no deadline of
//! its own (an event source is long-lived by design).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde_json::Value;

use crate::api::api_keys::{ApiKey, ApiKeyStore, Scope};
use crate::api::tests::hostile_wire::Peer;
use crate::api::{ApiState, router};
use crate::directory_store::AccountStore;
use crate::storage::FsSpool;

/// The configured static token: every scope, and its own caller.
pub(super) static TOKEN: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// A `read`-scoped key bound to `alice`.
pub(super) static READ_KEY: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// A `write`-scoped key bound to `alice`: it may not open a stream.
pub(super) static WRITE_KEY: LazyLock<String> = LazyLock::new(|| uuid::Uuid::now_v7().to_string());

/// Every type, the stream stays open, and a ping every second so a server
/// that is still serving the stream is visible from the wire.
pub(super) const LIVE: &str = "types=*&closeafter=no&ping=1";

/// The server under test: two accounts and three credentials.
pub(super) fn state(dir: &Path) -> ApiState {
	let accounts = ["alice", "carol"].map(|name| crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@example.org")],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	});
	let store = Arc::new(
		AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			HashMap::new(),
			accounts.to_vec(),
		)
		.expect("store"),
	);
	let mut keys = ApiKeyStore::open(dir).expect("key store");
	keys.add(key("read", READ_KEY.as_str(), &[Scope::Read], "alice"))
		.expect("add read key");
	keys.add(key("write", WRITE_KEY.as_str(), &[Scope::Write], "alice"))
		.expect("add write key");
	drop(keys);
	for name in ["alice", "carol"] {
		std::fs::create_dir_all(dir.join("accounts").join(name)).expect("mkdir");
	}
	let spool = FsSpool::open(dir).expect("spool");
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
}

/// One labeled API key.
fn key(label: &str, secret: &str, scopes: &[Scope], account: &str) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes
			.iter()
			.map(|scope| scope.as_str().to_string())
			.collect(),
		domains: Vec::new(),
		account: Some(account.to_string()),
	}
}

/// The server on a loopback port, with the whole authenticated router.
pub(super) async fn peer(state: ApiState) -> Peer {
	Peer::start(router(state)).await
}

/// A client with no timeout: an event stream outlives any request deadline.
pub(super) fn client() -> reqwest::Client {
	reqwest::Client::builder()
		.no_proxy()
		.redirect(reqwest::redirect::Policy::none())
		.build()
		.expect("event-source client")
}

/// `GET /jmap/eventsource?{query}` with `token` as the bearer.
pub(super) async fn open(
	client: &reqwest::Client,
	base: &str,
	token: Option<&str>,
	query: &str,
) -> reqwest::Response {
	let mut request = client.get(format!("{base}/jmap/eventsource?{query}"));
	if let Some(token) = token {
		request = request.bearer_auth(token);
	}
	request.send().await.expect("event-source response")
}

/// Open a stream, waiting for the server to give back a slot it still
/// holds (a socket closed a moment ago is noticed on the next write).
/// Fails when no slot comes back within `limit`.
pub(super) async fn open_when_free(
	client: &reqwest::Client,
	base: &str,
	token: &str,
	query: &str,
	limit: Duration,
) -> reqwest::Response {
	let deadline = tokio::time::Instant::now() + limit;
	loop {
		let response = open(client, base, Some(token), query).await;
		if response.status() == axum::http::StatusCode::OK {
			return response;
		}
		assert!(
			tokio::time::Instant::now() < deadline,
			"no event-source slot came back within {limit:?}"
		);
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

/// An open event source, read one event at a time.
pub(super) struct Stream {
	response: reqwest::Response,
	buffer: String,
}

impl Stream {
	/// Take the response of an opened stream.
	pub(super) fn new(response: reqwest::Response) -> Self {
		Self {
			response,
			buffer: String::new(),
		}
	}

	/// The next event as (name, data), `None` when the stream ended.
	pub(super) async fn next_event(&mut self) -> Option<(String, Value)> {
		loop {
			if let Some(event) = self.take_event() {
				return Some(event);
			}
			let chunk = self.response.chunk().await.expect("stream bytes")?;
			self.buffer.push_str(&String::from_utf8_lossy(&chunk));
		}
	}

	/// The next event, or `None` when none arrives within `limit`.
	pub(super) async fn next_event_within(&mut self, limit: Duration) -> Option<(String, Value)> {
		tokio::time::timeout(limit, self.next_event())
			.await
			.ok()
			.flatten()
	}

	/// The first complete event in the buffer, skipping comments.
	fn take_event(&mut self) -> Option<(String, Value)> {
		loop {
			let end = self.buffer.find("\n\n")?;
			let block = self.buffer[..end].to_string();
			self.buffer.drain(..end + 2);
			let mut name = None;
			let mut data = Vec::new();
			for line in block.lines() {
				if line.starts_with(':') {
					continue;
				}
				if let Some(value) = line.strip_prefix("event:") {
					name = Some(value.trim().to_string());
				} else if let Some(value) = line.strip_prefix("data:") {
					data.push(value.trim().to_string());
				}
			}
			let (Some(name), false) = (name, data.is_empty()) else {
				continue;
			};
			return Some((
				name,
				serde_json::from_str(&data.join("\n")).expect("event data is JSON"),
			));
		}
	}
}
