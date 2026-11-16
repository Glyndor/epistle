//! Fixtures: a server with two tenants, five credentials, a reader for the
//! event stream and a way to make each kind of change.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, BodyDataStream};
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use crate::api::api_keys::{ApiKey, ApiKeyStore};
use crate::api::{ApiState, EventLimits, router};
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;

/// Reads everything, confined to nothing.
pub(super) const ADMIN: &str = "admin-events-secret";
/// Reads, confined to `a.example`.
pub(super) const TENANT_A: &str = "tenant-a-events-secret";
/// Reads, confined to `b.example`.
pub(super) const TENANT_B: &str = "tenant-b-events-secret";
/// May write but not read.
pub(super) const WRITE_ONLY: &str = "write-events-secret";
/// Reads, bound to the account `alice`.
pub(super) const BOUND: &str = "bound-events-secret";

/// Limits that make the stream fast enough to test: the heartbeat, the
/// sampling window and the look all in tens of milliseconds.
pub(super) fn fast() -> EventLimits {
	EventLimits {
		sample: Duration::from_millis(40),
		look: Duration::from_millis(20),
		heartbeat: Duration::from_millis(150),
		..EventLimits::default()
	}
}

fn key(label: &str, secret: &str, scope: &str, domains: &[&str], account: Option<&str>) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![scope.to_string()],
		domains: domains.iter().map(|d| d.to_string()).collect(),
		account: account.map(str::to_string),
		auto_submitted: false,
	}
}

fn account(name: &str, address: &str) -> crate::config::Account {
	crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	}
}

/// Two domains with an account each, and the five credentials.
pub(super) fn state(dir: &Path, limits: EventLimits) -> ApiState {
	let store = Arc::new(
		AccountStore::open(
			dir,
			vec!["a.example".to_string(), "b.example".to_string()],
			HashMap::new(),
			vec![
				account("alice", "alice@a.example"),
				account("bob", "bob@b.example"),
			],
		)
		.expect("store"),
	);
	let mut keys = ApiKeyStore::open(dir).expect("key store");
	for key in [
		key("admin", ADMIN, "read", &[], None),
		key("tenant-a", TENANT_A, "read", &["a.example"], None),
		key("tenant-b", TENANT_B, "read", &["b.example"], None),
		key("write", WRITE_ONLY, "write", &[], None),
		key("bound", BOUND, "read", &[], Some("alice")),
	] {
		keys.add(key).expect("add key");
	}
	drop(keys);
	let spool = FsSpool::open(dir).expect("spool");
	ApiState::new(
		&crate::smtp::auth::tests::base::hash("static-token-unused"),
		dir.to_path_buf(),
		vec!["a.example".to_string(), "b.example".to_string()],
		store.clone(),
		spool,
	)
	.with_directory(store.handle())
	.with_delivery_log_days(1)
	.with_event_limits(limits)
}

/// The response of `GET /api/v1/events`.
pub(super) struct Opened {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: Body,
}

/// `GET /api/v1/events` with `token`, asking for a problem answer on failure.
pub(super) async fn open(app: &Router, token: Option<&str>, last_event_id: Option<&str>) -> Opened {
	let mut request = Request::builder().uri("/api/v1/events").header(
		header::ACCEPT,
		"text/event-stream, application/problem+json",
	);
	if let Some(token) = token {
		request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	if let Some(id) = last_event_id {
		request = request.header("last-event-id", id);
	}
	let response = app
		.clone()
		.oneshot(request.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	Opened {
		status: response.status(),
		headers: response.headers().clone(),
		body: response.into_body(),
	}
}

/// Open with `token` and expect a stream.
pub(super) async fn stream(app: &Router, token: &str, last_event_id: Option<&str>) -> Reader {
	let opened = open(app, Some(token), last_event_id).await;
	assert_eq!(opened.status, StatusCode::OK, "opening as {token}");
	Reader::new(opened.body)
}

/// One frame of the stream.
#[derive(Debug, Clone)]
pub(super) struct Frame {
	pub raw: String,
	pub id: Option<String>,
	pub event: Option<String>,
	pub data: Option<serde_json::Value>,
	pub comment: bool,
}

/// What a read of the stream found.
pub(super) enum Got {
	Frame(Frame),
	/// The server ended the stream.
	Ended,
	/// Nothing arrived in time.
	Silent,
}

/// An open stream, read one frame at a time.
pub(super) struct Reader {
	body: BodyDataStream,
	buffer: String,
}

impl Reader {
	pub(super) fn new(body: Body) -> Self {
		Self {
			body: body.into_data_stream(),
			buffer: String::new(),
		}
	}

	/// The next frame, comments included.
	pub(super) async fn next(&mut self, within: Duration) -> Got {
		use futures_core::Stream;
		let deadline = tokio::time::Instant::now() + within;
		loop {
			if let Some(end) = self.buffer.find("\n\n") {
				let raw: String = self.buffer.drain(..end + 2).collect();
				return Got::Frame(parse(raw));
			}
			let chunk = std::future::poll_fn(|cx| Pin::new(&mut self.body).poll_next(cx));
			match tokio::time::timeout_at(deadline, chunk).await {
				Err(_) => return Got::Silent,
				Ok(None) => return Got::Ended,
				Ok(Some(chunk)) => {
					let chunk = chunk.expect("body chunk");
					self.buffer.push_str(&String::from_utf8_lossy(&chunk));
				}
			}
		}
	}

	/// The next event (heartbeat comments skipped), `None` when none came in
	/// time or the stream ended.
	pub(super) async fn event(&mut self, within: Duration) -> Option<Frame> {
		let deadline = tokio::time::Instant::now() + within;
		loop {
			let left = deadline.saturating_duration_since(tokio::time::Instant::now());
			match self.next(left).await {
				Got::Frame(frame) if frame.comment => continue,
				Got::Frame(frame) => return Some(frame),
				Got::Ended | Got::Silent => return None,
			}
		}
	}

	/// The names of the events that arrive within `within`, in order.
	pub(super) async fn names(&mut self, within: Duration) -> Vec<String> {
		self.collect(within)
			.await
			.into_iter()
			.filter_map(|frame| frame.event)
			.collect()
	}

	/// Every event frame that arrives within `within`.
	pub(super) async fn collect(&mut self, within: Duration) -> Vec<Frame> {
		let deadline = tokio::time::Instant::now() + within;
		let mut frames = Vec::new();
		while let Some(frame) = self
			.event(deadline.saturating_duration_since(tokio::time::Instant::now()))
			.await
		{
			frames.push(frame);
		}
		frames
	}

	/// Whether the server ends the stream within `within`, reading and
	/// dropping whatever arrives before.
	pub(super) async fn ends_within(&mut self, within: Duration) -> bool {
		let deadline = tokio::time::Instant::now() + within;
		loop {
			let left = deadline.saturating_duration_since(tokio::time::Instant::now());
			match self.next(left).await {
				Got::Ended => return true,
				Got::Silent => return false,
				Got::Frame(_) => {}
			}
		}
	}
}

fn parse(raw: String) -> Frame {
	let mut frame = Frame {
		raw: raw.clone(),
		id: None,
		event: None,
		data: None,
		comment: false,
	};
	for line in raw.lines() {
		if line.starts_with(':') {
			frame.comment = true;
		} else if let Some(value) = line.strip_prefix("id:") {
			frame.id = Some(value.trim().to_string());
		} else if let Some(value) = line.strip_prefix("event:") {
			frame.event = Some(value.trim().to_string());
		} else if let Some(value) = line.strip_prefix("data:") {
			frame.data = serde_json::from_str(value.trim()).ok();
		}
	}
	frame
}

/// Wait for a stream to be told about the changes the sampler needs a first
/// look to see: give the sampler time to take its baseline.
pub(super) async fn settle() {
	tokio::time::sleep(Duration::from_millis(250)).await;
}

/// How long to wait for an event that should come.
pub(super) const SOON: Duration = Duration::from_secs(5);
/// How long to listen for one that should not.
pub(super) const QUIET: Duration = Duration::from_millis(600);

/// Add an account the way the API does.
pub(super) fn add_account(state: &ApiState, name: &str, address: &str) {
	state
		.store()
		.add(DynamicAccount {
			reset: None,
			rehashed: None,
			send: None,
			receive: None,
			display_name: None,
			name: name.to_string(),
			addresses: vec![address.to_string()],
			password_hash: "$argon2id$secret".to_string(),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			forward: Vec::new(),
			catch_all: Vec::new(),
			save_sent: None,
		})
		.expect("add account");
}

/// Put a message in the queue.
pub(super) fn enqueue(state: &ApiState, from: &str, to: &str) {
	state
		.spool()
		.store(
			&AcceptedMessage {
				reverse_path: from.to_string(),
				recipients: vec![to.to_string()],
				data: b"Subject: private subject\r\n\r\nprivate body\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
}

/// Suppress an address globally.
pub(super) fn suppress(dir: &Path, address: &str) {
	crate::queue::SuppressionList::open(dir)
		.expect("suppression list")
		.suppress(address);
}

/// Write one record to the delivery log.
pub(super) fn log_delivery(dir: &Path, recipient: &str) {
	let log = crate::storage::DeliveryLog::open(dir, 1);
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	log.append(&crate::storage::DeliveryRecord {
		time: now,
		spool_id: uuid::Uuid::now_v7(),
		account: Some("alice".to_string()),
		from: "alice@a.example".to_string(),
		recipient: recipient.to_string(),
		outcome: crate::storage::DeliveryOutcome::Delivered,
		remote: Some("mx.remote.example".to_string()),
		reply: Some("250 queued as secret-queue-id".to_string()),
		attempt: 1,
		extra: BTreeMap::new(),
		class: Default::default(),
	})
	.expect("log");
}

/// The router for `state`.
pub(super) fn app(state: &ApiState) -> Router {
	router(state.clone())
}

/// The reach of a read key confined to `domains`.
pub(super) fn confined(domains: &[&str]) -> crate::api::Principal {
	crate::api::Principal::of_key(&key("tenant", "unused", "read", domains, None), None)
}
