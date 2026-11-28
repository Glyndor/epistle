//! A removal whose request goes away half way: the removal is finished and
//! recorded, once, whatever the client does. The ban store of the test holds
//! the removal at the wait that follows the removal of the satellites, the
//! step the handler used to be dropped at.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

use super::base::{Capture, CapturedEvent};
use crate::antispam::bans::{BanInfo, BanStore};
use crate::api::account_removal::{Via, spawn_removal};
use crate::api::tests::base::TOKEN;
use crate::api::{ApiState, router};
use crate::directory_store::removal::QueuePolicy;
use crate::directory_store::{AccountStore, DynamicAccount};

type Wait<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A ban store that tells when the removal reaches it and holds the removal
/// there until it is let go.
#[derive(Debug)]
struct Gated {
	entered: tokio::sync::Notify,
	release: tokio::sync::Semaphore,
}

impl Default for Gated {
	fn default() -> Self {
		Self {
			entered: tokio::sync::Notify::new(),
			release: tokio::sync::Semaphore::new(0),
		}
	}
}

impl BanStore for Gated {
	fn record_failure(&self, _: &str, _: &str, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn is_banned(&self, _: &str, _: u64) -> Wait<'_, Option<BanInfo>> {
		Box::pin(async { None })
	}

	fn clear_success(&self, _: &str, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn sweep(&self, _: u64) -> Wait<'_, ()> {
		Box::pin(async {})
	}

	fn remove_account(&self, _: &str) -> Wait<'_, ()> {
		Box::pin(async {
			self.entered.notify_one();
			let _ = self.release.acquire().await;
		})
	}
}

/// A server with one dynamic account, `dana`, whose ban store is `bans`.
fn state(dir: &std::path::Path, bans: Arc<Gated>) -> ApiState {
	let store = Arc::new(
		AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			HashMap::new(),
			Vec::new(),
		)
		.expect("open store")
		.with_ban_store(bans),
	);
	store
		.add(DynamicAccount {
			name: "dana".to_string(),
			addresses: vec!["dana@example.org".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			..DynamicAccount::default()
		})
		.expect("add dana");
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store.clone(),
		crate::storage::FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

/// A `DELETE` request carrying `token`.
fn delete(uri: &str, peer: SocketAddr, token: &str) -> Request<Body> {
	let mut request = Request::builder()
		.method("DELETE")
		.uri(uri)
		.header(header::AUTHORIZATION, format!("Bearer {token}"))
		.body(Body::empty())
		.expect("request");
	request.extensions_mut().insert(ConnectInfo(peer));
	request
}

type Events = Arc<Mutex<Vec<CapturedEvent>>>;

/// Run `body` with the audit events captured, which it can look at while it
/// runs; every event it saw.
fn captured<F: Future<Output = ()>>(body: impl FnOnce(Events) -> F) -> Vec<CapturedEvent> {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = Capture::default();
	let events = Arc::clone(&capture.events);
	let subscriber = tracing_subscriber::Registry::default()
		.with(tracing::level_filters::LevelFilter::INFO)
		.with(capture);
	tokio::task::block_in_place(|| {
		tracing::subscriber::with_default(subscriber, || {
			tokio::runtime::Handle::current().block_on(body(Arc::clone(&events)));
		});
	});
	std::mem::take(&mut *events.lock().expect("events"))
}

fn named<'a>(events: &'a [CapturedEvent], event: &str) -> Vec<&'a CapturedEvent> {
	events
		.iter()
		.filter(|seen| {
			seen.target == "epistle::api::audit"
				&& seen.fields.get("event").map(String::as_str) == Some(event)
		})
		.collect()
}

/// How long a test waits for a line that should already be on its way.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait until `count` audit lines named `event` were written, or the deadline
/// passes.
async fn until_written(events: &Events, event: &str, count: usize) {
	tokio::time::timeout(DEADLINE, async {
		loop {
			if named(&events.lock().expect("events"), event).len() >= count {
				return;
			}
			tokio::time::sleep(std::time::Duration::from_millis(1)).await;
		}
	})
	.await
	.unwrap_or_else(|_| panic!("the {event} line was never written"));
}

/// Start `uri`, let it reach the ban store, drop the request as a client that
/// went away does, then let the removal go and wait for its line.
async fn abandon(state: &ApiState, gate: &Gated, uri: &str, events: &Events, lines: usize) {
	let peer: SocketAddr = "203.0.113.9:40000".parse().expect("peer");
	let mut call = Box::pin(router(state.clone()).oneshot(delete(uri, peer, TOKEN.as_str())));
	tokio::select! {
		() = gate.entered.notified() => {}
		_ = &mut call => panic!("the removal finished without reaching the ban store"),
	}
	drop(call);
	assert!(
		state.store().dynamic("dana").is_some(),
		"the account stays while the removal waits"
	);
	gate.release.add_permits(1);
	until_written(events, "account.removed", lines).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_rest_removal_is_finished_and_recorded_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let gate = Arc::new(Gated::default());
	let state = state(dir.path(), Arc::clone(&gate));
	let events = captured(|events| {
		let (state, gate) = (state.clone(), Arc::clone(&gate));
		async move {
			abandon(
				&state,
				&gate,
				"/api/v1/accounts/dana?queue=discard",
				&events,
				1,
			)
			.await
		}
	});
	assert!(
		state.store().dynamic("dana").is_none(),
		"the account is gone"
	);
	let lines = named(&events, "account.removed");
	assert_eq!(lines.len(), 1, "{events:?}");
	assert_eq!(
		lines[0].fields.get("client_ip").map(String::as_str),
		Some("203.0.113.9")
	);
	assert!(named(&events, "account.removal_incomplete").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_scim_removal_is_finished_and_recorded_as_before() {
	let dir = tempfile::tempdir().expect("tempdir");
	let gate = Arc::new(Gated::default());
	let state = state(dir.path(), Arc::clone(&gate));
	let events = captured(|events| {
		let (state, gate) = (state.clone(), Arc::clone(&gate));
		async move { abandon(&state, &gate, "/scim/v2/Users/dana", &events, 2).await }
	});
	assert!(
		state.store().dynamic("dana").is_none(),
		"the account is gone"
	);
	// SCIM writes the privilege line and the one with the counts: two, as it
	// always has, not more.
	let lines = named(&events, "account.removed");
	assert_eq!(lines.len(), 2, "{events:?}");
	assert_eq!(
		lines
			.iter()
			.filter(|line| line.fields.contains_key("mailbox_files"))
			.count(),
		1
	);
}

/// A removal that fails after it has cleared part of the footprint is recorded
/// as what it is, and the account is still there to be removed again.
#[tokio::test(flavor = "multi_thread")]
async fn a_removal_that_stops_half_way_is_recorded_as_incomplete() {
	let dir = tempfile::tempdir().expect("tempdir");
	let gate = Arc::new(Gated::default());
	gate.release.add_permits(1);
	let state = state(dir.path(), Arc::clone(&gate));
	// The keys bound to the account are revoked near the end, after the
	// satellites are gone: a key file that cannot be read stops it there.
	std::fs::create_dir(dir.path().join("api_keys.toml")).expect("directory in place of the file");
	let events = captured(|_| async {
		let peer: SocketAddr = "203.0.113.9:40000".parse().expect("peer");
		let response = router(state.clone())
			.oneshot(delete(
				"/api/v1/accounts/dana?queue=discard",
				peer,
				TOKEN.as_str(),
			))
			.await
			.expect("response");
		assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
	});
	assert!(
		state.store().dynamic("dana").is_some(),
		"the account remains"
	);
	assert_eq!(
		named(&events, "account.removal_incomplete").len(),
		1,
		"{events:?}"
	);
	assert!(named(&events, "account.removed").is_empty());
}

/// A removal whose task is cancelled after it began leaves the line that
/// says the account may be half removed: nothing else says so, and the
/// operator has to run the removal again.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_removal_task_leaves_the_incomplete_line() {
	let dir = tempfile::tempdir().expect("tempdir");
	let gate = Arc::new(Gated::default());
	let state = state(dir.path(), Arc::clone(&gate));
	let events = captured(|events| {
		let (state, gate) = (state.clone(), Arc::clone(&gate));
		async move {
			let peer: SocketAddr = "203.0.113.9:40000".parse().expect("peer");
			let handle = spawn_removal(
				&state,
				"dana",
				QueuePolicy::Discard,
				Via::Rest,
				Some(peer.ip()),
				|_| true,
			);
			// The removal is under way: the account is reserved and the
			// footprint is being cleared, and the ban store holds it there.
			gate.entered.notified().await;
			// The task is cancelled, the way a runtime that goes down
			// cancels it.
			handle.abort();
			let ended = handle.await.expect_err("the task was cancelled");
			assert!(ended.is_cancelled(), "{ended}");
			until_written(&events, "account.removal_incomplete", 1).await;
		}
	});
	let lines = named(&events, "account.removal_incomplete");
	assert_eq!(lines.len(), 1, "{events:?}");
	assert_eq!(
		lines[0].fields.get("client_ip").map(String::as_str),
		Some("203.0.113.9")
	);
	assert!(
		named(&events, "account.removed").is_empty(),
		"a removal that was cancelled wrote the line of one that finished"
	);
	// The account is still there: the removal can be run again.
	assert!(
		state.store().dynamic("dana").is_some(),
		"the account remains"
	);
}

/// A key that does not reach the route is turned away exactly as it was
/// before, and the account it named is still there.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_without_the_scope_is_turned_away_and_leaves_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = "reader-secret";
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	keys.add(crate::api::ApiKey {
		label: "reader".to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["manage:read".to_string()],
		grants: Vec::new(),
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	drop(keys);
	let gate = Arc::new(Gated::default());
	let state = state(dir.path(), Arc::clone(&gate));
	let events = captured(|_| async {
		let peer: SocketAddr = "203.0.113.9:40000".parse().expect("peer");
		let response = router(state.clone())
			.oneshot(delete("/api/v1/accounts/dana?queue=discard", peer, secret))
			.await
			.expect("response");
		assert_eq!(response.status(), StatusCode::FORBIDDEN);
		let body = axum::body::to_bytes(response.into_body(), usize::MAX)
			.await
			.expect("body");
		assert!(String::from_utf8_lossy(&body).contains("scope"), "{body:?}");
	});
	assert!(
		state.store().dynamic("dana").is_some(),
		"the account remains"
	);
	assert!(named(&events, "account.removed").is_empty());
	assert!(named(&events, "account.removal_incomplete").is_empty());
}
