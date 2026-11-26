//! One audit line per durable change, naming the key and never the bearer;
//! a refusal and a change that changed nothing write none.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::fixture::*;

/// The audit events seen, and a permit for each one, so that a test waits for
/// an event and not for a time.
#[derive(Clone)]
pub(super) struct Capture(
	Arc<Mutex<Vec<BTreeMap<String, String>>>>,
	Arc<tokio::sync::Semaphore>,
);

impl Default for Capture {
	fn default() -> Self {
		Capture(Arc::default(), Arc::new(tokio::sync::Semaphore::new(0)))
	}
}

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
			self.1.add_permits(1);
		}
	}
}

impl Capture {
	pub(super) fn events(&self) -> Vec<BTreeMap<String, String>> {
		self.0.lock().unwrap().clone()
	}

	/// Wait for one more event. The limit is only there so that a lost signal
	/// fails the test and does not hang it.
	pub(super) async fn next(&self) {
		tokio::time::timeout(std::time::Duration::from_secs(60), self.1.acquire())
			.await
			.expect("an audit line was written")
			.expect("open")
			.forget();
	}
}

#[tokio::test]
async fn every_change_is_audited_once_with_its_key_and_the_rest_is_silent() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	world
		.store
		.preload_ban("pair:alice@example.org|203.0.113.9", u64::MAX / 2);
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	async {
		let steps = [
			// Refused: wider than a key may name, junk, not there.
			(
				"POST",
				"/api/v1/bans",
				Some(json!({"target": "10.0.0.0/8"})),
				BANNER,
			),
			(
				"POST",
				"/api/v1/bans",
				Some(json!({"target": "nope"})),
				BANNER,
			),
			("DELETE", "/api/v1/bans/203.0.113.77", None, BANNER),
			("DELETE", "/api/v1/bans/allow/10.9.0.0%2F16", None, BANNER),
			// Refused for the key: no scope, confined.
			(
				"POST",
				"/api/v1/bans",
				Some(json!({"target": "203.0.113.5"})),
				READER,
			),
			(
				"POST",
				"/api/v1/bans",
				Some(json!({"target": "203.0.113.5"})),
				CONFINED,
			),
			// Changes.
			(
				"POST",
				"/api/v1/bans",
				Some(json!({"target": "203.0.113.9"})),
				BANNER,
			),
			(
				"POST",
				"/api/v1/bans/allow",
				Some(json!({"cidr": "10.9.0.0/16"})),
				BANNER,
			),
			// Nothing changed: the block is already there.
			(
				"POST",
				"/api/v1/bans/allow",
				Some(json!({"cidr": "10.9.0.0/16"})),
				BANNER,
			),
			("DELETE", "/api/v1/bans/allow/10.9.0.0%2F16", None, BANNER),
			(
				"DELETE",
				"/api/v1/bans/pair%3Aalice%40example.org%7C203.0.113.9",
				None,
				token(),
			),
		];
		for (method, path, body, key) in steps {
			call(&world, method, path, key, body).await;
		}
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.events();
	let kinds: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
	assert_eq!(
		kinds,
		[
			"ban.added",
			"ban.allow_added",
			"ban.allow_removed",
			"ban.removed"
		],
		"{events:?}"
	);
	assert_eq!(events[0]["key"], "banner");
	assert_eq!(events[0]["subject"], "ip:203.0.113.9");
	assert_eq!(events[3]["key"], "configured-token");
	let text = format!("{events:?}");
	for secret in [BANNER, READER, CONFINED, token()] {
		assert!(!text.contains(secret), "the audit carries a bearer");
	}
	assert!(
		!text.contains("alice@example.org"),
		"an account is written as the pseudonym the logs use: {text}"
	);
	assert!(events[3]["subject"].starts_with("pair:acct-"), "{events:?}");
}

/// Many requests for the same block at once: it joins the list once and the
/// audit says so once.
#[tokio::test]
async fn concurrent_adds_of_one_block_are_audited_once() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let dispatch = tracing::Dispatch::new(Registry::default().with(capture.clone()));
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..16 {
		let state = world.state.clone();
		let task = async move {
			let app = crate::api::router(state);
			crate::api::tests::base::request_with_body(
				&app,
				"POST",
				"/api/v1/bans/allow",
				Some(BANNER),
				Some(json!({"cidr": "10.7.0.0/16"})),
			)
			.await
			.0
		};
		tasks.spawn(task.with_subscriber(dispatch.clone()));
	}
	let mut created = 0;
	while let Some(status) = tasks.join_next().await {
		if status.expect("task") == axum::http::StatusCode::CREATED {
			created += 1;
		}
	}
	assert_eq!(created, 1, "exactly one request added the block");
	assert_eq!(world.store.allowed(), ["10.7.0.0/16"]);
	assert_eq!(capture.events().len(), 1, "{:?}", capture.events());
}

/// A client that goes away after the change was made leaves the change and
/// its line: the two are made on a task the request does not own.
///
/// The store holds each write after it was made, so the order is the one the
/// test fixes: the write is made, the request is dropped while the write is
/// held, and only then is the write let go and its line expected.
#[tokio::test]
async fn a_request_dropped_after_the_write_still_leaves_its_line() {
	crate::cli::trace::capture::keep_callsites_live();
	let cases: [(&str, &str, Option<serde_json::Value>, &str); 4] = [
		(
			"POST",
			"/api/v1/bans",
			Some(json!({"target": "203.0.113.9"})),
			"ban.added",
		),
		("DELETE", "/api/v1/bans/198.51.100.7", None, "ban.removed"),
		(
			"POST",
			"/api/v1/bans/allow",
			Some(json!({"cidr": "10.8.0.0/16"})),
			"ban.allow_added",
		),
		(
			"DELETE",
			"/api/v1/bans/allow/10.9.0.0%2F16",
			None,
			"ban.allow_removed",
		),
	];
	for (method, path, body, expected) in cases {
		let world = world();
		world.store.preload_ban("ip:198.51.100.7", u64::MAX / 2);
		world.store.allow_entries(["10.9.0.0/16".to_string()]);
		let held = world.store.hold_writes();
		let capture = Capture::default();
		let dispatch = tracing::Dispatch::new(Registry::default().with(capture.clone()));
		let state = world.state.clone();
		let request = tokio::spawn(
			async move {
				let world = World {
					_dir: tempfile::tempdir().unwrap(),
					state,
					store: Arc::new(Default::default()),
				};
				call(&world, method, path, BANNER, body).await
			}
			.with_subscriber(dispatch.clone()),
		);
		held.written().await;
		assert!(!world.store.writes().is_empty(), "{path}: not made");
		assert!(!request.is_finished(), "{path}: answered while held");
		assert!(capture.events().is_empty(), "{path}: a line came first");
		request.abort();
		assert!(request.await.expect_err("dropped").is_cancelled());
		held.resume();
		capture.next().await;
		let events = capture.events();
		assert_eq!(events.len(), 1, "{path}: {events:?}");
		assert_eq!(events[0]["event"], expected, "{path}");
	}
}
