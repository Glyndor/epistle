//! One audit line per durable change, naming the key and never the bearer;
//! a dry run, a no-op and a refusal write none.

use super::fixture::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

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

#[tokio::test]
async fn every_change_is_audited_once_with_its_key_and_the_rest_is_silent() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	async {
		let steps = [
			(
				"POST",
				"/api/v1/aliases",
				Some(json!({"alias":"new@a.example","members":["ann@a.example"],"dry_run":true})),
				TENANT_A,
			),
			(
				"POST",
				"/api/v1/aliases",
				Some(json!({"alias":"new@a.example","members":["ghost@a.example"]})),
				TENANT_A,
			),
			(
				"POST",
				"/api/v1/aliases",
				Some(json!({"alias":"new@a.example","members":["ann@a.example"]})),
				TENANT_A,
			),
			(
				"POST",
				"/api/v1/aliases",
				Some(json!({"alias":"new@a.example","members":["ann@a.example"]})),
				TENANT_A,
			),
			(
				"DELETE",
				"/api/v1/aliases/new@a.example?dry_run=true",
				None,
				TENANT_A,
			),
			("DELETE", "/api/v1/aliases/crew@b.example", None, TENANT_A),
			("DELETE", "/api/v1/aliases/new@a.example", None, token()),
		];
		for (method, path, body, key) in steps {
			call(&world, method, path, key, body).await;
		}
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.0.lock().unwrap().clone();
	let kinds: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
	assert_eq!(kinds, ["alias.added", "alias.removed"], "{events:?}");
	assert_eq!(events[0]["key"], "tenant-a");
	assert_eq!(events[0]["domain"], "a.example");
	assert_eq!(events[1]["key"], "configured-token");
	let text = format!("{events:?}");
	for secret in [TENANT_A, token(), "new@a.example"] {
		assert!(!text.contains(secret), "the audit carries {secret}");
	}
}
