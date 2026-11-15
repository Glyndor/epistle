//! Assert audit output of the full router, including no-op/refusal silence.

use super::fixture::*;
use super::writes::{call, disk};
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
async fn every_domain_change_is_audited_once_without_secrets_and_no_ops_are_silent() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	let secret = async {
		let steps = [
			(
				"POST",
				"/api/v1/domains",
				Some(json!({"domain":"new.example"})),
				"domain.added",
			),
			(
				"PUT",
				"/api/v1/domains/new.example",
				Some(json!({"role":"send-only","quota":42})),
				"domain.updated",
			),
			(
				"POST",
				"/api/v1/domains/new.example/disable",
				None,
				"domain.disabled",
			),
			(
				"POST",
				"/api/v1/domains/new.example/enable",
				None,
				"domain.enabled",
			),
			(
				"POST",
				"/api/v1/domains/new.example/aliases",
				Some(json!({"alias":"new-alias.example"})),
				"domain.alias_added",
			),
			(
				"DELETE",
				"/api/v1/domains/new.example/aliases/new-alias.example",
				None,
				"domain.alias_removed",
			),
			(
				"DELETE",
				"/api/v1/domains/new.example",
				None,
				"domain.removed",
			),
		];
		let mut secret = String::new();
		for (index, (method, path, body, event)) in steps.into_iter().enumerate() {
			let (status, body) = call(&world, method, path, WRITER, body).await;
			assert!(status.is_success(), "{path}: {body}");
			if index == 0 {
				secret = disk(&world)
					.domain("new.example")
					.unwrap()
					.srs_secret
					.clone()
					.unwrap();
			}
			let events = capture.0.lock().unwrap();
			assert_eq!(events.len(), index + 1);
			assert_eq!(events[index]["event"], event);
			assert!(events[index]["domain"].contains("example"));
			assert_eq!(events[index]["client_ip"], "unknown");
		}
		for (method, path, body) in [
			(
				"PUT",
				"/api/v1/domains/a.example",
				Some(json!({"quota":1000})),
			),
			("POST", "/api/v1/domains/a.example/enable", None),
			("POST", "/api/v1/domains/b.example/disable", None),
			(
				"POST",
				"/api/v1/domains",
				Some(json!({"domain":"a.example"})),
			),
			("DELETE", "/api/v1/domains/a.example", None),
		] {
			call(&world, method, path, WRITER, body).await;
		}
		secret
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.0.lock().unwrap();
	assert_eq!(events.len(), 7, "no-op/refusal must not emit change events");
	let blob = format!("{events:?}");
	for value in [
		secret.as_str(),
		WRITER,
		token(),
		"srs_secret",
		"PRIVATE KEY",
		"password_hash",
	] {
		assert!(!blob.contains(value), "audit leaked sensitive material");
	}
}
