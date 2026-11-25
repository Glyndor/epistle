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

/// The commit runs on a blocking thread that outlives the request. A client
/// that goes away after the commit started must still leave the audit line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_dropped_while_the_commit_runs_still_leaves_its_audit_line() {
	crate::cli::trace::capture::keep_callsites_live();
	for (method, path, body, event) in [
		(
			"POST",
			"/api/v1/domains",
			Some(json!({"domain":"new.example"})),
			"domain.added",
		),
		(
			"POST",
			"/api/v1/domains/a.example/aliases",
			Some(json!({"alias":"fresh.example"})),
			"domain.alias_added",
		),
		(
			"PUT",
			"/api/v1/domains/a.example",
			Some(json!({"role":"send-only"})),
			"domain.updated",
		),
		(
			"POST",
			"/api/v1/domains/a.example/disable",
			None,
			"domain.disabled",
		),
		(
			"DELETE",
			"/api/v1/domains/a.example/aliases/alias.example",
			None,
			"domain.alias_removed",
		),
		(
			"DELETE",
			"/api/v1/domains/new.example",
			None,
			"domain.removed",
		),
	] {
		let world = world();
		let capture = Capture::default();
		let subscriber = Registry::default().with(capture.clone());
		if path == "/api/v1/domains/new.example" {
			// A domain nobody uses, so that its removal is allowed.
			let (status, _) = call(
				&world,
				"POST",
				"/api/v1/domains",
				WRITER,
				Some(json!({"domain":"new.example"})),
			)
			.await;
			assert!(status.is_success());
		}
		let domains = crate::domain::state::path(world.state.data_dir());
		let before = std::fs::read(&domains).ok();
		let held =
			crate::storage::lock::FileLock::acquire(&crate::storage::locked::lock_path(&domains))
				.expect("lock");
		let state = world.state.clone();
		let request = tokio::spawn(
			async move {
				crate::api::tests::base::request_with_body(
					&crate::api::router(state),
					method,
					path,
					Some(WRITER),
					body,
				)
				.await
			}
			.with_subscriber(subscriber),
		);
		tokio::time::sleep(std::time::Duration::from_millis(400)).await;
		request.abort();
		assert!(request.await.expect_err("dropped").is_cancelled());
		assert!(capture.0.lock().unwrap().is_empty());
		drop(held);
		let mut written = false;
		for _ in 0..100 {
			if std::fs::read(&domains).ok() != before && capture.0.lock().unwrap().len() == 1 {
				written = true;
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(50)).await;
		}
		assert!(written, "{path}: the change and its line both arrive");
		let events = capture.0.lock().unwrap().clone();
		assert_eq!(events[0]["event"], event, "{events:?}");
	}
}
