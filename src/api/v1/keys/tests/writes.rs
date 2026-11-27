//! Making and revoking keys: what is returned, what is stored, what the
//! running server sees at once, and the audit.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::{StatusCode, header};
use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::fixture::*;

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
async fn a_new_key_is_returned_once_works_at_once_and_is_never_listed_with_its_secret() {
	let world = world();
	let (status, headers, body) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		token(),
		Some(json!({"label": "ci", "scopes": ["read"], "domains": ["a.example"], "expires_in": "30d", "auto_submitted": true})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
	let secret = body["key"].as_str().expect("the key").to_string();
	assert_eq!(secret.len(), 52);
	assert_eq!(body["scopes"], json!(["read"]));
	assert_eq!(body["domains"], json!(["a.example"]));
	assert_eq!(body["auto_submitted"], true);
	assert!(body["expires_at"].as_u64().unwrap() > 0);
	// The secret opens the API at once, without waiting for the watcher.
	let (status, _, _) = call(&world.state, "GET", "/api/v1/domains", &secret, None).await;
	assert_eq!(status, StatusCode::OK);
	// What is stored is its digest and nothing else of it.
	let text = std::fs::read_to_string(world.dir.path().join("api_keys.toml")).unwrap();
	assert!(!text.contains(&secret));
	assert!(text.contains(&crate::api::api_keys::sha256_hash(&secret)));
	// A listing shows the key and neither the secret nor the digest.
	let (_, headers, listing) = call(&world.state, "GET", "/api/v1/keys", token(), None).await;
	let shown = listing.to_string();
	assert!(
		!shown.contains(&secret) && !shown.contains("sha256"),
		"{shown}"
	);
	assert!(shown.contains("\"ci\""));
	assert!(
		headers.get(header::CACHE_CONTROL).is_none() || headers[header::CACHE_CONTROL] != "public"
	);
}

#[tokio::test]
async fn a_label_is_made_once() {
	let world = world();
	let body = json!({"label": "ci", "scopes": ["read"]});
	let (status, _, _) = call(
		&world.state,
		"POST",
		"/api/v1/keys",
		MAKER,
		Some(body.clone()),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
	let (status, _, reply) = call(&world.state, "POST", "/api/v1/keys", MAKER, Some(body)).await;
	assert_eq!(status, StatusCode::CONFLICT, "{reply}");
}

#[tokio::test]
async fn a_revoked_key_stops_working_at_once() {
	let world = world();
	let (status, _, _) = call(&world.state, "GET", "/api/v1/domains", OF_A, None).await;
	assert_eq!(status, StatusCode::OK);
	let (status, _, body) = call(&world.state, "DELETE", "/api/v1/keys/of-a", token(), None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["revoked"], "of-a");
	let (status, _, _) = call(&world.state, "GET", "/api/v1/domains", OF_A, None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert!(!labels(&world).contains(&"of-a".to_string()));
}

#[tokio::test]
async fn every_change_is_audited_once_with_its_key_and_never_with_a_secret() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	let secret = async {
		for (method, path, body, bearer) in [
			// Refused: no scope, escalation, invalid, not there.
			(
				"POST",
				"/api/v1/keys",
				Some(json!({"label": "x", "scopes": ["read"]})),
				PLAIN,
			),
			(
				"POST",
				"/api/v1/keys",
				Some(json!({"label": "x", "scopes": ["write"]})),
				MAKER_A,
			),
			(
				"POST",
				"/api/v1/keys",
				Some(json!({"label": "x", "scopes": []})),
				MAKER,
			),
			("DELETE", "/api/v1/keys/nobody", None, MAKER),
			("DELETE", "/api/v1/keys/of-b", None, MAKER_A),
		] {
			call(&world.state, method, path, bearer, body).await;
		}
		let (_, _, made) = call(
			&world.state,
			"POST",
			"/api/v1/keys",
			MAKER_A,
			Some(json!({"label": "child", "scopes": ["read"], "domains": ["a.example"]})),
		)
		.await;
		call(&world.state, "DELETE", "/api/v1/keys/child", MAKER_A, None).await;
		made["key"].as_str().unwrap().to_string()
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.0.lock().unwrap().clone();
	let kinds: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
	assert_eq!(kinds, ["key.created", "key.revoked"], "{events:?}");
	assert_eq!(events[0]["key"], "maker-a");
	assert_eq!(events[0]["subject"], "child");
	assert_eq!(events[0]["scopes"], "read");
	let text = format!("{events:?}");
	for hidden in [secret.as_str(), MAKER, MAKER_A, PLAIN, "sha256"] {
		assert!(!text.contains(hidden), "the audit carries {hidden}");
	}
}

/// Many requests for one label: one key, one line.
#[tokio::test]
async fn concurrent_creations_of_one_label_make_one_key() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let dispatch = tracing::Dispatch::new(Registry::default().with(capture.clone()));
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..12 {
		let state = world.state.clone();
		tasks.spawn(
			async move {
				call(
					&state,
					"POST",
					"/api/v1/keys",
					MAKER,
					Some(json!({"label": "race", "scopes": ["read"]})),
				)
				.await
				.0
			}
			.with_subscriber(dispatch.clone()),
		);
	}
	let mut created = 0;
	while let Some(status) = tasks.join_next().await {
		if status.unwrap() == StatusCode::CREATED {
			created += 1;
		}
	}
	assert_eq!(created, 1);
	assert_eq!(
		labels(&world)
			.iter()
			.filter(|label| *label == "race")
			.count(),
		1
	);
	assert_eq!(capture.0.lock().unwrap().len(), 1);
}
