//! Setting and clearing the quota of an account: who may, what is stored, what
//! is refused, and the audit. What a key that changes while its request waits
//! may do is in `api::tests::keys::held_quota`.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
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

async fn put(
	world: &World,
	bearer: &str,
	name: &str,
	quota: &str,
) -> (StatusCode, serde_json::Value) {
	call(
		&world.state,
		"PUT",
		&format!("/api/v1/accounts/{name}/quota"),
		bearer,
		Some(json!({"quota": quota})),
	)
	.await
}

async fn clear(world: &World, bearer: &str, name: &str) -> (StatusCode, serde_json::Value) {
	call(
		&world.state,
		"DELETE",
		&format!("/api/v1/accounts/{name}/quota"),
		bearer,
		None,
	)
	.await
}

fn quota_of(world: &World, name: &str) -> Option<u64> {
	world.store.dynamic(name).expect("account").quota_bytes
}

#[tokio::test]
async fn a_quota_is_set_and_cleared_and_the_answer_is_what_the_command_prints() {
	let world = world();
	let (status, body) = put(&world, token(), "alice", "500M").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["action"], "quota");
	assert_eq!(body["quota_bytes"], 500 * 1024 * 1024);
	assert_eq!(quota_of(&world, "alice"), Some(500 * 1024 * 1024));
	let (status, body) = clear(&world, WRITER, "alice").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["quota_bytes"], serde_json::Value::Null);
	assert_eq!(quota_of(&world, "alice"), None);
	// `none` is the same as clearing, as it is for the command.
	put(&world, token(), "alice", "1G").await;
	let (status, _) = put(&world, token(), "alice", "none").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(quota_of(&world, "alice"), None);
}

/// The test the route rule names.
#[tokio::test]
async fn a_confined_key_does_not_set_a_quota_and_learns_nothing_of_the_account() {
	let world = world();
	let mut answers = Vec::new();
	for name in ["alice", "bob", "split", "nobody"] {
		let (status, body) = put(&world, OF_A, name, "1G").await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
		answers.push(body);
		let (status, body) = clear(&world, OF_A, name).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert_eq!(quota_of(&world, "alice"), None);
}

#[tokio::test]
async fn a_key_that_does_not_write_or_is_bound_changes_nothing() {
	let world = world();
	for bearer in [READER, OF_ALICE] {
		let (status, body) = put(&world, bearer, "alice", "1G").await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
		let (status, body) = clear(&world, bearer, "alice").await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	}
	let (status, _) = call(
		&world.state,
		"PUT",
		"/api/v1/accounts/alice/quota",
		"nope",
		Some(json!({"quota": "1G"})),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(quota_of(&world, "alice"), None);
}

#[tokio::test]
async fn a_quota_that_is_not_one_is_refused_to_every_key() {
	let world = world();
	for quota in [
		"",
		" ",
		"10",
		"G",
		"-5G",
		"1.5G",
		"10X",
		"10GB",
		"0",
		"0G",
		"0K",
		"99999999999T",
		"10G 5M",
		&"9".repeat(400),
	] {
		for bearer in [token(), WRITER] {
			let (status, body) = put(&world, bearer, "alice", quota).await;
			assert!(
				status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
				"{quota:?}: {status} {body}"
			);
		}
	}
	assert_eq!(quota_of(&world, "alice"), None);
}

#[tokio::test]
async fn a_body_that_is_not_the_shape_changes_nothing() {
	let world = world();
	for body in [
		json!({}),
		json!({"quota": 5}),
		json!({"quota": null}),
		json!({"quota": "1G", "account": "bob"}),
		json!({"quota_bytes": 1000}),
		json!([]),
	] {
		let (status, reply) = call(
			&world.state,
			"PUT",
			"/api/v1/accounts/alice/quota",
			token(),
			Some(body.clone()),
		)
		.await;
		assert!(status.is_client_error(), "{body}: {status} {reply}");
	}
	assert_eq!(quota_of(&world, "alice"), None);
}

/// The body limit is 4 KiB: a body just under it is read and refused for its
/// shape, and one over it is not read.
#[tokio::test]
async fn a_body_over_four_kibibytes_is_not_read() {
	let world = world();
	for (pad, expected) in [
		(4000, StatusCode::UNPROCESSABLE_ENTITY),
		(4100, StatusCode::PAYLOAD_TOO_LARGE),
	] {
		let (status, reply) = call(
			&world.state,
			"PUT",
			"/api/v1/accounts/alice/quota",
			token(),
			Some(json!({"quota": "1G", "pad": "x".repeat(pad)})),
		)
		.await;
		assert_eq!(status, expected, "{pad}: {reply}");
	}
	assert_eq!(quota_of(&world, "alice"), None);
}

/// A size is at most 32 characters, also one the parser would read.
#[tokio::test]
async fn a_size_of_more_than_32_characters_is_refused() {
	let world = world();
	let longest = format!("{}1G", "0".repeat(30));
	let longer = format!("{}1G", "0".repeat(31));
	assert_eq!((longest.len(), longer.len()), (32, 33));
	let (status, body) = put(&world, token(), "alice", &longer).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(quota_of(&world, "alice"), None);
	let (status, body) = put(&world, token(), "alice", &longest).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(quota_of(&world, "alice"), Some(1 << 30));
}

/// Zero is refused for its own reason, and the smallest quota above it is taken.
#[tokio::test]
async fn a_quota_of_zero_is_refused_and_one_kibibyte_is_not() {
	let world = world();
	for zero in ["0K", "0M", "0T"] {
		let (status, body) = put(&world, token(), "alice", zero).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{zero}: {body}");
		assert!(body.to_string().contains("refuse all mail"), "{body}");
	}
	assert_eq!(quota_of(&world, "alice"), None);
	let (status, body) = put(&world, token(), "alice", "1K").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(quota_of(&world, "alice"), Some(1024));
}

/// A key that may not set a quota learns nothing about the size either.
#[tokio::test]
async fn a_confined_key_is_refused_before_its_size_is_read() {
	let world = world();
	for quota in ["0K", "not a size"] {
		let (status, body) = put(&world, OF_A, "alice", quota).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{quota}: {body}");
	}
}

#[tokio::test]
async fn an_account_that_is_not_there_is_the_stores_404() {
	let world = world();
	let (status, _) = put(&world, token(), "nobody", "1G").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = clear(&world, token(), "nobody").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_change_is_audited_once_and_no_refusal_is() {
	crate::cli::trace::capture::keep_callsites_live();
	let world = world();
	let capture = Capture::default();
	let subscriber = Registry::default().with(capture.clone());
	async {
		put(&world, READER, "alice", "1G").await;
		put(&world, OF_A, "alice", "1G").await;
		put(&world, token(), "alice", "bad").await;
		put(&world, token(), "nobody", "1G").await;
		put(&world, WRITER, "alice", "2G").await;
		clear(&world, WRITER, "alice").await;
		put(&world, WRITER, "alice", "none").await;
	}
	.with_subscriber(subscriber)
	.await;
	let events = capture.0.lock().unwrap().clone();
	let kinds: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
	assert_eq!(
		kinds,
		[
			"account.quota_set",
			"account.quota_cleared",
			"account.quota_cleared"
		],
		"{events:?}"
	);
	assert_eq!(events[0]["key"], "writer");
	assert_eq!(
		events[0]["quota_bytes"],
		(2u64 * 1024 * 1024 * 1024).to_string()
	);
	assert!(!format!("{events:?}").contains("alice"));
}

#[tokio::test]
async fn the_command_and_the_route_agree_on_every_step() {
	use crate::cli::account::actions::quota_with_store;
	let by_command = world();
	let by_route = world();
	for size in ["500M", "10G", "none", "1T", "500m", "7K"] {
		let parsed = crate::util::quota_size::parse_quota_size(size).expect("size");
		let mut out = Vec::new();
		let code = quota_with_store(&by_command.store, "alice", parsed, &mut out, true);
		assert_eq!(code, ExitCode::SUCCESS);
		let printed: serde_json::Value = serde_json::from_slice(&out).expect("json");
		let (status, body) = put(&by_route, token(), "alice", size).await;
		assert_eq!(status, StatusCode::OK, "{size}: {body}");
		assert_eq!(printed, body, "{size}");
		assert_eq!(quota_of(&by_command, "alice"), quota_of(&by_route, "alice"));
	}
}

/// A size too large for the account file is refused to every key, by the
/// parser the command reads too, and the quota stays as it was.
#[tokio::test]
async fn a_size_the_account_file_cannot_hold_is_refused() {
	let world = world();
	for quota in [
		"9000000T",
		"8388608T",
		"9999999999999T",
		"18446744073709551615K",
	] {
		for bearer in [token(), WRITER] {
			let (status, body) = put(&world, bearer, "alice", quota).await;
			assert_eq!(status, StatusCode::BAD_REQUEST, "{quota}: {body}");
		}
	}
	assert_eq!(quota_of(&world, "alice"), None);
	let (status, body) = put(&world, token(), "alice", "8388607T").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(crate::util::quota_size::parse_quota_size("9000000T").is_err());
	// Deleting a domain that accounts use stays refused.
	let config_less = crate::directory_store::dynamic_addresses_on_disk(world._dir.path())
		.expect("the file still reads");
	assert!(config_less.iter().any(|(name, _)| name == "alice"));
}
