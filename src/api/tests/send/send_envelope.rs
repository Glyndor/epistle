//! `envelope_from` on `POST /api/v1/send`: the address bounces return to,
//! apart from the `From` the reader sees. It is held to the same ownership
//! rule as `From`, so a key cannot send as an address its account lacks.

use super::base::request_with_body;
use super::send_as::{app, secret};
use crate::storage::FsSpool;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A send as `alice` from `alice@example.org` with `extra` merged in.
async fn send(app: &Router, extra: Value) -> (StatusCode, Value) {
	let mut request = json!({
		"from": "alice@example.org", "to": ["dest@remote.example"],
		"subject": "hello", "text": "hi",
	});
	request
		.as_object_mut()
		.expect("object")
		.extend(extra.as_object().expect("object").clone());
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(&secret("alice")),
		Some(request),
	)
	.await
}

/// The envelope sender and the bytes of every queued message.
fn queued(dir: &std::path::Path) -> Vec<(String, String)> {
	let spool = FsSpool::open(dir).expect("spool");
	spool
		.list()
		.expect("list")
		.into_iter()
		.map(|id| {
			let entry = spool.load(id).expect("load");
			(
				entry.envelope.reverse_path,
				String::from_utf8_lossy(&entry.data).into_owned(),
			)
		})
		.collect()
}

#[tokio::test]
async fn the_envelope_sender_defaults_to_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, body) = send(&app, json!({})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(queued(dir.path())[0].0, "alice@example.org");
}

#[tokio::test]
async fn an_owned_address_becomes_the_envelope_sender_and_from_stays() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, body) = send(&app, json!({"envelope_from": "Alice@Other.Example"})).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let queued = queued(dir.path());
	assert_eq!(queued.len(), 1);
	assert_eq!(queued[0].0, "alice@other.example");
	assert!(
		queued[0].1.contains("From: alice@example.org\r\n"),
		"{}",
		queued[0].1
	);
	assert!(
		!queued[0].1.contains("other.example"),
		"the header names no envelope address"
	);
}

#[tokio::test]
async fn an_address_the_account_does_not_own_is_refused_alike() {
	for envelope in [
		"bob@example.org",
		"stranger@elsewhere.example",
		"board@example.org",
		"name.surname@other.example",
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let (status, body) = send(&app, json!({"envelope_from": envelope})).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{envelope}: {body}");
		assert_eq!(body["error"]["code"], "forbidden_from", "{envelope}");
		assert!(
			queued(dir.path()).is_empty(),
			"{envelope}: nothing is queued"
		);
	}
}

#[tokio::test]
async fn the_refusal_is_the_same_whether_the_address_belongs_to_another_account_or_to_none() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (_, other) = send(&app, json!({"envelope_from": "bob@example.org"})).await;
	let (_, none) = send(&app, json!({"envelope_from": "nobody@example.org"})).await;
	assert_eq!(other, none);
}

#[tokio::test]
async fn a_malformed_envelope_sender_is_refused() {
	let long = format!("{}@example.org", "a".repeat(1100));
	for envelope in [
		json!(""),
		json!("not an address"),
		json!("<alice@example.org>"),
		json!("alice@example.org\r\nBcc: victim@elsewhere.example"),
		json!(long),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let (status, body) = send(&app, json!({"envelope_from": envelope})).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{envelope}: {body}");
		assert!(
			queued(dir.path()).is_empty(),
			"{envelope}: nothing is queued"
		);
	}
}

#[tokio::test]
async fn the_empty_string_is_not_the_null_sender() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, body) = send(&app, json!({"envelope_from": ""})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input");
	assert!(
		body["error"]["message"]
			.as_str()
			.is_some_and(|m| m.contains("envelope_from")),
		"{body}"
	);
}

#[tokio::test]
async fn an_envelope_sender_does_not_open_a_send_the_from_would_refuse() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	let (status, body) = send(
		&app,
		json!({"from": "bob@example.org", "envelope_from": "alice@example.org"}),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(queued(dir.path()).is_empty());
}

#[tokio::test]
async fn a_value_that_is_not_a_string_is_refused_before_anything_is_read() {
	for envelope in [
		json!(["alice@example.org"]),
		json!(7),
		json!({"address": "alice@example.org"}),
		json!(null),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let body = json!({
			"from": "alice@example.org", "to": ["dest@remote.example"],
			"text": "hi", "envelope_from": envelope,
		});
		let response = app
			.clone()
			.oneshot(
				Request::builder()
					.method("POST")
					.uri("/api/v1/send")
					.header(header::AUTHORIZATION, format!("Bearer {}", secret("alice")))
					.header(header::CONTENT_TYPE, "application/json")
					.body(Body::from(body.to_string()))
					.expect("request"),
			)
			.await
			.expect("response");
		// `null` is the same as an absent field: the send goes out as `from`.
		let expected = if envelope.is_null() {
			StatusCode::OK
		} else {
			StatusCode::UNPROCESSABLE_ENTITY
		};
		assert_eq!(response.status(), expected, "{envelope}");
		assert_eq!(
			queued(dir.path()).len(),
			usize::from(envelope.is_null()),
			"{envelope}"
		);
	}
}
