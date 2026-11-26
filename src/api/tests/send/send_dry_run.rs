//! `dry_run` on `POST /api/v1/send`: every check of a real send, none of its
//! effects. The same request is refused for the same reason with or without
//! it, and a request that passes changes nothing on disk.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::send_class::{sent_count, state};
use super::send_rich::send;
use crate::smtp::ratelimit::SendLimiter;
use crate::storage::FsSpool;

/// Every file under `dir` and its size, locks left out: they are made by
/// looking, not by sending.
fn snapshot(dir: &std::path::Path) -> BTreeMap<String, u64> {
	fn walk(root: &std::path::Path, at: &std::path::Path, out: &mut BTreeMap<String, u64>) {
		for entry in std::fs::read_dir(at).into_iter().flatten().flatten() {
			let path = entry.path();
			let name = path
				.strip_prefix(root)
				.expect("inside")
				.display()
				.to_string();
			if path.is_dir() {
				walk(root, &path, out);
			} else if !name.contains("lock") {
				out.insert(name, entry.metadata().expect("meta").len());
			}
		}
	}
	let mut out = BTreeMap::new();
	walk(dir, dir, &mut out);
	out
}

fn queued_count(dir: &std::path::Path) -> usize {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.len()
}

async fn post(app: &axum::Router, body: Value) -> (StatusCode, Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(body),
	)
	.await
}

fn request(extra: Value) -> Value {
	let mut body = json!({
		"from": "alice@example.org", "to": ["bob@elsewhere.example"],
		"subject": "s", "text": "hi",
	});
	body.as_object_mut()
		.expect("object")
		.extend(extra.as_object().expect("object").clone());
	body
}

#[tokio::test]
async fn a_dry_run_says_what_would_happen_and_sends_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (status, body) = send(
		dir.path(),
		json!({"text": "hello", "dry_run": true, "cc": ["c@elsewhere.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["dry_run"], true);
	assert_eq!(body["class"], "personal");
	assert_eq!(body["recipients"], 2);
	assert!(
		body["size"].as_u64().is_some_and(|size| size > 100),
		"{body}"
	);
	assert!(
		body.get("queued").is_none(),
		"no queue id for what was not queued: {body}"
	);
	assert!(body.get("message_id").is_none(), "{body}");
	assert_eq!(queued_count(dir.path()), 0);
	// The same request without the flag is the real send, of about that size.
	let other = tempfile::tempdir().expect("tempdir");
	let (status, real) = send(
		other.path(),
		json!({"text": "hello", "cc": ["c@elsewhere.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{real}");
	assert!(real.get("dry_run").is_none(), "{real}");
	let spool = FsSpool::open(other.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	let real_size = entry.data.len() as i64;
	assert!(
		(real_size - body["size"].as_i64().expect("size")).abs() <= 4,
		"{real_size} vs {body}"
	);
	assert_eq!(entry.envelope.recipients.len(), 2);
}

#[tokio::test]
async fn false_or_absent_is_a_real_send() {
	for extra in [json!({"text": "x"}), json!({"text": "x", "dry_run": false})] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (status, body) = send(dir.path(), extra.clone()).await;
		assert_eq!(status, StatusCode::OK, "{extra}: {body}");
		assert!(body["queued"].is_string(), "{extra}: {body}");
		assert_eq!(queued_count(dir.path()), 1, "{extra}");
	}
}

#[tokio::test]
async fn a_dry_run_leaves_the_data_directory_as_it_found_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("mkdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	for class in ["personal", "transactional", "marketing"] {
		let before = snapshot(dir.path());
		let (status, body) = post(
			&app,
			request(json!({
				"class": class, "dry_run": true,
				"list_unsubscribe": ["https://example.org/u"], "list_unsubscribe_post": true,
			})),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{class}: {body}");
		assert_eq!(body["class"], class);
		assert_eq!(
			snapshot(dir.path()),
			before,
			"{class}: a dry run wrote something"
		);
		assert_eq!(sent_count(dir.path()), 0, "{class}: no Sent copy");
	}
}

#[tokio::test]
async fn every_refusal_of_a_real_send_is_the_refusal_of_its_dry_run() {
	let long_header = "x".repeat(1001);
	let recipients: Vec<String> = (0..101)
		.map(|i| format!("r{i}@elsewhere.example"))
		.collect();
	let cases = [
		json!({"from": "mallory@elsewhere.example"}),
		json!({"from": "not an address"}),
		json!({"to": recipients}),
		json!({"to": []}),
		json!({"importance": "urgent"}),
		json!({"subject": long_header}),
		json!({"class": "bulk"}),
		json!({"class": "marketing"}),
		json!({"headers": {"Message-ID": "<x@y>"}}),
		json!({"inline": [{"data": ""}]}),
		json!({"text": null, "subject": "", "html": ""}),
	];
	for extra in cases {
		let dir = tempfile::tempdir().expect("tempdir");
		let (state, _) = state(dir.path());
		let app = router(state);
		let (real_status, real) = post(&app, request(extra.clone())).await;
		assert!(
			real_status.is_client_error(),
			"{extra}: the real send must be refused: {real}"
		);
		let mut dry = request(extra.clone());
		dry["dry_run"] = json!(true);
		let (dry_status, dry) = post(&app, dry).await;
		assert_eq!((dry_status, dry), (real_status, real), "{extra}");
	}
}

#[tokio::test]
async fn a_message_over_the_size_limit_is_refused_by_a_dry_run_too() {
	for dry_run in [false, true] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0).with_max_message_size(2000));
		let body = request(json!({"text": "x".repeat(5000), "dry_run": dry_run}));
		let response = app
			.clone()
			.oneshot(
				axum::http::Request::builder()
					.method("POST")
					.uri("/api/v1/send")
					.header(
						axum::http::header::AUTHORIZATION,
						format!("Bearer {}", TOKEN.as_str()),
					)
					.header(axum::http::header::CONTENT_TYPE, "application/json")
					.body(axum::body::Body::from(body.to_string()))
					.expect("request"),
			)
			.await
			.expect("response");
		assert_eq!(
			response.status(),
			StatusCode::PAYLOAD_TOO_LARGE,
			"dry_run {dry_run}"
		);
		assert_eq!(queued_count(dir.path()), 0);
	}
}

#[tokio::test]
async fn a_dry_run_does_not_spend_the_rate_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let app = router(test_state(dir.path(), 0).with_submission_limit(Some(limiter), Some(1)));
	for _ in 0..3 {
		let (status, body) = post(&app, request(json!({"dry_run": true}))).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
	let (status, body) = post(&app, request(json!({}))).await;
	assert_eq!(status, StatusCode::OK, "the budget was untouched: {body}");
	// With the budget gone a dry run is refused as the real send is.
	let (status, body) = post(&app, request(json!({"dry_run": true}))).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn a_dry_run_asks_the_new_recipient_cap_and_does_not_spend_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app =
		router(super::super::submissions::newrecipients::test_state_with_cap(dir.path(), Some(1)));
	let to = |address: &str| request(json!({"to": [address]}));
	for _ in 0..2 {
		let mut body = to("one@elsewhere.example");
		body["dry_run"] = json!(true);
		let (status, answer) = post(&app, body).await;
		assert_eq!(status, StatusCode::OK, "{answer}");
	}
	let mut over = request(json!({"to": ["a@elsewhere.example", "b@elsewhere.example"]}));
	over["dry_run"] = json!(true);
	let (status, answer) = post(&app, over).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
	// The allowance is whole: the first real send to a first-time recipient
	// goes out, although dry runs named another one, and the next is over the cap.
	let (status, answer) = post(&app, to("two@elsewhere.example")).await;
	assert_eq!(status, StatusCode::OK, "{answer}");
	let (status, answer) = post(&app, to("three@elsewhere.example")).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{answer}");
}

#[tokio::test]
async fn a_dry_run_lists_the_suppressed_recipients_without_touching_the_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	let (state, _) = state(dir.path());
	let app = router(state);
	let before = snapshot(dir.path());
	let (status, body) = post(
		&app,
		request(json!({
			"class": "marketing", "dry_run": true,
			"to": ["kept@elsewhere.example", "gone@elsewhere.example"],
			"list_unsubscribe": ["https://example.org/u"], "list_unsubscribe_post": true,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["suppressed"], json!(["gone@elsewhere.example"]));
	assert_eq!(body["recipients"], 1);
	assert_eq!(snapshot(dir.path()), before);
	let (status, body) = post(
		&app,
		request(json!({
			"class": "marketing", "dry_run": true, "to": ["gone@elsewhere.example"],
			"list_unsubscribe": ["https://example.org/u"], "list_unsubscribe_post": true,
		})),
	)
	.await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
	assert_eq!(body["error"]["code"], "marketing_refused");
}

#[tokio::test]
async fn a_dry_run_needs_the_same_credential_as_the_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		None,
		Some(request(json!({"dry_run": true}))),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("wrong-token"),
		Some(request(json!({"dry_run": true}))),
	)
	.await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	assert_eq!(queued_count(dir.path()), 0);
}

#[tokio::test]
async fn a_dry_run_does_not_tell_whose_address_it_is() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let ask = |from: &str| request(json!({"from": from, "dry_run": true}));
	let (_, nobody) = post(&app, ask("nobody@example.org")).await;
	let (_, elsewhere) = post(&app, ask("someone@elsewhere.example")).await;
	assert_eq!(nobody["error"]["code"], "forbidden_from");
	assert_eq!(nobody, elsewhere);
}

#[tokio::test]
async fn dry_runs_are_limited_per_account_and_cost_nothing_to_sends() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_dry_run_limits(5, 1000));
	let dry = || {
		let mut body = request(json!({}));
		body["dry_run"] = json!(true);
		body
	};
	for _ in 0..5 {
		let (status, body) = post(&app, dry()).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
	let (status, body) = post(&app, dry()).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"]["code"], "rate_limited");
	// Real sends are another budget: they still go out, and are not what the dry runs spent.
	let (status, body) = post(&app, request(json!({}))).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(queued_count(dir.path()), 1);
}

#[tokio::test]
async fn a_dry_run_is_charged_one_unit_per_recipient_and_all_or_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_dry_run_limits(4, 1000));
	let probe = |count: usize| {
		let to: Vec<String> = (0..count)
			.map(|i| format!("r{i}@elsewhere.example"))
			.collect();
		request(json!({"to": to, "dry_run": true}))
	};
	assert_eq!(
		post(&app, probe(5)).await.0,
		StatusCode::TOO_MANY_REQUESTS,
		"wider than the window"
	);
	assert_eq!(
		post(&app, probe(3)).await.0,
		StatusCode::OK,
		"the refused one cost nothing"
	);
	assert_eq!(
		post(&app, probe(2)).await.0,
		StatusCode::TOO_MANY_REQUESTS,
		"3 + 2 is over 4"
	);
	assert_eq!(post(&app, probe(1)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn addresses_never_written_to_are_capped_per_day_and_known_ones_are_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = super::super::submissions::newrecipients::test_state_with_cap(dir.path(), None)
		.with_dry_run_limits(1000, 3);
	let app = router(state);
	crate::storage::CorrespondentStore::open(dir.path())
		.expect("store")
		.record("alice", &["known@elsewhere.example"])
		.expect("record");
	let probe = |address: &str| request(json!({"to": [address], "dry_run": true}));
	for address in [
		"a@elsewhere.example",
		"b@elsewhere.example",
		"c@elsewhere.example",
	] {
		assert_eq!(
			post(&app, probe(address)).await.0,
			StatusCode::OK,
			"{address}"
		);
	}
	let (status, body) = post(&app, probe("d@elsewhere.example")).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	// Asking again about the same address does not get it past the cap,
	// and an address the account does write to is not a probe.
	assert_eq!(
		post(&app, probe("d@elsewhere.example")).await.0,
		StatusCode::TOO_MANY_REQUESTS
	);
	for _ in 0..5 {
		assert_eq!(
			post(&app, probe("known@elsewhere.example")).await.0,
			StatusCode::OK
		);
	}
}

#[tokio::test]
async fn a_dry_run_does_not_measure_the_mailboxes_the_key_does_not_reach() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("keys");
	keys.add(crate::api::api_keys::ApiKey {
		label: "alice-only".to_string(),
		hash: crate::api::api_keys::sha256_hash("alice-secret"),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["send".to_string()],
		grants: Vec::new(),
		domains: Vec::new(),
		account: Some("alice".to_string()),
		auto_submitted: false,
	})
	.expect("add");
	drop(keys);
	super::super::submissions::quota::fill_bob(dir.path(), 200);
	let app = router(super::super::submissions::quota::state(dir.path()));
	let body = |dry: bool| json!({"from": "alice@example.org", "to": ["bob@example.org"], "subject": "s", "text": "hi", "dry_run": dry});
	// The real send is refused: bob's mailbox is full.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("alice-secret"),
		Some(body(false)),
	)
	.await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	// A dry run of the same key does not look: it would answer for any address.
	let (status, answer) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some("alice-secret"),
		Some(body(true)),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{answer}");
	assert!(!answer.to_string().contains("bob"), "{answer}");
	// The key that reaches bob's account is told, as the real send is.
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(body(true)),
	)
	.await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
}

#[tokio::test]
async fn a_dry_run_refused_for_the_day_gives_its_minute_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = super::super::submissions::newrecipients::test_state_with_cap(dir.path(), None)
		.with_dry_run_limits(4, 2);
	let app = router(state);
	let known = [
		"k0@elsewhere.example",
		"k1@elsewhere.example",
		"k2@elsewhere.example",
		"k3@elsewhere.example",
	];
	crate::storage::CorrespondentStore::open(dir.path())
		.expect("store")
		.record("alice", &known)
		.expect("record");
	let (status, _) = post(
		&app,
		request(json!({"to": ["n0@elsewhere.example", "n1@elsewhere.example", "n2@elsewhere.example"], "dry_run": true})),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::TOO_MANY_REQUESTS,
		"three new addresses are over the day"
	);
	let (status, body) = post(&app, request(json!({"to": known, "dry_run": true}))).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"the refused request left the minute whole: {body}"
	);
}
