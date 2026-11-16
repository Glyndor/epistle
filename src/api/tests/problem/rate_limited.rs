//! Every `429` of the REST API says when to come back, in the default body
//! and in the problem.

use std::sync::Arc;
use std::time::Duration;

use super::super::base::{TOKEN, test_state};
use super::base::{Answer, PROBLEM, call};
use super::*;
use crate::smtp::ratelimit::SendLimiter;
use axum::http::StatusCode;
use serde_json::json;

fn retry_after(answer: &Answer) -> u64 {
	answer
		.header("retry-after")
		.expect("Retry-After")
		.parse()
		.expect("seconds")
}

#[tokio::test]
async fn the_authentication_limit_and_a_full_queue_say_when_to_retry() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0)
		.with_auth_window(Duration::from_secs(3600))
		.with_argon2_queue(0);
	let app = router(state);
	// The queue has no room: nothing was checked, the client waits a moment.
	let busy = call(&app, "GET", "/api/v1/status", Some("wrong"), None, None).await;
	assert_eq!(busy.status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(retry_after(&busy), 1);
	assert_eq!(busy.body["error"]["code"], "rate_limited");

	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 0).with_auth_window(Duration::from_secs(3600));
	state.prime_configured_token(TOKEN.as_str());
	let app = router(state);
	let mut limited = None;
	for _ in 0..40 {
		let answer = call(
			&app,
			"GET",
			"/api/v1/status",
			Some("wrong"),
			Some(PROBLEM),
			None,
		)
		.await;
		if answer.status == StatusCode::TOO_MANY_REQUESTS {
			limited = Some(answer);
			break;
		}
	}
	let limited = limited.expect("the failure limit was reached");
	let wait = retry_after(&limited);
	assert!((1..=3600).contains(&wait), "{wait}");
	assert_eq!(limited.header("content-type"), Some(PROBLEM));
	assert_eq!(limited.body["code"], "rate_limited");
	assert_eq!(limited.body["type"], "urn:epistle:problem:rate_limited");
	assert_eq!(limited.body["status"], 429);
}

#[tokio::test]
async fn a_send_limit_says_when_the_window_is_over() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let state = test_state(dir.path(), 0).with_submission_limit(Some(limiter), Some(1));
	let app = router(state);
	let message = json!({"from": "alice@example.org", "to": ["bob@elsewhere.example"],
		"subject": "s", "text": "t"});
	let first = call(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		None,
		Some(message.clone()),
	)
	.await;
	assert_eq!(first.status, StatusCode::OK, "{}", first.body);
	let refused = call(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		None,
		Some(message.clone()),
	)
	.await;
	assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(retry_after(&refused), 60);
	assert_eq!(refused.body["error"]["code"], "rate_limited");
	let problem = call(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(PROBLEM),
		Some(message),
	)
	.await;
	assert_eq!(problem.status, StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(retry_after(&problem), 60);
	assert_eq!(problem.body["code"], "rate_limited");
}

#[tokio::test]
async fn the_new_recipient_cap_says_when_a_day_is_over() {
	let dir = tempfile::tempdir().expect("tempdir");
	let correspondents = crate::storage::CorrespondentStore::open(dir.path()).expect("store");
	let state = test_state(dir.path(), 0)
		.with_correspondents(correspondents)
		.with_new_recipients_per_day(Some(1));
	let app = router(state);
	let answer = call(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		None,
		Some(json!({"from": "alice@example.org",
			"to": ["b@elsewhere.example", "c@elsewhere.example"],
			"subject": "s", "text": "t"})),
	)
	.await;
	assert_eq!(
		answer.status,
		StatusCode::TOO_MANY_REQUESTS,
		"{}",
		answer.body
	);
	assert_eq!(retry_after(&answer), 86_400);
}
