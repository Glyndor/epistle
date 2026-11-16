//! A `401` names the scheme it accepts (RFC 6750 section 3), whatever body
//! the client asked for.

use super::super::base::{TOKEN, test_state};
use super::base::{PROBLEM, call};
use super::*;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn every_401_carries_www_authenticate_bearer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	for (token, accept) in [
		(None, None),
		(Some("not-the-token"), None),
		(None, Some(PROBLEM)),
		(Some("not-the-token"), Some(PROBLEM)),
	] {
		let answer = call(&app, "GET", "/api/v1/status", token, accept, None).await;
		assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{token:?}");
		assert_eq!(answer.header("www-authenticate"), Some("Bearer"));
	}
	// A route that is a valid call does not carry it.
	let ok = call(
		&app,
		"GET",
		"/api/v1/status",
		Some(TOKEN.as_str()),
		None,
		None,
	)
	.await;
	assert_eq!(ok.status, StatusCode::OK);
	assert_eq!(ok.header("www-authenticate"), None);
}

#[tokio::test]
async fn a_401_is_a_problem_when_asked_and_the_old_body_otherwise() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let plain = call(&app, "GET", "/api/v1/status", None, None, None).await;
	assert_eq!(
		plain.body,
		json!({"error": {
			"code": "unauthenticated",
			"message": "A valid bearer token is required."
		}})
	);
	let problem = call(&app, "GET", "/api/v1/status", None, Some(PROBLEM), None).await;
	assert_eq!(problem.header("content-type"), Some(PROBLEM));
	assert_eq!(problem.body["type"], "urn:epistle:problem:unauthenticated");
	assert_eq!(problem.body["status"], 401);
	assert_eq!(problem.body["code"], "unauthenticated");
	assert_eq!(problem.body["title"], "Authentication required");
	assert!(problem.body["request_id"].is_string(), "{}", problem.body);
	assert_eq!(problem.header("www-authenticate"), Some("Bearer"));
}
