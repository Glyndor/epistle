//! A refused input: the default body is unchanged, the problem names the
//! cause and the field.

use super::super::base::{TOKEN, test_state};
use super::base::{PROBLEM, call};
use super::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

fn send(to: Value) -> Value {
	json!({"from": "alice@example.org", "to": to, "subject": "s", "text": "t"})
}

#[tokio::test]
async fn the_default_body_of_a_refused_input_is_unchanged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// No `Accept`, a JSON one, a wildcard and a refused problem type all get
	// the body the API always sent.
	for accept in [
		None,
		Some("application/json"),
		Some("*/*"),
		Some("application/problem+json;q=0"),
	] {
		let answer = call(
			&app,
			"POST",
			"/api/v1/send",
			Some(TOKEN.as_str()),
			accept,
			Some(send(json!([]))),
		)
		.await;
		assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{accept:?}");
		assert_eq!(
			answer.body,
			json!({"error": {
				"code": "invalid_input",
				"message": "At least one recipient is required."
			}}),
			"{accept:?}"
		);
		assert_eq!(
			answer.header("content-type"),
			Some("application/json"),
			"{accept:?}"
		);
	}
}

#[tokio::test]
async fn a_missing_field_is_a_problem_with_its_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let answer = call(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(PROBLEM),
		Some(send(json!([]))),
	)
	.await;
	assert_eq!(answer.status, StatusCode::BAD_REQUEST);
	assert_eq!(answer.header("content-type"), Some(PROBLEM));
	let body = &answer.body;
	assert_eq!(body["type"], "urn:epistle:problem:field_missing", "{body}");
	assert_eq!(body["title"], "A required field is missing", "{body}");
	assert_eq!(body["status"], 400, "{body}");
	assert_eq!(body["code"], "field_missing", "{body}");
	assert_eq!(
		body["detail"], "At least one recipient is required.",
		"{body}"
	);
	assert_eq!(body["errors"][0]["field"], "to", "{body}");
	let id = body["request_id"].as_str().expect("request_id");
	uuid::Uuid::parse_str(id).expect("a uuid");
	assert_eq!(body["instance"], format!("urn:uuid:{id}"), "{body}");
}

#[tokio::test]
async fn every_cause_has_its_own_code() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let many: Vec<String> = (0..200).map(|i| format!("r{i}@x.example")).collect();
	let cases = [
		(
			json!({"from": "alice@example.org", "to": many}),
			"field_out_of_range",
			"to",
		),
		(
			json!({"from": "not-an-address", "to": ["b@x.example"]}),
			"value_not_allowed",
			"from",
		),
		(
			json!({"from": "alice@example.org", "to": ["b@x.example"], "importance": "urgent"}),
			"value_not_allowed",
			"importance",
		),
	];
	for (request, code, field) in cases {
		let answer = call(
			&app,
			"POST",
			"/api/v1/send",
			Some(TOKEN.as_str()),
			Some(PROBLEM),
			Some(request),
		)
		.await;
		assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{code}");
		assert_eq!(answer.body["code"], code, "{}", answer.body);
		assert_eq!(
			answer.body["type"],
			format!("urn:epistle:problem:{code}"),
			"{}",
			answer.body
		);
		assert_eq!(answer.body["errors"][0]["field"], field, "{}", answer.body);
		// The default body of the same refusal still says `invalid_input`.
	}
}

#[tokio::test]
async fn an_error_without_a_field_is_a_problem_without_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let answer = call(
		&app,
		"DELETE",
		"/api/v1/queue/00000000-0000-7000-8000-000000000000",
		Some(TOKEN.as_str()),
		Some("text/html, application/problem+json;q=0.5"),
		None,
	)
	.await;
	assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.body);
	assert_eq!(answer.header("content-type"), Some(PROBLEM));
	assert_eq!(answer.body["code"], "not_found");
	assert_eq!(answer.body["title"], "Not found");
	assert!(answer.body.get("errors").is_none(), "{}", answer.body);
}
