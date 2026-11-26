//! Showing an entry: the envelope as the command prints it, and the headers
//! of the message only when asked, never the body.

use axum::http::StatusCode;

use super::fixture::*;

#[tokio::test]
async fn the_entry_is_what_the_command_shows_and_has_no_headers_unasked() {
	let world = world();
	let (status, body) = call(
		&world.state,
		"GET",
		&format!("/api/v1/queue/{}", world.mine),
		READER,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let envelope = world.state.spool().load_envelope(world.mine).unwrap();
	assert_eq!(body, crate::queue::inspect::show_view(&envelope));
	assert!(body.get("headers").is_none());
	assert!(!body.to_string().contains("quarterly"));
}

#[tokio::test]
async fn the_headers_are_returned_on_request_and_the_body_never() {
	let world = world();
	let (status, body) = call(
		&world.state,
		"GET",
		&format!("/api/v1/queue/{}?headers=true", world.mine),
		READER,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let headers = body["headers"].as_array().expect("headers");
	let names: Vec<&str> = headers
		.iter()
		.map(|h| h["name"].as_str().unwrap())
		.collect();
	assert_eq!(names, ["Subject", "From", "To", "Received", "X-Folded"]);
	assert_eq!(headers[0]["value"], "quarterly figures");
	assert_eq!(headers[4]["value"], "one two three");
	assert_eq!(body["headers_truncated"], false);
	assert!(!body.to_string().contains("top secret"), "{body}");
}

#[tokio::test]
async fn headers_of_another_tenants_message_are_not_returned() {
	let world = world();
	let (status, body) = call(
		&world.state,
		"GET",
		&format!("/api/v1/queue/{}?headers=true", world.theirs),
		TENANT_A,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
	assert!(!body.to_string().contains("quarterly"));
}
