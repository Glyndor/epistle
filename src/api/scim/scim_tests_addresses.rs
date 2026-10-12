//! SCIM user addresses: a refused email says which rule it breaks.

use axum::http::StatusCode;

use super::tests::*;

async fn create(
	state: &crate::api::state::ApiState,
	user: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
	send(
		&app(state.clone()),
		"POST",
		"/scim/v2/Users",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&user),
	)
	.await
}

#[tokio::test]
async fn create_names_the_rule_an_email_breaks() {
	let (_dir, state) = build_state();
	let (status, body) = create(
		&state,
		serde_json::json!({
			"userName": "bob",
			"active": true,
			"emails": [{"value": "bob..smith@example.org"}],
		}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["detail"], "email: consecutive dots in the local part");

	let (status, body) = create(
		&state,
		serde_json::json!({
			"userName": "bob",
			"active": true,
			"emails": [{"value": "bob@example.com"}],
		}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(
		body["detail"],
		"example.com is not a domain this server handles"
	);
}

#[tokio::test]
async fn create_and_replace_store_the_lowercase_form() {
	let (_dir, state) = build_state();
	let (status, body) = create(
		&state,
		serde_json::json!({
			"userName": "Carol",
			"active": true,
			"emails": [{"value": "Carol.Jones@Example.ORG"}],
		}),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{body}");
	assert_eq!(body["userName"], "carol");
	assert_eq!(body["emails"][0]["value"], "carol.jones@example.org");

	// The IdP keeps sending the userName it was created with.
	let replace = serde_json::json!({
		"userName": "Carol",
		"active": true,
		"emails": [{"value": "CJ@Example.ORG"}],
	});
	let (status, body) = send(
		&app(state.clone()),
		"PUT",
		"/scim/v2/Users/carol",
		Some(SCIM_KEY_SECRET.as_str()),
		Some(&replace),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["emails"][0]["value"], "cj@example.org");
}
