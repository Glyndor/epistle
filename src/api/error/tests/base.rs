use super::*;

#[test]
fn constructors_map_to_expected_status_and_code() {
	let cases = [
		(
			ApiError::unauthenticated(),
			StatusCode::UNAUTHORIZED,
			"unauthenticated",
		),
		(
			ApiError::not_found("gone"),
			StatusCode::NOT_FOUND,
			"not_found",
		),
		(
			ApiError::invalid_input("bad"),
			StatusCode::BAD_REQUEST,
			"invalid_input",
		),
		(
			ApiError::internal(),
			StatusCode::INTERNAL_SERVER_ERROR,
			"internal",
		),
		(
			ApiError::rate_limited(),
			StatusCode::TOO_MANY_REQUESTS,
			"rate_limited",
		),
	];
	for (error, status, code) in cases {
		assert_eq!(error.status, status);
		assert_eq!(error.code, code);
		assert!(!error.message.is_empty());
		// The response carries the status through into_response.
		assert_eq!(error.into_response().status(), status);
	}
}

#[test]
fn caller_messages_are_preserved() {
	assert_eq!(ApiError::not_found("no mailbox").message, "no mailbox");
	assert_eq!(ApiError::invalid_input("bad name").message, "bad name");
}
