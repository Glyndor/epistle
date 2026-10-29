use super::*;

#[test]
fn constructors_map_to_expected_codes() {
	assert_eq!(ScimError::not_found("x").status, StatusCode::NOT_FOUND);
	assert_eq!(ScimError::conflict("x").status, StatusCode::CONFLICT);
	assert_eq!(ScimError::invalid("x").status, StatusCode::BAD_REQUEST);
	assert_eq!(
		ScimError::not_implemented("x").status,
		StatusCode::NOT_IMPLEMENTED
	);
	assert_eq!(
		ScimError::internal().status,
		StatusCode::INTERNAL_SERVER_ERROR
	);
}

#[test]
fn status_text_matches_status_code() {
	for error in [
		ScimError::not_found("x"),
		ScimError::conflict("x"),
		ScimError::invalid("x"),
	] {
		assert_eq!(error.status_text, error.status.as_u16().to_string());
	}
}

#[test]
fn response_carries_scim_content_type() {
	let response = ScimError::not_found("missing").into_response();
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
	assert_eq!(
		response
			.headers()
			.get(axum::http::header::CONTENT_TYPE)
			.expect("content-type"),
		CONTENT_TYPE,
	);
}
