//! SCIM 2.0 error envelope.
//!
//! RFC 7644 §3.7 defines the shape: every error response carries the
//! `urn:ietf:params:scim:api:messages:2.0:Error` schema URN, a numeric
//! `status` (HTTP-style), and a human-readable `detail`. We expose a single
//! [`ScimError`] type that maps to `StatusCode` + `IntoResponse`, keeping
//! every SCIM endpoint honest about its failure shape.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// The `Content-Type` SCIM requires on responses (`application/scim+json`).
/// Distinct from `application/json` per RFC 7644 §8.1 so a client can
/// negotiate SCIM-aware behaviour.
pub const CONTENT_TYPE: &str = "application/scim+json";

/// The schema URN every SCIM error response advertises.
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// A SCIM error response, carrying the status code the IdP sees on the
/// wire, the schema URN (always `ERROR_SCHEMA`), the matching numeric
/// status (RFC 7644 §3.7 expects it as a string-form integer), and the
/// detail message the operator reads.
#[derive(Debug)]
pub struct ScimError {
	/// The HTTP status code emitted on the wire.
	pub status: StatusCode,
	/// The numeric status, serialised as a string. Equal to `status.as_u16()`
	/// for every constructor.
	pub status_text: String,
	/// A short, single-sentence detail of what went wrong. Never includes
	/// the secret material that may have triggered the error.
	pub detail: String,
}

impl ScimError {
	/// Build an error from a status code and a detail. The numeric
	/// `status_text` is derived from the code so it cannot drift.
	fn new(status: StatusCode, detail: impl Into<String>) -> Self {
		ScimError {
			status,
			status_text: status.as_u16().to_string(),
			detail: detail.into(),
		}
	}

	/// 404 — the requested resource is absent.
	pub fn not_found(detail: impl Into<String>) -> Self {
		Self::new(StatusCode::NOT_FOUND, detail)
	}

	/// 409 — the request collides with an existing resource (duplicate
	/// `userName`, address already owned by another account).
	pub fn conflict(detail: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, detail)
	}

	/// 400 — the request body is malformed or violates a constraint we
	/// can name.
	pub fn invalid(detail: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_REQUEST, detail)
	}

	/// 501 — endpoint intentionally not implemented in this release (Groups).
	pub fn not_implemented(detail: impl Into<String>) -> Self {
		Self::new(StatusCode::NOT_IMPLEMENTED, detail)
	}

	/// 500 — the server could not satisfy the request for reasons outside
	/// the request's control (storage failure, CSPRNG unavailable, …).
	pub fn internal() -> Self {
		Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")
	}
}

#[derive(Serialize)]
struct ErrorBody<'a> {
	schemas: [&'static str; 1],
	status: &'a str,
	detail: &'a str,
}

impl IntoResponse for ScimError {
	fn into_response(self) -> Response {
		let body = ErrorBody {
			schemas: [ERROR_SCHEMA],
			status: &self.status_text,
			detail: &self.detail,
		};
		(
			self.status,
			[(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)],
			Json(body),
		)
			.into_response()
	}
}

#[cfg(test)]
mod tests {
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
}
