//! The request limits the JMAP Session advertises (RFC 8620 §2) and the
//! checks that enforce them (§3.6.1). One constant per limit, read both by
//! the Session resource and by the code that applies it, so what a client is
//! told and what the server does cannot drift apart.

use axum::http::StatusCode;

/// `maxSizeUpload`: the most octets accepted in one `POST /jmap/upload`
/// body (RFC 8620 §6.1). Anything larger is refused with the `limit`
/// problem, however much larger it is.
pub const MAX_UPLOAD_SIZE: usize = 50_000_000;

/// `maxSizeRequest`: the most octets accepted in one `POST /jmap/api` body.
/// 10 MB, not the 2 MiB axum applies by default: Email/set and
/// EmailSubmission/set carry message bodies inline, and the uploads a client
/// references by blob id are already allowed up to `maxSizeUpload`.
pub const MAX_SIZE_REQUEST: usize = 10_000_000;

/// `maxCallsInRequest`: the most method calls accepted in one request.
pub const MAX_CALLS_IN_REQUEST: usize = 16;

/// The request-level error for a request with more than
/// [`MAX_CALLS_IN_REQUEST`] method calls (RFC 8620 §3.6.1). Nothing is run
/// for a refused request.
pub(super) fn too_many_calls() -> serde_json::Value {
	problem(
		"maxCallsInRequest",
		StatusCode::BAD_REQUEST,
		&format!("a request may carry at most {MAX_CALLS_IN_REQUEST} method calls"),
	)
}

/// The request-level error for a request body, HTTP or WebSocket, over
/// [`MAX_SIZE_REQUEST`].
pub(super) fn request_too_large() -> serde_json::Value {
	problem(
		"maxSizeRequest",
		StatusCode::PAYLOAD_TOO_LARGE,
		&format!("a request may be at most {MAX_SIZE_REQUEST} octets"),
	)
}

/// The error for an upload body over [`MAX_UPLOAD_SIZE`].
pub(super) fn upload_too_large() -> serde_json::Value {
	problem(
		"maxSizeUpload",
		StatusCode::PAYLOAD_TOO_LARGE,
		"upload exceeds maxSizeUpload",
	)
}

/// The `urn:ietf:params:jmap:error:limit` problem (RFC 8620 §3.6.1), whose
/// `limit` property names the Session limit that was applied.
fn problem(limit: &str, status: StatusCode, detail: &str) -> serde_json::Value {
	serde_json::json!({
		"type": "urn:ietf:params:jmap:error:limit",
		"limit": limit,
		"status": status.as_u16(),
		"detail": detail,
	})
}
