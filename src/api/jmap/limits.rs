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

/// `maxConcurrentRequests`: the most `POST /jmap/api` requests, and
/// WebSocket `Request` frames, one credential may have in flight at once.
pub const MAX_CONCURRENT_REQUESTS: usize = 4;

/// `maxConcurrentUpload`: the most `POST /jmap/upload` requests one
/// credential may have in flight at once.
pub const MAX_CONCURRENT_UPLOAD: usize = 4;

/// `maxObjectsInGet`: the most ids one `/get` call may name, and the most
/// records `ids: null` may return (RFC 8620 §5.1).
pub const MAX_OBJECTS_IN_GET: usize = 500;

/// `maxObjectsInSet`: the most creates, updates and destroys, counted
/// together, one `/set` call may carry (RFC 8620 §5.3).
pub const MAX_OBJECTS_IN_SET: usize = 500;

/// Whether a `/get` call names more ids than [`MAX_OBJECTS_IN_GET`], a
/// `/set` call carries more creates, updates and destroys than
/// [`MAX_OBJECTS_IN_SET`], or a `/copy` more creates than that. Such a call
/// is answered `requestTooLarge` (RFC 8620 §5.1, §5.3) and not run. A
/// `/copy` creates objects the way a `/set` does, so it gets the same cap.
pub(super) fn too_many_objects(method: &str, args: &serde_json::Value) -> bool {
	let count = |key: &str| match args.get(key) {
		Some(serde_json::Value::Array(items)) => items.len(),
		Some(serde_json::Value::Object(items)) => items.len(),
		_ => 0,
	};
	if method.ends_with("/get") {
		count("ids") > MAX_OBJECTS_IN_GET
	} else if method.ends_with("/set") {
		count("create") + count("update") + count("destroy") > MAX_OBJECTS_IN_SET
	} else if method.ends_with("/copy") {
		count("create") > MAX_OBJECTS_IN_SET
	} else {
		false
	}
}

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

/// The error for a request refused because its credential already has
/// `max` of them in flight; `limit` is `maxConcurrentRequests` or
/// `maxConcurrentUpload`. 429, as the same request succeeds once one of the
/// others ends.
pub(super) fn too_many_concurrent(limit: &str, max: usize) -> serde_json::Value {
	problem(
		limit,
		StatusCode::TOO_MANY_REQUESTS,
		&format!("at most {max} such requests may be in flight per credential"),
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
pub(super) fn problem(limit: &str, status: StatusCode, detail: &str) -> serde_json::Value {
	serde_json::json!({
		"type": "urn:ietf:params:jmap:error:limit",
		"limit": limit,
		"status": status.as_u16(),
		"detail": detail,
	})
}
