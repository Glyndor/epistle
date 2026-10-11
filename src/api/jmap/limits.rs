//! The request limits the JMAP Session advertises (RFC 8620 §2) and the
//! checks that enforce them (§3.6.1). One constant per limit, read both by
//! the Session resource and by the code that applies it, so what a client is
//! told and what the server does cannot drift apart.

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
	serde_json::json!({
		"type": "urn:ietf:params:jmap:error:limit",
		"limit": "maxCallsInRequest",
		"status": 400,
		"detail": format!("a request may carry at most {MAX_CALLS_IN_REQUEST} method calls"),
	})
}
