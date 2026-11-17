//! The API error shape: `{"error": {"code", "message"}}`, or an RFC 9457
//! problem when the request asks for `application/problem+json` (see
//! [`problem`]). A `401` always carries `WWW-Authenticate: Bearer` and a
//! `429` always carries `Retry-After`.

mod problem;

use axum::Json;
use axum::http::header::{RETRY_AFTER, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub(in crate::api) use problem::negotiate;

/// What a refused input is wrong with. The default body keeps the one code
/// `invalid_input`; the problem body names the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
	/// A field the request needs is absent or empty.
	Missing,
	/// A value over or under what the field accepts (a length, a count).
	OutOfRange,
	/// A value of the right kind that the field does not accept.
	NotAllowed,
}

impl Cause {
	pub(crate) fn code(self) -> &'static str {
		match self {
			Self::Missing => "field_missing",
			Self::OutOfRange => "field_out_of_range",
			Self::NotAllowed => "value_not_allowed",
		}
	}
}

/// An API error with a machine-readable code.
#[derive(Debug, Default)]
pub struct ApiError {
	pub status: StatusCode,
	pub code: &'static str,
	pub message: String,
	/// Seconds a `429` asks the client to wait, sent as `Retry-After`.
	pub retry_after: Option<u64>,
	/// The cause of an `invalid_input`, when known.
	pub cause: Option<Cause>,
	/// The request field an `invalid_input` is about, when known.
	pub field: Option<&'static str>,
}

/// What a response needs to be rewritten as a problem: put in its
/// extensions by [`ApiError::into_response`], read by [`negotiate`].
#[derive(Debug, Clone)]
pub(crate) struct ErrorInfo {
	status: StatusCode,
	code: &'static str,
	message: String,
	field: Option<&'static str>,
}

impl ApiError {
	pub fn unauthenticated() -> Self {
		ApiError {
			status: StatusCode::UNAUTHORIZED,
			code: "unauthenticated",
			message: "A valid bearer token is required.".to_string(),
			..Default::default()
		}
	}

	pub fn not_found(message: &str) -> Self {
		ApiError {
			status: StatusCode::NOT_FOUND,
			code: "not_found",
			message: message.to_string(),
			..Default::default()
		}
	}

	pub fn invalid_input(message: &str) -> Self {
		ApiError {
			status: StatusCode::BAD_REQUEST,
			code: "invalid_input",
			message: message.to_string(),
			..Default::default()
		}
	}

	/// `400` for a required `field` that is absent or empty. The default
	/// body is the same `invalid_input` as any other bad input.
	pub fn field_missing(field: &'static str, message: &str) -> Self {
		Self::invalid_field(Cause::Missing, field, message)
	}

	/// `400` for a `field` whose value is over or under what it accepts.
	pub fn field_out_of_range(field: &'static str, message: &str) -> Self {
		Self::invalid_field(Cause::OutOfRange, field, message)
	}

	/// `400` for a `field` whose value is not one it accepts.
	pub fn value_not_allowed(field: &'static str, message: &str) -> Self {
		Self::invalid_field(Cause::NotAllowed, field, message)
	}

	fn invalid_field(cause: Cause, field: &'static str, message: &str) -> Self {
		ApiError {
			cause: Some(cause),
			field: Some(field),
			..Self::invalid_input(message)
		}
	}

	pub fn internal() -> Self {
		ApiError {
			status: StatusCode::INTERNAL_SERVER_ERROR,
			code: "internal",
			message: "Internal error.".to_string(),
			..Default::default()
		}
	}

	/// `429` for the authentication limits; `retry_after` is the wait in
	/// seconds, which every `429` states.
	pub fn rate_limited(retry_after: u64) -> Self {
		ApiError {
			status: StatusCode::TOO_MANY_REQUESTS,
			code: "rate_limited",
			message: "Too many failed authentication attempts. Try again later.".to_string(),
			retry_after: Some(retry_after),
			..Default::default()
		}
	}

	/// `429` for an outbound submission rate limit, with the caller-supplied
	/// detail (which tenant rejected, which cap was hit) and the wait in
	/// seconds. Distinct from `rate_limited`, which is reserved for the
	/// auth-failure sliding window on the bearer-token middleware.
	pub fn rate_limited_with_message(message: impl Into<String>, retry_after: u64) -> Self {
		ApiError {
			status: StatusCode::TOO_MANY_REQUESTS,
			code: "rate_limited",
			message: message.into(),
			retry_after: Some(retry_after),
			..Default::default()
		}
	}

	/// `403` for a route the calling credential may not use at all.
	pub fn forbidden(message: &str) -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "forbidden",
			message: message.to_string(),
			..Default::default()
		}
	}

	/// `403` for a submission whose envelope sender the acting account does
	/// not own. One answer for every such sender, owned by another account
	/// or by none, so the refusal says nothing about which addresses exist.
	pub fn forbidden_from() -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "forbidden_from",
			message: "The sender address is not owned by an account this credential may act for."
				.to_string(),
			..Default::default()
		}
	}

	/// `403` for a submission by an account whose sending is switched off.
	/// Unlike `forbidden_from` it names the cause, which is the account's
	/// own state and tells nothing about other addresses.
	pub fn sending_off() -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "sending_off",
			message: "Sending is turned off for this account.".to_string(),
			..Default::default()
		}
	}

	/// `403` for an account-bound API key on a route outside its account
	/// surface.
	pub fn account_bound_route() -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "forbidden",
			message: "This key is bound to one account and only reaches JMAP, /api/v1/send, /api/v1/deliveries and its suppression list."
				.to_string(),
			..Default::default()
		}
	}

	/// `403` for an account-bound API key whose account is disabled or no
	/// longer exists. One answer for both, the same refusal the JMAP
	/// WebSocket gives such a key mid-connection.
	pub fn bound_account_unavailable() -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "forbidden",
			message: "The account this key is bound to is disabled or no longer exists."
				.to_string(),
			..Default::default()
		}
	}

	/// `507` for a local recipient whose mailbox is full, or would be with
	/// this message: nothing was queued; the recipient has to make room or
	/// be left out.
	pub fn mailbox_full(recipient: &str) -> Self {
		ApiError {
			status: StatusCode::INSUFFICIENT_STORAGE,
			code: "mailbox_full",
			message: format!("The mailbox of {recipient} is full; nothing was sent."),
			..Default::default()
		}
	}

	/// `413` for a message that is over the size limit once built: the
	/// encoded bodies and attachments did not fit, whatever the request size.
	pub fn message_too_large(limit: usize) -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "message_too_large",
			message: format!("The message is larger than {limit} bytes once built."),
			..Default::default()
		}
	}

	/// `422` for a message the antivirus refused: nothing was sent, and
	/// sending it again is refused again. The signature tells the sender
	/// what was found.
	pub fn virus_detected(signature: &str) -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "virus_detected",
			message: format!("The message was rejected: virus detected ({signature})."),
			..Default::default()
		}
	}

	/// `422` for a message the attachment policy refused; `reasons` are
	/// the comma-separated reason codes, never text from the message.
	pub fn attachment_refused(reasons: &str) -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "attachment_refused",
			message: format!("The message was rejected: attachment type not accepted ({reasons})."),
			..Default::default()
		}
	}

	/// `503` when the content scan cannot run now: retrying later works,
	/// and nothing was sent.
	pub fn scan_unavailable() -> Self {
		ApiError {
			status: StatusCode::SERVICE_UNAVAILABLE,
			code: "scan_unavailable",
			message: "The content scan is unavailable. Try again later.".to_string(),
			..Default::default()
		}
	}

	/// `413` for a message too large for the content scan while the server
	/// lets nothing pass unscanned: retrying cannot help, nothing was sent.
	pub fn scan_too_large() -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "scan_too_large",
			message: "The message is too large for the content scan and was not sent.".to_string(),
			..Default::default()
		}
	}

	/// `422` for a message with more header fields than a filter reads:
	/// sending it again unchanged is refused again, nothing was sent.
	pub fn too_many_header_fields() -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "too_many_header_fields",
			message: "The message has too many header fields and was not sent.".to_string(),
			..Default::default()
		}
	}

	/// `422` for marketing mail without the one-click unsubscribe RFC 8058
	/// requires: sending it again unchanged is refused again.
	pub fn marketing_refused(message: &str) -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "marketing_refused",
			message: format!("The message was refused: {message}."),
			..Default::default()
		}
	}

	/// `503` for transactional mail whose evidence cannot be recorded right
	/// now (or is held until an operator acknowledges a break): nothing was
	/// sent, and the request may be retried later.
	pub fn evidence_unavailable() -> Self {
		ApiError {
			status: StatusCode::SERVICE_UNAVAILABLE,
			code: "evidence_unavailable",
			message: "Transactional mail cannot be recorded as evidence right now; retry later."
				.into(),
			..Default::default()
		}
	}

	/// `409` for a submission that can no longer be cancelled: it was already
	/// handed on, and nothing can take it back.
	pub fn already_sent() -> Self {
		ApiError {
			status: StatusCode::CONFLICT,
			code: "already_sent",
			message: "The message was already handed on and cannot be cancelled.".into(),
			..Default::default()
		}
	}

	/// `409` for a configured cap that stopped the request: the message says
	/// which limit, its value, the scope that set it and how to make room.
	/// Waiting will not lift it, so it is not a `429`.
	pub fn limit_reached(reached: &crate::limits::LimitReached) -> Self {
		ApiError {
			status: StatusCode::CONFLICT,
			code: "limit_reached",
			message: reached.to_string(),
			..Default::default()
		}
	}

	/// `413` for a message over the size cap of the account that sends it.
	pub fn message_over_cap(reached: &crate::limits::LimitReached) -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "message_too_large",
			message: reached.to_string(),
			..Default::default()
		}
	}

	/// `413` for a message over the size cap of a local recipient. The cap of
	/// a recipient is not told to the sender.
	pub fn recipient_over_cap() -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "message_too_large",
			message: "The message is over the size limit of a recipient of this server.".into(),
			..Default::default()
		}
	}

	/// `409` for a limit that waiting will never clear. A `429` here would
	/// tell the client to retry, which is the one thing that cannot help: the
	/// cap lifts when the caller deletes something or an admin raises it.
	pub fn conflict(message: impl Into<String>) -> Self {
		ApiError {
			status: StatusCode::CONFLICT,
			code: "conflict",
			message: message.into(),
			..Default::default()
		}
	}
}

#[derive(Serialize)]
struct ErrorBody {
	error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
	code: &'static str,
	message: String,
}

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		let info = ErrorInfo {
			status: self.status,
			code: self.cause.map_or(self.code, Cause::code),
			message: self.message.clone(),
			field: self.field,
		};
		let body = ErrorBody {
			error: ErrorDetail {
				code: self.code,
				message: self.message,
			},
		};
		let mut response = (self.status, Json(body)).into_response();
		if self.status == StatusCode::UNAUTHORIZED {
			// RFC 6750 section 3: a 401 names the scheme that is accepted.
			response
				.headers_mut()
				.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
		}
		if let Some(seconds) = self.retry_after {
			response.headers_mut().insert(RETRY_AFTER, seconds.into());
		}
		response.extensions_mut().insert(info);
		response
	}
}

#[cfg(test)]
mod tests;
