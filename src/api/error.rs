//! The API error shape: `{"error": {"code", "message"}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// An API error with a machine-readable code.
#[derive(Debug)]
pub struct ApiError {
	pub status: StatusCode,
	pub code: &'static str,
	pub message: String,
}

impl ApiError {
	pub fn unauthenticated() -> Self {
		ApiError {
			status: StatusCode::UNAUTHORIZED,
			code: "unauthenticated",
			message: "A valid bearer token is required.".to_string(),
		}
	}

	pub fn not_found(message: &str) -> Self {
		ApiError {
			status: StatusCode::NOT_FOUND,
			code: "not_found",
			message: message.to_string(),
		}
	}

	pub fn invalid_input(message: &str) -> Self {
		ApiError {
			status: StatusCode::BAD_REQUEST,
			code: "invalid_input",
			message: message.to_string(),
		}
	}

	pub fn internal() -> Self {
		ApiError {
			status: StatusCode::INTERNAL_SERVER_ERROR,
			code: "internal",
			message: "Internal error.".to_string(),
		}
	}

	pub fn rate_limited() -> Self {
		ApiError {
			status: StatusCode::TOO_MANY_REQUESTS,
			code: "rate_limited",
			message: "Too many failed authentication attempts. Try again later.".to_string(),
		}
	}

	/// `429` for an outbound submission rate limit, with the caller-supplied
	/// detail (which tenant rejected, which cap was hit). Distinct from
	/// `rate_limited`, which is reserved for the auth-failure sliding window
	/// on the bearer-token middleware.
	pub fn rate_limited_with_message(message: impl Into<String>) -> Self {
		ApiError {
			status: StatusCode::TOO_MANY_REQUESTS,
			code: "rate_limited",
			message: message.into(),
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
		}
	}

	/// `403` for an account-bound API key on a route outside JMAP and
	/// `/api/v1/send`.
	pub fn account_bound_route() -> Self {
		ApiError {
			status: StatusCode::FORBIDDEN,
			code: "forbidden",
			message: "This key is bound to one account and only reaches JMAP and /api/v1/send."
				.to_string(),
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
		}
	}

	/// `413` for a message that is over the size limit once built: the
	/// encoded bodies and attachments did not fit, whatever the request size.
	pub fn message_too_large(limit: usize) -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "message_too_large",
			message: format!("The message is larger than {limit} bytes once built."),
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
		}
	}

	/// `422` for a message the attachment policy refused; `reasons` are
	/// the comma-separated reason codes, never text from the message.
	pub fn attachment_refused(reasons: &str) -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "attachment_refused",
			message: format!("The message was rejected: attachment type not accepted ({reasons})."),
		}
	}

	/// `503` when the content scan cannot run now: retrying later works,
	/// and nothing was sent.
	pub fn scan_unavailable() -> Self {
		ApiError {
			status: StatusCode::SERVICE_UNAVAILABLE,
			code: "scan_unavailable",
			message: "The content scan is unavailable. Try again later.".to_string(),
		}
	}

	/// `413` for a message too large for the content scan while the server
	/// lets nothing pass unscanned: retrying cannot help, nothing was sent.
	pub fn scan_too_large() -> Self {
		ApiError {
			status: StatusCode::PAYLOAD_TOO_LARGE,
			code: "scan_too_large",
			message: "The message is too large for the content scan and was not sent.".to_string(),
		}
	}

	/// `422` for marketing mail without the one-click unsubscribe RFC 8058
	/// requires: sending it again unchanged is refused again.
	pub fn marketing_refused(message: &str) -> Self {
		ApiError {
			status: StatusCode::UNPROCESSABLE_ENTITY,
			code: "marketing_refused",
			message: format!("The message was refused: {message}."),
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
		let body = ErrorBody {
			error: ErrorDetail {
				code: self.code,
				message: self.message,
			},
		};
		(self.status, Json(body)).into_response()
	}
}

#[cfg(test)]
mod tests {
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
}
