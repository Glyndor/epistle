//! The limits inbound mail is held to before it is accepted: a well-framed
//! line and a bounded number of header fields.

use crate::smtp::line::LineError;
use crate::smtp::reply::Reply;

/// The reply sent when the line decoder rejects a malformed line, closing the
/// connection (RFC 5321 framing violations).
pub(crate) fn line_error_reply(error: &LineError) -> Reply {
	match error {
		LineError::BareControlCharacter => Reply::single(
			554,
			"5.5.2 bare CR or LF is not allowed, closing connection",
		),
		LineError::TooLong => Reply::single(500, "5.5.2 line too long, closing connection"),
		LineError::NulByte => Reply::single(554, "5.5.2 NUL byte received, closing connection"),
	}
}

/// The most header fields inbound mail may carry. A Sieve filter reads the
/// first 10 000 headers of a message and the server adds a few dozen of its
/// own, so a message past this would have fields the filter never sees, and
/// no real message has anywhere near this many.
pub(crate) const MAX_HEADER_FIELDS: usize = 9_900;

/// Refuse a message with more header fields than [`MAX_HEADER_FIELDS`], and
/// say so: it is counted (`rejected_header_fields`) and logged at most once an
/// hour. This one check is made where SMTP has the message and again where
/// local delivery starts, so it is the same whichever way a message arrives.
/// The delivery counts the fields the server added too, so for mail with a
/// local recipient the effective limit is a few less than the constant.
pub(crate) fn refuse_padded_headers(
	data: &[u8],
	metrics: Option<&crate::metrics::Metrics>,
) -> Result<(), crate::smtp::sink::SinkError> {
	if crate::util::header_block::field_count(data) <= MAX_HEADER_FIELDS {
		return Ok(());
	}
	if let Some(metrics) = metrics {
		metrics.rejected(crate::metrics::RejectReason::HeaderFields);
	}
	if crate::util::warn_limited::allow("header-fields") {
		tracing::warn!("rejecting message: too many header fields");
	}
	Err(crate::smtp::sink::SinkError::TooManyHeaderFields)
}
