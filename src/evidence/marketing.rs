//! What a `marketing` submission must carry, and what the server adds.
//!
//! Bulk mail is accepted only with a working one-click unsubscribe (RFC
//! 8058): a `List-Unsubscribe` field naming an `https` URI and exactly one
//! `List-Unsubscribe-Post: List-Unsubscribe=One-Click`. The large mailbox
//! providers have refused bulk mail without it since 2024, and a sender
//! that cannot honour an unsubscribe has no business sending bulk mail
//! from this server. The server then marks the message `Precedence: bulk`
//! so auto-responders on the other side stay quiet (RFC 3834 section 2).

use crate::smtp::trace::{header_values, strip_headers_in_place};

/// Why a submission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarketingRefusal {
	/// No `List-Unsubscribe` field naming an `https` URI.
	NoUnsubscribeUri,
	/// No single `List-Unsubscribe-Post: List-Unsubscribe=One-Click` field.
	NoOneClick,
	/// A header field name contains embedded whitespace or a control byte.
	AmbiguousHeaderName,
	/// A header block contains a bare carriage return or mixed line endings.
	AmbiguousHeaderFraming,
	/// A header line does not follow RFC 5322 field or folding syntax.
	MalformedHeaderLine,
	/// I cannot read the submitted header block as UTF-8.
	InvalidHeaderEncoding,
	/// I see different identity field counts through the two header readers.
	HeaderReaderMismatch,
	/// I see a field consumed by another field's parser.
	HeaderReaderFramingMismatch,
	/// The header block holds more fields than the server reads.
	TooManyHeaderFields,
	/// The message carries a NUL or a bare carriage return.
	AmbiguousLineFraming,
}

impl MarketingRefusal {
	/// The text of the refusal, the same on SMTP, REST and JMAP.
	pub fn message(self) -> &'static str {
		match self {
			Self::HeaderReaderFramingMismatch => {
				"I cannot accept headers whose field boundaries disagree between readers"
			}
			Self::TooManyHeaderFields => "submission headers hold more fields than I accept",
			Self::InvalidHeaderEncoding => "I cannot accept submission headers that are not UTF-8",
			Self::HeaderReaderMismatch => {
				"I cannot accept headers whose From or Sender field counts disagree between readers"
			}
			Self::NoUnsubscribeUri => {
				"marketing mail needs a List-Unsubscribe field with an https URI (RFC 8058)"
			}
			Self::NoOneClick => {
				"marketing mail needs List-Unsubscribe-Post: List-Unsubscribe=One-Click (RFC 8058)"
			}
			Self::AmbiguousHeaderName => {
				"submission header field names must use printable ASCII without embedded whitespace"
			}
			Self::AmbiguousHeaderFraming => {
				"submission headers must use one line-ending style without a bare carriage return"
			}
			Self::AmbiguousLineFraming => {
				"a submitted message must not contain a NUL or a bare carriage return"
			}
			Self::MalformedHeaderLine => {
				"submission header lines must follow RFC 5322 field and folding syntax"
			}
		}
	}

	/// The SMTP reply refusing the message: permanent, the same message
	/// would be refused again.
	pub fn smtp_reply(self) -> crate::smtp::reply::Reply {
		crate::smtp::reply::Reply::single(550, &format!("5.7.1 {}", self.message()))
	}
}

/// The value RFC 8058 section 3.1 requires in `List-Unsubscribe-Post`.
const ONE_CLICK: &str = "List-Unsubscribe=One-Click";

/// Check that `data` carries the one-click unsubscribe RFC 8058 requires.
pub fn check(data: &[u8]) -> Result<(), MarketingRefusal> {
	let has_https = header_values(data, "list-unsubscribe")
		.iter()
		.any(|value| has_https_uri(value));
	if !has_https {
		return Err(MarketingRefusal::NoUnsubscribeUri);
	}
	match header_values(data, "list-unsubscribe-post").as_slice() {
		[value] if value == ONE_CLICK => Ok(()),
		_ => Err(MarketingRefusal::NoOneClick),
	}
}

/// Whether a `List-Unsubscribe` value names an `https` URI in angle
/// brackets (RFC 2369 section 2), the form RFC 8058 posts to.
fn has_https_uri(value: &str) -> bool {
	value.split('<').skip(1).any(|part| {
		part.split_once('>').is_some_and(|(uri, _)| {
			uri.len() > "https://".len()
				&& uri
					.get(..8)
					.is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
		})
	})
}

/// Mark `data` as bulk mail: any `Precedence` field the client wrote is
/// replaced by one `Precedence: bulk` at the top of the header block.
pub fn mark_bulk(data: &mut Vec<u8>) {
	strip_headers_in_place(data, &["precedence"]);
	let mut marked = Vec::with_capacity(data.len() + 18);
	marked.extend_from_slice(b"Precedence: bulk\r\n");
	marked.append(data);
	*data = marked;
}

#[cfg(test)]
#[path = "marketing_tests.rs"]
mod tests;
