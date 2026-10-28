//! How a CA refuses a request: the ACME problem document (RFC 8555 §6.7).
//!
//! A CA that does not accept a request answers with a non-2xx status and a
//! JSON document naming the error: its `type` URI and a human-readable
//! `detail`. Reading that document is the difference between "expected value
//! at line 4 column 13" and the reason the request was refused: parsed as
//! the resource that was asked for, the document's numeric `status` lands on
//! an enum field and the JSON parser stops there, taking the real cause with
//! it.
//!
//! A body that is not a problem document is a different failure: something in
//! front of the CA answered (a proxy, a captive portal, a misrouted request).
//! Only the status and the bytes are known then, and the bytes are kept as a
//! snippet so the operator can still see what came back.

use serde::Deserialize;

/// A CA's problem document (RFC 8555 §6.7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Problem {
	/// The error type URI, for example
	/// `urn:ietf:params:acme:error:unauthorized`.
	#[serde(rename = "type")]
	pub kind: Option<String>,
	/// The human-readable explanation of the failure.
	#[serde(default)]
	pub detail: Option<String>,
}

/// A refusal, read from an answer that was not a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
	/// The HTTP status of the answer.
	pub status: u16,
	/// The problem type URI, when the answer was a problem document.
	pub kind: Option<String>,
	/// The problem detail, when the answer was a problem document.
	pub detail: Option<String>,
	/// A snippet of the body, when the answer was not a problem document.
	pub snippet: Option<String>,
}

/// How many characters of a body that is not a problem document are kept.
const SNIPPET_LIMIT: usize = 200;

impl Refusal {
	/// Read the refusal out of an answer that was not a success.
	///
	/// A body that parses as a problem document with a `type` is one; any
	/// other body (invalid JSON, JSON without a `type`, an HTML error page) is
	/// kept as a snippet instead.
	pub fn read(status: u16, body: &[u8]) -> Self {
		match serde_json::from_slice::<Problem>(body) {
			Ok(problem) if problem.kind.is_some() => Refusal {
				status,
				kind: problem.kind,
				detail: problem.detail,
				snippet: None,
			},
			_ => Refusal {
				status,
				kind: None,
				detail: None,
				snippet: Some(snippet(body)),
			},
		}
	}

	/// Whether the CA refused in ACME terms: the answer was a problem
	/// document, so its `type` and `detail` name the reason.
	pub fn is_problem(&self) -> bool {
		self.kind.is_some()
	}

	/// One line naming what the answer said.
	pub fn describe(&self) -> String {
		if let Some(kind) = &self.kind {
			let mut out = format!("ACME answered {}: {kind}", self.status);
			if let Some(detail) = &self.detail {
				out.push_str(": ");
				out.push_str(detail);
			}
			return out;
		}
		match self.snippet.as_deref() {
			Some(snippet) if !snippet.is_empty() => {
				format!("ACME answered {}: {snippet}", self.status)
			}
			_ => format!("ACME answered {} with an empty body", self.status),
		}
	}
}

/// The first characters of a body that is not a problem document, with the
/// whitespace collapsed so a log line stays one line.
fn snippet(body: &[u8]) -> String {
	let text = String::from_utf8_lossy(body);
	let mut out = String::new();
	let mut kept = 0;
	let mut pending_space = false;
	for ch in text.chars() {
		if kept >= SNIPPET_LIMIT {
			break;
		}
		if ch.is_whitespace() {
			pending_space = !out.is_empty();
			continue;
		}
		if pending_space {
			out.push(' ');
			pending_space = false;
		}
		out.push(ch);
		kept += 1;
	}
	out
}

#[cfg(test)]
#[path = "problem_tests.rs"]
mod tests;
