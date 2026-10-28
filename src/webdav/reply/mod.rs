//! The body of a `207 Multi-Status` REPORT reply, built in one `String` that
//! never grows past a byte budget.
//!
//! Every resource is escaped straight into the body, so the budget counts
//! the bytes the client receives and there is no second copy of the data. A
//! resource that does not fit is never left out silently: it is answered
//! with its own `507`, or, when the reply simply ran out, the reply ends with
//! the `DAV:number-of-matches-within-limits` truncation of RFC 6578 §3.6.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::propfind::{escape_into, escaped_len};

/// Whether a member was added to the reply.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Added {
	/// The member is in the reply.
	Yes,
	/// It does not fit what is left of the budget; nothing was added.
	NoRoom,
}

/// A multistatus under construction.
pub struct Reply {
	out: String,
	limit: usize,
	members: usize,
}

impl Reply {
	/// Start a reply with `head` (the XML declaration and the opening
	/// `multistatus` tag) that may reach `limit` bytes.
	pub fn new(head: &str, limit: u64) -> Self {
		Self {
			out: head.to_string(),
			limit: usize::try_from(limit).unwrap_or(usize::MAX),
			members: 0,
		}
	}

	/// How many bytes the body may still grow by.
	pub fn remaining(&self) -> u64 {
		self.limit.saturating_sub(self.out.len()) as u64
	}

	/// How many members with data or an etag were added.
	pub fn members(&self) -> usize {
		self.members
	}

	/// Append framing that is not a resource (a `404` entry, the sync
	/// token). The caller keeps it small.
	pub fn raw(&mut self, text: &str) {
		self.out.push_str(text);
	}

	/// Add a member carrying `getetag` and, when `data` is given, its
	/// content under the element `qname`.
	pub fn member(&mut self, href: &str, etag: &str, data: Option<(&str, &[u8])>) -> Added {
		let text = data.map(|(_, bytes)| String::from_utf8_lossy(bytes));
		let size = 400
			+ escaped_len(href)
			+ escaped_len(etag)
			+ text.as_ref().map_or(0, |text| 2 * 32 + escaped_len(text));
		if size as u64 > self.remaining() {
			return Added::NoRoom;
		}
		self.out.push_str("\t<D:response>\n\t\t<D:href>");
		escape_into(&mut self.out, href);
		self.out
			.push_str("</D:href>\n\t\t<D:propstat>\n\t\t\t<D:prop>\n\t\t\t\t<D:getetag>");
		escape_into(&mut self.out, etag);
		self.out.push_str("</D:getetag>\n");
		if let (Some((qname, _)), Some(text)) = (data, text) {
			self.out.push_str("\t\t\t\t<");
			self.out.push_str(qname);
			self.out.push('>');
			escape_into(&mut self.out, &text);
			self.out.push_str("</");
			self.out.push_str(qname);
			self.out.push_str(">\n");
		}
		self.out.push_str(
			"\t\t\t</D:prop>\n\t\t\t<D:status>HTTP/1.1 200 OK</D:status>\n\t\t</D:propstat>\n\t</D:response>\n",
		);
		self.members += 1;
		Added::Yes
	}

	/// Answer `href` with `507`: it is too large to be part of this reply and
	/// has to be asked for on its own.
	pub fn too_large(&mut self, href: &str) {
		self.out.push_str("\t<D:response>\n\t\t<D:href>");
		escape_into(&mut self.out, href);
		self.out.push_str(
			"</D:href>\n\t\t<D:status>HTTP/1.1 507 Insufficient Storage</D:status>\n\t</D:response>\n",
		);
	}

	/// End the results early: the reply holds what fitted, and `href` (the
	/// resource the request addressed) is answered `507` with the
	/// `number-of-matches-within-limits` condition.
	pub fn truncated(&mut self, href: &str) {
		self.out.push_str("\t<D:response>\n\t\t<D:href>");
		escape_into(&mut self.out, href);
		self.out.push_str(
			"</D:href>\n\t\t<D:status>HTTP/1.1 507 Insufficient Storage</D:status>\n\
			\t\t<D:error><D:number-of-matches-within-limits/></D:error>\n\t</D:response>\n",
		);
	}

	/// Close the multistatus after `tail` (the sync token, or nothing).
	pub fn finish(mut self, tail: &str) -> Response {
		self.out.push_str(tail);
		self.out.push_str("</D:multistatus>\n");
		(
			StatusCode::MULTI_STATUS,
			[(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
			self.out,
		)
			.into_response()
	}
}

#[cfg(test)]
mod tests;
