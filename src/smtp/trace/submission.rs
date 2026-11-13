//! The header fixes the submission paths apply before queueing: the
//! `Message-ID` and `Date` a client forgot, and the `Bcc` it must not leak.

use std::time::SystemTime;

use super::{header_block_end, strip_headers, strip_headers_in_place};

/// Stamp the two submission-mandatory headers the receiver contract expects
/// (`Message-ID` and `Date`) on an authenticated client submission when the
/// client omitted them.
///
/// The function scans the header block (everything up to the first blank
/// line, CRLF or LF terminator) for `Message-ID:` and `Date:` field names,
/// case-insensitive and respecting folded continuation lines (a line that
/// starts with WSP is part of the previous header, never a fresh one). If
/// either field is absent the server adds it at the top of the block; the
/// fresh pair is prepended in `Message-ID`, `Date` order so a single
/// observation reveals both. When both are already present the bytes are
/// returned unchanged.
///
/// Applied only on the authenticated submission paths: the SMTP relay hop
/// from another server is never modified, so the inbound trace keeps the
/// sender's own Message-ID and Date exactly as received. Receivers score
/// outbound mail down (and Gmail and Yahoo have outright rejected it since
/// 2024) when these headers are missing on authenticated submission, so
/// the server stamps them only when the client forgot.
///
/// `domain` is the local part's authoritative domain (the reverse-path
/// domain for the SMTP submission path, the envelope `mailFrom` for JMAP
/// `EmailSubmission/set`). The minted `Message-ID` reads
/// `<uuidv7@domain>`, matching the shape `POST /api/v1/send` already emits.
pub fn ensure_submission_headers(data: &[u8], domain: &str, now: SystemTime) -> Vec<u8> {
	let header_end = header_block_end(data);
	let headers = &data[..header_end];
	let body = &data[header_end..];
	let (has_message_id, has_date) = scan_submission_headers(headers);
	if has_message_id && has_date {
		return data.to_vec();
	}
	let ending = std::str::from_utf8(crate::util::header_block::line_ending(data))
		.expect("ASCII line ending");
	let mut prepended = String::new();
	if !has_message_id {
		prepended.push_str(&format!(
			"Message-ID: <{}@{domain}>{ending}",
			uuid::Uuid::now_v7()
		));
	}
	if !has_date {
		prepended.push_str(&format!("Date: {}{ending}", crate::clock::rfc5322(now)));
	}
	let mut out = Vec::with_capacity(data.len() + prepended.len());
	out.extend_from_slice(prepended.as_bytes());
	out.extend_from_slice(headers);
	out.extend_from_slice(body);
	out
}

/// In-place submission-header stamp: rewrite `data` to carry the
/// `Message-ID` and `Date` headers the receiver contract expects when
/// the client omitted them. When both are already present, the
/// buffer is left untouched. The header lines are prepended in
/// `Message-ID`, `Date` order; the message is shifted up inside the
/// same buffer instead of being copied into a new one.
pub fn ensure_submission_headers_in_place(data: &mut Vec<u8>, domain: &str, now: SystemTime) {
	let header_end = header_block_end(data);
	let (has_message_id, has_date) = scan_submission_headers(&data[..header_end]);
	if has_message_id && has_date {
		return;
	}
	let ending = std::str::from_utf8(crate::util::header_block::line_ending(data))
		.expect("ASCII line ending");
	let prepended = build_prepended_headers(domain, now, has_message_id, has_date, ending);
	// Grow by exactly the prepended size (no doubling of a 25 MiB
	// buffer), shift the message up with one memmove, then write the
	// new headers in front.
	let original_len = data.len();
	data.reserve_exact(prepended.len());
	data.resize(original_len + prepended.len(), 0);
	data.copy_within(..original_len, prepended.len());
	data[..prepended.len()].copy_from_slice(&prepended);
}

/// Build the prepended submission-header bytes for the in-place
/// stamp helper. Kept in a small function so the allocation lives
/// only as long as the byte slice we copy from.
fn build_prepended_headers(
	domain: &str,
	now: SystemTime,
	has_message_id: bool,
	has_date: bool,
	ending: &str,
) -> Vec<u8> {
	let mut out = Vec::new();
	if !has_message_id {
		out.extend_from_slice(
			format!("Message-ID: <{}@{domain}>{ending}", uuid::Uuid::now_v7()).as_bytes(),
		);
	}
	if !has_date {
		out.extend_from_slice(format!("Date: {}{ending}", crate::clock::rfc5322(now)).as_bytes());
	}
	out
}

/// `data` without its `Bcc:` and `Resent-Bcc:` header fields, continuation
/// lines included; the body is untouched.
///
/// The submission paths (authenticated SMTP, JMAP `EmailSubmission/set`)
/// apply this before queueing: a Bcc recipient is on the envelope only, and
/// every copy that leaves the server, local or remote, must not name it
/// (RFC 5322 section 3.6.3, RFC 8621 section 7.5).
pub fn strip_bcc(data: &[u8]) -> Vec<u8> {
	strip_headers(data, &["bcc", "resent-bcc"])
}

/// In-place Bcc strip: `data` is cleared and rewritten without the
/// `Bcc:` and `Resent-Bcc:` fields (and their folded continuations).
/// Saves a full body copy at the cost of growing the buffer up to
/// `data.len()` once, which is what the original allocator would
/// have done anyway.
pub fn strip_bcc_in_place(data: &mut Vec<u8>) {
	strip_headers_in_place(data, &["bcc", "resent-bcc"]);
}

/// Whether the header block already carries each of `Message-ID:` and
/// `Date:`. Field names match case-insensitively; folded continuation
/// lines (starting with WSP) belong to the previous field and never start
/// a new one.
fn scan_submission_headers(headers: &[u8]) -> (bool, bool) {
	let mut has_message_id = false;
	let mut has_date = false;
	for line in split_header_lines(headers) {
		if line.is_empty() {
			break;
		}
		if matches!(line.first(), Some(b' ' | b'\t')) {
			continue;
		}
		let name = match line.iter().position(|&b| b == b':') {
			Some(pos) => &line[..pos],
			None => continue,
		};
		if name.eq_ignore_ascii_case(b"message-id") {
			has_message_id = true;
		} else if name.eq_ignore_ascii_case(b"date") {
			has_date = true;
		}
		if has_message_id && has_date {
			break;
		}
	}
	(has_message_id, has_date)
}

/// Iterate the header block line by line, stripping the trailing CR of a
/// CRLF terminator. A blank line is yielded as an empty slice.
fn split_header_lines(headers: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
	headers.split(|&b| b == b'\n').map(strip_cr)
}

/// Drop a trailing `\r` from a header line slice.
fn strip_cr(line: &[u8]) -> &[u8] {
	if line.last() == Some(&b'\r') {
		&line[..line.len() - 1]
	} else {
		line
	}
}
