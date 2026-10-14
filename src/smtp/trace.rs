//! Trace and authentication headers stamped onto accepted mail.

use std::net::IpAddr;
use std::time::SystemTime;

use super::line::LineError;
use super::reply::Reply;

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

/// The domain SPF evaluates: the MAIL FROM domain, or the HELO domain for
/// the null reverse-path (RFC 7208 section 2.4).
pub(crate) fn spf_domain(reverse_path: &str, helo: Option<&str>) -> Option<String> {
	if reverse_path.is_empty() {
		return helo.map(|h| h.to_string());
	}
	reverse_path
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_ascii_lowercase())
}

/// The maximum number of `Received:` trace headers tolerated on inbound mail
/// before it is treated as a loop (RFC 5321 section 6.3).
pub(crate) const RECEIVED_HOP_LIMIT: usize = 100;

/// Count the `Received:` header fields already present in a raw message,
/// scanning only the header block (up to the first blank line). Folded
/// continuation lines do not start a new header, so they are not counted.
pub(crate) fn received_hop_count(data: &[u8]) -> usize {
	let header_end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|p| p + 2)
		.unwrap_or(data.len());
	let block = String::from_utf8_lossy(&data[..header_end]);
	block
		.split_inclusive('\n')
		.filter(|line| {
			let first = line.as_bytes().first();
			// A new header starts at the line start (no leading WSP).
			!matches!(first, Some(b' ' | b'\t'))
				&& line.len() >= 9
				&& line[..9].eq_ignore_ascii_case("received:")
		})
		.count()
}

/// Build the RFC 5321 section 4.4 trace header prepended to accepted mail.
pub(crate) fn received_header(
	helo: Option<&str>,
	peer: Option<IpAddr>,
	hostname: &str,
	esmtp: bool,
	tls: bool,
	auth: bool,
	now: std::time::SystemTime,
) -> String {
	let client = helo.unwrap_or("unknown");
	let peer = match peer {
		Some(ip) => format!("[{ip}]"),
		None => "[unknown]".to_string(),
	};
	let protocol = received_protocol(esmtp, tls, auth);
	format!(
		"Received: from {client} ({peer})\r\n\tby {hostname} with {protocol};\r\n\t{}\r\n",
		crate::clock::rfc5322(now)
	)
}

/// The `with` protocol keyword for the trace header, per RFC 3848.
/// Plain HELO is `SMTP`; EHLO is `ESMTP`, gaining an `S` over TLS and an
/// `A` once authenticated (`ESMTPS`, `ESMTPA`, `ESMTPSA`).
pub(crate) fn received_protocol(esmtp: bool, tls: bool, auth: bool) -> &'static str {
	if !esmtp {
		return "SMTP";
	}
	match (tls, auth) {
		(true, true) => "ESMTPSA",
		(true, false) => "ESMTPS",
		(false, true) => "ESMTPA",
		(false, false) => "ESMTP",
	}
}

/// Build a folded `Authentication-Results` header (RFC 8601 §2.2).
/// Each method result is placed on a separate folded continuation line.
pub(crate) fn format_auth_results(hostname: &str, methods: &[String]) -> String {
	let mut out = format!("Authentication-Results: {hostname}");
	for method in methods {
		out.push_str(";\r\n\t");
		out.push_str(method);
	}
	out.push_str("\r\n");
	out
}

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
	let mut prepended = String::new();
	if !has_message_id {
		prepended.push_str(&format!(
			"Message-ID: <{}@{domain}>\r\n",
			uuid::Uuid::now_v7()
		));
	}
	if !has_date {
		prepended.push_str(&format!("Date: {}\r\n", crate::clock::rfc5322(now)));
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
	let prepended = build_prepended_headers(domain, now, has_message_id, has_date);
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
) -> Vec<u8> {
	let mut out = Vec::new();
	if !has_message_id {
		out.extend_from_slice(
			format!("Message-ID: <{}@{domain}>\r\n", uuid::Uuid::now_v7()).as_bytes(),
		);
	}
	if !has_date {
		out.extend_from_slice(format!("Date: {}\r\n", crate::clock::rfc5322(now)).as_bytes());
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

/// `data` without any header field whose name is one of `names` (compared
/// case-insensitively), folded continuation lines included. The body and
/// every other field are kept byte for byte.
pub fn strip_headers(data: &[u8], names: &[&str]) -> Vec<u8> {
	let header_end = header_block_end(data);
	let mut out = Vec::with_capacity(data.len());
	let mut dropping = false;
	for line in data[..header_end].split_inclusive(|&b| b == b'\n') {
		let continuation = matches!(line.first(), Some(b' ' | b'\t'));
		if !continuation {
			dropping = field_name(line).is_some_and(|name| {
				names
					.iter()
					.any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
			});
		}
		if !dropping {
			out.extend_from_slice(line);
		}
	}
	out.extend_from_slice(&data[header_end..]);
	out
}

/// In-place header strip: rewrite `data` in place to remove every
/// header field whose name is one of `names`, folded continuation
/// lines included. Saves the body copy the slice-returning variant
/// forces. The buffer grows up to `data.len()` once; nothing is
/// reallocated when no field matches.
pub fn strip_headers_in_place(data: &mut Vec<u8>, names: &[&str]) {
	let header_end = header_block_end(data);
	// Pre-compute the kept lines' (original start, length) so the
	// in-place copy can read from the right place in the original
	// buffer even after earlier lines have been moved down. The
	// structure mirrors the slice-returning `strip_headers`: walk
	// the header block line by line, drop the right ones, and keep
	// a list of (kept_offset, kept_length) pairs to copy afterwards.
	struct Kept {
		offset: usize,
		length: usize,
	}
	let mut kept: Vec<Kept> = Vec::new();
	let mut dropping = false;
	let mut cursor = 0usize;
	while cursor < header_end {
		let line_start = cursor;
		let mut line_end = line_start;
		while line_end < header_end && data[line_end] != b'\n' {
			line_end += 1;
		}
		if line_end < header_end {
			line_end += 1; // include the LF
		}
		let line = &data[line_start..line_end];
		let continuation = matches!(line.first(), Some(b' ' | b'\t'));
		if !continuation {
			dropping = field_name(line).is_some_and(|name| {
				names
					.iter()
					.any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
			});
		}
		if !dropping {
			kept.push(Kept {
				offset: line_start,
				length: line.len(),
			});
		}
		cursor = line_end;
	}
	// Compact: copy every kept line to its new offset, then move
	// the body up to follow. Forward iteration with forward
	// copies works because the kept lines' sources are
	// monotonically increasing and each destination lies below
	// the next source: the first copy reads from [0, len) and
	// writes to [0, len) (no-op), the second reads from a
	// higher range and writes below it, and so on. When the
	// destination range overlaps the source (which happens when
	// the kept line sits in the same offset range as the next
	// kept line, with the dropped bytes in between), the
	// destination is below the source so a forward copy reads
	// from the source before any write touches it.
	let mut write_to = 0usize;
	for kept_line in &kept {
		let dst_start = write_to;
		let dst_end = dst_start + kept_line.length;
		if dst_start >= kept_line.offset {
			// Destination is at or past the start of the
			// source: the two ranges overlap. The destination
			// is below the source (the kept line was dropped
			// from a higher offset), so a forward copy reads
			// the source before the write touches it.
			for i in 0..kept_line.length {
				data[dst_start + i] = data[kept_line.offset + i];
			}
		} else {
			data.copy_within(
				kept_line.offset..kept_line.offset + kept_line.length,
				dst_start,
			);
		}
		write_to = dst_end;
	}
	let body_len = data.len() - header_end;
	if body_len > 0 {
		// Move the body up to follow the kept header block. The
		// source (`header_end..data.len()`) and destination
		// (`write_to..write_to + body_len`) may overlap when the
		// kept header block is shorter than the original; do the
		// copy with two disjoint mutable slices, reading from
		// `right` (the body) and writing into `left` at the new
		// offset. When the destination extends past the original
		// header end we have to push the body back to its
		// destination in two phases: the part that fits in `left`
		// goes there, the remainder goes after the original
		// header end.
		if write_to + body_len <= header_end {
			// Destination fits entirely inside the original
			// header range; one copy does it.
			let (left, right) = data.split_at_mut(header_end);
			left[write_to..write_to + body_len].copy_from_slice(right);
		} else {
			// Destination extends past the original header end.
			// Copy the first part (size `header_end - write_to`)
			// from the body's head into the tail of the kept
			// header block, then move the body's tail to its
			// final position.
			let head = header_end - write_to;
			let (left, right) = data.split_at_mut(header_end);
			left[write_to..header_end].copy_from_slice(&right[..head]);
			right.copy_within(head..body_len, 0);
		}
		write_to += body_len;
	}
	data.truncate(write_to);
}

/// The unfolded, trimmed values of every `name` field in the header block
/// of `data`, in order. Bytes that are not UTF-8 are replaced.
pub fn header_values(data: &[u8], name: &str) -> Vec<String> {
	let header_end = header_block_end(data);
	let mut values: Vec<String> = Vec::new();
	let mut collecting = false;
	for line in data[..header_end].split_inclusive(|&b| b == b'\n') {
		let text = String::from_utf8_lossy(line);
		let text = text.trim_end_matches(['\r', '\n']);
		if matches!(line.first(), Some(b' ' | b'\t')) {
			if collecting && let Some(value) = values.last_mut() {
				value.push(' ');
				value.push_str(text.trim());
			}
			continue;
		}
		collecting =
			field_name(line).is_some_and(|field| field.eq_ignore_ascii_case(name.as_bytes()));
		if collecting && let Some((_, value)) = text.split_once(':') {
			values.push(value.trim().to_string());
		}
	}
	for value in &mut values {
		*value = value.trim().to_string();
	}
	values
}

/// The name of the field a header line starts, without trailing blanks;
/// `None` for a line with no colon.
fn field_name(line: &[u8]) -> Option<&[u8]> {
	line.contains(&b':')
		.then(|| line.split(|&b| b == b':').next())
		.flatten()
		.map(|name| name.trim_ascii_end())
}

/// Byte index of the body's first byte (the start of the blank-line
/// separator that ends the header block). The header block is everything
/// up to but not including that separator; for CRLF CRLF the separator
/// starts at the second `\r`, for LF LF it starts at the second `\n`.
/// Returns `data.len()` when no blank line is present.
fn header_block_end(data: &[u8]) -> usize {
	let mut i = 0;
	while i < data.len() {
		if data[i] == b'\n' {
			match data.get(i + 1) {
				Some(b'\n') | Some(b'\r') => return i + 1,
				_ => {}
			}
		}
		i += 1;
	}
	data.len()
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

/// Prepend the two spam-marking headers a downstream client uses to tell
/// ham from junk: `X-Spam-Status: Yes` plus the raw probability in
/// `X-Spam-Score`. The injector only fires when the corpus returned a
/// score at or above `bayes_junk_at`: a below-threshold message must not
/// grow headers the recipient did not ask for.
///
/// Header lines are inserted at the top of the existing header block (the
/// prefix before the first blank line, CRLF or LF). The byte boundary is
/// not re-scanned for "X-Spam-Status" already present: in practice the
/// SMTP server runs this exactly once per accepted message, so a
/// duplicate pass would imply a real bug in the call site, not a
/// repeated correlate header.
pub fn inject_spam_headers(data: &[u8], score: f64) -> Vec<u8> {
	let header_end = header_block_end(data);
	let (headers, body) = data.split_at(header_end);
	// Six decimals is plenty for a probability and avoids leaking the
	// floating-point noise that `f64::to_string` would emit.
	let prefix = format!("X-Spam-Status: Yes\r\nX-Spam-Score: {score:.6}\r\n");
	let mut out = Vec::with_capacity(data.len() + prefix.len());
	out.extend_from_slice(prefix.as_bytes());
	out.extend_from_slice(headers);
	out.extend_from_slice(body);
	out
}

#[cfg(test)]
#[path = "trace_tests.rs"]
mod tests;
