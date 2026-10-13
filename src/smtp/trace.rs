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
