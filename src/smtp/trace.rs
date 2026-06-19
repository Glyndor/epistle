//! Trace and authentication headers stamped onto accepted mail.

use std::net::IpAddr;

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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn counts_received_headers_in_the_block_only() {
		let data = b"Received: from a\r\nReceived: from b\r\n\tby folded\r\n\
Subject: hi\r\n\r\nReceived: not a header in the body\r\n";
		// Two Received headers; the folded continuation and the body line
		// are not counted.
		assert_eq!(received_hop_count(data), 2);
	}

	#[test]
	fn counts_zero_when_no_received_headers() {
		assert_eq!(received_hop_count(b"From: a@b\r\n\r\nbody\r\n"), 0);
	}

	#[test]
	fn received_protocol_follows_rfc3848() {
		// HELO is plain SMTP regardless of TLS or auth.
		assert_eq!(received_protocol(false, false, false), "SMTP");
		assert_eq!(received_protocol(false, true, true), "SMTP");
		// EHLO gains S over TLS and A once authenticated.
		assert_eq!(received_protocol(true, false, false), "ESMTP");
		assert_eq!(received_protocol(true, true, false), "ESMTPS");
		assert_eq!(received_protocol(true, false, true), "ESMTPA");
		assert_eq!(received_protocol(true, true, true), "ESMTPSA");
	}

	#[test]
	fn spf_domain_prefers_mail_from_then_helo() {
		assert_eq!(
			spf_domain("a@Example.ORG", Some("helo.example")),
			Some("example.org".to_string())
		);
		assert_eq!(
			spf_domain("", Some("helo.example")),
			Some("helo.example".to_string())
		);
		assert_eq!(spf_domain("", None), None);
	}
}
