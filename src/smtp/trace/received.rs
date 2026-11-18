//! The `Received:` trace header: how it is written, and how many of them a
//! message may already carry before it is treated as a loop.

use std::net::IpAddr;

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
