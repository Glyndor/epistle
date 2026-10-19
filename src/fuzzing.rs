//! Entry points for the cargo-fuzz targets under `fuzz/`.
//!
//! Not an API. The parsers worth fuzzing sit behind crate-private
//! modules; these functions reach them without making those modules
//! public, and each one runs every consumer of the same untrusted bytes
//! so a target covers the whole path a hostile message or command takes.

/// IMAP command line: the literal announcement the connection loop reads
/// before anything else, then the command parser.
pub fn imap_command_line(line: &str) {
	if let Some(literal) = crate::imap::command::literal_announcement_in_line(line) {
		std::hint::black_box(literal.size);
	}
	let _ = crate::imap::command::parse(line, crate::imap::command::DEFAULT_APPEND_LIMIT);
}

/// DKIM-Signature header value: the tag-list parser (`b=`, `bh=`, `h=`
/// and the rest) and the header canonicalisation it feeds.
pub fn dkim_signature(value: &str) {
	let _ = crate::dkim::signature::parse(value);
	std::hint::black_box(crate::dkim::canon::header(
		crate::dkim::signature::Canon::Relaxed,
		"DKIM-Signature",
		value,
	));
}

/// A whole message through every MIME consumer: IMAP BODYSTRUCTURE and
/// ENVELOPE, JMAP body properties, the DMARC and TLS-RPT report walkers,
/// the From field DMARC and submission read, and DKIM body hashing.
pub fn mime(raw: &[u8]) {
	std::hint::black_box(crate::imap::fetch::render_for_fuzzing(raw));
	std::hint::black_box(crate::api::jmap::email_body_for_fuzzing(raw));
	for kind in [crate::reports::Kind::Dmarc, crate::reports::Kind::TlsRpt] {
		let _ = crate::reports::mime::find_report_part(raw, kind);
	}
	std::hint::black_box(crate::dmarc::author::author(raw));
	std::hint::black_box(crate::dmarc::from_domain(raw));
	std::hint::black_box(crate::dkim::canon::body(
		crate::dkim::signature::Canon::Relaxed,
		raw,
	));
}
