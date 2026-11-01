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

/// The most bytes an input of the targets below is given: they read network
/// bodies and headers, which the listeners bound well under this.
const INPUT_CAP: usize = 64 * 1024;

/// Attachment content sniffing: the real type of the bytes of an attachment,
/// which the antispam rules and the attachment policy read.
pub fn attachment_inspect(content: &[u8]) {
	let content = &content[..content.len().min(INPUT_CAP)];
	let real = crate::antispam::attachments::sniff::sniff(content);
	std::hint::black_box((
		real.as_str(),
		real.is_executable(),
		real.is_image(),
		real.is_binary(),
	));
}

/// A CalDAV or CardDAV query body, the iCalendar and vCard text it is matched
/// against, and the recurrence rule that expands an event: the XML filter
/// parser, the component walker and the bounded RRULE expansion.
pub fn webdav_filter_rrule(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	if let Ok(filter) = crate::webdav::caldav_filter::parse(input) {
		std::hint::black_box(crate::webdav::caldav_filter::matches(&filter, input));
	}
	if let Ok(filter) = crate::webdav::carddav_filter::parse(input) {
		std::hint::black_box(crate::webdav::carddav_filter::matches(&filter, input));
	}
	std::hint::black_box(crate::webdav::rrule::parse_datetime(input));
	if let Some(rule) = crate::webdav::rrule::parse_rule(input) {
		std::hint::black_box(crate::webdav::rrule::expand_bounded(
			0,
			Some(&rule),
			0,
			4_000_000_000,
			1_000,
		));
	}
}

/// The ARC header fields: the message signature, the seal, the chain
/// validation keyword and a tag lookup.
pub fn arc_headers(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let text = String::from_utf8_lossy(raw);
	let _ = crate::arc::signature::parse_message_signature(&text);
	let _ = crate::arc::signature::parse_seal(&text);
	std::hint::black_box(crate::arc::chain::ChainValidation::parse(&text));
	std::hint::black_box(crate::arc::chain::tag(&text, "cv"));
}

/// A JWT as an identity provider would present it: the three parts, the
/// header and the payload decoding and the claim checks. The key is fixed and
/// does not match, so a signature never verifies and every path before that
/// check is the one that runs.
pub fn jwt_decode(token: &str) {
	let token = &token[..floor_char_boundary(token, INPUT_CAP)];
	let validation = crate::jwt::Validation {
		now: 1_800_000_000,
		issuer: Some("https://issuer.example"),
		audience: Some("epistle"),
	};
	for algorithm in [crate::jwt::Algorithm::Rs256, crate::jwt::Algorithm::Es256] {
		let _ = crate::jwt::validate(token, algorithm, &[0u8; 32], &validation);
	}
}

/// The reply of a remote SMTP server as the outbound client frames it: where
/// the first complete reply ends, for any bytes a hostile server sends.
pub fn smtp_reply(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	std::hint::black_box(crate::queue::client::complete_reply_for_fuzzing(raw));
}

/// The records a sending domain publishes and the server reads before it
/// delivers: the MTA-STS policy file, the TLS-RPT record and a TLSA record in
/// its presentation form.
pub fn dns_security_records(text: &str) {
	let text = &text[..floor_char_boundary(text, INPUT_CAP)];
	let _ = crate::mtasts::parse_policy(text);
	std::hint::black_box(crate::tlsrpt::parse(text));
	std::hint::black_box(crate::dane::tlsa::TlsaRecord::parse_presentation(text));
}

/// A DMARC or TLS-RPT report as a remote reporter sends it: the XML and the
/// JSON parsers and the three ways an attachment is unpacked.
pub fn report_payload(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let _ = crate::reports::dmarc::parse(raw);
	let _ = crate::reports::tlsrpt::parse(raw);
	for encoding in [
		crate::reports::Encoding::Gzip,
		crate::reports::Encoding::Zip,
		crate::reports::Encoding::Uncompressed,
	] {
		let _ = crate::reports::inflate_attachment(raw, encoding);
	}
}

/// Delivery rules matched against a message: the header block is read,
/// unfolded and searched for any bytes a sender puts in it.
pub fn rules_match(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let rules = [
		crate::rules::Rule {
			sender_domain: None,
			header: Some("Subject".into()),
			header_contains: Some("a".into()),
			junk: true,
			mailbox: None,
		},
		crate::rules::Rule {
			sender_domain: Some("example.org".into()),
			header: Some("List-Id".into()),
			header_contains: Some("list".into()),
			junk: false,
			mailbox: Some("Lists".into()),
		},
	];
	std::hint::black_box(crate::rules::evaluate(&rules, raw, Some("example.org")));
}

/// The largest index at most `max` that is a character boundary of `text`.
fn floor_char_boundary(text: &str, max: usize) -> usize {
	let mut end = max.min(text.len());
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	end
}
