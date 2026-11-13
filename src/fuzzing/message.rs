//! The message adapters: every consumer of a hostile message, and the rules that read them.

use super::common::INPUT_CAP;

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

/// The DKIM signer's socket frame: a request as the signer reads it,
/// through every check it runs before the key holder sees the block, and
/// an answer as the client reads it. Both sides read bytes from a process
/// that may be compromised.
pub fn signer_frame(data: &[u8]) {
	let _ = crate::dkim::remote::admit(data);
	let _ = crate::dkim::remote::frame::SignResponse::decode(data);
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

/// An ARF feedback report as a remote feedback loop sends it, and the report
/// built from the sender and source IP such a complaint carries.
pub fn arf_report(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::antispam::arf::fuzzing::report_for_fuzzing(raw);
}

/// Decoded bytes one walk of [`attachment_walk`] may spend: several times the
/// input, so nested encodings are followed rather than cut at once.
const WALK_DECODED: usize = 4 * INPUT_CAP;

/// A whole message through the attachment inspection: the MIME walk the rules
/// read and the one the text reader takes, the zip and OLE2 directory readers
/// on every part they hand over and on the bytes themselves, and the complete
/// inspection that joins them. A walk keeps to its depth and part limits, and
/// a listing to its entry cap, whatever the message claims.
pub fn attachment_walk(raw: &[u8]) {
	use crate::antispam::attachments::{self, walk};
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let limits = walk::Limits {
		max_depth: attachments::MAX_DEPTH,
		max_parts: attachments::MAX_PARTS,
		max_decoded: WALK_DECODED,
		deadline: None,
	};
	let visit = |leaf: walk::Leaf| {
		// A uuencoded file inside a text part sits one level below it.
		assert!(
			leaf.depth <= limits.max_depth + 1,
			"leaf at depth {}",
			leaf.depth
		);
		directories(&leaf.content);
		for alternate in &leaf.alternates {
			directories(alternate);
		}
	};
	for walked in [
		walk::walk(raw, &limits, visit),
		walk::walk_text(raw, &limits, visit),
	] {
		// The part that goes past the limit is counted, then the walk stops.
		assert!(
			walked.parts <= limits.max_parts + 1,
			"{} parts",
			walked.parts
		);
		if walked.parts > limits.max_parts {
			assert_eq!(walked.stopped, Some(walk::Stop::TooManyParts));
		}
	}
	directories(raw);
	let report = attachments::inspect(
		raw,
		&attachments::rules::Extensions::default(),
		attachments::Budget::bytes(WALK_DECODED),
	);
	std::hint::black_box(report.reasons());
}

/// The zip and OLE2 directory readers over one buffer.
fn directories(bytes: &[u8]) {
	use crate::antispam::attachments::archive;
	let listing = archive::list_zip(bytes);
	assert!(listing.names.len() <= archive::MAX_ENTRIES);
	std::hint::black_box((
		archive::has_end_record(bytes),
		archive::is_ooxml(&listing),
		archive::ooxml_has_macros(&listing),
	));
	let ole = archive::inspect_ole2(bytes);
	assert_eq!(ole.macros, archive::ole2_has_macros(bytes));
}
