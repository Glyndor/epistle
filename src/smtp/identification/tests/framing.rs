use super::*;
use crate::dmarc::author::from_fields;
use crate::evidence::marketing::MarketingRefusal;

const MALFORMED_LINE: &str =
	"submission header lines must follow RFC 5322 field and folding syntax";

fn reader_field_count(raw: &[u8], name: &str) -> usize {
	mail_parser::MessageParser::default()
		.parse_headers(raw)
		.map_or(0, |message| {
			message
				.headers()
				.iter()
				.filter(|header| header.name().eq_ignore_ascii_case(name))
				.count()
		})
}

fn author_from_count(raw: &[u8]) -> usize {
	from_fields(raw).expect("UTF-8 headers").len()
}

#[test]
fn the_strict_header_shapes_are_accepted() {
	for raw in [
		b"From : me@example.org\r\nSubject: s\r\n\r\nbody\r\n".as_slice(),
		b"From \t: me@example.org\r\nSubject: s\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\n folded\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\nSubject: s\n\nbody\n".as_slice(),
		b"From: me@example.org\r\nSubject: s".as_slice(),
		b"From: me@example.org\r\n\r\nX: y\r\nFr om: z\r\n".as_slice(),
		b"\r\nHello world: x\r\n".as_slice(),
		b"\nHello world: x\n".as_slice(),
	] {
		assert_eq!(
			reject_ambiguous_headers(raw),
			Ok(()),
			"{:?}",
			String::from_utf8_lossy(raw)
		);
	}
}

#[test]
fn malformed_header_lines_are_refused() {
	for raw in [
		b" From: victim@example.org\r\nFrom: me@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\n:From: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nGarbage\r\n Fr om: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nMissing colon\r\n\r\nbody\r\n".as_slice(),
		b" From: victim@example.org\r\n\r\nbody\r\n".as_slice(),
	] {
		let refusal = reject_ambiguous_headers(raw).expect_err("malformed header lines");
		assert_eq!(refusal.message(), MALFORMED_LINE, "{:?}", raw);
	}
}

#[test]
fn mixed_line_endings_are_refused() {
	for raw in [
		b"From: me@example.org\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nSubject: s\nDate: x\r\n\r\nbody".as_slice(),
		b"From: me@example.org\r\nSubject: s\r".as_slice(),
	] {
		assert_eq!(
			reject_ambiguous_headers(raw),
			Err(MarketingRefusal::AmbiguousHeaderFraming)
		);
	}
}

#[test]
fn invalid_field_names_are_refused() {
	for raw in [
		b"From: me@example.org\r\nFr\tom: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nFr\x0Bom: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nFr\x0Com: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: me@example.org\r\nFr\x00om: victim@example.org\r\n\r\nbody\r\n".as_slice(),
	] {
		let refusal = reject_ambiguous_headers(raw).expect_err("invalid field name");
		assert_eq!(refusal, MarketingRefusal::AmbiguousHeaderName, "{raw:?}");
	}
}

#[test]
fn accepted_messages_make_the_author_and_reader_agree_on_from_fields() {
	let mut accepted_count = 0;
	for (raw, accepted) in [
		(
			b" From: victim@example.org\r\nFrom: me@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\n:From: victim@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\nGarbage\r\n Fr om: victim@example.org\r\n\r\nbody\r\n"
				.as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\nFr\tom: victim@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\nFr\x0Bom: victim@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\nFr\x0Com: victim@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From: me@example.org\r\nFr\x00om: victim@example.org\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(b"From: me@example.org\n\r\nbody\r\n".as_slice(), false),
		(
			b"From: me@example.org\r\n folded\r\n\r\nbody\r\n".as_slice(),
			true,
		),
		(
			b"From: me@example.org\r\rSubject: s\r\n\r\nbody\r\n".as_slice(),
			false,
		),
		(
			b"From : me@example.org\r\nSubject: s\r\n\r\nbody\r\n".as_slice(),
			true,
		),
		(
			b"From \t: me@example.org\r\nSubject: s\r\n\r\nbody\r\n".as_slice(),
			true,
		),
		(b"From: me@example.org\r\nSubject: s".as_slice(), true),
		(
			b"From: me@example.org\nSubject: s\n\nbody\n".as_slice(),
			true,
		),
		(
			b"Subject: s\nFrom: me@example.org\n\nbody\n".as_slice(),
			true,
		),
		(
			b"From: one@example.org\nFrom: two@example.org\n\nbody\n".as_slice(),
			true,
		),
		(
			b"From: me@example.org\r\n\r\nX: y\r\nFr om: z\r\n".as_slice(),
			true,
		),
		(b"\r\nHello world: x\r\n".as_slice(), true),
		(b"\nHello world: x\n".as_slice(), true),
	] {
		assert_eq!(reject_ambiguous_headers(raw).is_ok(), accepted, "{raw:?}");
		if accepted {
			accepted_count += 1;
			assert_eq!(
				author_from_count(raw),
				reader_field_count(raw, "From"),
				"{:?}",
				String::from_utf8_lossy(raw)
			);
		}
	}
	assert_eq!(accepted_count, 10);
}

#[test]
fn reader_disagreement_is_refused_for_from_and_sender() {
	for ending in ["\r\n", "\n"] {
		for date in ["Date", "Resent-Date"] {
			for zone in ["-0500x", "+0000x"] {
				for (header, body) in [
					("From: me@example.org", "From: victim@example.org"),
					("Subject: s", "From: victim@example.org"),
					("From: me@example.org", "Sender: victim@example.org"),
				] {
					let filler = if ending == "\n" {
						"Subject: body\n"
					} else {
						""
					};
					let raw = format!(
						"{header}{ending}{date}: Mon, 1 Jan 2020 00:00:00 {zone}{ending}{ending}{filler}{body}{ending}"
					);
					let field = if body.starts_with("Sender:") {
						"Sender"
					} else {
						"From"
					};
					let own = if field == "From" {
						author_from_count(raw.as_bytes())
					} else {
						0
					};
					assert!(reader_field_count(raw.as_bytes(), field) > own, "{raw:?}");
					let refusal =
						reject_ambiguous_headers(raw.as_bytes()).expect_err("reader disagreement");
					assert_eq!(
						refusal.message(),
						"I cannot accept headers whose From or Sender field counts disagree between readers"
					);
					assert_eq!(
						refusal.smtp_reply().to_string(),
						format!("550 5.7.1 {}\r\n", refusal.message())
					);
				}
			}
		}
	}
}

#[test]
fn non_utf8_headers_report_the_encoding_cause() {
	let refusal = reject_ambiguous_headers(b"From: me@example.org\r\nSubject: caf\xe9\r\n\r\nx")
		.expect_err("non-UTF-8 header");
	assert_eq!(
		refusal.message(),
		"I cannot accept submission headers that are not UTF-8"
	);
	assert_eq!(
		reject_ambiguous_headers(b"From: me@example.org\r\n\r\ncaf\xe9"),
		Ok(())
	);
}

#[test]
fn a_field_swallowed_before_header_removal_is_refused() {
	for field in [
		"Authentication-Results: forged",
		"Epistle-Class: personal",
		"X-Epistle: forged",
	] {
		let raw = format!(
			"From: me@example.org\r\nDate: Mon, 1 Jan 2020 00:00:00 -0500x\r\n{field}\r\n\r\nFrom: body@example.net\r\n"
		);
		assert_eq!(
			reader_field_count(raw.as_bytes(), "From"),
			author_from_count(raw.as_bytes())
		);
		let refusal = reject_ambiguous_headers(raw.as_bytes())
			.expect_err("I expect the swallowed field to be refused before removal");
		assert_eq!(
			refusal.message(),
			"I cannot accept headers whose field boundaries disagree between readers"
		);
	}
}

#[test]
fn a_header_block_with_too_many_fields_is_refused_before_it_is_parsed() {
	let limit = crate::smtp::trace::MAX_HEADER_FIELDS;
	let block = |count: usize| {
		let mut raw = String::from("From: me@example.org\r\n");
		for _ in 1..count {
			raw.push_str("A:\r\n");
		}
		raw.push_str("\r\nbody\r\n");
		raw
	};
	assert!(reject_ambiguous_headers(block(limit).as_bytes()).is_ok());
	let refusal = reject_ambiguous_headers(block(limit + 1).as_bytes())
		.expect_err("I expect a block over the field limit to be refused");
	assert_eq!(
		refusal.message(),
		"submission headers hold more fields than I accept"
	);
}
