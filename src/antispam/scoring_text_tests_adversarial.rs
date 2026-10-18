//! Messages built to get past [`scoring_text`]: text hidden behind a second
//! reading of the structure, behind an encoding or a charset the walk does not
//! follow, or placed where a cut falls inside a character.

use super::*;
use crate::antispam::bayes::tokenize;

fn has(raw: &[u8], word: &str) -> bool {
	tokenize(&scoring_text(raw).text).iter().any(|t| t == word)
}

fn base64_of(bytes: &[u8]) -> String {
	use base64::Engine as _;
	let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
	encoded
		.as_bytes()
		.chunks(76)
		.map(|line| std::str::from_utf8(line).unwrap())
		.collect::<Vec<_>>()
		.join("\r\n")
}

/// `size` bytes of base64 that decode to bytes, as an attachment.
fn big_attachment(size: usize) -> String {
	format!(
		"--bb\r\nContent-Type: application/octet-stream\r\n\
		 Content-Disposition: attachment; filename=\"a.bin\"\r\n\
		 Content-Transfer-Encoding: base64\r\n\r\n{}\r\n",
		base64_of(&vec![0x5au8; size])
	)
}

fn multipart(parts: &str) -> Vec<u8> {
	format!("Subject: x\r\nContent-Type: multipart/mixed; boundary=\"bb\"\r\n\r\n{parts}--bb--\r\n")
		.into_bytes()
}

/// Attachments that use up the decoding budget must not leave the text that
/// follows them unread: the budget is for text.
#[test]
fn text_after_attachments_that_fill_the_budget_is_still_decoded() {
	// Nearly the whole budget in one attachment, or all of it in a few; the
	// text after them is an ordinary 30 KiB message.
	let sizes: [&[usize]; 3] = [
		&[MAX_DECODED / 100 * 97],
		&[MAX_DECODED / 100 * 24; 4],
		&[MAX_DECODED / 2, MAX_DECODED / 100 * 47, MAX_DECODED],
	];
	for sizes in sizes {
		let words = "filler ".repeat(100_000 / 7);
		let attachments: String = sizes.iter().map(|size| big_attachment(*size)).collect();
		for (encoding, body) in [
			(
				"base64",
				base64_of(format!("{words} hiddenword").as_bytes()),
			),
			("quoted-printable", format!("{words} hidden=77ord")),
		] {
			let text = format!(
				"--bb\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n"
			);
			let raw = multipart(&format!("{attachments}{text}"));
			assert!(has(&raw, "hiddenword"), "{sizes:?} {encoding}");
		}
	}
}

/// A message the walk could not read part by part is read as bytes, and it is
/// not one that was read in full: encoded text in it is not decoded.
#[test]
fn a_message_read_as_bytes_is_never_taken_for_clean() {
	let mut raw = String::from("Subject: x\r\n");
	for level in 0..15 {
		raw.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
		));
	}
	raw.push_str(&format!(
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
		base64_of(b"hiddenword")
	));
	assert!(scoring_text(raw.as_bytes()).clipped, "too deep");
	let huge = base64_of(&b"filler ".repeat(MAX_DECODED / 7 + 10));
	let raw = format!(
		"Subject: x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n{huge}\r\n"
	);
	assert!(scoring_text(raw.as_bytes()).clipped, "past the budget");
}

/// Two `Content-Transfer-Encoding` headers: a client may take either, so the
/// text is read under both.
#[test]
fn a_part_that_declares_two_encodings_is_read_under_both() {
	let body = base64_of(b"hiddenword is here");
	for headers in [
		"Content-Transfer-Encoding: 7bit\r\nContent-Transfer-Encoding: base64\r\n",
		"Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n",
		"Content-Transfer-Encoding: quoted-printable\r\nContent-Transfer-Encoding: base64\r\n",
	] {
		let raw = multipart(&format!(
			"--bb\r\nContent-Type: text/plain\r\n{headers}\r\n{body}\r\n"
		));
		assert!(has(&raw, "hiddenword"), "{headers}");
	}
}

/// A part with no `Content-Type` that is marked as an attachment is text to a
/// client (RFC 2045), so it is read, however it is encoded.
#[test]
fn a_typeless_attachment_is_read_as_text() {
	for headers in [
		"Content-Disposition: attachment\r\n",
		"Content-Disposition: attachment; filename=\"a.txt\"\r\n",
		"Content-Type:\r\nContent-Disposition: attachment\r\n",
	] {
		let raw = multipart(&format!(
			"--bb\r\n{headers}Content-Transfer-Encoding: base64\r\n\r\n{}\r\n",
			base64_of(b"hiddenword is here")
		));
		assert!(has(&raw, "hiddenword"), "{headers}");
	}
}
