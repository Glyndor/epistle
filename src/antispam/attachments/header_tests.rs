use super::*;

#[test]
fn names_that_only_differ_in_case_or_padding_agree() {
	assert!(!names_disagree(&["a.PDF".into(), "a.pdf ".into()]));
	assert!(names_disagree(&[
		"invoice.pdf".into(),
		"invoice.exe".into()
	]));
}

#[test]
fn every_copy_and_every_name_parameter_is_a_candidate() {
	let header = parse(
		b"Content-Type: application/pdf; name=\"one.pdf\"\r\n\
		  Content-Disposition: attachment; filename=\"two.pdf\"\r\n\
		  Content-Disposition: attachment; filename=\"three.scr\"\r\n",
	);
	assert_eq!(header.names, vec!["two.pdf", "three.scr", "one.pdf"]);
	assert!(header.ambiguous);
}

#[test]
fn a_long_boundary_is_followed_and_flagged() {
	let boundary = "b".repeat(200);
	let header =
		parse(format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n").as_bytes());
	assert_eq!(header.boundary.as_deref(), Some(boundary.as_bytes()));
	assert!(header.ambiguous);
}

#[test]
fn a_header_block_mail_parser_cannot_read_is_scanned_as_an_attachment() {
	let header = parse(b"\x00\x01\x02 no colon here\r\n");
	assert!(header.attachment, "parsed as {header:?}");
	assert!(header.ambiguous);
}

#[test]
fn a_repeated_content_type_or_encoding_is_ambiguous() {
	for block in [
		&b"Content-Type: text/plain\r\nContent-Type: application/x-msdownload\r\n"[..],
		b"Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\
		  Content-Transfer-Encoding: 7bit\r\n",
		b"Content-Disposition: inline\r\nContent-Disposition: attachment\r\n",
	] {
		assert!(parse(block).ambiguous, "{}", String::from_utf8_lossy(block));
	}
	assert!(!parse(b"Content-Type: application/pdf\r\n").ambiguous);
}

#[test]
fn an_unreadable_content_type_or_any_binary_type_makes_an_attachment() {
	let unparsed = parse(b"Content-Type: ;;;\r\n");
	assert!(unparsed.attachment && unparsed.ambiguous, "{unparsed:?}");
	let doubled = parse(b"Content-Type: text/plain\r\nContent-Type: application/x-msdownload\r\n");
	assert!(doubled.attachment, "{doubled:?}");
	assert_eq!(
		doubled.declared_types,
		vec!["text/plain", "application/x-msdownload"]
	);
}

#[test]
fn every_encoding_a_part_declares_is_kept_beyond_the_first() {
	let header = parse(
		b"Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit\r\n\
		  Content-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: base64\r\n\
		  Content-Transfer-Encoding: Quoted-Printable\r\nContent-Transfer-Encoding: nonsense\r\n",
	);
	assert_eq!(header.encoding, Encoding::Identity);
	assert_eq!(
		header.other_encodings,
		[Encoding::Base64, Encoding::QuotedPrintable]
	);
	assert!(header.ambiguous);
	let plain = parse(b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n");
	assert!(plain.other_encodings.is_empty());
}

#[test]
fn a_part_could_be_text_unless_it_is_plainly_a_file() {
	let could = |block: &[u8]| parse(block).could_be_text();
	assert!(could(b"Content-Type: text/plain\r\n"));
	assert!(could(b"Subject: no type at all\r\n"));
	assert!(could(b"Content-Type: message/rfc822\r\n"));
	assert!(could(b"Content-Type: multipart/mixed\r\n"));
	assert!(could(
		b"Content-Type: text/plain; name=a.txt\r\nContent-Disposition: attachment\r\n"
	));
	// Two readers disagree about it: either may show text.
	assert!(could(
		b"Content-Type: application/pdf\r\nContent-Type: application/zip\r\n"
	));
	assert!(!could(
		b"Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n"
	));
	assert!(!could(b"Content-Type: image/png; name=a.png\r\n"));
}

/// No `Content-Type` is `text/plain` (RFC 2045), also on a part marked as an
/// attachment, and a type nobody can read is text to the client that falls
/// back to it.
#[test]
fn a_part_with_no_readable_type_could_be_text() {
	for block in [
		&b"Content-Disposition: attachment\r\n"[..],
		b"Content-Disposition: attachment; filename=a.txt\r\n",
		b"Content-Type:\r\nContent-Disposition: attachment\r\n",
		b"Content-Type: ;;\r\nContent-Disposition: attachment\r\n",
		b"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment\r\n",
	] {
		assert!(parse(block).could_be_text(), "{block:?}");
	}
}

#[test]
fn every_charset_a_part_declares_is_kept_in_lower_case() {
	let header = parse(
		b"Content-Type: text/plain; charset=\"UTF-16LE\"\r\n\
		  Content-Type: text/plain; charset=utf-8\r\nContent-Type: text/html; charset=UTF-8\r\n",
	);
	assert_eq!(header.charsets, ["utf-16le", "utf-8"]);
	assert!(parse(b"Content-Type: text/plain\r\n").charsets.is_empty());
	assert!(parse(b"Subject: x\r\n").charsets.is_empty());
}
