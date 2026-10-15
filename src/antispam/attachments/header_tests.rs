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
