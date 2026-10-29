//! Messages that mail clients and a strict parser read differently. The
//! walk must see whatever a client could show, or say it is ambiguous.

use super::*;
use crate::antispam::attachments::tests::corpus;

const LIMITS: Limits = Limits {
	max_depth: 10,
	max_parts: 1000,
	max_decoded: 1 << 20,
	deadline: None,
};

fn run(raw: &[u8]) -> (Vec<Leaf>, Walked) {
	let mut out = Vec::new();
	let walked = walk(raw, &LIMITS, |leaf| out.push(leaf));
	(out, walked)
}

fn named<'a>(leaves: &'a [Leaf], name: &str) -> Option<&'a Leaf> {
	leaves
		.iter()
		.find(|leaf| leaf.names.iter().any(|candidate| candidate == name))
}

#[test]
fn duplicate_headers_keep_every_name_and_mark_the_part() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: text/plain\r\nContent-Type: application/octet-stream\r\n\
		Content-Disposition: attachment; filename=\"safe.txt\"\r\n\
		Content-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nMZ\r\n--b--\r\n";
	let (found, _) = run(raw);
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].names, vec!["safe.txt", "evil.exe"]);
	assert!(found[0].ambiguous);
}

#[test]
fn name_and_filename_that_disagree_are_both_kept() {
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/pdf; name=\"invoice.exe\"\r\n\
		 Content-Disposition: attachment; filename=\"invoice.pdf\"; filename*=utf-8''invoice.scr",
		b"MZ",
	)]);
	let (found, _) = run(&raw);
	let leaf = named(&found, "invoice.exe").expect("the Content-Type name is a candidate");
	assert!(leaf.names.iter().any(|name| name == "invoice.pdf"));
	assert!(leaf.names.iter().any(|name| name == "invoice.scr"));
	assert!(leaf.ambiguous);
}

#[test]
fn an_encoded_word_filename_is_decoded() {
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/octet-stream\r\n\
		 Content-Disposition: attachment; filename=\"=?utf-8?b?ZXZpbC5leGU=?=\"",
		b"MZ",
	)]);
	let (found, _) = run(&raw);
	assert!(
		named(&found, "evil.exe").is_some(),
		"names: {:?}",
		found.iter().map(|leaf| &leaf.names).collect::<Vec<_>>()
	);
}

#[test]
fn quoted_and_bare_boundaries_split_alike() {
	for declaration in ["boundary=abc", "boundary=\"abc\""] {
		let raw = format!(
			"Content-Type: multipart/mixed; {declaration}\r\n\r\n--abc\r\n\
			 Content-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n--abc--\r\n"
		);
		let (found, walked) = run(raw.as_bytes());
		assert!(named(&found, "a.exe").is_some(), "{declaration}");
		assert!(!walked.ambiguous, "{declaration}");
	}
}

#[test]
fn a_delimiter_in_other_case_or_with_junk_marks_the_message() {
	for line in ["--ABC", "--abcJUNK", "--abc--x"] {
		let raw = format!(
			"Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\
			 Content-Type: text/plain\r\n\r\nhi\r\n{line}\r\n\
			 Content-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n--abc--\r\n"
		);
		let (_, walked) = run(raw.as_bytes());
		assert!(walked.ambiguous, "{line} must mark the message ambiguous");
	}
}

#[test]
fn a_part_after_a_missing_final_boundary_is_still_seen() {
	let raw = b"Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\n\
		Content-Type: text/plain\r\n\r\nhi\r\n--abc\r\n\
		Content-Type: application/octet-stream; name=last.exe\r\n\
		Content-Transfer-Encoding: base64\r\n\r\nTVqQAA==\r\n";
	let (found, walked) = run(raw);
	let last = named(&found, "last.exe").expect("the unterminated part is visited");
	assert_eq!(last.content, b"MZ\x90\x00");
	assert_eq!(walked.stopped, None);
}

#[test]
fn a_delimiter_in_the_preamble_starts_the_first_part() {
	let raw = b"Content-Type: multipart/mixed; boundary=abc\r\n\r\nThis is a preamble.\r\n\
		--abc\r\nContent-Type: application/octet-stream; name=early.exe\r\n\r\nMZ\r\n--abc--\r\n";
	let (found, _) = run(raw);
	assert!(named(&found, "early.exe").is_some());
}

#[test]
fn base64_with_junk_and_glued_blocks_is_decoded_like_a_client() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream; name=a.bin\r\n\
		Content-Transfer-Encoding: base64\r\n\r\nT V!o=\r\nkAA=\r\n--b--\r\n";
	let (found, _) = run(raw);
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].content, b"MZ\x90\x00");
	assert!(found[0].ambiguous, "data after padding reads two ways");
}

#[test]
fn an_unknown_transfer_encoding_is_read_raw_and_marked() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream; name=a.bin\r\n\
		Content-Transfer-Encoding: x-gzip64\r\n\r\nMZraw\r\n--b--\r\n";
	let (found, _) = run(raw);
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].content, b"MZraw");
	assert!(found[0].ambiguous);
}

#[test]
fn uuencode_as_a_transfer_encoding_and_inside_a_text_body_is_decoded() {
	let encoded = corpus::uu("run.exe", b"MZ\x90\x00");
	let raw = format!(
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		 Content-Type: text/plain\r\n\r\nSee the file:\r\n{encoded}\r\n--b\r\n\
		 Content-Type: application/octet-stream; name=tool.bin\r\n\
		 Content-Transfer-Encoding: x-uuencode\r\n\r\n{encoded}--b--\r\n"
	);
	let (found, _) = run(raw.as_bytes());
	let pasted = named(&found, "run.exe").expect("the uuencoded block in the text is a leaf");
	assert!(pasted.attachment);
	assert_eq!(pasted.content, b"MZ\x90\x00");
	let part = named(&found, "tool.bin").expect("the uuencoded part is visited");
	assert_eq!(part.content, b"MZ\x90\x00");
}

#[test]
fn octet_stream_without_name_or_disposition_is_an_attachment() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream\r\n\r\nMZ\r\n--b--\r\n";
	let (found, _) = run(raw);
	assert_eq!(found.len(), 1);
	assert!(found[0].attachment);
	assert!(found[0].names.is_empty());
}

#[test]
fn a_multipart_without_a_boundary_is_scanned_as_one_attachment() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: multipart/mixed\r\n\r\nMZ hidden\r\n--b--\r\n";
	let (found, _) = run(raw);
	assert_eq!(found.len(), 1);
	assert!(found[0].attachment);
	assert!(found[0].ambiguous);
	assert_eq!(found[0].content, b"MZ hidden");
}

#[test]
fn a_boundary_longer_than_the_rfc_allows_is_still_split() {
	let boundary = "x".repeat(120);
	let raw = format!(
		"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n\
		 Content-Type: application/octet-stream; name=long.exe\r\n\r\nMZ\r\n--{boundary}--\r\n"
	);
	let (found, walked) = run(raw.as_bytes());
	assert!(named(&found, "long.exe").is_some());
	assert!(walked.ambiguous);
}
