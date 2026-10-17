use super::*;
use crate::antispam::attachments::corpus::uu;

#[test]
fn base64_skips_junk_and_whitespace() {
	assert_eq!(base64(b"TV!o\r\n AA \t=="), (b"MZ\x00".to_vec(), false));
}

#[test]
fn base64_keeps_data_after_padding_and_says_so() {
	let (bytes, ambiguous) = base64(b"TVo=\r\nTVo=");
	assert_eq!(bytes, b"MZMZ");
	assert!(ambiguous);
}

#[test]
fn uuencode_round_trips() {
	let payload: Vec<u8> = (0..=255).collect();
	let text = uu("x.bin", &payload);
	assert_eq!(uuencode(text.as_bytes()), payload);
}

#[test]
fn an_embedded_block_needs_a_real_begin_line() {
	let text = format!("hello\n{}bye\n", uu("tool.exe", b"MZ\x90\x00"));
	let (found, capped) = embedded_uuencode(text.as_bytes());
	assert!(!capped);
	assert_eq!(
		found,
		vec![Embedded {
			name: "tool.exe".into(),
			content: b"MZ\x90\x00".to_vec()
		}]
	);
	assert!(
		embedded_uuencode(b"begin the meeting at 9\nend\n")
			.0
			.is_empty()
	);
	assert!(embedded_uuencode(b"begin 999 x.exe\n").0.is_empty());
}

#[test]
fn embedded_blocks_are_capped() {
	let text = uu("a.txt", b"x").repeat(MAX_EMBEDDED + 10);
	let (found, capped) = embedded_uuencode(text.as_bytes());
	assert_eq!(found.len(), MAX_EMBEDDED);
	assert!(
		capped,
		"blocks past the cap were not read, and that must show"
	);
}
