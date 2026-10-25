use super::{has_unframed_byte, outbound_crlf};

#[test]
fn a_framed_message_is_borrowed() {
	let data = b"A: 1\r\n\r\nbody\r\n";
	assert!(matches!(outbound_crlf(data), std::borrow::Cow::Borrowed(_)));
}

#[test]
fn a_lone_lf_becomes_crlf_and_nothing_else_is_repaired() {
	assert_eq!(outbound_crlf(b"a\nb").as_ref(), b"a\r\nb\r\n");
	assert_eq!(outbound_crlf(b"a\rb\r\n").as_ref(), b"a\rb\r\n");
	assert_eq!(outbound_crlf(b"a\0b\r\n").as_ref(), b"a\0b\r\n");
}

#[test]
fn unframed_bytes_are_found() {
	assert!(has_unframed_byte(b"a\rb\r\n"));
	assert!(has_unframed_byte(b"a\r"));
	assert!(has_unframed_byte(b"a\0\r\n"));
	assert!(has_unframed_byte(b"a\r\0\nb"));
	assert!(!has_unframed_byte(b"a\r\nb\r\n"));
	assert!(!has_unframed_byte(b"a\nb\n"));
}
