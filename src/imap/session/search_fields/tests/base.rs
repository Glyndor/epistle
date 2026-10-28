
use super::body_of;

#[test]
fn body_starts_after_the_first_blank_line() {
	assert_eq!(body_of("subject: a\r\n\r\nbody\r\n"), "body\r\n");
	assert_eq!(body_of("subject: a\n\nbody\n"), "body\n");
	assert_eq!(body_of("subject: a\r\n"), "");
}

#[test]
fn the_field_count_is_never_below_the_headers_imap_takes() {
	use crate::util::header_block::{cases, field_count};
	for raw in cases::messages() {
		let text = String::from_utf8_lossy(&raw);
		let headers = &text[..text.len() - body_of(&text).len()];
		assert!(
			field_count(&raw) >= cases::fields_in(headers.as_bytes()),
			"{raw:?}"
		);
	}
}
