use super::*;

#[test]
fn uid_sets_are_compact() {
	assert_eq!(uid_set(&[1, 2, 3, 5, 7, 8]), "1:3,5,7:8");
	assert_eq!(uid_set(&[4]), "4");
	assert_eq!(uid_set(&[]), "");
}

#[test]
fn quoting_escapes_and_refuses_line_breaks() {
	assert_eq!(quote(br#"a"b\c"#), br#""a\"b\\c""#.to_vec());
	assert!(quote_mailbox(b"a\r\nb").is_err());
	assert!(quote_mailbox(b"a\0b").is_err());
}

#[test]
fn server_text_is_sanitized_and_short() {
	assert_eq!(sanitize(b"bad\x1b[31m\xff"), "bad?[31m?");
	assert_eq!(sanitize(&[b'a'; 500]).len(), 200);
}
