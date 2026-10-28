
use super::*;

#[test]
fn renders_single_line_with_crlf() {
	assert_eq!(Reply::ok().to_string(), "250 2.0.0 ok\r\n");
}

#[test]
fn renders_multiline_with_continuation() {
	let reply = Reply::new(
		250,
		vec![
			"mail.example.org".into(),
			"PIPELINING".into(),
			"SIZE 1000".into(),
		],
	);
	assert_eq!(
		reply.to_string(),
		"250-mail.example.org\r\n250-PIPELINING\r\n250 SIZE 1000\r\n"
	);
}

#[test]
fn positive_detection() {
	assert!(Reply::ok().is_positive());
	assert!(Reply::start_mail_input().is_positive());
	assert!(!Reply::syntax_error().is_positive());
	assert!(!Reply::bad_sequence().is_positive());
}

#[test]
#[should_panic(expected = "invalid SMTP reply code")]
fn rejects_invalid_code() {
	let _ = Reply::single(102, "nope");
}

#[test]
#[should_panic(expected = "at least one line")]
fn rejects_empty_lines() {
	let _ = Reply::new(250, vec![]);
}
