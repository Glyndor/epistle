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

#[test]
fn a_reference_goes_at_the_end_of_the_last_line_and_nothing_else_changes() {
	let reply = Reply::new(550, vec!["5.7.1 first".into(), "5.7.1 last".into()]);
	let stamped = reply.clone().with_reference("7f3a9c");
	assert_eq!(stamped.code(), 550);
	assert_eq!(
		stamped.to_string(),
		"550-5.7.1 first\r\n550 5.7.1 last (ref 7f3a9c)\r\n"
	);
	assert_eq!(reply.text(), "5.7.1 first 5.7.1 last");
}
