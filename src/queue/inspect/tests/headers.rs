use crate::queue::inspect::{MAX_HEADERS, headers_of};

fn names(message: &[u8]) -> Vec<String> {
	headers_of(message).0.into_iter().map(|h| h.name).collect()
}

#[test]
fn the_fields_are_read_in_order_with_their_folding_undone() {
	let (headers, truncated) = headers_of(
		b"Subject: hi\r\nX-A: one\r\n two\r\n\tthree\r\nTo: a@b\r\n\r\nSubject: not me\r\n",
	);
	assert!(!truncated);
	let pairs: Vec<(&str, &str)> = headers
		.iter()
		.map(|h| (h.name.as_str(), h.value.as_str()))
		.collect();
	assert_eq!(
		pairs,
		[("Subject", "hi"), ("X-A", "one two three"), ("To", "a@b")]
	);
}

#[test]
fn bare_line_feeds_end_the_block_too_and_the_body_is_never_read() {
	assert_eq!(names(b"A: 1\nB: 2\n\nC: 3\n"), ["A", "B"]);
	assert_eq!(names(b"A: 1\r\n\r\nB: 2\r\n"), ["A"]);
	assert_eq!(names(b"\r\nA: 1\r\n"), Vec::<String>::new());
}

#[test]
fn a_message_with_no_blank_line_gives_its_fields_and_a_long_block_is_cut() {
	assert_eq!(names(b"A: 1\r\nB: 2\r\n"), ["A", "B"]);
	let mut long = b"A: 1\r\n".to_vec();
	long.extend(std::iter::repeat_n(b'x', 200_000));
	let (headers, truncated) = headers_of(&long);
	assert!(truncated);
	assert_eq!(headers.len(), 1);
}

#[test]
fn the_number_of_fields_and_the_length_of_a_value_are_capped() {
	let mut message = String::new();
	for n in 0..MAX_HEADERS + 50 {
		message.push_str(&format!("X-{n}: v\r\n"));
	}
	message.push_str("\r\n");
	let (headers, truncated) = headers_of(message.as_bytes());
	assert!(truncated);
	assert_eq!(headers.len(), MAX_HEADERS);
	let (headers, truncated) = headers_of(format!("A: {}\r\n\r\n", "y".repeat(5000)).as_bytes());
	assert!(truncated);
	assert_eq!(headers[0].value.chars().count(), 1000);
}

#[test]
fn bytes_that_are_not_text_do_not_stop_the_reading() {
	let (headers, _) = headers_of(b"A: \xff\xfe\r\nB: ok\r\n\r\n");
	assert_eq!(headers.len(), 2);
	assert_eq!(headers[1].value, "ok");
}
