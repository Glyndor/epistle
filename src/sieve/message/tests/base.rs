//! The edges of what `Message::parse` reads: the longest header name, what is
//! cut off a name, and the one octet either side of the 64 KiB a value keeps.

use super::Message;
use crate::sieve::env::HEADER_NAME_WINDOW;

fn has(raw: &str, name: &str) -> bool {
	Message::parse(raw.as_bytes()).has_header(name)
}

fn truncated(raw: &str) -> bool {
	Message::parse(raw.as_bytes())
		.visible_headers(&["subject"])
		.truncated
}

#[test]
fn a_header_name_of_998_octets_is_a_header_and_999_is_not() {
	for (length, is_header) in [(997, true), (998, true), (999, false), (1000, false)] {
		let name = "n".repeat(length);
		let raw = format!("{name}: x\r\nSubject: s\r\n\r\nb\r\n");
		assert_eq!(has(&raw, &name), is_header, "{length}");
		assert!(has(&raw, "subject"), "the next line is read ({length})");
		assert_eq!(
			truncated(&raw),
			!is_header,
			"{length}: a name left out is said"
		);
	}
}

#[test]
fn only_spaces_and_tabs_are_cut_off_the_end_of_a_name() {
	assert!(has("Subject \t : x\r\n\r\n", "subject"));
	for blank in ["\u{b}", "\u{c}", "\u{a0}", "\u{3000}", "\u{85}", "\r"] {
		let raw = format!("Subject{blank}: x\r\n\r\n");
		assert!(!has(&raw, "subject"), "{blank:?}");
	}
}

/// Whether parsing cut a value, as the parser knows it and not as a lookup
/// that windows again would say.
fn cut(raw: &str) -> bool {
	Message::parse(raw.as_bytes()).values_cut
}

#[test]
fn a_value_keeps_exactly_65536_octets_and_says_so_when_it_has_more() {
	let text = |n: usize| format!("Subject: {}\r\n\r\n", "a".repeat(n));
	assert!(!cut(&text(HEADER_NAME_WINDOW)));
	assert!(cut(&text(HEADER_NAME_WINDOW + 1)));
	// A blank between words takes a place of its own.
	let split = |left: usize, right: usize| {
		format!(
			"Subject: {} {}\r\n\r\n",
			"a".repeat(left),
			"b".repeat(right)
		)
	};
	assert!(!cut(&split(HEADER_NAME_WINDOW - 2, 1)));
	assert!(cut(&split(HEADER_NAME_WINDOW - 1, 1)));
	// Trailing blanks cost nothing, and do not count as text left out.
	assert!(!cut(&format!(
		"Subject: {}{}\r\n\r\n",
		"a".repeat(HEADER_NAME_WINDOW),
		" ".repeat(100)
	)));
}

#[test]
fn octets_that_are_not_utf8_are_one_character_each_even_in_runs() {
	// 70 000 octets in runs of two and three: a replacement per run would be
	// shorter than the octets and a lossy one three times longer.
	let mut raw = b"Subject: ".to_vec();
	for _ in 0..10_000 {
		raw.extend_from_slice(&[0xff, 0xfe, 0xfd, b'a', 0xff, 0xfe, b'b']);
	}
	raw.extend_from_slice(b"\r\n\r\n");
	let message = Message::parse(&raw);
	let seen = message.visible_headers(&["subject"]);
	assert_eq!(seen.values.len(), 1);
	assert_eq!(seen.values[0].len(), HEADER_NAME_WINDOW, "cut at 64 KiB");
	assert!(seen.truncated);
	assert!(
		seen.values[0].starts_with("???a??b"),
		"{}",
		&seen.values[0][..10]
	);
}
