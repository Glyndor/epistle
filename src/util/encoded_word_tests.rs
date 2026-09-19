//! Tests for the RFC 2047 encoded-word decoder.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::decode;

/// Inputs that look like the start of an encoded-word and are not one. Each
/// has to come back byte for byte.
const HOSTILE: &[&str] = &[
	"=?",
	"=?UTF-8",
	"=?UTF-8?",
	"=?UTF-8?B",
	"=?UTF-8?B?",
	"=?UTF-8?B?w6E=",
	"=?UTF-8?B?w6E=?",
	"=?UTF-8?B?w6E=?x",
	"=????=",
	"=??B?w6E=?=",
	"=?UTF-8??w6E=?=",
	"=?UTF-8?B??=",
	"=?UTF-8?B?!!!!?=",
	"=?UTF-8?B?w6E?=",
	"=?UTF-8?Q?abc=?=",
	"=?UTF-8?Q?abc=4?=",
	"=?UTF-8?Q?=G1?=",
	"=?UTF-8?Q?a b?=",
	"=?UTF-8?X?abc?=",
	"=?UTF-8?BQ?abc?=",
	"=?UTF-8?B?/w==?=",
	"=?UTF-8?Q?=FF?=",
	"=?US-ASCII?Q?=E9?=",
	"=?=?=?=?=?=?",
	"?==?",
	"caf\u{e9} =?UTF-8?B?",
];

#[test]
fn b_and_q_words_decode_in_the_three_charsets() {
	assert_eq!(decode("=?UTF-8?B?w6E=?="), "\u{e1}");
	assert_eq!(decode("=?UTF-8?Q?=C3=A1?="), "\u{e1}");
	assert_eq!(decode("=?ISO-8859-1?Q?Andr=E9?="), "Andr\u{e9}");
	assert_eq!(decode("=?ISO-8859-1?B?QW5kcuk=?="), "Andr\u{e9}");
	assert_eq!(decode("=?US-ASCII?Q?Keith_Moore?="), "Keith Moore");
	assert_eq!(decode("=?US-ASCII?B?S2VpdGg=?="), "Keith");
}

#[test]
fn charset_and_encoding_names_are_case_insensitive() {
	assert_eq!(decode("=?utf-8?q?=c3=a1?="), "\u{e1}");
	assert_eq!(decode("=?Iso-8859-1?b?QW5kcuk=?="), "Andr\u{e9}");
	// RFC 2231 language suffix on the charset.
	assert_eq!(decode("=?US-ASCII*EN?Q?Keith_Moore?="), "Keith Moore");
}

#[test]
fn text_around_a_word_is_kept_with_its_whitespace() {
	assert_eq!(
		decode("Re:  =?UTF-8?Q?=C3=A1gil?=  plan"),
		"Re:  \u{e1}gil  plan"
	);
	assert_eq!(decode("plain ascii subject"), "plain ascii subject");
	assert_eq!(decode(""), "");
	assert_eq!(decode("  "), "  ");
	// Non-ASCII literal text next to a word: slicing stays on boundaries.
	assert_eq!(decode("caf\u{e9} =?UTF-8?Q?x?= \u{e9}"), "caf\u{e9} x \u{e9}");
}

#[test]
fn whitespace_between_adjacent_words_is_dropped() {
	// RFC 2047 section 6.2.
	assert_eq!(decode("=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?="), "ab");
	assert_eq!(decode("=?ISO-8859-1?Q?a?=\r\n\t=?UTF-8?B?Yg==?="), "ab");
	assert_eq!(decode("=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?= c"), "ab c");
	// A space that belongs to the text travels inside a word.
	assert_eq!(decode("=?ISO-8859-1?Q?a_?= =?ISO-8859-1?Q?b?="), "a b");
	// Between a word and plain text the whitespace is text.
	assert_eq!(decode("=?ISO-8859-1?Q?a?= b"), "a b");
	assert_eq!(decode("a =?ISO-8859-1?Q?b?="), "a b");
}

#[test]
fn a_word_in_an_unknown_charset_is_left_alone() {
	let word = "=?KOI8-R?B?8NLJ18XU?=";
	assert_eq!(decode(word), word);
	let shift_jis = "=?Shift_JIS?Q?=82=A0?=";
	assert_eq!(decode(shift_jis), shift_jis);
	// It is plain text to its neighbours, so the whitespace around it stays.
	let mixed = format!("=?UTF-8?Q?a?= {word} =?UTF-8?Q?b?=");
	assert_eq!(decode(&mixed), format!("a {word} b"));
}

#[test]
fn hostile_input_comes_back_unchanged() {
	for input in HOSTILE {
		assert_eq!(decode(input), *input, "input {input:?}");
	}
	// The same fragments glued together and surrounded by real words.
	let glued = HOSTILE.join(" ");
	assert_eq!(decode(&glued), glued);
	let wrapped = format!("=?UTF-8?Q?a?= {glued} =?UTF-8?Q?b?=");
	assert_eq!(decode(&wrapped), format!("a {glued} b"));
}

#[test]
fn a_malformed_word_does_not_stop_the_next_one_from_decoding() {
	assert_eq!(decode("=?UTF-8?B?!!!!?= =?UTF-8?Q?ok?="), "=?UTF-8?B?!!!!?= ok");
	assert_eq!(decode("=?UTF-8?Q?=?UTF-8?Q?ok?="), "=?UTF-8?Q?ok");
}

#[test]
fn decoding_never_grows_the_input() {
	// Sixty 0xFF bytes are 80 base64 characters and 120 bytes of UTF-8 once
	// read as ISO-8859-1, which is more than the 97 bytes of the word.
	let payload = BASE64.encode([0xFFu8; 60]);
	let growing = format!("=?ISO-8859-1?B?{payload}?=");
	assert_eq!(decode(&growing), growing);
	// Just inside the limit: six 0xFF bytes are 12 bytes of text in a
	// 25-byte word, and they decode.
	let small = format!("=?ISO-8859-1?B?{}?=", BASE64.encode([0xFFu8; 6]));
	assert_eq!(decode(&small), "\u{ff}".repeat(6));

	let mut inputs: Vec<String> = HOSTILE.iter().map(|s| s.to_string()).collect();
	inputs.push(growing.clone());
	inputs.push(format!("{growing} {growing}"));
	inputs.push(small);
	inputs.push("=?ISO-8859-1?Q?=FF=FF=FF?= =?ISO-8859-1?Q?=FF?=".to_string());
	for input in &inputs {
		assert!(
			decode(input).len() <= input.len(),
			"decoding grew {input:?}"
		);
	}
}
