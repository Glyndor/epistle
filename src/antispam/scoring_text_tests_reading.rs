//! Text a person reads that is not plain UTF-8 in the bytes: another charset,
//! and encoded words in the headers.

use super::*;
use crate::antispam::bayes::tokenize;

fn has(raw: &[u8], word: &str) -> bool {
	tokenize(&scoring_text(raw).text).iter().any(|t| t == word)
}

fn base64_of(bytes: &[u8]) -> String {
	use base64::Engine as _;
	base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn multipart(parts: &str) -> Vec<u8> {
	format!("Subject: x\r\nContent-Type: multipart/mixed; boundary=\"bb\"\r\n\r\n{parts}--bb--\r\n")
		.into_bytes()
}

/// Text in a charset whose bytes are not UTF-8: UTF-16 with or without a mark,
/// and Latin-1.
#[test]
fn text_in_another_charset_is_read() {
	let utf16le: Vec<u8> = "hiddenword is here"
		.encode_utf16()
		.flat_map(u16::to_le_bytes)
		.collect();
	let utf16be: Vec<u8> = "hiddenword is here"
		.encode_utf16()
		.flat_map(u16::to_be_bytes)
		.collect();
	let mut marked = vec![0xff, 0xfe];
	marked.extend(&utf16le);
	for (name, bytes) in [("le", utf16le), ("be", utf16be), ("bom", marked)] {
		let raw = multipart(&format!(
			"--bb\r\nContent-Type: text/plain; charset=utf-16\r\n\
			 Content-Transfer-Encoding: base64\r\n\r\n{}\r\n",
			base64_of(&bytes)
		));
		assert!(has(&raw, "hiddenword"), "utf-16 {name}");
	}
	// A word with a letter outside ASCII, in Latin-1, would otherwise be cut
	// in two at the byte.
	let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\nthe caf\xe9s hiddenword\r\n";
	assert!(has(raw, "cafés"));
	assert!(has(raw, "hiddenword"));
}

/// A subject or a name sent as an RFC 2047 encoded word is what a person
/// reads, not the base64 or the `=XX` it travels in.
#[test]
fn an_encoded_word_in_a_header_is_read_decoded() {
	let raw = b"Subject: =?utf-8?B?aGlkZGVud29yZCBpcyBoZXJl?=\r\n\
		From: =?utf-8?q?other=77ord?= <a@example.org>\r\n\r\nbody\r\n";
	assert!(has(raw, "hiddenword"));
	assert!(has(raw, "otherword"));
}

/// Characters that take no room on the screen are not a space between two
/// halves of a word: a person reads `viagra`.
#[test]
fn invisible_characters_do_not_split_a_word() {
	for invisible in [
		'\u{200b}',
		'\u{200c}',
		'\u{200d}',
		'\u{00ad}',
		'\u{2060}',
		'\u{feff}',
		'\u{034f}',
		'\u{180e}',
		'\u{fe0f}',
		'\u{e0020}',
	] {
		let raw = format!(
			"Subject: x\r\n\r\ncheap vi{invisible}agra n{invisible}ow café{invisible}s\r\n"
		);
		assert!(has(raw.as_bytes(), "viagra"), "U+{:04X}", invisible as u32);
		assert!(has(raw.as_bytes(), "cafés"));
	}
	// Plain accented text is read as before.
	assert!(has("Subject: x\r\n\r\nñandú comió\r\n".as_bytes(), "ñandú"));
}

/// The same in the readings that go through [`read::push_chars`]: UTF-16 in
/// both orders and with a mark, and Latin-1 where 0xAD is a soft hyphen.
#[test]
fn invisible_characters_do_not_split_a_word_in_utf16_or_latin1() {
	let text = "cheap f\u{200b}ree v\u{00ad}iagra now";
	let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
	let be: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
	let mut marked = vec![0xfe, 0xff];
	marked.extend(&be);
	for (name, bytes) in [("le", le), ("be", be), ("bom", marked)] {
		let raw = multipart(&format!(
			"--bb\r\nContent-Type: text/plain; charset=utf-16\r\n\
			 Content-Transfer-Encoding: base64\r\n\r\n{}\r\n",
			base64_of(&bytes)
		));
		assert!(has(&raw, "free"), "utf-16 {name}");
		assert!(has(&raw, "viagra"), "utf-16 {name}");
	}
	let raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncheap fr\xadee vi\xadagra caf\xe9\r\n";
	assert!(has(raw, "free"));
	assert!(has(raw, "viagra"));
}
