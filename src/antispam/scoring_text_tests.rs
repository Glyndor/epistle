//! What a message is reduced to before it is scored.

use super::*;
use crate::antispam::bayes::tokenize;

fn tokens_of(text: &str) -> Vec<String> {
	tokenize(text)
}

/// A multipart message with a text part and an attachment of `blob` bytes of
/// base64 made of letters and digits that do not repeat.
fn with_attachment(body: &str, blob: usize) -> Vec<u8> {
	let mut state = 0x2545_f491_4f6c_dd1du64;
	let mut encoded = String::with_capacity(blob + blob / 76 + 2);
	for index in 0..blob {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		encoded.push(
			b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				[(state % 64) as usize] as char,
		);
		if index % 76 == 75 {
			encoded.push('\n');
		}
	}
	format!(
		"From: a@example.org\r\nSubject: hello\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=\"bb\"\r\n\r\n\
		 --bb\r\nContent-Type: text/plain\r\n\r\n{body}\r\n\
		 --bb\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\
		 Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--bb--\r\n"
	)
	.into_bytes()
}

#[test]
fn a_plain_message_keeps_exactly_the_tokens_it_always_had() {
	let raw =
		b"From: a@example.org\r\nSubject: Cheap Pills\r\n\r\nBuy cheap pills at 50% off today\r\n";
	let reduced = scoring_text(raw);
	assert!(!reduced.clipped);
	assert_eq!(
		tokens_of(&reduced.text),
		tokens_of(&String::from_utf8_lossy(raw))
	);
}

#[test]
fn a_message_without_a_blank_line_is_read_as_it_is() {
	let reduced = scoring_text(b"cheap pills offer");
	assert_eq!(tokens_of(&reduced.text), ["cheap", "pills", "offer"]);
}

#[test]
fn an_attachment_is_not_text_and_costs_nothing() {
	let small = scoring_text(&with_attachment("agenda budget review", 1000));
	let large = scoring_text(&with_attachment("agenda budget review", 1_000_000));
	assert_eq!(small, large);
	assert!(!large.clipped);
	assert!(
		large.text.len() < 400,
		"the attachment leaked: {}",
		large.text.len()
	);
}

#[test]
fn a_text_part_sent_as_base64_is_read_decoded() {
	let raw = b"Subject: x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nY2hlYXAgcGlsbHMgb2ZmZXI=\r\n";
	let reduced = scoring_text(raw);
	let tokens = tokens_of(&reduced.text);
	assert!(
		["cheap", "pills", "offer"]
			.iter()
			.all(|word| tokens.iter().any(|t| t == word))
	);
}

#[test]
fn filler_that_is_not_made_of_tokens_costs_nothing() {
	let mut raw = b"Subject: x\r\n\r\nfirst spam paragraph ".to_vec();
	raw.extend(std::iter::repeat_n(b' ', 3 * MAX_TRAINING_BYTES));
	raw.extend(b"\n".repeat(MAX_TRAINING_BYTES));
	raw.extend("x ".repeat(MAX_TRAINING_BYTES).bytes());
	raw.extend(b"last spam paragraph\r\n");
	let reduced = scoring_text(&raw);
	assert!(!reduced.clipped);
	let tokens = tokens_of(&reduced.text);
	assert_eq!(tokens, ["subject", "first", "spam", "paragraph", "last"]);
}

#[test]
fn text_that_does_not_fit_is_cut_to_its_start_and_its_end() {
	let body: String = (0..60_000).map(|n| format!("wd{n:07x} ")).collect();
	let raw = format!("Subject: x\r\n\r\nstartword {body}endword\r\n");
	let reduced = scoring_text(raw.as_bytes());
	assert!(reduced.clipped);
	assert!(reduced.text.len() <= MAX_TRAINING_BYTES);
	assert!(reduced.text.starts_with("Subject startword"));
	assert!(reduced.text.trim_end().ends_with("endword"));
	assert!(!reduced.text.contains("wd0007530"), "the middle was kept");
	assert!(reduced.text.contains('\n'));
}

#[test]
fn text_that_just_fits_is_not_clipped() {
	// 25 000 tokens of 9 bytes and a space: 250 000 bytes.
	let body: String = (0..25_000).map(|n| format!("wd{n:07x} ")).collect();
	let reduced = scoring_text(format!("\r\n{body}").as_bytes());
	assert!(!reduced.clipped, "{} bytes", reduced.text.len());
	assert_eq!(tokens_of(&reduced.text).len(), 25_000);
}

#[test]
fn bytes_that_are_not_utf8_separate_words() {
	let mut raw = b"\r\nalpha".to_vec();
	raw.push(0xff);
	raw.extend(b"beta gamma");
	assert_eq!(
		tokens_of(&scoring_text(&raw).text),
		["alpha", "beta", "gamma"]
	);
}

/// Nesting deeper than the walk follows is read as bytes, not skipped.
#[test]
fn a_structure_the_walk_gives_up_on_is_read_as_bytes() {
	let mut raw = String::from("Subject: x\r\n");
	for level in 0..15 {
		raw.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
		));
	}
	raw.push_str("Content-Type: text/plain\r\n\r\ndeepword\r\n");
	let reduced = scoring_text(raw.as_bytes());
	assert!(tokens_of(&reduced.text).iter().any(|t| t == "deepword"));
}

/// A text part larger than the decoding budget is not all of the text: the
/// message is read as bytes, start and end.
#[test]
fn a_text_part_past_the_budget_is_read_as_bytes() {
	let body = format!("startword {} endword", "filler ".repeat(MAX_DECODED / 4));
	let raw = format!("Subject: x\r\n\r\n{body}\r\n");
	let reduced = scoring_text(raw.as_bytes());
	let tokens = tokens_of(&reduced.text);
	assert!(tokens.iter().any(|t| t == "startword"));
	assert!(tokens.iter().any(|t| t == "endword"));
	assert!(reduced.clipped);
}
