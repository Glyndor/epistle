//! Cuts of the window that fall inside a character, and input built to make
//! the pass cost more than its size.
//!
//! These call [`reduce`] where they can: [`scoring_text`] catches a panic and
//! reports the message as unread, and a test through it would not see one.

use super::*;
use crate::antispam::bayes::tokenize;

/// A token of `width`-byte characters, `chars` of them, numbered so tokens
/// differ.
fn wide_token(width: usize, chars: usize, n: usize) -> String {
	let letter = match width {
		2 => 'é',
		3 => '日',
		_ => '𝐚',
	};
	let mut token: String = std::iter::repeat_n(letter, chars).collect();
	token.push_str(&format!("{n:x}"));
	token
}

fn assert_window(reduced: &ScoringText, first: &str, last: &str) {
	assert!(reduced.text.len() <= MAX_TRAINING_BYTES, "too long");
	assert!(
		reduced.clipped,
		"{} bytes of tokens were not clipped",
		reduced.text.len()
	);
	let tokens = tokenize(&reduced.text);
	assert!(tokens.iter().any(|t| t == first), "the start is gone");
	assert!(tokens.iter().any(|t| t == last), "the end is gone");
}

/// Wide tokens of every width, shifted one byte at a time, so that the end of
/// the head, the start of the tail and the cut of its front each fall on every
/// byte of a character in turn.
#[test]
fn every_cut_falls_between_characters() {
	for width in [2, 3, 4] {
		for chars in [1, 2, 6] {
			for shift in 0..(2 * width + 3) {
				let mut body = "a".repeat(shift);
				body.push(' ');
				body.push_str("firstword ");
				let mut n = 0;
				while body.len() < 3 * MAX_TRAINING_BYTES {
					body.push_str(&wide_token(width, chars, n));
					body.push(' ');
					n += 1;
				}
				body.push_str("lastword");
				let raw = format!("Subject: x\r\n\r\n{body}\r\n").into_bytes();
				// No catch: a bad cut is a panic here.
				let reduced = reduce(&raw);
				assert_window(&reduced, "firstword", "lastword");
				assert!(reduced.text.is_char_boundary(reduced.text.len()));
			}
		}
	}
}

/// The same cut where the window is filled with one run of wide characters
/// and no ASCII at all to stop at.
#[test]
fn a_window_of_wide_characters_with_no_ascii_in_it() {
	for unit in ["é", "日", "𝐚", "éa", "日a", "𝐚a"] {
		for shift in 0..4 {
			let body = format!(
				"{}{} lastword",
				"q".repeat(shift),
				unit.repeat(MAX_TRAINING_BYTES)
			);
			let reduced = reduce(format!("\r\n{body}").as_bytes());
			assert!(reduced.text.len() <= MAX_TRAINING_BYTES);
		}
	}
}

/// Bytes that are not text in every position of the window: continuation
/// bytes with no lead, lead bytes with no continuation, a character cut by the
/// end of the part.
#[test]
fn bytes_that_are_not_utf8_at_every_edge() {
	let pieces: [&[u8]; 8] = [
		b"\x80",
		b"\xbf",
		b"\xc3",
		b"\xe6\x97",
		b"\xf0\x9d\x90",
		b"\xff\xfe",
		b"\xed\xa0\x80",
		b"\xf4\x90\x80\x80",
	];
	for (index, piece) in pieces.iter().enumerate() {
		for shift in 0..5 {
			let mut raw = b"Subject: x\r\n\r\nfirstword ".to_vec();
			raw.extend(b"b".repeat(shift));
			let mut n = 0usize;
			while raw.len() < 3 * MAX_TRAINING_BYTES {
				raw.extend(format!("wd{n:x}").bytes());
				raw.extend_from_slice(piece);
				raw.push(b' ');
				n += 1;
			}
			raw.extend(b" lastword");
			raw.extend_from_slice(piece);
			let reduced = reduce(&raw);
			assert!(reduced.text.len() <= MAX_TRAINING_BYTES);
			let tokens = tokenize(&reduced.text);
			assert!(tokens.iter().any(|t| t == "firstword"), "piece {index}");
			// The text was read in two ways and does not fit: the message is
			// said not to have been read in full, which the scorer never takes
			// for clean.
			assert!(reduced.clipped, "piece {index}");
		}
	}
}

/// A part that ends inside a character, followed by another that starts with
/// a continuation byte: the two are not joined into one character.
#[test]
fn parts_do_not_join_into_a_character() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n\
		--b\r\nContent-Type: text/plain\r\n\r\nalpha\xe6\x97\r\n\
		--b\r\nContent-Type: text/plain\r\n\r\n\xa5beta gamma\r\n--b--\r\n";
	let tokens = tokenize(&reduce(raw).text);
	for word in ["alpha", "beta", "gamma"] {
		assert!(tokens.iter().any(|t| t == word), "{word}: {tokens:?}");
	}
	assert!(
		tokens.iter().all(|t| !t.contains('日')),
		"the two parts were joined: {tokens:?}"
	);
}

/// Pseudo-random messages from the pieces a hostile one is made of. None may
/// panic, and the result is always within the window.
#[test]
fn random_hostile_messages_never_panic() {
	let pieces: [&[u8]; 22] = [
		b"\r\n",
		b"\n",
		b"\r",
		b"--b",
		b"--b--",
		b"--B\r\n",
		b"Content-Type: multipart/mixed; boundary=b\r\n",
		b"Content-Type: text/plain; charset=utf-16\r\n",
		b"Content-Transfer-Encoding: base64\r\n",
		b"Content-Transfer-Encoding: quoted-printable\r\n",
		b"Content-Transfer-Encoding: 7bit\r\n",
		b"=?utf-8?B?5pel5pys?=",
		b"=E6=97",
		"日本語".as_bytes(),
		"𝐚𝐛𝐜".as_bytes(),
		b"\xff",
		b"\xe6\x97",
		b"\0",
		b"\0a\0b",
		b"word ",
		b"QUJD",
		b"=\r\n",
	];
	let mut state = 0x9e37_79b9_7f4a_7c15u64;
	for round in 0..400 {
		let mut raw = Vec::new();
		let target = if round % 40 == 0 {
			3 * MAX_TRAINING_BYTES
		} else {
			400
		};
		while raw.len() < target {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			raw.extend_from_slice(pieces[(state % pieces.len() as u64) as usize]);
		}
		let reduced = reduce(&raw);
		assert!(reduced.text.len() <= MAX_TRAINING_BYTES, "round {round}");
		let again = reduce(&raw);
		assert_eq!(reduced, again, "round {round}: not deterministic");
	}
}

/// Input that is cheap to write and expensive to read if any step is worse
/// than linear. 8 MiB each; a quadratic step takes hours, so the bound is
/// loose enough for a loaded machine.
#[test]
fn pathological_input_costs_about_its_size() {
	const SIZE: usize = 8 * 1024 * 1024;
	let cases: Vec<(&str, Vec<u8>)> = vec![
		("one token", vec![b'a'; SIZE]),
		("one-letter words", b"a ".repeat(SIZE / 2)),
		("delimiter lookalikes", b"--b\r\n".repeat(SIZE / 5)),
		("closing lookalikes", b"--b--x\r\n".repeat(SIZE / 8)),
		("blank lines", b"\r\n".repeat(SIZE / 2)),
		("header lines", b"X-A: b\r\n".repeat(SIZE / 8)),
		("nul bytes", vec![0u8; SIZE]),
		("invalid utf-8", b"\xe6\x97".repeat(SIZE / 2)),
		("encoded words", b"=?utf-8?B?5pel?= ".repeat(SIZE / 17)),
		("equals signs", b"=".repeat(SIZE)),
	];
	for (name, body) in cases {
		for shape in ["bare", "headers", "multipart"] {
			let mut raw = match shape {
				"bare" => Vec::new(),
				"headers" => b"Subject: x\r\n\r\n".to_vec(),
				_ => b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec(),
			};
			raw.extend_from_slice(&body);
			let started = std::time::Instant::now();
			let reduced = reduce(&raw);
			let took = started.elapsed();
			assert!(reduced.text.len() <= MAX_TRAINING_BYTES, "{name} {shape}");
			assert!(
				took < std::time::Duration::from_secs(30),
				"{name} {shape}: {took:?}"
			);
		}
	}
}
