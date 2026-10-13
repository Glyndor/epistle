//! The RFC 5256 §2.1 base subject, the SUBJECT key of SORT and the grouping
//! key of THREAD=ORDEREDSUBJECT.

use crate::util::encoded_word;

/// The base subject of a raw Subject header value, uppercased for the
/// i;ascii-casemap comparison both commands use.
pub(super) fn base_subject(raw: &str) -> String {
	// (1) Decode encoded words and collapse every run of whitespace.
	let decoded = encoded_word::decode(raw);
	let mut subject = decoded
		.split([' ', '\t', '\r', '\n'])
		.filter(|word| !word.is_empty())
		.collect::<Vec<_>>()
		.join(" ");
	loop {
		strip_trailers(&mut subject);
		// (5) Repeat (3) and (4) until neither removes anything.
		loop {
			let before = subject.len();
			strip_leaders(&mut subject);
			strip_blob(&mut subject);
			if subject.len() == before {
				break;
			}
		}
		// (6) A `[fwd: ...]` wrapper is removed and the whole run starts over.
		let wrapped = subject.len() >= 6
			&& subject.is_char_boundary(5)
			&& subject[..5].eq_ignore_ascii_case("[fwd:")
			&& subject.ends_with(']');
		if !wrapped {
			return subject.to_ascii_uppercase();
		}
		subject = subject[5..subject.len() - 1].to_string();
	}
}

/// (2) Remove trailing whitespace and `(fwd)` trailers.
fn strip_trailers(subject: &mut String) {
	loop {
		if subject.ends_with(' ') {
			subject.pop();
		} else if subject.len() >= 5
			&& subject.is_char_boundary(subject.len() - 5)
			&& subject[subject.len() - 5..].eq_ignore_ascii_case("(fwd)")
		{
			subject.truncate(subject.len() - 5);
		} else {
			return;
		}
	}
}

/// (3) Remove leading whitespace and `*subj-blob subj-refwd` leaders, where
/// subj-refwd is `re`, `fw` or `fwd`, optional whitespace and an optional
/// blob, then a colon.
fn strip_leaders(subject: &mut String) {
	loop {
		if subject.starts_with(' ') {
			subject.remove(0);
		} else if let Some(length) = refwd_leader(subject.as_bytes()) {
			subject.drain(..length);
		} else {
			return;
		}
	}
}

/// (4) Remove a leading blob when something is left after it.
fn strip_blob(subject: &mut String) {
	if let Some(length) = blob(subject.as_bytes())
		&& length < subject.len()
	{
		subject.drain(..length);
	}
}

/// The length of a `*subj-blob subj-refwd` prefix of `text`, if it has one.
fn refwd_leader(text: &[u8]) -> Option<usize> {
	let mut at = 0;
	while let Some(length) = blob(&text[at..]) {
		at += length;
	}
	let rest = &text[at..];
	if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case(b"re") {
		at += 2;
	} else if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case(b"fw") {
		at += 2;
		if text.get(at).is_some_and(|b| b.eq_ignore_ascii_case(&b'd')) {
			at += 1;
		}
	} else {
		return None;
	}
	at += spaces(&text[at..]);
	if let Some(length) = blob(&text[at..]) {
		at += length;
	}
	(text.get(at) == Some(&b':')).then_some(at + 1)
}

/// The length of a `[...]` blob (no brackets inside) and the whitespace
/// after it, at the start of `text`.
fn blob(text: &[u8]) -> Option<usize> {
	if text.first() != Some(&b'[') {
		return None;
	}
	let close = text[1..].iter().position(|&b| b == b'[' || b == b']')? + 1;
	if text[close] != b']' {
		return None;
	}
	Some(close + 1 + spaces(&text[close + 1..]))
}

fn spaces(text: &[u8]) -> usize {
	text.iter().take_while(|&&b| b == b' ').count()
}

#[cfg(test)]
mod tests {
	use super::base_subject;

	#[test]
	fn prefixes_trailers_and_blobs_are_removed() {
		for (raw, base) in [
			("a", "A"),
			("[foo] Fwd: [bar] Re: fw: b (fWd)  (fwd)", "B"),
			("Re: [FWD: c]", "C"),
			("[xyz]", "[XYZ]"),
			("=?iso-8859-1?q?_?=", ""),
			("Re: =?utf-8?q?b?=", "B"),
			("=?iso-8859-1?q?RE:_C?=", "C"),
			("=?us-ascii?b?UmU6IGM=?=", "C"),
			("Ad: Re: Ad: Re: Ad: x", "AD: RE: AD: RE: AD: X"),
			("re: [fwd: [fwd: re: [fwd: babylon]]]", "BABYLON"),
			("b  (a)", "B (A)"),
			("Re:\tRe :  hi", "HI"),
			("[a] [b]", "[B]"),
			("", ""),
		] {
			assert_eq!(base_subject(raw), base, "{raw}");
		}
	}
}
