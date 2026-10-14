//! Message-ID extraction for THREAD=REFERENCES (RFC 5256 §3).
//!
//! Every header read here is client-controlled. A list is scanned once, left
//! to right, so the work is linear in the header. What is kept is bounded:
//! an id is reduced to a fixed-size [`Key`] right away, and a References
//! list keeps only its last [`MAX_REFERENCES`] valid ids, the ones nearest
//! the message (the last one is its parent).

use std::collections::VecDeque;

/// The identity of a normalized Message-ID: the first 128 bits of its
/// SHA-256. A fixed-size key keeps the memory per id constant however long
/// the id is, and finding two ids with the same key takes about 2^64 work.
pub(super) type Key = [u8; 16];

/// How many References ids a message contributes, counted from the end of
/// the list. Each one can become a container, so this bounds the containers
/// at `messages * (MAX_REFERENCES + 1)`. Truncating keeps the parent and the
/// nearest ancestors, which is all RFC 5256 §3 step 1.B relies on, and
/// MUAs already truncate the list from the front the same way.
pub(super) const MAX_REFERENCES: usize = 64;

/// The longest normalized Message-ID accepted, in bytes. A longer one is
/// not a valid Message ID, which RFC 5256 §3 treats like a missing one.
/// RFC 5322 §2.1.1 limits a line to 998 characters, so no conforming id
/// comes near it.
pub(super) const MAX_MSGID_LEN: usize = 1024;

/// The first valid Message ID in a Message-ID or In-Reply-To value.
pub(super) fn first_id(value: &str) -> Option<Key> {
	let mut found = None;
	scan(value, |key| {
		found = Some(key);
		false
	});
	found
}

/// A message's references (RFC 5256 §3): the valid ids of its References
/// header, or, when that has none, the first valid id of In-Reply-To. At
/// most the last [`MAX_REFERENCES`] are returned, in header order.
pub(super) fn references(references: Option<&str>, in_reply_to: Option<&str>) -> Vec<Key> {
	let mut kept = VecDeque::with_capacity(MAX_REFERENCES);
	if let Some(value) = references {
		scan(value, |key| {
			if kept.len() == MAX_REFERENCES {
				kept.pop_front();
			}
			kept.push_back(key);
			true
		});
	}
	if kept.is_empty() {
		return in_reply_to.and_then(first_id).into_iter().collect();
	}
	kept.into()
}

/// Call `visit` with the key of every valid `<...>` id in `value`, in
/// order, until it returns false. Text outside the brackets (comments,
/// phrases, addresses after an In-Reply-To id) is skipped, and a `<` with
/// no `>` before the next `<` is not an id.
fn scan(value: &str, mut visit: impl FnMut(Key) -> bool) {
	let bytes = value.as_bytes();
	let mut buffer = Vec::new();
	let mut at = 0;
	while let Some(open) = position(bytes, at, |b| b == b'<') {
		let Some(close) = position(bytes, open + 1, |b| b == b'<' || b == b'>') else {
			return;
		};
		if bytes[close] == b'<' {
			at = close;
			continue;
		}
		at = close + 1;
		if normalize(&bytes[open + 1..close], &mut buffer) && !visit(digest(&buffer)) {
			return;
		}
	}
}

/// The offset of the first byte at or after `from` that matches.
fn position(bytes: &[u8], from: usize, matches: impl Fn(u8) -> bool) -> Option<usize> {
	bytes[from..]
		.iter()
		.position(|&b| matches(b))
		.map(|offset| from + offset)
}

/// Write the normalized form of the text between `<` and `>` into `out`
/// and report whether it is a valid Message ID. RFC 5256 §3 requires
/// `<"a b"@x>`-style quoting to compare equal to the unquoted form, so
/// quotes and quoted-pair backslashes are dropped, and folding whitespace
/// outside quotes is removed. Valid means `left@right` with both sides
/// non-empty and at most [`MAX_MSGID_LEN`] bytes in all.
fn normalize(inner: &[u8], out: &mut Vec<u8>) -> bool {
	out.clear();
	let (mut quoted, mut escaped) = (false, false);
	for &byte in inner {
		if escaped {
			escaped = false;
		} else if byte == b'\\' && quoted {
			escaped = true;
			continue;
		} else if byte == b'"' {
			quoted = !quoted;
			continue;
		} else if !quoted && matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
			continue;
		}
		if out.len() == MAX_MSGID_LEN {
			return false;
		}
		out.push(byte);
	}
	out.iter()
		.rposition(|&b| b == b'@')
		.is_some_and(|at| at > 0 && at + 1 < out.len())
}

/// The [`Key`] of a normalized id, or of any other text compared for
/// equality only, such as a base subject.
pub(super) fn digest(id: &[u8]) -> Key {
	let hash = ring::digest::digest(&ring::digest::SHA256, id);
	let mut key = Key::default();
	key.copy_from_slice(&hash.as_ref()[..std::mem::size_of::<Key>()]);
	key
}

#[cfg(test)]
#[path = "msgid_tests.rs"]
mod tests;
