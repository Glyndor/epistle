//! Address-header tokenizer: split a header value at top-level commas,
//! peel each piece into a display name + angle-addr, and skip past
//! `<...>`, quoted strings, and `=?...?=` encoded-words.
//!
//! ## Linear work
//!
//! The historical per-opener implementation called a `find_matching` /
//! `find_quoted_end` / `find_encoded_word_end` helper for every byte
//! that could open a sub-token, and each helper re-walked the rest of
//! the header to find the closer. With N openers and a header of
//! length L the historical work was O(N * L) = O(L^2); a header with
//! 8 KiB of `=?UTF-8?...?=` openers hung for many seconds.
//!
//! The tokenizer here is two linear passes when encoded-words are
//! involved:
//!
//! 1. A right-to-left precompute records the position of the next `?=`
//!    (the encoded-word closer) for every byte index, but only when
//!    the first `=?` opener is reached. Headers with no `=?` openers
//!    pay nothing for the table.
//! 2. A single forward pass walks each byte once. An opener either
//!    reads the closer from the precomputed table and validates the
//!    candidate, or sets a short-circuit flag and advances by one
//!    byte. The validation walks at most the encoded-word length cap
//!    and refuses anything longer without examining it: per RFC 2047
//!    §5 an encoded-word is at most 75 octets of header
//!    (`=?charset?encoding?text?=`), and our cap keeps the per-opener
//!    work bounded regardless of the size of the rest of the header.
//!
//! Every byte the tokenizer examines, in any pass, increments the
//! test-only step counter so a regression test can assert the per-call
//! work stays linear and the counter is actually driven by work (a
//! reverted algorithm that does not touch the counter silently leaves
//! it at zero and the new `counter > 0` assertion fails).

thread_local! {
	#[cfg(test)]
	static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_steps() -> u64 {
	STEPS.with(|c| c.replace(0))
}

#[cfg(test)]
fn step_tokenizer() {
	STEPS.with(|c| c.set(c.get() + 1));
}

/// Maximum bytes the encoded-word validator is willing to walk for a
/// single opener. Per RFC 2047 §5 an encoded-word is at most 75 octets
/// of header; we round up to 128 to leave slack for real-world
/// encoders that ship a slightly longer payload. Anything longer is
/// non-conformant and we refuse it without walking the body: a
/// follow-up opener that shares the same trailing `?=` would
/// otherwise pay for the whole suffix on every call.
pub(super) const MAX_ENCODED_WORD_LEN: usize = 128;

/// Three outcomes an opener can produce. Different from a single
/// `Option<usize>` because the caller needs to keep looking when the
/// candidate is malformed (the `=?` is permitted atom text at the
/// start of a header per RFC 5322 §3.2.3) but give up when the rest
/// of the header has no closer at all.
#[derive(Debug)]
pub(super) enum OpenerEnd {
	/// Position just past the matching closer.
	Found(usize),
	/// The candidate at `start` is not a valid opener. Treat it as
	/// plain text; a later opener may still be valid.
	Invalid,
	/// No `?=` appears anywhere from `start + 2` to the end of the
	/// value. No later `=?` opener can match. Caller can short-circuit
	/// further suffix searches.
	NoCloser,
}

/// Split `value` at every top-level `delimiter`. A delimiter is at top
/// level when it is outside `<...>`, outside `"..."`, and outside a
/// `=?...?=` encoded-word. The scan is one forward pass; sub-token
/// closers are located via the precomputed `?=` table when relevant
/// and via single-byte walking when not.
pub(super) fn split_top_level(value: &str, delimiter: char) -> Vec<String> {
	let mut next_closer: Option<Vec<usize>> = None;
	let mut out = Vec::new();
	let mut start = 0usize;
	let bytes = value.as_bytes();
	let mut i = 0usize;
	let mut no_more_angle = false;
	let mut no_more_quoted = false;
	let mut no_more_encoded = false;
	let delim_byte = delimiter as u8;
	while i < bytes.len() {
		#[cfg(test)]
		step_tokenizer();
		let byte = bytes[i];
		if byte == b'<' && !no_more_angle {
			let end = skip_angle_addr(bytes, i);
			if end > i + 1 {
				i = end;
			} else {
				no_more_angle = true;
				if byte == delim_byte {
					out.push(value[start..i].to_string());
					start = i + 1;
				}
				i += 1;
			}
			continue;
		}
		if byte == b'"' && !no_more_quoted {
			let end = skip_quoted_string(bytes, i);
			if end > i + 1 {
				i = end;
			} else {
				no_more_quoted = true;
				if byte == delim_byte {
					out.push(value[start..i].to_string());
					start = i + 1;
				}
				i += 1;
			}
			continue;
		}
		if byte == b'=' && i + 1 < bytes.len() && bytes[i + 1] == b'?' && !no_more_encoded {
			if next_closer.is_none() {
				next_closer = Some(build_closer_table(value));
			}
			let table = next_closer.as_ref().expect("closer table built");
			match encoded_word_end(value, i, table) {
				OpenerEnd::Found(close) => i = close,
				OpenerEnd::NoCloser => {
					no_more_encoded = true;
					if byte == delim_byte {
						out.push(value[start..i].to_string());
						start = i + 1;
					}
					i += 1;
				}
				OpenerEnd::Invalid => {
					if byte == delim_byte {
						out.push(value[start..i].to_string());
						start = i + 1;
					}
					i += 1;
				}
			}
			continue;
		}
		if byte == delim_byte {
			out.push(value[start..i].to_string());
			start = i + 1;
		}
		i += 1;
	}
	out.push(value[start..].to_string());
	out
}

/// The byte positions of `<` and `>` that wrap the email of an
/// address, both outside any quoted-string and outside any
/// encoded-word. Returns `None` when no angle-addr is present.
pub(super) fn find_angle_addr(value: &str) -> Option<(usize, usize)> {
	let mut next_closer: Option<Vec<usize>> = None;
	let bytes = value.as_bytes();
	let mut last: Option<(usize, usize)> = None;
	let mut i = 0usize;
	let mut no_more_angle = false;
	let mut no_more_quoted = false;
	let mut no_more_encoded = false;
	while i < bytes.len() {
		#[cfg(test)]
		step_tokenizer();
		let byte = bytes[i];
		if byte == b'<' && !no_more_angle {
			let start = i;
			let end = skip_angle_addr(bytes, i);
			if end > start + 1 {
				last = Some((start, end - 1));
				i = end;
			} else {
				no_more_angle = true;
				i += 1;
			}
			continue;
		}
		if byte == b'"' && !no_more_quoted {
			let start = i;
			let end = skip_quoted_string(bytes, i);
			if end > start + 1 {
				i = end;
			} else {
				no_more_quoted = true;
				i += 1;
			}
			continue;
		}
		if byte == b'=' && i + 1 < bytes.len() && bytes[i + 1] == b'?' && !no_more_encoded {
			if next_closer.is_none() {
				next_closer = Some(build_closer_table(value));
			}
			let table = next_closer.as_ref().expect("closer table built");
			match encoded_word_end(value, i, table) {
				OpenerEnd::Found(close) => i = close,
				OpenerEnd::NoCloser => {
					no_more_encoded = true;
					i += 1;
				}
				OpenerEnd::Invalid => i += 1,
			}
			continue;
		}
		i += 1;
	}
	last
}

/// Right-to-left table mapping every byte index to the position of
/// the next `?` that is part of a `?=` closer at-or-after that index,
/// or `value.len()` if no closer exists. The returned position is the
/// `?`, so the closer end is `pos + 2`.
///
/// Building the table walks `value` exactly once, so the total work
/// across every opener is O(value.len()) plus each opener's bounded
/// validation cost.
fn build_closer_table(value: &str) -> Vec<usize> {
	let bytes = value.as_bytes();
	let len = bytes.len();
	let mut next = vec![len; len + 1];
	let mut candidate = len;
	for i in (0..len).rev() {
		#[cfg(test)]
		step_tokenizer();
		next[i] = candidate;
		if bytes[i] == b'?' && i + 1 < len && bytes[i + 1] == b'=' {
			candidate = i;
		}
	}
	next
}

fn skip_angle_addr(bytes: &[u8], start: usize) -> usize {
	let mut i = start + 1;
	while i < bytes.len() {
		#[cfg(test)]
		step_tokenizer();
		match bytes[i] {
			b'\\' if i + 1 < bytes.len() => i += 2,
			b'>' => return i + 1,
			_ => i += 1,
		}
	}
	start + 1
}

fn skip_quoted_string(bytes: &[u8], start: usize) -> usize {
	let mut i = start + 1;
	while i < bytes.len() {
		#[cfg(test)]
		step_tokenizer();
		match bytes[i] {
			b'\\' if i + 1 < bytes.len() => i += 2,
			b'"' => return i + 1,
			_ => i += 1,
		}
	}
	start + 1
}

/// Resolve an encoded-word opener at `value[start]` (which must point
/// at `=`). The closer position comes from the precomputed
/// `next_closer` table so each opener knows in O(1) whether the rest
/// of the header has a closer. The validation walk is bounded by
/// [`MAX_ENCODED_WORD_LEN`]: a candidate longer than the cap is
/// non-conformant and is refused without examining its body, which
/// keeps the per-opener cost O(1) regardless of the size of the rest
/// of the header.
fn encoded_word_end(value: &str, start: usize, next_closer: &[usize]) -> OpenerEnd {
	let bytes = value.as_bytes();
	let len = bytes.len();
	let payload_start = start + 2;
	let closer = next_closer[payload_start];
	if closer >= len {
		// No `?=` exists anywhere in the rest of the header. No later
		// opener can match.
		return OpenerEnd::NoCloser;
	}
	let closer_end = closer + 2;
	let candidate_len = closer_end - start;
	if candidate_len > MAX_ENCODED_WORD_LEN {
		// Per RFC 2047 §5 an encoded-word is at most 75 octets of
		// header characters. Anything longer is non-conformant and we
		// refuse without walking the body: a follow-up opener that
		// shares the same trailing `?=` would otherwise pay for the
		// whole suffix on every call. The reversion test below relies
		// on this branch, so any restored `find("?=")` algorithm that
		// walks the suffix shows up as a per-opener slowdown the test
		// measures via the step counter.
		return OpenerEnd::Invalid;
	}
	// Walk the bounded candidate `bytes[start+2..closer]`. The shape
	// is `=?CHARSET?ENCODING?TEXT?=`. We collect the two `?` separator
	// positions; a third `?` makes the candidate invalid because a
	// valid encoded-word has exactly two separators inside its body.
	let mut first_q: Option<usize> = None;
	let mut second_q: Option<usize> = None;
	let mut offset = 0usize;
	while start + 2 + offset < closer {
		#[cfg(test)]
		step_tokenizer();
		let idx = payload_start + offset;
		let b = bytes[idx];
		if b == b'?' {
			if first_q.is_none() {
				first_q = Some(idx);
			} else if second_q.is_none() {
				second_q = Some(idx);
			} else {
				return OpenerEnd::Invalid;
			}
		} else if !b.is_ascii_graphic() {
			return OpenerEnd::Invalid;
		}
		offset += 1;
	}
	let Some(first_q) = first_q else {
		return OpenerEnd::Invalid;
	};
	let Some(second_q) = second_q else {
		return OpenerEnd::Invalid;
	};
	let charset = &bytes[payload_start..first_q];
	let encoding = &bytes[first_q + 1..second_q];
	let text = &bytes[second_q + 1..closer];
	if charset.is_empty()
		|| encoding.is_empty()
		|| text.is_empty()
		|| !charset
			.iter()
			.all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
		|| !encoding.iter().all(|b| *b == b'B' || *b == b'Q')
		|| !text.iter().all(|b| b.is_ascii_graphic())
	{
		return OpenerEnd::Invalid;
	}
	OpenerEnd::Found(closer_end)
}

#[cfg(test)]
#[path = "address_tokenizer_tests.rs"]
mod tests;
