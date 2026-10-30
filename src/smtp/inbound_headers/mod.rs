//! Remove sender-supplied authority before stamping an inbound SMTP message.

// Counter of bytes moved by `copy_within_tracking` during tests. The
// compaction test exposes this so a regression to per-field `Vec::drain`
// (which moves the suffix once per removed field, and so is quadratic)
// fails an assertion instead of the existing pointer/contents checks
// that pass even when the algorithm is quadratic.
#[cfg(test)]
thread_local! {
	static BYTES_MOVED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_moves(bytes: usize) {
	BYTES_MOVED.with(|c| c.set(c.get() + bytes));
}

#[cfg(test)]
fn reset_moves() {
	BYTES_MOVED.with(|c| c.set(0));
}

#[cfg(test)]
fn moves() -> usize {
	BYTES_MOVED.with(|c| c.get())
}

/// Strip local trust fields in one pass, including folded continuations.
/// Authentication and ARC validation must run on the original bytes first.
/// Each retained field and the body are moved at most once, in place.
pub(crate) fn strip(data: &mut Vec<u8>, hostname: &str) {
	strip_with(data, hostname, true, false);
}

/// Same pass as [`strip`], with `skip_leader` controlling whether leading
/// `:` and ASCII whitespace bytes are folded before the name starts.
/// `false` reproduces the old behaviour the second review flagged as
/// unable to match `:Authentication-Results:`; the test suite drives it
/// through `false` to simulate a hypothetical hole in [`strip`]. The
/// `drain_per_field` flag is a test-only escape hatch that replaces the
/// in-place compaction with one `Vec::drain` per removed field, which
/// moves the suffix once per field and so is quadratic.
#[cfg_attr(not(test), allow(unused_variables))]
fn strip_with(data: &mut Vec<u8>, hostname: &str, skip_leader: bool, drain_per_field: bool) {
	#[cfg(test)]
	if drain_per_field {
		strip_drain(data, hostname, skip_leader);
		return;
	}
	let mut read = 0;
	let mut write = 0;
	while read < data.len() {
		let start = read;
		let end = line_end(data, read);
		if matches!(&data[read..end], b"\r\n" | b"\n") {
			break;
		}
		read = end;
		while read < data.len() && matches!(data[read], b' ' | b'\t') {
			read = line_end(data, read);
		}
		if !remove(&data[start..read], hostname, skip_leader) {
			copy_within_tracking(data, start..read, write);
			write += read - start;
		}
	}
	let tail = data.len() - read;
	copy_within_tracking(data, read.., write);
	data.truncate(write + tail);
}

/// Test-only quadratic version of the strip pass: one `Vec::drain` per
/// removed field. The compaction test asserts that the in-place pass
/// stays linear and that swapping to this version is caught.
#[cfg(test)]
fn strip_drain(data: &mut Vec<u8>, hostname: &str, skip_leader: bool) {
	let mut read = 0;
	let mut write = 0;
	while read < data.len() {
		let start = read;
		let end = line_end(data, read);
		if matches!(&data[read..end], b"\r\n" | b"\n") {
			break;
		}
		read = end;
		while read < data.len() && matches!(data[read], b' ' | b'\t') {
			read = line_end(data, read);
		}
		if remove(&data[start..read], hostname, skip_leader) {
			// Per-field drain: the suffix moves once per removed field.
			let len = data.len();
			record_moves(len - start);
			data.drain(start..read);
			read = start;
		} else {
			if write != start {
				let len = data.len();
				record_moves(len - start);
				data.copy_within(start..read, write);
			}
			write += read - start;
		}
	}
}

/// Same pass as [`strip`], with `skip_leader` controlling whether leading
/// `:` and ASCII whitespace bytes are folded before the name starts.
/// `false` reproduces the old behaviour the second review flagged as
/// unable to match `:Authentication-Results:`; the test suite drives it
/// through `false` to simulate a hypothetical hole in [`strip`].
#[cfg(test)]
pub(crate) fn strip_with_drain_for_test(data: &mut Vec<u8>, hostname: &str) {
	strip_with(data, hostname, true, true);
}

#[cfg(test)]
#[allow(clippy::ptr_arg)]
fn copy_within_tracking<R: std::ops::RangeBounds<usize>>(data: &mut Vec<u8>, src: R, dst: usize) {
	let len = match src.end_bound() {
		std::ops::Bound::Included(n) => n + 1,
		std::ops::Bound::Excluded(n) => *n,
		std::ops::Bound::Unbounded => data.len(),
	} - match src.start_bound() {
		std::ops::Bound::Included(n) => *n,
		std::ops::Bound::Excluded(n) => n + 1,
		std::ops::Bound::Unbounded => 0,
	};
	record_moves(len);
	data.copy_within(src, dst);
}

#[cfg(not(test))]
fn copy_within_tracking<R: std::ops::RangeBounds<usize>>(data: &mut [u8], src: R, dst: usize) {
	data.copy_within(src, dst);
}

fn line_end(data: &[u8], start: usize) -> usize {
	data[start..]
		.iter()
		.position(|&byte| byte == b'\n')
		.map_or(data.len(), |at| start + at + 1)
}

fn remove(field: &[u8], hostname: &str, skip_leader: bool) -> bool {
	use super::trace::{name_start, split_field_from};
	// One extraction for the name of a field, shared with the submission
	// strip: `name_start` folds the `:` and ASCII whitespace bytes mail-parser
	// folds while the name has not started, and `split_field_from` folds the
	// trailing whitespace DKIM and ARC-AMS fold. Without the first, `:X: x`
	// parses to an empty name and no reserved-name branch fires.
	let offset = if skip_leader { name_start(field) } else { 0 };
	let Some((name, value)) = split_field_from(field, offset) else {
		return false;
	};
	if name_matches(name, b"Authentication-Results") {
		return authserv_id(value).is_none_or(|id| {
			id.trim_end_matches('.')
				.eq_ignore_ascii_case(hostname.trim_end_matches('.'))
		});
	}
	[
		&b"Received-SPF"[..],
		&b"Delivered-To"[..],
		&b"Return-Path"[..],
		&b"Epistle-Class"[..],
		&b"X-Epistle"[..],
	]
	.iter()
	.any(|wanted| name_matches(name, wanted))
		|| [b"X-Spam-".as_slice(), b"X-Epistle-".as_slice()]
			.iter()
			.any(|prefix| name_starts_with(name, prefix))
}

/// Whether `name` is exactly `reserved` (case-insensitive), tolerating internal
/// whitespace and form-feed-like bytes in `name` that aligners downstream of
/// SMTP accept as part of the header name. Such bytes may appear at the start
/// of the name, between characters, or at the end. `-` in `name` is treated as
/// a separator so a stray dash never blocks an otherwise-clean match.
pub(crate) fn name_matches(name: &[u8], reserved: &[u8]) -> bool {
	let (mut i, j) = align(name, reserved);
	if j != reserved.len() {
		return false;
	}
	while i < name.len() && is_obfuscation_byte(name[i]) {
		i += 1;
	}
	i == name.len()
}

/// Whether `name` starts with `prefix` under the same rules, ignoring anything
/// after the matched prefix.
pub(crate) fn name_starts_with(name: &[u8], prefix: &[u8]) -> bool {
	let (_, j) = align(name, prefix);
	j == prefix.len()
}

/// Walk `name` and `reserved` in lockstep. A name byte that is a foldable
/// obfuscation byte (whitespace-like bytes other than `-`, see
/// [`is_obfuscation_byte`]) is dropped without consuming the reserved
/// byte at the same position; a reserved `-` matches a foldable name
/// byte and consumes both. A `-` in `name` that follows a fold from
/// whitespace to a reserved `-` is consumed as part of the same fold
/// (mail-parser includes the `-` in the effective header bytes). A `-` in
/// `name` outside that case breaks the match: no reader folds the stray
/// dash, so the field is a distinct foreign header and stays in the
/// message.
fn align(name: &[u8], reserved: &[u8]) -> (usize, usize) {
	let mut i = 0;
	let mut j = 0;
	let mut last_fold_was_dash = false;
	while i < name.len() && j < reserved.len() {
		let nc = name[i];
		let rc = reserved[j];
		if nc.eq_ignore_ascii_case(&rc) {
			i += 1;
			j += 1;
			last_fold_was_dash = false;
		} else if rc == b'-' && is_obfuscation_byte(nc) {
			i += 1;
			j += 1;
			last_fold_was_dash = true;
		} else if last_fold_was_dash && nc == b'-' {
			i += 1;
			last_fold_was_dash = false;
		} else if is_obfuscation_byte(nc) {
			i += 1;
		} else {
			break;
		}
	}
	(i, j)
}

/// Whitespace-like bytes that lenient downstream readers may fold out of
/// an otherwise-matching header name. `-` is no longer foldable here: it
/// only maps to a `-` at the same position in the canonical name, so a
/// stray `-` (`-Delivered-To`, `Authentication--Results`) breaks the
/// match instead of being silently consumed as obfuscation.
fn is_obfuscation_byte(byte: u8) -> bool {
	matches!(byte, b' ' | b'\t' | 0x0c | 0x0b | 0x1f | 0x7f)
}

/// Read the RFC 8601 preamble: CFWS, a MIME token or quoted value, an
/// optional numeric version, and the result separator. Results from other
/// services remain untrusted and are not interpreted here.
fn authserv_id(value: &[u8]) -> Option<String> {
	let mut rest = value.trim_ascii_end();
	cfws(&mut rest)?;
	let mut id = Vec::new();
	if rest.first() == Some(&b'"') {
		rest = &rest[1..];
		loop {
			let (&byte, tail) = rest.split_first()?;
			rest = tail;
			match byte {
				b'"' => break,
				b'\\' => {
					let (&escaped, tail) = rest.split_first()?;
					if escaped.is_ascii_control() && escaped != b'\t' {
						return None;
					}
					id.push(escaped);
					rest = tail;
				}
				b'\r' => {
					rest = rest.strip_prefix(b"\n")?;
					if !matches!(rest.first(), Some(b' ' | b'\t')) {
						return None;
					}
				}
				byte if byte.is_ascii_control() && byte != b'\t' => return None,
				byte => id.push(byte),
			}
		}
	} else {
		let end = rest
			.iter()
			.position(|&byte| !token(byte))
			.unwrap_or(rest.len());
		id.extend_from_slice(&rest[..end]);
		rest = &rest[end..];
	}
	if id.is_empty() {
		return None;
	}
	let before = rest.len();
	cfws(&mut rest)?;
	if rest.first().is_some_and(u8::is_ascii_digit) {
		if before == rest.len() {
			return None;
		}
		while rest.first().is_some_and(u8::is_ascii_digit) {
			rest = &rest[1..];
		}
		cfws(&mut rest)?;
	}
	rest.strip_prefix(b";")?;
	String::from_utf8(id).ok()
}

fn token(byte: u8) -> bool {
	byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&byte)
}

/// Skip whitespace and nested comments without recursion or backtracking.
fn cfws(rest: &mut &[u8]) -> Option<()> {
	let mut depth = 0usize;
	while let Some((&byte, tail)) = rest.split_first() {
		match byte {
			b' ' | b'\t' => {}
			b'\r' => {
				*rest = tail.strip_prefix(b"\n")?;
				if !matches!(rest.first(), Some(b' ' | b'\t')) {
					return None;
				}
				continue;
			}
			b'(' => depth += 1,
			b')' if depth > 0 => depth -= 1,
			b'\\' if depth > 0 => {
				let (&escaped, tail) = tail.split_first()?;
				if escaped.is_ascii_control() && escaped != b'\t' {
					return None;
				}
				*rest = tail;
				continue;
			}
			byte if depth > 0 && (!byte.is_ascii_control() || byte == b'\t') => {}
			_ if depth == 0 => break,
			_ => return None,
		}
		*rest = tail;
	}
	(depth == 0).then_some(())
}

/// Defence in depth: re-parse the header section with the same parser the
/// downstream readers use, and report the first reserved field that
/// survived [`strip`]. Returns the canonical form of the offending name
/// (one of the eight lists below) so the caller can log it.
///
/// Strip is meant to be authoritative, but the byte-level fuzz matcher
/// it relies on is reactive: any future mail-parser change that folds a
/// byte we did not consider reopens the bypass. This check turns the
/// next such leak from "forged header delivered" into "the message is
/// refused". The cost is one extra linear pass over the header section.
///
/// `Authentication-Results` is only flagged when its remaining value
/// parses to the server's own authserv-id or does not parse at all; a
/// foreign, parseable authserv-id is kept as untrusted information, by
/// design.
pub(crate) fn reserved_remaining(data: &[u8], hostname: &str) -> Option<&'static str> {
	// When the reader finds no header section at all there is nothing it
	// could take for a trust field, so there is nothing to refuse; a message
	// with odd lines before its headers must not be refused for that alone.
	let message = mail_parser::MessageParser::default().parse_headers(data)?;
	for header in message.headers() {
		let name = header.name();
		let value = header.value().as_text().map(|cow| cow.as_bytes());
		if let Some(canonical) = check_reserved_name(name.as_str(), hostname, value) {
			return Some(canonical);
		}
	}
	None
}

fn check_reserved_name(name: &str, hostname: &str, value: Option<&[u8]>) -> Option<&'static str> {
	// Use the union of mail-parser's reading (which keeps the case and
	// every byte of the name) and DKIM/ARC's reading (which fold trailing
	// Unicode whitespace with `name.trim_end()`). mail-parser alone misses
	// the trailing non-ASCII whitespace that DKIM/ARC fold, which is how
	// a forged `Authentication-Results\u{00A0}` would survive strip and
	// be presented to the downstream readers as canonical.
	let lower = crate::util::mail_parser::trust_header_name(name)
		.trim_end()
		.to_ascii_lowercase();
	match lower.as_str() {
		"authentication-results" => {
			// A value that is not text cannot be shown to name a foreign
			// authserv-id, so it counts as ours.
			let Some(value) = value else {
				return Some("Authentication-Results");
			};
			authserv_id(value)
				.is_none_or(|id| {
					id.trim_end_matches('.')
						.eq_ignore_ascii_case(hostname.trim_end_matches('.'))
				})
				.then_some("Authentication-Results")
		}
		"received-spf" => Some("Received-SPF"),
		"delivered-to" => Some("Delivered-To"),
		"return-path" => Some("Return-Path"),
		"epistle-class" => Some("Epistle-Class"),
		"x-epistle" => Some("X-Epistle"),
		other if other.starts_with("x-spam-") => Some("X-Spam-Status"),
		other if other.starts_with("x-epistle-") => Some("X-Epistle-Attachment-Warning"),
		_ => None,
	}
}

#[cfg(test)]
pub(crate) fn strip_buggy(data: &mut Vec<u8>, hostname: &str) {
	strip_with(data, hostname, false, false);
}

#[cfg(test)]
mod tests;
