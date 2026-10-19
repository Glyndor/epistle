//! Remove sender-supplied authority before stamping an inbound SMTP message.

/// Strip local trust fields in one pass, including folded continuations.
/// Authentication and ARC validation must run on the original bytes first.
/// Each retained field and the body are moved at most once, in place.
pub(crate) fn strip(data: &mut Vec<u8>, hostname: &str) {
	strip_with(data, hostname, true);
}

/// Same pass as [`strip`], with `skip_leader` controlling whether leading
/// `:` and ASCII whitespace bytes are folded before the name starts.
/// `false` reproduces the old behaviour the second review flagged as
/// unable to match `:Authentication-Results:`; the test suite drives it
/// through `false` to simulate a hypothetical hole in [`strip`].
fn strip_with(data: &mut Vec<u8>, hostname: &str, skip_leader: bool) {
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
			data.copy_within(start..read, write);
			write += read - start;
		}
	}
	let tail = data.len() - read;
	data.copy_within(read.., write);
	data.truncate(write + tail);
}

fn line_end(data: &[u8], start: usize) -> usize {
	data[start..]
		.iter()
		.position(|&byte| byte == b'\n')
		.map_or(data.len(), |at| start + at + 1)
}

fn remove(field: &[u8], hostname: &str, skip_leader: bool) -> bool {
	let mut i = 0;
	// Mirror mail-parser 0.11.9 (`src/parsers/header.rs::parse_header_name`):
	// while the name has not started, fold `:` and every ASCII whitespace
	// byte. The first byte that is neither starts the name; the first `:`
	// after that ends it. Without this, `:Authentication-Results: x` parses
	// to an empty name and no reserved-name branch fires.
	if skip_leader {
		while i < field.len() && (field[i] == b':' || field[i].is_ascii_whitespace()) {
			i += 1;
		}
	}
	if i >= field.len() {
		return false;
	}
	let Some(rel) = field[i..].iter().position(|&byte| byte == b':') else {
		return false;
	};
	let name = field[i..i + rel].trim_ascii_end();
	if name_matches(name, b"Authentication-Results") {
		return authserv_id(&field[i + rel + 1..]).is_none_or(|id| {
			id.trim_end_matches('.')
				.eq_ignore_ascii_case(hostname.trim_end_matches('.'))
		});
	}
	[
		&b"Received-SPF"[..],
		&b"Delivered-To"[..],
		&b"Return-Path"[..],
		&b"Epistle-Class"[..],
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
fn name_matches(name: &[u8], reserved: &[u8]) -> bool {
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
fn name_starts_with(name: &[u8], prefix: &[u8]) -> bool {
	let (_, j) = align(name, prefix);
	j == prefix.len()
}

/// Walk `name` and `reserved` in lockstep. `name` may contain any of the
/// obfuscation bytes in place of the corresponding reserved byte. A `-` in
/// `reserved` is matched by an obfuscation byte in `name` (so a header like
/// `X Spam-Foo` lines up with the canonical `X-Spam-` prefix). `-` in `name`
/// that does not align with the current reserved byte is treated as a
/// separator and skipped.
fn align(name: &[u8], reserved: &[u8]) -> (usize, usize) {
	let mut i = 0;
	let mut j = 0;
	while i < name.len() && j < reserved.len() {
		let nc = name[i];
		let rc = reserved[j];
		if nc.eq_ignore_ascii_case(&rc) || (rc == b'-' && is_obfuscation_byte(nc)) {
			i += 1;
			j += 1;
		} else if is_obfuscation_byte(nc) {
			i += 1;
		} else {
			break;
		}
	}
	(i, j)
}

/// Bytes that are valid as field-name character (CRLF aside) per RFC 5322 §3.6.8
/// only when the byte sequence forms the canonical name; here we list the bytes
/// that lenient downstream readers may fold out of an otherwise-matching
/// header, and that align against `-` to keep the prefix position intact.
fn is_obfuscation_byte(byte: u8) -> bool {
	matches!(byte, b' ' | b'\t' | 0x0c | 0x0b | 0x1f | 0x7f | b'-')
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
	let message = mail_parser::MessageParser::default().parse_headers(data)?;
	for header in message.headers() {
		let name = header.name();
		let value = header.value().as_text().map(|cow| cow.as_bytes());
		if let Some(canonical) = check_reserved_name(name, hostname, value) {
			return Some(canonical);
		}
	}
	None
}

fn check_reserved_name(name: &str, hostname: &str, value: Option<&[u8]>) -> Option<&'static str> {
	match name {
		"Authentication-Results" => {
			let value = value?;
			authserv_id(value)
				.is_none_or(|id| {
					id.trim_end_matches('.')
						.eq_ignore_ascii_case(hostname.trim_end_matches('.'))
				})
				.then_some("Authentication-Results")
		}
		"Received-SPF" => Some("Received-SPF"),
		"Delivered-To" => Some("Delivered-To"),
		"Return-Path" => Some("Return-Path"),
		"Epistle-Class" => Some("Epistle-Class"),
		other if other.starts_with("X-Spam-") => Some("X-Spam-Status"),
		other if other.starts_with("X-Epistle-") => Some("X-Epistle-Attachment-Warning"),
		_ => None,
	}
}

#[cfg(test)]
pub(crate) fn strip_buggy(data: &mut Vec<u8>, hostname: &str) {
	strip_with(data, hostname, false);
}

#[cfg(test)]
#[path = "inbound_headers_tests.rs"]
mod tests;
