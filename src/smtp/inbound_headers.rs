//! Remove sender-supplied authority before stamping an inbound SMTP message.

/// Strip local trust fields in one pass, including folded continuations.
/// Authentication and ARC validation must run on the original bytes first.
/// Each retained field and the body are moved at most once, in place.
pub(crate) fn strip(data: &mut Vec<u8>, hostname: &str) {
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
		if !remove(&data[start..read], hostname) {
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

fn remove(field: &[u8], hostname: &str) -> bool {
	let Some(colon) = field.iter().position(|&byte| byte == b':') else {
		return false;
	};
	let name = field[..colon].trim_ascii_end();
	if name.eq_ignore_ascii_case(b"Authentication-Results") {
		return authserv_id(&field[colon + 1..]).is_none_or(|id| {
			id.trim_end_matches('.')
				.eq_ignore_ascii_case(hostname.trim_end_matches('.'))
		});
	}
	[
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
	]
	.iter()
	.any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
		|| [b"X-Spam-".as_slice(), b"X-Epistle-".as_slice()]
			.iter()
			.any(|prefix| {
				name.get(..prefix.len())
					.is_some_and(|start| start.eq_ignore_ascii_case(prefix))
			})
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

#[cfg(test)]
#[path = "inbound_headers_tests.rs"]
mod tests;
