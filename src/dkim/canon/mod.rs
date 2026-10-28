//! Header and body canonicalization (RFC 6376 section 3.4).

use super::signature::Canon;

/// Canonicalize one header for hashing: `name` is the original header name,
/// `value` the raw value (without the terminating CRLF).
pub fn header(canon: Canon, name: &str, value: &str) -> String {
	match canon {
		Canon::Simple => format!("{name}:{value}\r\n"),
		Canon::Relaxed => {
			let name = name.to_ascii_lowercase();
			// Unfold, collapse runs of WSP, trim.
			let mut collapsed = String::with_capacity(value.len());
			let mut in_space = false;
			for c in value.chars() {
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					in_space = true;
				} else {
					if in_space && !collapsed.is_empty() {
						collapsed.push(' ');
					}
					in_space = false;
					collapsed.push(c);
				}
			}
			format!("{name}:{collapsed}\r\n")
		}
	}
}

/// Canonicalize the message body.
pub fn body(canon: Canon, body: &[u8]) -> Vec<u8> {
	match canon {
		Canon::Simple => simple_body(body),
		Canon::Relaxed => relaxed_body(body),
	}
}

/// Simple body: strip trailing empty lines, ensure one final CRLF.
fn simple_body(body: &[u8]) -> Vec<u8> {
	let mut out = body.to_vec();
	while out.ends_with(b"\r\n\r\n") {
		out.truncate(out.len() - 2);
	}
	if out == b"\r\n" {
		return b"\r\n".to_vec();
	}
	if !out.is_empty() && !out.ends_with(b"\r\n") {
		out.extend_from_slice(b"\r\n");
	}
	if out.is_empty() {
		out.extend_from_slice(b"\r\n");
	}
	out
}

/// Relaxed body (RFC 6376 section 3.4.4): reduce every run of WSP within a
/// line to one space and drop the WSP at the end of the line, then ignore
/// the empty lines at the end of the body.
fn relaxed_body(body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(body.len());
	// The empty lines at the end of the body are ignored, so they are only
	// written once a line with content follows them.
	let mut empty_lines = 0usize;
	for line in body.split_inclusive(|&b| b == b'\n') {
		let line = line
			.strip_suffix(b"\r\n")
			.or_else(|| line.strip_suffix(b"\n"))
			.unwrap_or(line);
		let canonical = collapse_wsp(line);
		if canonical.is_empty() {
			empty_lines += 1;
			continue;
		}
		for _ in 0..empty_lines {
			out.extend_from_slice(b"\r\n");
		}
		empty_lines = 0;
		out.extend_from_slice(&canonical);
		out.extend_from_slice(b"\r\n");
	}
	out
}

/// Reduce every run of WSP within a line to one space and drop the WSP at
/// the end of the line. The WSP at the start of the line becomes that one
/// space too: relaxed keeps the indentation, it does not delete it.
fn collapse_wsp(line: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(line.len());
	let mut in_space = false;
	for &byte in line {
		if byte == b' ' || byte == b'\t' {
			in_space = true;
			continue;
		}
		if in_space {
			out.push(b' ');
			in_space = false;
		}
		out.push(byte);
	}
	out
}

#[cfg(test)]
mod tests;
