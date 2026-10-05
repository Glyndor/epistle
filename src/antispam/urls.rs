//! URL host extraction from a MIME message body.
//!
//! Used by the URI DNSBL screen to feed [`crate::dnsbl::Dnsbl::check_url_hosts`].
//! Only the host of every `http://` / `https://` URL is returned, never the
//! path, query, or credentials, and only the first `cap` unique hosts in
//! order of appearance.

/// Maximum number of body bytes scanned (256 KiB). Beyond this the rest is
/// ignored to keep the extraction bounded.
pub const MAX_SCAN_BYTES: usize = 256 * 1024;

/// Default cap when the caller does not specify one. Mirrors the URIBL
/// guidance of "first few dozen" hosts.
pub const DEFAULT_HOST_CAP: usize = 50;

/// Scan at most the first [`MAX_SCAN_BYTES`] bytes of `body` and return up to
/// `cap` unique URL hosts (deduped, lower-cased, IP literals and `localhost`
/// dropped). Quoted-printable soft breaks (`=\r\n`) are unfolded and `=3D`
/// is decoded back to `=` so URLs hidden inside HTML mail come through; base64
/// bodies are not decoded and are ignored here.
///
/// The returned strings are A-label form (the on-the-wire encoding); any
/// `xn--` IDN already in the source is preserved verbatim.
pub fn extract_hosts(body: &[u8], cap: usize) -> Vec<String> {
	let mut out = Vec::new();
	let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
	let scan_window = if body.len() > MAX_SCAN_BYTES {
		&body[..MAX_SCAN_BYTES]
	} else {
		body
	};
	let decoded = unfold_quoted_printable(scan_window);
	for host in scan_hosts(&decoded) {
		if !seen.insert(host.clone()) {
			continue;
		}
		if out.len() >= cap {
			break;
		}
		out.push(host);
	}
	out
}

/// Unfold quoted-printable soft breaks (`=\r\n` and `=\n`) and decode `=XX`
/// hex escapes (notably `=3D` → `=`). Other `=XX` escapes are passed through
/// as their literal bytes; only the ones that change URL detection are
/// decoded, which keeps the implementation focused and avoids turning the
/// extractor into a general QP decoder.
fn unfold_quoted_printable(input: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(input.len());
	let mut i = 0;
	while i < input.len() {
		let b = input[i];
		if b == b'=' && i + 1 < input.len() {
			let next = input[i + 1];
			if next == b'\r' && i + 2 < input.len() && input[i + 2] == b'\n' {
				i += 3;
				continue;
			}
			if next == b'\n' {
				i += 2;
				continue;
			}
			if i + 2 < input.len()
				&& let Some(decoded) = hex_byte(next, input[i + 2])
			{
				out.push(decoded);
				i += 3;
				continue;
			}
		}
		out.push(b);
		i += 1;
	}
	out
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
	let h = hex_value(hi)?;
	let l = hex_value(lo)?;
	Some((h << 4) | l)
}

fn hex_value(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

/// Iterate every `http(s)://host` host found in `input`, decoded form.
fn scan_hosts(input: &[u8]) -> Vec<String> {
	let mut hosts = Vec::new();
	let mut offset = 0;
	while offset < input.len() {
		let rest = &input[offset..];
		let http = find_subslice(rest, b"http://");
		let https = find_subslice(rest, b"https://");
		let pick = match (http, https) {
			(Some(a), Some(b)) => {
				if a <= b {
					(a, "http")
				} else {
					(b, "https")
				}
			}
			(Some(a), None) => (a, "http"),
			(None, Some(b)) => (b, "https"),
			(None, None) => break,
		};
		let after = offset + pick.0 + pick.1.len() + 3; // past "://"
		let (host, consumed) = read_host(&input[after..]);
		offset = after + consumed;
		if let Some(host) = host {
			hosts.push(host);
		}
	}
	hosts
}

/// Read a host starting at `input[0]`. Returns the host and the number of
/// bytes consumed (so the caller can advance past the whole token even when
/// the host is rejected by the validator).
fn read_host(input: &[u8]) -> (Option<String>, usize) {
	let mut end = 0;
	while end < input.len() && is_host_byte(input[end]) {
		end += 1;
	}
	if end == 0 {
		return (None, 0);
	}
	let host = normalize_host(&input[..end]);
	(host, end)
}

fn is_host_byte(b: u8) -> bool {
	matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.')
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() || haystack.len() < needle.len() {
		return None;
	}
	haystack
		.windows(needle.len())
		.position(|window| window == needle)
}

fn normalize_host(raw: &[u8]) -> Option<String> {
	let mut end = raw.len();
	while end > 0 && raw[end - 1] == b'.' {
		end -= 1;
	}
	if end == 0 {
		return None;
	}
	let host = std::str::from_utf8(&raw[..end]).ok()?;
	let lower = host.to_ascii_lowercase();
	if is_ip_literal(&lower) || lower == "localhost" {
		return None;
	}
	if !lower.contains('.') {
		return None;
	}
	for label in lower.split('.') {
		if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
			return None;
		}
	}
	Some(lower)
}

fn is_ip_literal(host: &str) -> bool {
	host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
#[path = "urls_tests.rs"]
mod tests;
