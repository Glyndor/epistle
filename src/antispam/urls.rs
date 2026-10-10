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

// Test-only step counter incremented once per byte the scheme scan
// examines. Lets a regression test assert the per-call work stays
// bounded (linear in the scan window, not quadratic in the number of
// matches). The counter is per-thread so parallel tests do not
// observe each other's increments.
#[cfg(test)]
thread_local! {
	static SCAN_STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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
	scan_hosts(&decoded, cap, &mut out, &mut seen);
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

/// Single forward scan that recognises `http://` and `https://` without
/// re-scanning the suffix on every match. Hosts are deduplicated and
/// bounded inline so the function never materialises more than `cap`
/// unique results, and the scan stops as soon as the cap is reached.
fn scan_hosts(
	input: &[u8],
	cap: usize,
	out: &mut Vec<String>,
	seen: &mut std::collections::HashSet<String>,
) {
	let bytes = input;
	let mut i = 0usize;
	while i < bytes.len() {
		#[cfg(test)]
		SCAN_STEPS.with(|c| c.set(c.get() + 1));
		// Fast path: match `http://` (7 bytes) or `https://` (8 bytes) at
		// the current position. A direct byte compare is O(1) per
		// position; the old `find_subslice(rest, b"http://")` call was
		// O(rest) and made the whole scan quadratic when the body held
		// many URLs.
		if i + 7 <= bytes.len() && &bytes[i..i + 7] == b"http://" {
			let host_start = i + 7;
			let (host, consumed) = read_host(&bytes[host_start..]);
			i = host_start + consumed;
			push_unique(host, cap, out, seen);
			if out.len() >= cap {
				return;
			}
			continue;
		}
		if i + 8 <= bytes.len() && &bytes[i..i + 8] == b"https://" {
			let host_start = i + 8;
			let (host, consumed) = read_host(&bytes[host_start..]);
			i = host_start + consumed;
			push_unique(host, cap, out, seen);
			if out.len() >= cap {
				return;
			}
			continue;
		}
		i += 1;
	}
}

fn push_unique(
	host: Option<String>,
	cap: usize,
	out: &mut Vec<String>,
	seen: &mut std::collections::HashSet<String>,
) {
	if let Some(host) = host
		&& seen.insert(host.clone())
		&& out.len() < cap
	{
		out.push(host);
	}
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

#[cfg(test)]
#[allow(dead_code)]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.is_empty() || haystack.len() < needle.len() {
		return None;
	}
	for i in 0..=(haystack.len() - needle.len()) {
		#[cfg(test)]
		SCAN_STEPS.with(|c| c.set(c.get() + 1));
		if &haystack[i..i + needle.len()] == needle {
			return Some(i);
		}
	}
	None
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

/// Reset and read the test-only step counter. Returns the counter to zero
/// and hands the previous total to the caller so a test can assert the
/// delta a single `extract_hosts` call contributed.
#[cfg(test)]
fn reset_scan_steps() -> u64 {
	SCAN_STEPS.with(|c| c.replace(0))
}

#[cfg(test)]
#[path = "urls_tests.rs"]
mod tests;
