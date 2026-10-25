//! The `<href>` list of a CalDAV multiget body, read in one linear pass.

/// Extract every `<...:href>VALUE</...:href>` value from a REPORT body, matching
/// on the local name `href` regardless of namespace prefix.
pub(super) fn hrefs(body: &str) -> Vec<String> {
	let mut out = Vec::new();
	let mut rest = body;
	while let Some(start) = find_open(rest, "href") {
		let after = &rest[start..];
		let Some(close) = after.find('>') else {
			break;
		};
		let value_start = close + 1;
		let Some(end) = after[value_start..].find('<') else {
			break;
		};
		let value = after[value_start..value_start + end].trim();
		if !value.is_empty() {
			out.push(value.to_string());
		}
		rest = &after[value_start + end..];
	}
	out
}

/// Find the byte index of an opening tag whose local name is `local`, allowing
/// an optional `prefix:`.
///
/// The implementation walks the body once, byte by byte. The previous
/// quadratic version restarted the search from the cursor after every
/// non-match, and `tag.split(['>', ' ', '/']).next()` returned the whole
/// remaining tail as one piece when the tag was unclosed, so a body of
/// N unclosed tags cost O(N²) bytes touched. The linear scan advances
/// past the tag name in one jump and bounds the name by the next `<`
/// when no closing delimiter is found, so the total stays O(N) bytes
/// touched. The byte counter [`SCAN_STEPS`] is exposed for tests that
/// want to assert the bound.
pub(super) fn find_open(body: &str, local: &str) -> Option<usize> {
	let bytes = body.as_bytes();
	let needle = local.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		#[cfg(test)]
		{
			SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		}
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let name_start = i + 1;
		let mut name_end = name_start;
		while name_end < bytes.len() {
			#[cfg(test)]
			{
				SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			}
			let c = bytes[name_end];
			if c == b'>' || c == b' ' || c == b'/' || c == b'<' {
				break;
			}
			name_end += 1;
		}
		let mut local_start = name_start;
		for (k, b) in bytes[name_start..name_end].iter().enumerate() {
			#[cfg(test)]
			{
				SCAN_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			}
			if *b == b':' {
				local_start = name_start + k + 1;
			}
		}
		let local_len = name_end - local_start;
		if local_len == needle.len() && &bytes[local_start..name_end] == needle {
			return Some(i);
		}
		i = name_end.max(i + 1);
	}
	None
}

/// Per-process counter of how many bytes the report scanner compared.
/// Read in tests to assert the body scan is linear, not quadratic.
#[cfg(test)]
pub(super) static SCAN_STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
