//! The XML-scanning helpers used by [`super::caldav_filter`]: finding
//! the first opening tag with a given local name, walking past a
//! matching closing tag, pulling attribute values out of a tag, and
//! recognising a `<...is-not-defined/>` element. The parsers they
//! support are the `comp-filter` / `prop-filter` / `text-match` /
//! `time-range` set the calendar-query filter allows; the rest of the
//! module composes them.

/// Find the byte index of the first opening tag whose local name is
/// `local`, allowing an optional `prefix:`. Returns `None` if no
/// such tag is present.
pub fn first_open(body: &str, local: &str) -> Option<usize> {
	let bytes = body.as_bytes();
	let needle = local.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		// A closing tag (`</...>`) is never an opening one.
		if bytes[i] != b'<' || bytes.get(i + 1) == Some(&b'/') {
			i += 1;
			continue;
		}
		let name_start = i + 1;
		let mut name_end = name_start;
		while name_end < bytes.len() {
			let c = bytes[name_end];
			if c == b'>' || c == b'/' || c == b'<' || c.is_ascii_whitespace() {
				break;
			}
			name_end += 1;
		}
		let mut local_start = name_start;
		for (k, b) in bytes[name_start..name_end].iter().enumerate() {
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

/// Find the index just past the `</TAG>` that closes the open element
/// at `start`. Nesting of the same tag name is honoured, and the
/// matching accept any of the two XML namespace forms (`<tag>` and
/// `<prefix:tag>`).
pub fn matching_close(body: &str, start: usize, tag: &str) -> Option<(usize, usize)> {
	let bytes = body.as_bytes();
	let mut i = start;
	let mut depth = 1;
	while i < bytes.len() {
		let rel = body[i..].find('<')?;
		let at = i + rel;
		if bytes.get(at + 1) == Some(&b'/') {
			let after = &body[at + 2..];
			let local_close = local_name(after);
			if local_close.as_deref() == Some(tag) {
				depth -= 1;
				if depth == 0 {
					let end = at + 2 + local_close.as_ref().unwrap().len();
					let close_idx = body[end..].find('>')? + end;
					return Some((at, close_idx + 1));
				}
			}
		} else if matches!(bytes.get(at + 1), Some(b'!') | Some(b'?')) {
			// Comment or PI: skip.
		} else {
			let after = &body[at + 1..];
			let local_open = local_name(after);
			if local_open.as_deref() == Some(tag) {
				let after_name = &after[local_open.as_ref().unwrap().len()..];
				let next = after_name.chars().next()?;
				if next == '>' || next == '/' || next.is_ascii_whitespace() {
					depth += 1;
				}
			}
		}
		i = at + 1;
	}
	None
}

/// Extract the local name of a tag from the slice after its opening
/// `<` (or `</` for closing). The slice is everything up to the
/// first `>`, ` `, `/`, `\t`, `\n`, or `<`; a prefix is stripped
/// with `rsplit(':').next()`.
pub fn local_name(after: &str) -> Option<String> {
	let bytes = after.as_bytes();
	let mut name_end = 0;
	while name_end < bytes.len() {
		let c = bytes[name_end];
		if c == b'>' || c == b' ' || c == b'/' || c == b'<' || c == b'\t' || c == b'\n' {
			break;
		}
		name_end += 1;
	}
	let name = &after[..name_end];
	Some(name.rsplit(':').next().unwrap_or(name).to_string())
}

/// Read the value of an XML attribute `name="value"` from `body`,
/// starting the search at `from`. The whole attribute must be
/// present at or after `from`; returns `None` if no attribute is
/// found.
pub fn attr(body: &str, from: usize, name: &str) -> Option<String> {
	let needle = format!("{name}=");
	let mut from = from;
	while let Some(rel) = body[from..].find(&needle) {
		let at = from + rel;
		let before_ok = at == 0 || !body.as_bytes()[at - 1].is_ascii_alphanumeric();
		let rest = &body[at + needle.len()..];
		if before_ok {
			let quote = rest.chars().next()?;
			if quote == '"' || quote == '\'' {
				let value = &rest[1..];
				if let Some(close) = value.find(quote) {
					return Some(value[..close].to_string());
				}
			}
		}
		from = at + needle.len();
	}
	None
}

/// Replace the five predefined XML entities and numeric character
/// references in `text`. An unknown or malformed entity is kept verbatim.
pub fn unescape(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	let mut rest = text;
	while let Some(amp) = rest.find('&') {
		out.push_str(&rest[..amp]);
		let tail = &rest[amp..];
		let Some(semi) = tail.find(';') else {
			break;
		};
		let entity = &tail[1..semi];
		let decoded = match entity {
			"amp" => Some('&'),
			"lt" => Some('<'),
			"gt" => Some('>'),
			"quot" => Some('"'),
			"apos" => Some('\''),
			_ => entity
				.strip_prefix("#x")
				.and_then(|hex| u32::from_str_radix(hex, 16).ok())
				.or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
				.and_then(char::from_u32),
		};
		match decoded {
			Some(c) => {
				out.push(c);
				rest = &tail[semi + 1..];
			}
			None => {
				out.push('&');
				rest = &tail[1..];
			}
		}
	}
	out.push_str(rest);
	out
}

/// One element found by [`elements`]: the text of its opening tag (between
/// `<` and `>`) and its content, empty for a self-closing tag.
pub struct Element<'a> {
	/// The opening tag without its angle brackets, attributes included.
	pub tag: &'a str,
	/// Everything between the opening and the matching closing tag.
	pub inner: &'a str,
}

/// Every element with local name `local` in `content`, in document order,
/// not descending into a match once found. `None` when one of them is not
/// closed, so the caller can refuse a malformed filter instead of guessing.
pub fn elements<'a>(content: &'a str, local: &str) -> Option<Vec<Element<'a>>> {
	let mut out = Vec::new();
	let mut from = 0;
	while let Some(rel) = first_open(&content[from..], local) {
		let open = from + rel;
		let gt = open + content[open..].find('>')?;
		let tag = &content[open + 1..gt];
		if tag.ends_with('/') {
			out.push(Element { tag, inner: "" });
			from = gt + 1;
			continue;
		}
		let (close, next) = matching_close(content, gt + 1, local)?;
		out.push(Element {
			tag,
			inner: &content[gt + 1..close],
		});
		from = next;
	}
	Some(out)
}

/// The value of attribute `name` on an opening tag (the text between `<`
/// and `>`, as [`Element::tag`] holds it), XML-unescaped. Only this tag is
/// searched, so a missing attribute is never read from a later element.
pub fn tag_attr(tag: &str, name: &str) -> Option<String> {
	let needle = format!("{name}=");
	let mut start = 0;
	while let Some(rel) = tag[start..].find(&needle) {
		let at = start + rel;
		let before_ok = at > 0 && tag.as_bytes()[at - 1].is_ascii_whitespace();
		let rest = &tag[at + needle.len()..];
		if before_ok {
			let quote = rest.chars().next()?;
			if quote == '"' || quote == '\'' {
				let value = &rest[1..];
				let close = value.find(quote)?;
				return Some(unescape(&value[..close]));
			}
		}
		start = at + needle.len();
	}
	None
}

/// Whether the content contains a `<...:local_name/>` (or
/// `<local_name/>`) element. The search honours namespace prefixes.
pub fn contains_local_element(content: &str, local: &str) -> bool {
	let bytes = content.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let name_start = i + 1;
		let mut name_end = name_start;
		while name_end < bytes.len() {
			let c = bytes[name_end];
			if c == b'>' || c == b' ' || c == b'/' || c == b'<' || c == b'\t' || c == b'\n' {
				break;
			}
			name_end += 1;
		}
		let name = &content[name_start..name_end];
		let local_name = name.rsplit(':').next().unwrap_or(name);
		if local_name == local {
			return true;
		}
		i = name_end.max(i + 1);
	}
	false
}

/// Walk the body and return every element's local name in document
/// order. The caller uses this to reject unsupported elements.
pub fn local_names(body: &str) -> Vec<String> {
	let mut out = Vec::new();
	let bytes = body.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] != b'<' {
			i += 1;
			continue;
		}
		let rest = &body[i..];
		let Some(close) = rest.find('>') else {
			break;
		};
		let tag = &rest[1..close];
		if tag.starts_with('?') || tag.starts_with('!') {
			i += close + 1;
			continue;
		}
		let name = tag
			.trim_start_matches('/')
			.split(|c: char| c.is_whitespace() || c == '/' || c == '>')
			.next()
			.unwrap_or("");
		let local = name.rsplit(':').next().unwrap_or(name);
		if !local.is_empty() {
			out.push(local.to_string());
		}
		i += close + 1;
	}
	out
}

/// Whether `name` is one of the elements the calendar-query filter
/// understands. Anything else is treated as unsupported.
pub fn is_supported_element(name: &str) -> bool {
	matches!(
		name,
		"comp-filter"
			| "time-range"
			| "prop-filter"
			| "text-match"
			| "is-not-defined"
			| "filter"
			| "calendar-query"
	)
}
