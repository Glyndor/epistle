//! The XML-scanning helpers shared by the `calendar-query` and
//! `addressbook-query` filter parsers: finding opening tags by local name
//! (namespace prefix ignored), walking to the matching closing tag, listing
//! child elements, reading an attribute from one opening tag, and decoding
//! XML entities. Report bodies are a few hundred bytes, so linear scans are
//! enough.

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
					// The name may carry a prefix that `local_name` leaves out,
					// so the end of the tag is found from where the name starts.
					let close_idx = at + 2 + after.find('>')?;
					return Some((at, close_idx + 1));
				}
			}
		} else if matches!(bytes.get(at + 1), Some(b'!') | Some(b'?')) {
			// Comment or PI: skip.
		} else {
			// A nested element of the same name opens one more level,
			// unless it closes itself (`<C:comp-filter name="X"/>`).
			// The next `<` before a `>` makes the tag malformed, and
			// stopping there keeps the whole scan linear.
			let gt = at + 1 + body[at + 1..].find(['>', '<'])?;
			if bytes[gt] == b'<' {
				return None;
			}
			let open_tag = &body[at + 1..gt];
			if local_name(open_tag).as_deref() == Some(tag) && !open_tag.ends_with('/') {
				depth += 1;
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
		if c == b'>' || c == b'/' || c == b'<' || c.is_ascii_whitespace() {
			break;
		}
		name_end += 1;
	}
	let name = &after[..name_end];
	Some(name.rsplit(':').next().unwrap_or(name).to_string())
}

/// The longest entity body decoded: room for the `#x10FFFF` of the highest
/// code point after a run of leading zeros. A longer one is kept as text.
const MAX_ENTITY: usize = 32;

/// Replace the five predefined XML entities and numeric character
/// references in `text`. An unknown or malformed entity is kept verbatim.
pub fn unescape(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	let mut rest = text;
	while let Some(amp) = rest.find('&') {
		out.push_str(&rest[..amp]);
		let tail = &rest[amp..];
		// No entity is longer than `MAX_ENTITY` bytes, so the search for the
		// `;` never looks further than that.
		let window = &tail.as_bytes()[1..tail.len().min(MAX_ENTITY + 2)];
		let Some(semi) = window.iter().position(|b| *b == b';').map(|at| at + 1) else {
			out.push('&');
			rest = &tail[1..];
			continue;
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
#[derive(Clone, Copy)]
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

/// The direct child elements of `content` with their local names, in
/// document order. Text between them is ignored. `None` when an element is
/// not closed or a closing tag has no opening one, so a malformed filter is
/// refused rather than half read.
pub fn children(content: &str) -> Option<Vec<(String, Element<'_>)>> {
	let mut out = Vec::new();
	let mut i = 0;
	while let Some(rel) = content[i..].find('<') {
		let open = i + rel;
		let gt = open + content[open..].find('>')?;
		let tag = &content[open + 1..gt];
		if tag.starts_with('?') || tag.starts_with('!') {
			i = gt + 1;
			continue;
		}
		if tag.starts_with('/') {
			return None;
		}
		let local = local_name(tag)?;
		if tag.ends_with('/') {
			out.push((local, Element { tag, inner: "" }));
			i = gt + 1;
			continue;
		}
		let (close, next) = matching_close(content, gt + 1, &local)?;
		out.push((
			local,
			Element {
				tag,
				inner: &content[gt + 1..close],
			},
		));
		i = next;
	}
	Some(out)
}

#[cfg(test)]
mod tests;
