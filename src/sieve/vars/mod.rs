//! Sieve variables (RFC 5229): `${name}` substitution into string arguments.

/// Substitute `${name}` references with set variable values; an unknown
/// variable expands to the empty string. A `${` with no closing `}` is kept
/// literally. Nothing is appended past `limit` octets: the result is built no
/// longer than that, not built whole and cut afterwards.
pub(super) fn expand<'a>(
	input: &str,
	lookup: impl Fn(&str) -> Option<&'a str>,
	limit: usize,
) -> String {
	let mut out = String::with_capacity(input.len().min(limit));
	let mut rest = input;
	while let Some(start) = rest.find("${") {
		push_bounded(&mut out, &rest[..start], limit);
		let after = &rest[start + 2..];
		match after.find('}') {
			Some(end) => {
				push_bounded(&mut out, lookup(&after[..end]).unwrap_or(""), limit);
				rest = &after[end + 1..];
			}
			None => {
				push_bounded(&mut out, &rest[start..], limit);
				return out;
			}
		}
		if out.len() >= limit {
			return out;
		}
	}
	push_bounded(&mut out, rest, limit);
	out
}

/// Append as much of `text` as keeps `out` within `limit` octets, cutting at
/// a character boundary.
fn push_bounded(out: &mut String, text: &str, limit: usize) {
	let room = limit.saturating_sub(out.len());
	let mut end = text.len().min(room);
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	out.push_str(&text[..end]);
}

#[cfg(test)]
mod tests;
