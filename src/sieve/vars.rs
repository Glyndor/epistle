//! Sieve variables (RFC 5229): `${name}` substitution into string arguments.

use std::collections::HashMap;

/// Substitute `${name}` references with set variable values; an unknown
/// variable expands to the empty string. A `${` with no closing `}` is kept
/// literally. Nothing is appended past `limit` octets: the result is built no
/// longer than that, not built whole and cut afterwards.
pub(super) fn expand(input: &str, vars: &HashMap<String, String>, limit: usize) -> String {
	let mut out = String::with_capacity(input.len().min(limit));
	let mut rest = input;
	while let Some(start) = rest.find("${") {
		push_bounded(&mut out, &rest[..start], limit);
		let after = &rest[start + 2..];
		match after.find('}') {
			Some(end) => {
				push_bounded(
					&mut out,
					vars.get(&after[..end]).map_or("", String::as_str),
					limit,
				);
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
mod tests {
	use super::*;

	fn vars() -> HashMap<String, String> {
		HashMap::from([("name".to_string(), "Work".to_string())])
	}

	#[test]
	fn expands_known_and_unknown_variables() {
		assert_eq!(expand("a/${name}/b", &vars(), usize::MAX), "a/Work/b");
		// An unset variable expands to empty.
		assert_eq!(expand("x${missing}y", &vars(), usize::MAX), "xy");
		// No reference: returned unchanged via the fast path.
		assert_eq!(expand("plain", &vars(), usize::MAX), "plain");
	}

	#[test]
	fn unterminated_reference_is_kept_literally() {
		assert_eq!(expand("a${name", &vars(), usize::MAX), "a${name");
		assert_eq!(expand("${", &vars(), usize::MAX), "${");
	}
}
