//! Sieve variables (RFC 5229): `${name}` substitution into string arguments.

use std::collections::HashMap;

/// Substitute `${name}` references with set variable values; an unknown
/// variable expands to the empty string. A `${` with no closing `}` is kept
/// literally.
pub(super) fn expand(input: &str, vars: &HashMap<String, String>) -> String {
	if !input.contains("${") {
		return input.to_string();
	}
	let mut out = String::with_capacity(input.len());
	let mut rest = input;
	while let Some(start) = rest.find("${") {
		out.push_str(&rest[..start]);
		let after = &rest[start + 2..];
		match after.find('}') {
			Some(end) => {
				out.push_str(vars.get(&after[..end]).map(String::as_str).unwrap_or(""));
				rest = &after[end + 1..];
			}
			None => {
				out.push_str(&rest[start..]);
				return out;
			}
		}
	}
	out.push_str(rest);
	out
}
