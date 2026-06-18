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

#[cfg(test)]
mod tests {
	use super::*;

	fn vars() -> HashMap<String, String> {
		HashMap::from([("name".to_string(), "Work".to_string())])
	}

	#[test]
	fn expands_known_and_unknown_variables() {
		assert_eq!(expand("a/${name}/b", &vars()), "a/Work/b");
		// An unset variable expands to empty.
		assert_eq!(expand("x${missing}y", &vars()), "xy");
		// No reference: returned unchanged via the fast path.
		assert_eq!(expand("plain", &vars()), "plain");
	}

	#[test]
	fn unterminated_reference_is_kept_literally() {
		assert_eq!(expand("a${name", &vars()), "a${name");
		assert_eq!(expand("${", &vars()), "${");
	}
}
