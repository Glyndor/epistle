	use std::collections::HashMap;

	use super::*;

	fn expand_with(input: &str) -> String {
		let table = HashMap::from([("name".to_string(), "Work".to_string())]);
		expand(
			input,
			|name| table.get(name).map(String::as_str),
			usize::MAX,
		)
	}

	#[test]
	fn expands_known_and_unknown_variables() {
		assert_eq!(expand_with("a/${name}/b"), "a/Work/b");
		// An unset variable expands to empty.
		assert_eq!(expand_with("x${missing}y"), "xy");
		// No reference: returned unchanged via the fast path.
		assert_eq!(expand_with("plain"), "plain");
	}

	#[test]
	fn unterminated_reference_is_kept_literally() {
		assert_eq!(expand_with("a${name"), "a${name");
		assert_eq!(expand_with("${"), "${");
	}
