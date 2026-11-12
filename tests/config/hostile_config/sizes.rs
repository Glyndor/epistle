//! Huge keys, huge values, a flood of keys and control characters.

use epistle::config::ConfigError;

use super::harness::{MAX_MESSAGE, VALID, file, load, refusal};

#[test]
fn a_three_megabyte_key_is_refused_with_a_bounded_message() {
	let (error, message) = refusal(&format!("{VALID}{} = 1\n", "k".repeat(3_000_000)));
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_three_megabyte_value_is_refused_with_a_bounded_message() {
	let (error, message) = refusal(&format!(
		"hostname = \"{}.example.org\"\ndata_dir = \"/var/lib/mail\"\n",
		"h".repeat(3_000_000)
	));
	assert!(matches!(error, ConfigError::Invalid(_)), "{error:?}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn three_hundred_thousand_unknown_keys_stop_at_the_first() {
	let text: String = (0..300_000).map(|i| format!("k{i} = 1\n")).collect();
	let (error, message) = refusal(&(text + VALID));
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.contains("unknown field `k0`"), "{message}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_nul_written_as_an_escape_is_refused_by_validation() {
	let (error, message) = refusal("hostname = \"a\\u0000b\"\ndata_dir = \"/x\"\n");
	assert!(matches!(error, ConfigError::Invalid(_)), "{error:?}");
	assert!(message.contains("hostname"), "{message}");
}

#[test]
fn a_raw_nul_is_refused_by_the_parser() {
	let (error, message) = refusal("hostname = \"a\0b\"\ndata_dir = \"/x\"\n");
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_clean_file_of_the_same_shape_loads() {
	// Pair for the refusals above: the same two keys, no hostile byte.
	let file = file(VALID.as_bytes());
	assert!(load(file.path()).is_ok());
}
