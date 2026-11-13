//! Deep nesting must end at a limit, not at the end of the stack.

use epistle::config::ConfigError;

use super::harness::{MAX_MESSAGE, VALID, file, load, refusal};

#[test]
fn a_hundred_thousand_nested_arrays_end_at_the_parser_limit() {
	let text = format!(
		"{VALID}x = {}{}\n",
		"[".repeat(100_000),
		"]".repeat(100_000)
	);
	let (error, message) = refusal(&text);
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.contains("max recursion depth"), "{message}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_hundred_thousand_nested_inline_tables_end_at_the_parser_limit() {
	let text = format!(
		"{VALID}x = {}1{}\n",
		"{a=".repeat(100_000),
		"}".repeat(100_000)
	);
	let (error, message) = refusal(&text);
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.contains("max recursion depth"), "{message}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_table_header_of_a_hundred_thousand_segments_is_refused() {
	let text = format!("{VALID}[{}]\n", vec!["a"; 100_000].join("."));
	let (error, message) = refusal(&text);
	assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn nesting_just_inside_the_limit_still_reaches_the_schema_check() {
	// Control for the refusals above: a shallow unknown key is refused by the
	// schema, so the limit message is not what every nested file gets.
	let text = format!("{VALID}x = [[[1]]]\n");
	let file = file(text.as_bytes());
	let message = load(file.path()).expect_err("refused").to_string();
	assert!(message.contains("unknown field `x`"), "{message}");
	assert!(!message.contains("max recursion depth"), "{message}");
}
