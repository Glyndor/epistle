//! `${VAR}` references in a file the operator did not write line by line.

use epistle::config::ConfigError;

use super::harness::{MAX_MESSAGE, VALID, file, load, refusal};

#[test]
fn an_unterminated_reference_is_refused_by_name() {
	let (error, message) = refusal(&format!("{VALID}# ${{never closed\n"));
	assert!(matches!(error, ConfigError::Invalid(_)), "{error:?}");
	assert!(message.contains("unterminated"), "{message}");
}

#[test]
fn a_reference_with_a_huge_name_is_refused_with_a_bounded_message() {
	let (error, message) = refusal(&format!("{VALID}# ${{{}}}\n", "V".repeat(2_000_000)));
	assert!(matches!(error, ConfigError::MissingEnv(_)), "{error:?}");
	assert!(message.len() <= MAX_MESSAGE, "{} bytes", message.len());
}

#[test]
fn a_hundred_thousand_references_to_one_variable_expand_once_each() {
	// SAFETY: the name is unique to this test.
	unsafe { std::env::set_var("EPISTLE_HOSTILE_CONFIG_ONCE", "mail.example.org") };
	let text = format!(
		"hostname = \"${{EPISTLE_HOSTILE_CONFIG_ONCE}}\"\ndata_dir = \"/var/lib/mail\"\n{}",
		"# ${EPISTLE_HOSTILE_CONFIG_ONCE}\n".repeat(100_000)
	);
	let file = file(text.as_bytes());
	let config = load(file.path()).expect("loads");
	assert_eq!(config.hostname, "mail.example.org");
	// SAFETY: same unique name.
	unsafe { std::env::remove_var("EPISTLE_HOSTILE_CONFIG_ONCE") };
}

#[test]
fn a_value_that_looks_like_a_reference_is_not_expanded_again() {
	// SAFETY: the names are unique to this test.
	unsafe {
		std::env::set_var(
			"EPISTLE_HOSTILE_CONFIG_OUTER",
			"${EPISTLE_HOSTILE_CONFIG_INNER}",
		);
		std::env::set_var("EPISTLE_HOSTILE_CONFIG_INNER", "inner.example.org");
	}
	let expanded =
		file(b"hostname = \"mail.example.org\"\ndata_dir = \"/${EPISTLE_HOSTILE_CONFIG_OUTER}\"\n");
	let config = load(expanded.path()).expect("loads");
	assert_eq!(
		config.data_dir.to_string_lossy(),
		"/${EPISTLE_HOSTILE_CONFIG_INNER}",
		"the value of a variable is text, not another reference"
	);
	// SAFETY: same unique names.
	unsafe {
		std::env::remove_var("EPISTLE_HOSTILE_CONFIG_OUTER");
		std::env::remove_var("EPISTLE_HOSTILE_CONFIG_INNER");
	}
}
