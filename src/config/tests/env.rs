//! Tests for the `${VAR}` expansion of the raw configuration file.

use super::*;

#[test]
fn expands_environment_variables() {
	// SAFETY: the variable name is unique to this test, so no other test
	// reads or writes it concurrently.
	unsafe { std::env::set_var("EPISTLE_TEST_HOSTNAME", "mail.expanded.example") };
	let file = write_temp(
		r#"
hostname = "${EPISTLE_TEST_HOSTNAME}"
data_dir = "/var/lib/mail"
"#,
	);
	let config = Config::load(file.path()).expect("config loads");
	assert_eq!(config.hostname, "mail.expanded.example");
	// SAFETY: same uniquely-named variable as set above.
	unsafe { std::env::remove_var("EPISTLE_TEST_HOSTNAME") };
}

#[test]
fn rejects_undefined_environment_variable() {
	let file = write_temp(
		r#"
hostname = "${EPISTLE_DEFINITELY_UNSET_VAR_XYZ}"
data_dir = "/var/lib/mail"
"#,
	);
	assert!(matches!(
		Config::load(file.path()),
		Err(ConfigError::MissingEnv(_))
	));
}
