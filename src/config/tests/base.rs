//! Tests for loading the configuration file: parsing, defaults and the
//! checks `Config::load` runs before validation.

use super::*;

fn write_temp(content: &str) -> tempfile::NamedTempFile {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("create temp file");
	file.write_all(content.as_bytes()).expect("write temp file");
	file
}

#[test]
fn loads_minimal_valid_config() {
	let file = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	let config = Config::load(file.path()).expect("valid config loads");
	assert_eq!(config.hostname, "mail.example.org");
	assert!(config.listeners.is_empty());
}

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

#[cfg(unix)]
#[test]
fn rejects_group_or_world_accessible_config() {
	use std::os::unix::fs::PermissionsExt;
	let file = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).expect("chmod");
	assert!(matches!(
		Config::load(file.path()),
		Err(ConfigError::InsecurePermissions { .. })
	));
}

#[test]
fn rejects_unknown_keys() {
	let file = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
surprise = true
"#,
	);
	assert!(matches!(
		Config::load(file.path()),
		Err(ConfigError::Parse { .. })
	));
}

#[test]
fn rejects_missing_file() {
	let missing = Path::new("/nonexistent/mail.toml");
	assert!(matches!(
		Config::load(missing),
		Err(ConfigError::Read { .. })
	));
}

#[test]
fn rejects_invalid_toml() {
	let file = write_temp("hostname = ");
	assert!(matches!(
		Config::load(file.path()),
		Err(ConfigError::Parse { .. })
	));
}

#[test]
fn outbound_tls_defaults_strict_and_parses() {
	// Absent [queue] section: strict (fail closed, back-compatible).
	let default = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	assert_eq!(
		Config::load(default.path())
			.expect("loads")
			.queue
			.outbound_tls,
		OutboundTls::Strict
	);

	// Explicit opportunistic parses.
	let opportunistic = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
[queue]
outbound_tls = "opportunistic"
"#,
	);
	assert_eq!(
		Config::load(opportunistic.path())
			.expect("loads")
			.queue
			.outbound_tls,
		OutboundTls::Opportunistic
	);

	// An unknown key inside [queue] is rejected (deny_unknown_fields).
	let bad = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
[queue]
surprise = true
"#,
	);
	assert!(matches!(
		Config::load(bad.path()),
		Err(ConfigError::Parse { .. })
	));
}

#[test]
fn default_bind_is_loopback() {
	assert!(Config::default_bind_addr().is_loopback());
}

#[test]
fn max_connections_per_listener_parses_and_defaults_none() {
	let default = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	assert_eq!(
		Config::load(default.path())
			.expect("loads")
			.max_connections_per_listener,
		None
	);

	let set = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
max_connections_per_listener = 2048
"#,
	);
	assert_eq!(
		Config::load(set.path())
			.expect("loads")
			.max_connections_per_listener,
		Some(2048)
	);
}

#[test]
fn message_size_and_memory_budget_cap_parse_and_default_none() {
	let default = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	let default = Config::load(default.path()).expect("default loads");
	assert_eq!(default.max_message_size, None);
	assert_eq!(default.message_memory_budget, None);
	assert_eq!(default.max_connections_per_ip, None);

	let set = write_temp(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
max_message_size = 10485760
message_memory_budget = 134217728
max_connections_per_ip = 5
"#,
	);
	let set = Config::load(set.path()).expect("loaded with caps");
	assert_eq!(set.max_message_size, Some(10485760));
	assert_eq!(set.message_memory_budget, Some(134217728));
	assert_eq!(set.max_connections_per_ip, Some(5));
}
