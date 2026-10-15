use super::*;

fn load(settings: &str) -> Result<Config, ConfigError> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{settings}"
	)
	.expect("write config");
	Config::load(file.path())
}

#[test]
fn scanner_defaults_and_overrides_load() {
	let config = load("").expect("default config");
	assert!(config.antispam.clamd_socket.is_none());
	assert!(config.scanner_hook_url.is_none());
	// The Bayesian junk default is on, the reject default is off. The
	// assertion pins both because the SMTP server relies on the same
	// numbers when it has no `[antispam]` section.
	assert_eq!(config.antispam.bayes_junk_at, DEFAULT_BAYES_JUNK_AT);
	assert_eq!(config.antispam.bayes_reject_at, None);
	let config = load("[antispam]\nclamd_socket = '/run/clamav/clamd.sock'").expect("defaults");
	assert_eq!(
		config.antispam.clamd_socket,
		Some(PathBuf::from("/run/clamav/clamd.sock"))
	);
	assert_eq!(config.antispam.clamd_on_found, ClamdOnFound::Quarantine);
	assert_eq!(config.antispam.clamd_timeout_secs, 30);
	assert_eq!(config.antispam.clamd_max_bytes, 25 * 1024 * 1024);
	let config = load("[antispam]\nclamd_socket = '/tmp/clamd.sock'\nclamd_on_found = 'reject'\nclamd_timeout_secs = 2\nclamd_max_bytes = 1024").expect("overrides");
	assert_eq!(config.antispam.clamd_on_found, ClamdOnFound::Reject);
	assert_eq!(config.antispam.clamd_timeout_secs, 2);
	assert_eq!(config.antispam.clamd_max_bytes, 1024);
}

#[test]
fn bayes_thresholds_parse_and_default() {
	let config = load("[antispam]\nbayes_junk_at = 0.9\nbayes_reject_at = 0.99").expect("load");
	assert_eq!(config.antispam.bayes_junk_at, 0.9);
	assert_eq!(config.antispam.bayes_reject_at, Some(0.99));
}

#[test]
fn bayes_reject_at_must_not_below_junk_at() {
	let error = load("[antispam]\nbayes_junk_at = 0.95\nbayes_reject_at = 0.9")
		.expect_err("inverted bands must fail");
	let message = format!("{error:?}");
	assert!(
		message.contains("bayes_reject_at"),
		"validation must name the offending field: {message}"
	);
	assert!(
		message.contains("subset of the junked one"),
		"validation must explain the subset rule: {message}"
	);
}

#[test]
fn bayes_thresholds_must_be_in_range() {
	assert!(load("[antispam]\nbayes_junk_at = 1.5").is_err());
	assert!(load("[antispam]\nbayes_junk_at = -0.1").is_err());
	assert!(load("[antispam]\nbayes_reject_at = 2.0").is_err());
}

#[test]
fn only_one_scanner_may_be_configured() {
	let http = "scanner_hook_url = 'http://scanner.example/scan'";
	let clamd = "[antispam]\nclamd_socket = '/run/clamav/clamd.sock'";
	assert!(load(http).is_ok(), "HTTP alone must load");
	assert!(load(clamd).is_ok(), "clamd alone must load");
	match load(&format!("{http}\n{clamd}")) {
		Err(ConfigError::Invalid(message)) => assert!(message.contains(
			"clamd_socket and scanner_hook_url cannot be set together: only one scanner per server"
		)),
		_ => panic!("expected scanner conflict validation error"),
	}
}

#[test]
fn clamd_on_found_refuses_delete_and_accepts_supported_actions() {
	for action in ["quarantine", "reject"] {
		assert!(load(&format!("[antispam]\nclamd_on_found = '{action}'")).is_ok());
	}
	match load("[antispam]\nclamd_on_found = 'delete'") {
		Err(ConfigError::Parse { source, .. }) => {
			let message = source.to_string();
			assert!(message.contains("unknown variant `delete`"));
			assert!(message.contains("quarantine") && message.contains("reject"));
		}
		_ => panic!("expected invalid clamd action parse error"),
	}
}

#[test]
fn scan_authenticated_defaults_on_and_can_be_turned_off() {
	assert!(load("").expect("defaults").antispam.scan_authenticated);
	let config = load("[antispam]\nscan_authenticated = false").expect("off");
	assert!(!config.antispam.scan_authenticated);
}

#[test]
fn clamd_on_error_defaults_to_accept_and_takes_defer() {
	assert_eq!(
		load("").expect("default").antispam.clamd_on_error,
		ClamdOnError::Accept
	);
	assert_eq!(
		load("[antispam]\nclamd_on_error = 'defer'")
			.expect("defer")
			.antispam
			.clamd_on_error,
		ClamdOnError::Defer
	);
	let error = load("[antispam]\nclamd_on_error = 'drop'").expect_err("unknown value");
	assert!(
		error.to_string().contains("unknown variant `drop`"),
		"{error}"
	);
}
