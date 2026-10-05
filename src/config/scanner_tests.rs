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
