use super::*;

fn config(settings: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{settings}"
	))
	.expect("parse")
}

#[test]
fn absent_keys_keep_the_built_in_deadline() {
	let limits = MailboxLimits::from_config(&config(""));
	assert_eq!(limits.preauth_timeout, Duration::from_secs(60));
}

#[test]
fn a_configured_deadline_is_used() {
	let limits = MailboxLimits::from_config(&config("preauth_timeout = 120"));
	assert_eq!(limits.preauth_timeout, Duration::from_secs(120));
}
