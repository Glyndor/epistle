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

#[test]
fn absent_or_zero_caps_keep_the_built_in_ones() {
	for settings in [
		"",
		"max_mailbox_connections_per_ip = 0\nmax_http_connections = 0\nmax_http_connections_per_ip = 0",
	] {
		let config = config(settings);
		assert_eq!(
			MailboxLimits::from_config(&config).per_ip,
			200,
			"{settings}"
		);
		let http = http_limits(&config);
		assert_eq!((http.connections, http.per_ip), (1024, 256), "{settings}");
	}
}

#[test]
fn configured_caps_are_used() {
	let config = config(
		"max_mailbox_connections_per_ip = 7\nmax_http_connections = 50\nmax_http_connections_per_ip = 9",
	);
	assert_eq!(MailboxLimits::from_config(&config).per_ip, 7);
	let http = http_limits(&config);
	assert_eq!((http.connections, http.per_ip), (50, 9));
}
