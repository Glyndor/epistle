//! Tests for configuration validation.

use super::*;

fn config_from(toml: &str) -> Result<Config, ConfigError> {
	let config: Config = toml::from_str(toml).map_err(|e| ConfigError::Invalid(e.to_string()))?;
	config.validate()?;
	Ok(config)
}

#[test]
fn accepts_valid_config_with_listeners() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"

[[listeners]]
kind = "submission"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn parses_quota_bytes() {
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]
quota_bytes = 1073741824

[[listeners]]
kind = "smtp"
"#,
	)
	.expect("valid config");
	assert_eq!(config.quota_bytes, Some(1_073_741_824));
}

#[test]
fn rejects_empty_hostname() {
	let result = config_from(
		r#"
hostname = ""
data_dir = "/var/lib/mail"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_unqualified_hostname() {
	let result = config_from(
		r#"
hostname = "localhost"
data_dir = "/var/lib/mail"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_hostname_with_invalid_characters() {
	let result = config_from(
		r#"
hostname = "mail.exa mple.org"
data_dir = "/var/lib/mail"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_hostname_with_empty_label() {
	let result = config_from(
		r#"
hostname = "mail..example.org"
data_dir = "/var/lib/mail"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_overlong_hostname() {
	let label = "a".repeat(64);
	let result = config_from(&format!(
		"hostname = \"{label}.example.org\"\ndata_dir = \"/var/lib/mail\"\n"
	));
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_relative_data_dir() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "relative/path"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_duplicate_listeners() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"

[[listeners]]
kind = "smtp"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_submissions_listener_without_tls() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "submissions"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn accepts_submissions_listener_with_tls() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "submissions"

[tls]
cert_file = "/etc/mail/cert.pem"
key_file = "/etc/mail/key.pem"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_listeners_without_domains() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[[listeners]]
kind = "smtp"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_invalid_domain_entry() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["nodot"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_duplicate_domains_case_insensitively() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "EXAMPLE.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn accepts_valid_accounts() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@EXAMPLE.org"]
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn accepts_catch_all_for_a_configured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
catch_all = ["example.org"]
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_catch_all_for_unconfigured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
catch_all = ["elsewhere.example"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_two_catch_all_accounts_for_one_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
catch_all = ["example.org"]

[[accounts]]
name = "bob"
addresses = ["bob@example.org"]
catch_all = ["example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn accepts_domain_alias_to_configured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[domain_aliases]
"alias.example" = "example.org"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_domain_alias_to_unconfigured_target() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[domain_aliases]
"alias.example" = "elsewhere.example"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_domain_alias_that_is_also_a_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "second.example"]

[domain_aliases]
"second.example" = "example.org"
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_account_with_unsafe_name() {
	for name in ["", "Alice", "a/b", "-x", "a b"] {
		let result = config_from(&format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n\n[[accounts]]\nname = \"{name}\"\naddresses = [\"a@example.org\"]\n"
		));
		assert!(
			matches!(result, Err(ConfigError::Invalid(_))),
			"name {name:?} must be rejected"
		);
	}
}

#[test]
fn rejects_account_without_addresses() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = []
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_address_outside_domains() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@elsewhere.example"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_address_claimed_twice() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["shared@example.org"]

[[accounts]]
name = "bob"
addresses = ["SHARED@example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_duplicate_account_names() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["a@example.org"]

[[accounts]]
name = "alice"
addresses = ["b@example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn accepts_same_port_on_different_addresses() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"
addr = "127.0.0.1"

[[listeners]]
kind = "smtp"
addr = "127.0.0.2"
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn accepts_acme_for_configured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
domains = ["example.org"]
"#,
	);
	assert!(result.is_ok());
}

#[test]
fn rejects_acme_with_unconfigured_domain() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "https://acme.example/dir"
domains = ["other.example"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_acme_with_non_https_directory() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[acme]
directory_url = "http://acme.example/dir"
domains = ["example.org"]
"#,
	);
	assert!(matches!(result, Err(ConfigError::Invalid(_))));
}

#[test]
fn alert_with_webhook_but_no_webhook_section_is_rejected() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[alerts]]
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
cooldown_secs = 900
webhook = true
"#,
	);
	let error = result.expect_err("alert.webhook=true with no [webhook]");
	assert!(error.to_string().contains("webhook"), "{error}");
	assert!(error.to_string().contains("bounce-storm"), "{error}");
}

#[test]
fn alert_with_webhook_section_passes() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[webhook]
url = "https://hooks.example/mail"

[[alerts]]
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
cooldown_secs = 900
webhook = true
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn duplicate_alert_names_are_rejected() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[webhook]
url = "https://hooks.example/mail"

[[alerts]]
name = "bounce-storm"
metric = "bounced"
op = ">="
threshold = 50
window_secs = 300
cooldown_secs = 900
webhook = true

[[alerts]]
name = "bounce-storm"
metric = "deferred"
op = ">="
threshold = 1
window_secs = 60
cooldown_secs = 60
email = ["ops@example.org"]
"#,
	);
	let error = result.expect_err("duplicate name");
	let message = error.to_string();
	assert!(
		message.contains("more than once"),
		"duplicate-name control must be the one that fires; got: {message}"
	);
	assert!(message.contains("bounce-storm"), "{message}");
}

#[test]
fn unknown_metric_in_alert_is_rejected_with_list() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[alerts]]
name = "broken"
metric = "not_a_counter"
op = ">="
threshold = 1
window_secs = 60
cooldown_secs = 60
email = ["ops@example.org"]
"#,
	);
	let error = result.expect_err("unknown metric");
	let message = error.to_string();
	assert!(message.contains("not_a_counter"), "{message}");
	assert!(message.contains("bounced"), "{message}");
}

#[path = "validate_privileges_tests.rs"]
mod privileges;
