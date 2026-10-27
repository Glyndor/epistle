//! Validation tests for the `[[alerts]]` section. Split out of
//! `src/config/validate/tests/base.rs`, which crossed the line limit with them in; the sibling
//! `src/config/validate/tests/b.rs` set the precedent.

use super::base::config_from;

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

fn webhook_config(url: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	webhook_config_with(url, false)
}

/// The same section, with or without the option that lets the webhook
/// reach a private destination.
fn webhook_config_with(
	url: &str,
	allow_private: bool,
) -> Result<crate::config::Config, crate::config::ConfigError> {
	let option = if allow_private {
		"allow_private_webhooks = true\n"
	} else {
		""
	};
	config_from(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\"]\n\n[webhook]\nurl = \"{url}\"\n{option}"
	))
}

/// Plain http is allowed only when the host really is loopback. A name that
/// merely starts like one resolves wherever its owner wants and would carry
/// event payloads in clear text.
#[test]
fn webhook_http_is_accepted_only_for_a_real_loopback_host() {
	for url in [
		"https://hooks.example/mail",
		"http://127.0.0.1:8080/hook",
		"http://127.0.0.53/hook",
		"http://[::1]:9000/hook",
		"http://localhost/hook",
		"http://LOCALHOST:8080/hook",
	] {
		assert!(
			webhook_config_with(url, true).is_ok(),
			"{url} must be accepted with the option"
		);
	}
	for url in [
		"http://localhost.evil.example/hook",
		"http://127.0.0.1.evil.example/hook",
		"http://[::1].evil.example/hook",
		"http://hooks.example/mail",
		"ftp://127.0.0.1/hook",
		"not a url",
	] {
		assert!(webhook_config(url).is_err(), "{url} must be refused");
	}
}

/// A private destination is refused until the operator says so in the
/// section: the webhook client would not reach it either way.
#[test]
fn a_private_webhook_needs_the_option() {
	for url in [
		"http://127.0.0.1:8080/hook",
		"http://[::1]:9000/hook",
		"http://localhost/hook",
		"http://10.0.0.1/hook",
		"https://10.0.0.1/hook",
		"http://2130706433/hook",
	] {
		assert!(webhook_config(url).is_err(), "{url} must be refused");
		assert!(
			webhook_config_with(url, true).is_ok(),
			"{url} must be accepted with the option"
		);
	}
}
