//! Validation tests for the `[[alerts]]` section. Split out of
//! `validate_tests.rs`, which crossed the line limit with them in; the sibling
//! `validate_tests_b.rs` set the precedent.

use super::tests::config_from;

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
