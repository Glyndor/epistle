//! The webhook the queue actions notify follows `enabled`.

use super::webhook_for;
use crate::config::Config;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 [webhook]\nurl = \"https://hooks.example.net/in\"\n{extra}"
	))
	.expect("config")
}

#[test]
fn an_enabled_webhook_is_notified() {
	assert!(webhook_for(&config("")).is_some());
}

#[test]
fn a_disabled_webhook_is_not_notified() {
	assert!(webhook_for(&config("enabled = false\n")).is_none());
}

#[test]
fn no_webhook_section_means_no_notification() {
	let bare: Config =
		toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
			.expect("config");
	assert!(webhook_for(&bare).is_none());
}
