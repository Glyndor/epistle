//! `send_only_domains` names hosted domains, once each.

use super::super::super::tests::base::config_from;

const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "example.net"]
domain_aliases = { "alias.example.org" = "example.org" }
"#;

fn with(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	config_from(&format!("{BASE}{extra}"))
}

#[test]
fn a_configured_domain_can_be_send_only() {
	let config = with("send_only_domains = [\"example.net\"]").expect("valid");
	assert_eq!(config.send_only_domains, vec!["example.net".to_string()]);
}

#[test]
fn every_domain_can_be_send_only() {
	with("send_only_domains = [\"example.org\", \"example.net\"]").expect("valid");
}

#[test]
fn a_domain_that_is_not_configured_is_refused_by_name() {
	let error = with("send_only_domains = [\"other.example\"]").expect_err("unknown domain");
	assert_eq!(
		error.to_string(),
		"invalid configuration: send_only_domains entry \"other.example\" is not in domains"
	);
}

#[test]
fn a_repeated_entry_is_refused() {
	let error = with("send_only_domains = [\"example.net\", \"Example.NET\"]").expect_err("repeat");
	assert_eq!(
		error.to_string(),
		"invalid configuration: duplicate send_only_domains entry \"Example.NET\""
	);
}
