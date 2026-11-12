//! `receive_only_domains` names hosted domains, once each, and never one that
//! is also send-only.

use super::super::super::tests::base::config_from;

const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "example.net"]
"#;

fn with(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	config_from(&format!("{BASE}{extra}"))
}

#[test]
fn a_configured_domain_can_be_receive_only() {
	let config = with("receive_only_domains = [\"example.net\"]").expect("valid");
	assert_eq!(config.receive_only_domains, vec!["example.net".to_string()]);
}

#[test]
fn a_domain_that_is_not_configured_is_refused_by_name() {
	let error = with("receive_only_domains = [\"other.example\"]").expect_err("unknown domain");
	assert_eq!(
		error.to_string(),
		"invalid configuration: receive_only_domains entry \"other.example\" is not in domains"
	);
}

#[test]
fn a_repeated_entry_is_refused() {
	let error =
		with("receive_only_domains = [\"example.net\", \"Example.NET\"]").expect_err("repeat");
	assert_eq!(
		error.to_string(),
		"invalid configuration: duplicate receive_only_domains entry \"Example.NET\""
	);
}

#[test]
fn a_domain_cannot_be_send_only_and_receive_only() {
	let error =
		with("send_only_domains = [\"example.net\"]\nreceive_only_domains = [\"example.net\"]")
			.expect_err("both roles");
	assert!(
		error
			.to_string()
			.contains("is in both send_only_domains and receive_only_domains"),
		"{error}"
	);
}

#[test]
fn different_domains_can_have_different_roles() {
	with("send_only_domains = [\"example.org\"]\nreceive_only_domains = [\"example.net\"]")
		.expect("valid");
}
