//! `disabled_domains` names hosted domains and nothing else.

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
fn a_configured_domain_can_be_disabled() {
	let config = with("disabled_domains = [\"example.net\"]").expect("valid");
	assert_eq!(config.disabled_domains, vec!["example.net".to_string()]);
}

#[test]
fn a_domain_that_is_not_configured_is_refused_by_name() {
	let error = with("disabled_domains = [\"other.example\"]").expect_err("unknown domain");
	assert_eq!(
		error.to_string(),
		"invalid configuration: disabled_domains entry \"other.example\" is not in domains"
	);
}

#[test]
fn a_domain_alias_cannot_be_disabled_on_its_own() {
	let error = with("disabled_domains = [\"alias.example.org\"]").expect_err("alias domain");
	assert_eq!(
		error.to_string(),
		"invalid configuration: disabled_domains entry \"alias.example.org\" is not in domains"
	);
}

#[test]
fn a_repeated_entry_is_refused() {
	let error = with("disabled_domains = [\"example.net\", \"Example.NET\"]").expect_err("repeat");
	assert_eq!(
		error.to_string(),
		"invalid configuration: duplicate disabled_domains entry \"Example.NET\""
	);
}

#[test]
fn every_domain_cannot_be_disabled_while_listeners_serve() {
	let error = with(
		"disabled_domains = [\"example.org\", \"example.net\"]\n[[listeners]]\nkind = \"smtp\"\n",
	)
	.expect_err("all domains off");
	assert_eq!(
		error.to_string(),
		"invalid configuration: disabled_domains switches off every entry of domains; \
		 remove the listeners or keep one domain enabled"
	);
}
