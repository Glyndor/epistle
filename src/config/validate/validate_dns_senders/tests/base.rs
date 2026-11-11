//! `[dns_publish] senders` names hosted domains and names under them.

use super::super::super::tests::base::config_from;

const BASE: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]
"#;

fn with(senders: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	config_from(&format!("{BASE}[dns_publish]\nsenders = {senders}\n"))
}

#[test]
fn a_name_under_a_hosted_domain_is_accepted() {
	let config =
		with("[\"news.example.org\", \"a.b.example.org\", \"example.org\"]").expect("valid");
	assert_eq!(config.dns_publish.senders.len(), 3);
}

#[test]
fn the_list_is_empty_by_default() {
	let config = config_from(BASE).expect("valid");
	assert!(config.dns_publish.senders.is_empty());
}

#[test]
fn a_name_outside_the_hosted_domains_is_refused() {
	for name in ["example.net", "notexample.org", "example.org.evil.test"] {
		let error = with(&format!("[\"{name}\"]")).expect_err(name);
		assert!(
			error
				.to_string()
				.contains("is not a hosted domain or a name under one"),
			"{name}: {error}"
		);
	}
}

#[test]
fn a_duplicate_is_refused_whatever_its_case() {
	let error = with("[\"news.example.org\", \"News.Example.org\"]").expect_err("duplicate");
	assert!(
		error
			.to_string()
			.contains("duplicate [dns_publish] senders entry")
	);
}

#[test]
fn a_name_that_is_not_a_dns_name_is_refused() {
	assert!(with("[\"bad name.example.org\"]").is_err());
	assert!(with("[\"\"]").is_err());
}
