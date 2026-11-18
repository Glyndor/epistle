//! `[acme] domains` accepts the names the public endpoint answers for a
//! hosted domain, and still refuses a name that is not the server's.

use super::base::config_from;
use super::*;

fn with_acme_domains(names: &[&str]) -> Result<Config, ConfigError> {
	let list = names
		.iter()
		.map(|n| format!("\"{n}\""))
		.collect::<Vec<_>>()
		.join(", ");
	config_from(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n\n[acme]\n\
		 directory_url = \"https://acme.example/dir\"\ndomains = [{list}]\n"
	))
}

#[test]
fn the_three_public_names_of_a_hosted_domain_are_accepted() {
	let result = with_acme_domains(&[
		"mail.example.org",
		"autoconfig.example.org",
		"autodiscover.example.org",
		"mta-sts.example.org",
	]);
	assert!(result.is_ok(), "{result:?}");
}

#[test]
fn the_public_names_are_matched_without_regard_to_case() {
	assert!(with_acme_domains(&["MTA-STS.Example.ORG"]).is_ok());
}

#[test]
fn a_name_that_is_not_the_servers_is_still_refused() {
	for name in [
		"other.example",
		"www.example.org",
		"imap.example.org",
		"autoconfig.other.example",
		"autoconfig.mail.example.org",
		"xautoconfig.example.org",
	] {
		let result = with_acme_domains(&[name]);
		assert!(
			matches!(&result, Err(ConfigError::Invalid(why)) if why.contains("not a configured domain")),
			"{name}: {result:?}"
		);
	}
}

#[test]
fn the_public_names_of_a_domain_that_is_not_hosted_are_refused() {
	let result = with_acme_domains(&["autoconfig.example.net", "mta-sts.example.net"]);
	assert!(matches!(result, Err(ConfigError::Invalid(_))), "{result:?}");
}
