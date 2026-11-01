//! One `[dns]` table or several `[[dns]]` tables: parsing, the entry that
//! serves a name, validation, and the provider built from all of them.

use crate::config::Config;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [\"example.org\", \"example.net\"]\n";

fn config(dns: &str) -> Config {
	toml::from_str(&format!("{BASE}{dns}")).expect("parses")
}

fn entry(zone: &str, extra: &str) -> String {
	format!("[[dns]]\nprovider = \"cloudflare\"\nzone = \"{zone}\"\n{extra}\n")
}

/// A token nobody wrote down: built at run time so no credential literal sits
/// next to a credential-named field.
fn token() -> String {
	format!("token = \"{}\"", uuid::Uuid::new_v4().simple())
}

#[test]
fn a_single_dns_table_is_one_entry() {
	let config = config("[dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n");
	assert_eq!(config.dns.len(), 1);
	assert_eq!(config.dns.first().unwrap().zone, "example.org");
}

#[test]
fn no_dns_section_is_no_entry() {
	assert!(config("").dns.is_empty());
}

#[test]
fn several_dns_tables_keep_the_file_order() {
	let text = format!("{}{}", entry("example.org", ""), entry("example.net", ""));
	let config = config(&text);
	assert_eq!(config.dns.zones(), vec!["example.org", "example.net"]);
}

#[test]
fn an_unknown_key_in_an_entry_is_still_refused() {
	let text = entry("example.org", "surprise = 1");
	assert!(toml::from_str::<Config>(&format!("{BASE}{text}")).is_err());
}

#[test]
fn the_longest_zone_serves_a_name() {
	let text = format!(
		"{}{}",
		entry("example.org", ""),
		entry("eu.example.org", "")
	);
	let config = config(&text);
	let serves = |name: &str| config.dns.entry_for(name).map(|dns| dns.zone.as_str());
	assert_eq!(serves("mail.eu.example.org"), Some("eu.example.org"));
	assert_eq!(serves("eu.example.org"), Some("eu.example.org"));
	assert_eq!(serves("mail.example.org"), Some("example.org"));
	assert_eq!(serves("MAIL.Example.ORG."), Some("example.org"));
}

#[test]
fn a_name_outside_every_zone_has_no_entry() {
	let text = format!("{}{}", entry("example.org", ""), entry("example.net", ""));
	let config = config(&text);
	assert!(config.dns.entry_for("mail.example.com").is_none());
	// Ending with the zone's text does not put a name inside the zone.
	assert!(config.dns.entry_for("evilexample.org").is_none());
}

#[test]
fn a_lone_entry_serves_every_name_as_before() {
	let config = config("[dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n");
	assert!(config.dns.entry_for("mail.example.com").is_some());
}

#[test]
fn two_entries_for_one_zone_are_refused() {
	let text = format!("{}{}", entry("example.org", ""), entry("EXAMPLE.org", ""));
	let error = config(&text).validate().unwrap_err().to_string();
	assert!(error.contains("appears twice"), "{error}");
}

#[test]
fn an_unknown_provider_in_a_later_entry_is_refused() {
	let text = format!(
		"{}[[dns]]\nprovider = \"cloudfare\"\nzone = \"example.net\"\n",
		entry("example.org", "")
	);
	let error = config(&text).validate().unwrap_err().to_string();
	assert!(error.contains("not a supported provider"), "{error}");
}

#[test]
fn a_zone_that_is_not_a_name_is_refused_when_there_are_several() {
	let text = format!("{}{}", entry("example.org", ""), entry("not a zone", ""));
	assert!(config(&text).validate().is_err());
}

#[test]
fn dns01_needs_an_entry_that_publishes_for_every_certificate_name() {
	let acme = "[acme]\ndirectory_url = \"https://acme.example/dir\"\ndomains = [\"mail.example.org\", \"example.net\"]\nchallenge = \"dns-01\"\n";
	let only_org = format!("{BASE}{acme}{}{}", entry("example.org", ""), {
		"[[dns]]\nprovider = \"manual\"\nzone = \"example.net\"\n"
	});
	let error = toml::from_str::<Config>(&only_org)
		.unwrap()
		.validate()
		.unwrap_err()
		.to_string();
	assert!(error.contains("example.net"), "{error}");

	let both = format!(
		"{BASE}{acme}{}{}",
		entry("example.org", ""),
		entry("example.net", "")
	);
	toml::from_str::<Config>(&both)
		.unwrap()
		.validate()
		.expect("every name has an entry");
}

#[test]
fn debug_of_several_entries_hides_every_token() {
	let first = token();
	let second = token();
	let text = format!(
		"{}{}",
		entry("example.org", &first),
		entry("example.net", &second)
	);
	let rendered = format!("{:?}", config(&text).dns);
	for secret in [&first, &second] {
		let value = secret.trim_start_matches("token = ").trim_matches('"');
		assert!(
			!rendered.contains(value),
			"a token reached the Debug output"
		);
	}
	assert!(rendered.contains("example.org") && rendered.contains("example.net"));
}

#[test]
fn several_entries_build_one_provider_and_nothing_when_none_can() {
	let usable = format!(
		"{}{}",
		entry("example.org", &token()),
		entry("example.net", &token())
	);
	assert!(
		config(&usable)
			.dns
			.build_for_host("mail.example.org")
			.is_some()
	);

	let none = format!("{}{}", entry("example.org", ""), entry("example.net", ""));
	assert!(
		config(&none)
			.dns
			.build_for_host("mail.example.org")
			.is_none()
	);
}

#[tokio::test]
async fn an_entry_without_credentials_does_not_lend_its_zone_to_its_parent() {
	use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
	// The parent zone has a token; the child zone's entry has none. A write in
	// the child must be refused, not sent with the parent's token.
	let text = format!(
		"{}{}",
		entry("example.org", &token()),
		entry("eu.example.org", "")
	);
	let provider = config(&text)
		.dns
		.build_for_host("mail.example.org")
		.expect("the parent builds");
	let record = DnsRecord {
		name: "x.eu.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=spf1 -all".into(),
		ttl: 300,
		proxied: None,
	};
	let error = provider
		.upsert("eu.example.org", record)
		.await
		.expect_err("refused");
	assert!(matches!(error, ProviderError::Unsupported));
}
