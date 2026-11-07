//! DKIM rotation decides per zone when the configuration has one `[[dns]]`
//! entry per zone.

use super::super::DnsWrite;
use super::dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

/// A token nobody wrote down, built at run time.
fn token() -> String {
	format!("token = \"{}\"\n", uuid::Uuid::new_v4().simple())
}

fn plan_with(domains: &str, entries: &str) -> (Vec<String>, Vec<String>) {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = {domains}\n[dkim]\nselector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n{entries}"
	))
	.expect("parses");
	match decide_dkim_rotation(&config, &DnsWrite::Direct) {
		DkimRotationPlan::Run {
			signing_domains,
			out_of_zone,
			..
		} => (signing_domains, out_of_zone),
		DkimRotationPlan::Off => panic!("rotation should run"),
	}
}

fn plan(domains: &str) -> (Vec<String>, Vec<String>) {
	plan_with(
		domains,
		&format!(
			"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"desec\"\nzone = \"client.net\"\n{}",
			token(),
			token()
		),
	)
}

#[test]
fn a_domain_in_any_configured_zone_is_rotated() {
	let (signing, outside) = plan("[\"example.org\", \"client.net\", \"shop.client.net\"]");
	assert_eq!(
		signing,
		vec!["client.net", "example.org", "shop.client.net"]
	);
	assert!(outside.is_empty());
}

#[test]
fn a_domain_in_no_configured_zone_is_still_out_of_zone() {
	let (signing, outside) = plan("[\"example.org\", \"other.example\"]");
	assert_eq!(signing, vec!["example.org"]);
	assert_eq!(outside, vec!["other.example"]);
}

#[test]
fn a_domain_in_a_manual_zone_holds_the_rotation_back() {
	let (signing, outside) = plan_with(
		"[\"example.org\", \"client.net\"]",
		&format!(
			"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"manual\"\nzone = \"client.net\"\n",
			token()
		),
	);
	assert_eq!(signing, vec!["example.org"]);
	assert_eq!(outside, vec!["client.net"]);
}

#[test]
fn a_domain_in_a_zone_with_unreadable_credentials_holds_the_rotation_back() {
	let (signing, outside) = plan_with(
		"[\"example.org\", \"client.net\"]",
		&format!(
			"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"desec\"\nzone = \"client.net\"\n",
			token()
		),
	);
	assert_eq!(signing, vec!["example.org"]);
	assert_eq!(outside, vec!["client.net"]);
}

#[test]
fn a_nested_manual_zone_is_not_published_with_its_parents_credential() {
	let (signing, outside) = plan_with(
		"[\"example.org\", \"eu.example.org\"]",
		&format!(
			"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"manual\"\nzone = \"eu.example.org\"\n",
			token()
		),
	);
	assert_eq!(signing, vec!["example.org"]);
	assert_eq!(outside, vec!["eu.example.org"]);
}

#[test]
fn a_list_of_one_entry_is_scoped_to_its_zone() {
	let (signing, outside) = plan_with(
		"[\"example.org\", \"other.example\"]",
		&format!(
			"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}",
			token()
		),
	);
	assert_eq!(signing, vec!["example.org"]);
	assert_eq!(outside, vec!["other.example"]);
}

/// With the certificates container on the credential is in the other
/// container: an entry this process cannot read a credential for still
/// publishes, through the hand-off.
#[test]
fn with_the_split_a_zone_whose_credential_is_not_here_still_rotates() {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = [\"example.org\", \"client.net\"]\n[dkim]\nselector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"desec\"\nzone = \"client.net\"\n",
		token()
	))
	.expect("parses");
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = decide_dkim_rotation(
		&config,
		&DnsWrite::Handoff(std::path::PathBuf::from("/var/lib/mail/dns-handoff")),
	)
	else {
		panic!("rotation should run");
	};
	assert_eq!(signing_domains, vec!["client.net", "example.org"]);
	assert!(
		out_of_zone.is_empty(),
		"the credential is in the certificates container: {out_of_zone:?}"
	);
}

/// The same configuration without the split: the entry whose credential
/// this process cannot read holds the rotation back, as it always did.
#[test]
fn without_the_split_a_zone_whose_credential_is_not_here_holds_the_rotation_back() {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = [\"example.org\", \"client.net\"]\n[dkim]\nselector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"desec\"\nzone = \"client.net\"\n",
		token()
	))
	.expect("parses");
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = decide_dkim_rotation(&config, &DnsWrite::Direct)
	else {
		panic!("rotation should run");
	};
	assert_eq!(signing_domains, vec!["example.org"]);
	assert_eq!(out_of_zone, vec!["client.net"]);
}

/// A manual zone publishes nothing, in either mode.
#[test]
fn with_the_split_a_manual_zone_still_holds_the_rotation_back() {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = [\"example.org\", \"client.net\"]\n[dkim]\nselector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}[[dns]]\nprovider = \"manual\"\nzone = \"client.net\"\n",
		token()
	))
	.expect("parses");
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = decide_dkim_rotation(
		&config,
		&DnsWrite::Handoff(std::path::PathBuf::from("/var/lib/mail/dns-handoff")),
	)
	else {
		panic!("rotation should run");
	};
	assert_eq!(signing_domains, vec!["example.org"]);
	assert_eq!(out_of_zone, vec!["client.net"]);
}
