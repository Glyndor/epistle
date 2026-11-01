//! DKIM rotation decides per zone when the configuration has one `[[dns]]`
//! entry per zone.

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
	match decide_dkim_rotation(&config) {
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
