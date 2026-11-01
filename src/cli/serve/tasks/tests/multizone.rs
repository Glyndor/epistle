//! DKIM rotation decides per zone when the configuration has one `[[dns]]`
//! entry per zone.

use super::dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

fn plan(domains: &str) -> (Vec<String>, Vec<String>) {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = {domains}\n[dkim]\nselector = \"mail\"\nkey_file = \"/etc/mail/dkim.pem\"\n[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n[[dns]]\nprovider = \"desec\"\nzone = \"client.net\"\n"
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
