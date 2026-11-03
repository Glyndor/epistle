//! Which domains' own keys the server rotates: each domain on its own, held
//! back only by its own zone.

use super::super::domain_rotation::{DomainRotationPlan, decide_domain_rotation};
use crate::config::Config;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

/// A token nobody wrote down, built at run time.
fn token() -> String {
	format!("token = \"{}\"\n", uuid::Uuid::new_v4().simple())
}

fn plan(dns: &str) -> DomainRotationPlan {
	let config: Config = toml::from_str(&format!(
		"{BASE}domains = ['a.example.org', 'b.example.org', 'other.net']\n\
		 [dkim]\nselector = 's1'\nkey_file = '/etc/mail/dkim.pem'\n\
		 [[dkim.domain]]\nname = 'B.example.org'\nselector = 'own1'\nkey_file = '/etc/mail/b.pem'\n\
		 [[dkim.domain]]\nname = 'other.net'\nselector = 'own1'\nkey_file = '/etc/mail/net.pem'\n{dns}"
	))
	.expect("parses");
	decide_domain_rotation(&config)
}

#[test]
fn a_domain_outside_the_zone_does_not_hold_back_one_inside_it() {
	let plan = plan(&format!(
		"[dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}",
		token()
	));
	assert_eq!(plan.rotating, ["b.example.org"]);
	assert_eq!(plan.unmanaged, ["other.net"]);
}

#[test]
fn every_domain_with_a_publishing_zone_rotates() {
	let plan = plan(&format!(
		"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}\
		 [[dns]]\nprovider = \"cloudflare\"\nzone = \"other.net\"\n{}",
		token(),
		token()
	));
	assert_eq!(plan.rotating, ["b.example.org", "other.net"]);
	assert!(plan.unmanaged.is_empty());
}

#[test]
fn a_manual_zone_does_not_rotate_its_domain() {
	let plan = plan(&format!(
		"[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n{}\
		 [[dns]]\nprovider = \"manual\"\nzone = \"other.net\"\n",
		token()
	));
	assert_eq!(plan.rotating, ["b.example.org"]);
	assert_eq!(plan.unmanaged, ["other.net"]);
}

#[test]
fn without_dns_no_domain_rotates() {
	let plan = plan("");
	assert!(plan.rotating.is_empty());
	assert_eq!(plan.unmanaged, ["b.example.org", "other.net"]);
}
