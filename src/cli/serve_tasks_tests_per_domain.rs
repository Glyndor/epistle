//! The default key's rotation leaves alone the domains that sign with a
//! `[[dkim.domain]]` override: it neither publishes nor retires records
//! there, and an override outside the `[dns]` zone does not stop it.

use super::dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

fn config(domains: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = {domains}\n\
		 [dkim]\nselector = 'mail'\nkey_file = '/etc/mail/dkim.pem'\n\
		 [[dkim.domain]]\nname = 'Other.NET'\nselector = 'net'\nkey_file = '/etc/mail/net.pem'\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\n"
	))
	.expect("config")
}

#[test]
fn an_overridden_domain_is_not_a_signing_domain_of_the_default_key() {
	match decide_dkim_rotation(&config("['example.org', 'other.net']")) {
		DkimRotationPlan::Run {
			signing_domains,
			out_of_zone,
			..
		} => {
			assert_eq!(signing_domains, ["example.org"]);
			assert!(
				out_of_zone.is_empty(),
				"an override outside the zone must not stop the default's rotation: {out_of_zone:?}"
			);
		}
		DkimRotationPlan::Off => panic!("the default key still rotates"),
	}
}
