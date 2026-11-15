//! The certificate refresh publishes the DANE record only when the
//! configuration says the zone is signed.

use super::*;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '.'\n{extra}"
	))
	.expect("config")
}

#[test]
fn by_default_the_refresh_publishes_no_tlsa_record() {
	assert!(skips_tlsa(&config("")));
}

#[test]
fn with_dane_on_the_refresh_publishes_it() {
	assert!(!skips_tlsa(&config("[dns_publish]\ndane = true\n")));
}

#[test]
fn an_explicit_skip_of_the_group_still_wins() {
	assert!(skips_tlsa(&config(
		"[dns_publish]\ndane = true\nskip = ['tlsa']\n"
	)));
}
