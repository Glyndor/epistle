//! The DANE record is published only in a zone the operator says is
//! signed: `[dns_publish] dane` is off by default and puts the `tlsa`
//! group in the set of skipped records.

use crate::dns::skip::SkipGroup;

fn parse(extra: &str) -> crate::config::Config {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{extra}",
		dir.path()
	);
	crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml")).expect("config")
}

#[test]
fn dane_is_off_by_default_and_the_tlsa_group_is_skipped() {
	let config = parse("");
	assert!(!config.dns_publish.dane);
	assert!(config.skip_set().contains(SkipGroup::Tlsa));
}

#[test]
fn dane_on_takes_the_tlsa_group_out_of_the_skipped_set() {
	let config = parse("[dns_publish]\ndane = true\n");
	assert!(!config.skip_set().contains(SkipGroup::Tlsa));
}

#[test]
fn an_explicit_skip_of_tlsa_wins_over_dane() {
	let config = parse("[dns_publish]\ndane = true\nskip = ['tlsa']\n");
	assert!(config.skip_set().contains(SkipGroup::Tlsa));
}

#[test]
fn dane_leaves_the_other_skipped_groups_as_the_operator_wrote_them() {
	let config = parse("[dns_publish]\ndane = true\nskip = ['client-locators']\n");
	let set = config.skip_set();
	assert!(set.contains(SkipGroup::ClientLocators));
	assert!(!set.contains(SkipGroup::Tlsa));
}

#[test]
fn the_section_alone_does_not_carry_the_dane_default() {
	// The flag is applied where the whole configuration is known:
	// `DnsPublish::skip_set` is only what the operator listed.
	let config = parse("");
	assert!(!config.dns_publish.skip_set().contains(SkipGroup::Tlsa));
}
