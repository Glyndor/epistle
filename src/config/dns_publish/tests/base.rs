//! `[dns_publish]` defaults and the interval range.

use super::*;

fn parse(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{extra}",
		dir.path()
	);
	crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
}

#[test]
fn the_default_is_six_hours() {
	let config = parse("").expect("config");
	assert_eq!(config.dns_publish.interval_secs, DEFAULT_INTERVAL_SECS);
	assert_eq!(DEFAULT_INTERVAL_SECS, 6 * 3600);
}

#[test]
fn zero_turns_the_loop_off_and_is_accepted() {
	assert!(parse("[dns_publish]\ninterval_secs = 0\n").is_ok());
}

#[test]
fn an_interval_inside_the_range_is_accepted_and_one_outside_is_refused() {
	for (secs, ok) in [
		(MIN_INTERVAL_SECS - 1, false),
		(MIN_INTERVAL_SECS, true),
		(MAX_INTERVAL_SECS, true),
		(MAX_INTERVAL_SECS + 1, false),
	] {
		let result = parse(&format!("[dns_publish]\ninterval_secs = {secs}\n"));
		assert_eq!(result.is_ok(), ok, "interval_secs = {secs}: {result:?}");
		if let Err(error) = result {
			assert!(error.to_string().contains("[dns_publish] interval_secs"));
		}
	}
}

#[test]
fn an_unknown_key_is_refused() {
	assert!(parse("[dns_publish]\nintervals = 60\n").is_err());
}

#[test]
fn skip_is_empty_by_default_and_names_groups_when_set() {
	let config = parse("").expect("config");
	assert!(config.dns_publish.skip_set().is_empty());
	let config = parse("[dns_publish]\nskip = ['client-locators', 'tlsa']\n").expect("config");
	let set = config.dns_publish.skip_set();
	assert!(set.contains(crate::dns::skip::SkipGroup::ClientLocators));
	assert!(set.contains(crate::dns::skip::SkipGroup::Tlsa));
	assert!(!set.contains(crate::dns::skip::SkipGroup::Caa));
}

#[test]
fn an_unknown_skip_group_is_refused_naming_the_groups_that_exist() {
	let error = parse("[dns_publish]\nskip = ['srv']\n").expect_err("a DNS type is no group");
	let text = error.to_string();
	assert!(
		text.contains("client-locators") && text.contains("mta-sts"),
		"{text}"
	);
}
