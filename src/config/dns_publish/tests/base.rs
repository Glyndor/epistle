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

#[test]
fn extra_txt_is_empty_by_default() {
	let config = parse("").expect("config");
	assert!(config.dns_publish.extra_txt.is_empty());
	assert!(DnsPublish::default().extra_txt.is_empty());
}

#[test]
fn a_supplied_record_is_accepted() {
	let config = parse(
		"[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'google-site-verification=abc' }, { name = 'Mail.Example.ORG', value = 'x' }]\n",
	)
	.expect("config");
	assert_eq!(config.dns_publish.extra_txt.len(), 2);
	assert_eq!(config.dns_publish.extra_txt[0].name, "example.org");
	assert_eq!(
		config.dns_publish.extra_txt[0].value,
		"google-site-verification=abc"
	);
}

#[test]
fn a_name_outside_the_hosted_domains_is_refused() {
	for name in ["other.example.net", "notexample.org", "org"] {
		let error = parse(&format!(
			"[dns_publish]\nextra_txt = [{{ name = '{name}', value = 'v' }}]\n"
		))
		.expect_err("outside the hosted domains");
		assert!(error.to_string().contains("extra_txt"), "{name}: {error}");
	}
}

#[test]
fn an_empty_value_is_refused() {
	for value in ["", "   "] {
		let error = parse(&format!(
			"[dns_publish]\nextra_txt = [{{ name = 'example.org', value = '{value}' }}]\n"
		))
		.expect_err("empty value");
		assert!(error.to_string().contains("extra_txt"), "{error}");
	}
}

#[test]
fn an_invalid_dns_name_is_refused() {
	let error = parse("[dns_publish]\nextra_txt = [{ name = 'not a name.example.org', value = 'v' }]\n")
		.expect_err("not a DNS name");
	assert!(error.to_string().contains("extra_txt"), "{error}");
}

#[test]
fn a_duplicate_entry_is_refused_and_a_second_value_at_one_name_is_not() {
	let error = parse(
		"[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'v' }, { name = 'EXAMPLE.org', value = 'v' }]\n",
	)
	.expect_err("duplicate");
	assert!(error.to_string().contains("duplicate"), "{error}");
	assert!(
		parse(
			"[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'a' }, { name = 'example.org', value = 'b' }]\n"
		)
		.is_ok()
	);
}

#[test]
fn an_unknown_key_in_an_entry_is_refused() {
	assert!(
		parse("[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'v', ttl = 5 }]\n")
			.is_err()
	);
}
