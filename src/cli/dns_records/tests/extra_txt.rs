//! `dns-records` prints the TXT records the operator supplies, in the same
//! zone form as the TXT records epistle derives.

use super::*;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

fn printed(config: &Config) -> String {
	let mut out = Vec::new();
	assert_eq!(run(config, false, &mut out), ExitCode::SUCCESS);
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn the_supplied_record_is_printed_like_the_other_txt_records() {
	let text = printed(&config(
		"[dns_publish]\nextra_txt = [{ name = 'example.org', value = 'google-site-verification=abc' }]\n",
	));
	let supplied: Vec<&str> = text
		.lines()
		.filter(|line| line.contains("google-site-verification=abc"))
		.collect();
	assert_eq!(supplied.len(), 1, "{text}");
	assert!(supplied[0].starts_with("example.org"), "{text}");
	assert_eq!(supplied[0].split_whitespace().nth(3), Some("TXT"), "{text}");
	let spf = text
		.lines()
		.find(|line| line.contains("v=spf1"))
		.expect("the SPF line");
	assert_eq!(
		supplied[0].split_whitespace().take(4).collect::<Vec<_>>(),
		spf.split_whitespace().take(4).collect::<Vec<_>>(),
		"the same name, ttl, class and type as the SPF"
	);
}

#[test]
fn nothing_supplied_prints_nothing_extra() {
	assert!(!printed(&config("")).contains("google-site-verification"));
}
