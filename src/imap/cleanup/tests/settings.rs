//! What the configuration accepts and what it leaves off.

use std::path::Path;

fn parse(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[[tenant]]\nname = 'acme'\ndomains = ['example.org']\n{extra}",
		dir.path()
	);
	crate::config::Config::parse_text(&text, Path::new("mail.toml"))
}

#[test]
fn without_the_section_nothing_is_removed() {
	let config = parse("").expect("config");
	assert!(super::Policy::from_config(&config).is_none());
	let config = parse("[storage]\n").expect("config");
	assert!(super::Policy::from_config(&config).is_none());
}

#[test]
fn the_section_alone_turns_nothing_on_but_the_cap_defaults_to_a_thousand() {
	let config = parse("[storage.cleanup]\n").expect("config");
	let policy = super::Policy::from_config(&config).expect("policy");
	assert_eq!(policy.max_per_run(), 1000);
	let subject = policy.subject("a@example.org");
	assert_eq!(policy.operator_days(&subject, &["trash".to_string()]), None);
}

#[test]
fn bad_rules_stop_the_start() {
	for bad in [
		"scope = 'server'\nname = 'x'\nfolder = 'trash'\ndays = 1",
		"scope = 'domain'\nfolder = 'trash'\ndays = 1",
		"scope = 'domain'\nname = 'nowhere.example'\nfolder = 'trash'\ndays = 1",
		"scope = 'tenant'\nname = 'ghost'\nfolder = 'trash'\ndays = 1",
		"scope = 'account'\nname = '../x'\nfolder = 'trash'\ndays = 1",
		"scope = 'server'\nfolder = 'INBOX'\ndays = 1",
		"scope = 'server'\nfolder = 'trash'\ndays = 36501",
	] {
		let text = format!("[storage.cleanup]\n[[storage.cleanup.rule]]\n{bad}\n");
		assert!(parse(&text).is_err(), "{bad}");
	}
	assert!(parse("[storage.cleanup]\nmax_per_run = 0\n").is_err());
}

#[test]
fn good_rules_load_at_every_scope() {
	let text = "[storage.cleanup]\nmax_per_run = 50\n\
[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 30\n\
[[storage.cleanup.rule]]\nscope = 'tenant'\nname = 'acme'\nfolder = 'junk'\ndays = 14\n\
[[storage.cleanup.rule]]\nscope = 'domain'\nname = 'example.org'\nfolder = 'Old mail'\ndays = 90\n\
[[storage.cleanup.rule]]\nscope = 'account'\nname = 'a@example.org'\nfolder = 'rejects'\ndays = 0\n";
	let config = parse(text).expect("config");
	let policy = super::Policy::from_config(&config).expect("policy");
	assert_eq!(policy.max_per_run(), 50);
}
