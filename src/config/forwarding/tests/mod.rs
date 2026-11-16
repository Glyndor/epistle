//! `[forwarding]` and the forwarding keys of a scope load, default to
//! today's behaviour and refuse a limit of zero by name.

use super::*;

fn load(settings: &str) -> Result<Config, ConfigError> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n{settings}"
	)
	.expect("write config");
	Config::load(file.path())
}

#[test]
fn the_defaults_forward_anywhere_with_no_limit() {
	let config = load("").expect("loads");
	assert_eq!(config.forwarding, Forwarding::default());
	assert_eq!(config.forwarding.policy, ForwardPolicy::Any);
	assert_eq!(config.forwarding.account_per_min, None);
	assert_eq!(config.forwarding.server_per_min, None);
}

#[test]
fn each_policy_parses() {
	for (word, policy) in [
		("any", ForwardPolicy::Any),
		("hosted-only", ForwardPolicy::HostedOnly),
		("none", ForwardPolicy::None),
	] {
		let config = load(&format!("[forwarding]\npolicy = \"{word}\"")).expect("loads");
		assert_eq!(config.forwarding.policy, policy);
	}
	assert!(load("[forwarding]\npolicy = \"some\"").is_err());
}

#[test]
fn the_policy_decides_by_whether_the_domain_is_hosted() {
	assert!(ForwardPolicy::Any.allows(false));
	assert!(ForwardPolicy::HostedOnly.allows(true));
	assert!(!ForwardPolicy::HostedOnly.allows(false));
	assert!(!ForwardPolicy::None.allows(true));
}

#[test]
fn a_limit_of_zero_is_refused_and_names_its_key() {
	for (settings, key) in [
		("[forwarding]\naccount_per_min = 0", "account_per_min"),
		("[forwarding]\nserver_per_min = 0", "server_per_min"),
		(
			"[[antispam_scope]]\naccount = \"alice\"\nforward_per_min = 0",
			"forward_per_min",
		),
	] {
		let error = load(settings).expect_err(settings);
		assert!(format!("{error:?}").contains(key), "{settings}: {error:?}");
	}
}

#[test]
fn an_unknown_key_is_refused() {
	assert!(load("[forwarding]\npolicy_all = true").is_err());
}
