use super::*;
use crate::config::{Config, ForwardPolicy};

fn scopes(extra: &str) -> Scopes {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.com\", \"example.org\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\n{extra}"
	)
	.expect("write config");
	Scopes::from_config(&Config::load(file.path()).expect("config loads"))
}

fn target(domain: &str, account: &str) -> Target {
	Target {
		domain: domain.into(),
		account: Some(account.into()),
	}
}

#[test]
fn without_scopes_the_server_policy_stands() {
	let scopes = scopes("");
	let settings =
		scopes.forward_settings(&target("example.org", "bob"), ForwardPolicy::HostedOnly);
	assert_eq!(settings.policy, ForwardPolicy::HostedOnly);
	assert_eq!(settings.per_min, None);
}

#[test]
fn the_most_specific_scope_wins_and_keeps_what_it_does_not_set() {
	let scopes = scopes(
		"[[antispam_scope]]\ntenant = \"acme\"\nforward_policy = \"hosted-only\"\nforward_per_min = 10\n\
		 [[antispam_scope]]\ndomain = \"example.com\"\nforward_per_min = 5\n\
		 [[antispam_scope]]\naccount = \"bob\"\nforward_policy = \"none\"",
	);
	let any = ForwardPolicy::Any;
	let carol = scopes.forward_settings(&target("example.com", "carol"), any);
	assert_eq!(carol.policy, ForwardPolicy::HostedOnly, "the tenant's");
	assert_eq!(
		carol.per_min,
		Some(5),
		"the domain's limit over the tenant's"
	);
	let bob = scopes.forward_settings(&target("example.com", "bob"), any);
	assert_eq!(bob.policy, ForwardPolicy::None);
	assert_eq!(bob.per_min, Some(5));
	let other = scopes.forward_settings(&target("example.org", "bob"), any);
	assert_eq!(
		other.policy,
		ForwardPolicy::None,
		"the account's scope follows it"
	);
	let untouched = scopes.forward_settings(&target("example.org", "dave"), any);
	assert_eq!(untouched.policy, ForwardPolicy::Any);
}

#[test]
fn a_scope_that_only_sets_forwarding_is_not_inert() {
	assert!(scopes("").is_inert());
	assert!(!scopes("[[antispam_scope]]\naccount = \"bob\"\nforward_per_min = 1").is_inert());
}
