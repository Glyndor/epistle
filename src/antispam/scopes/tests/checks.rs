//! The DKIM, ARC and reverse-DNS checks of a scope.

use super::*;
use crate::antispam::scopes::Checks;
use crate::config::{CheckPolicy, Config};

fn scopes(extra: &str) -> Scopes {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.com\", \"example.org\", \"example.net\"]\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.com\"]\n{extra}"
	)
	.expect("write config");
	Scopes::from_config(&Config::load(file.path()).expect("config loads"))
}

fn target(domain: &str, account: Option<&str>) -> Target {
	Target {
		domain: domain.into(),
		account: account.map(str::to_string),
	}
}

#[test]
fn without_scopes_the_checks_are_what_the_server_does_today() {
	let scopes = scopes("");
	assert!(scopes.is_inert());
	assert_eq!(
		scopes.checks(&[target("example.org", None)]),
		Checks::default()
	);
	assert_eq!(scopes.checks(&[]), Checks::default());
	let today = Checks::default();
	assert_eq!(today.dkim, CheckPolicy::Annotate);
	assert_eq!(today.arc, CheckPolicy::Off);
	assert_eq!(today.reverse_dns, CheckPolicy::Off);
	assert!(!today.dkim_require_signature);
}

#[test]
fn a_scope_with_only_checks_is_not_inert() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\ndkim = \"reject\"",
	);
	assert!(!scopes.is_inert());
}

#[test]
fn the_most_specific_scope_wins_and_each_key_is_its_own() {
	let scopes = scopes(
		"[[antispam_scope]]\ntenant = \"acme\"\n[antispam_scope.checks]\ndkim = \"reject\"\narc = \"annotate\"\n\
		 [[antispam_scope]]\ndomain = \"example.com\"\n[antispam_scope.checks]\narc = \"reject\"\n\
		 [[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.checks]\ndkim = \"off\"",
	);
	let tenant = scopes.checks(&[target("example.net", None)]);
	assert_eq!(tenant, Checks::default(), "another domain is untouched");
	let domain = scopes.checks(&[target("example.com", None)]);
	assert_eq!(domain.dkim, CheckPolicy::Reject, "from the tenant");
	assert_eq!(
		domain.arc,
		CheckPolicy::Reject,
		"the domain over the tenant"
	);
	let account = scopes.checks(&[target("example.com", Some("bob"))]);
	assert_eq!(
		account.dkim,
		CheckPolicy::Off,
		"the account over the tenant"
	);
	assert_eq!(account.arc, CheckPolicy::Reject);
}

#[test]
fn several_recipients_get_the_strictest_setting_of_any() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.com\"\n[antispam_scope.checks]\nreverse_dns = \"reject\"\ndkim_require_signature = true\n\
		 [[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.checks]\nreverse_dns = \"annotate\"\narc = \"off\"",
	);
	let merged = scopes.checks(&[target("example.org", None), target("example.com", None)]);
	assert_eq!(merged.reverse_dns, CheckPolicy::Reject);
	assert!(merged.dkim_require_signature);
	let lenient = scopes.checks(&[target("example.org", None)]);
	assert_eq!(lenient.reverse_dns, CheckPolicy::Annotate);
	assert!(!lenient.dkim_require_signature);
}
