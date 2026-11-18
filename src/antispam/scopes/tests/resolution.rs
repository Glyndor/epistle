use super::*;
use crate::config::Config;

const BASE: &str = r#"
domains = ["example.com", "example.org", "example.net"]

[[tenant]]
name = "acme"
domains = ["example.com"]

[antispam.senders]
deny = ["*.spam.example.net"]
allow = ["partner.example.net"]
deny_recipients = ["blocked.example.net"]
"#;

fn scopes(extra: &str) -> Scopes {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{BASE}\n{extra}"
	)
	.expect("write config");
	let config = Config::load(file.path()).expect("config loads");
	Scopes::from_config(&config)
}

fn target(domain: &str, account: Option<&str>) -> Target {
	Target {
		domain: domain.into(),
		account: account.map(str::to_string),
	}
}

#[test]
fn the_server_lists_apply_to_every_recipient() {
	let scopes = scopes("");
	assert!(scopes.refuses_sender("a@x.spam.example.net", &target("example.org", None)));
	assert!(scopes.refuses_sender("a@x.spam.example.net", &target("example.com", Some("bob"))));
	assert!(!scopes.refuses_sender("a@spam.example.net", &target("example.org", None)));
	assert!(scopes.favours_sender("a@partner.example.net", &target("example.org", None)));
	assert!(scopes.refuses_recipient("a@blocked.example.net", &target("example.org", None)));
}

#[test]
fn a_domain_scope_reaches_only_its_domain() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny = [\"bad.example.net\"]",
	);
	assert!(scopes.refuses_sender("a@bad.example.net", &target("example.org", None)));
	assert!(!scopes.refuses_sender("a@bad.example.net", &target("example.com", None)));
}

#[test]
fn a_tenant_scope_reaches_the_domains_of_the_tenant() {
	let scopes = scopes(
		"[[antispam_scope]]\ntenant = \"acme\"\n[antispam_scope.senders]\ndeny = [\"bad.example.net\"]",
	);
	assert!(scopes.refuses_sender("a@bad.example.net", &target("example.com", None)));
	assert!(!scopes.refuses_sender("a@bad.example.net", &target("example.org", None)));
}

#[test]
fn an_account_scope_reaches_only_that_account() {
	let scopes = scopes(
		"[[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.senders]\ndeny = [\"bad.example.net\"]\ndeny_recipients = [\"*.example.net\"]",
	);
	assert!(scopes.refuses_sender("a@bad.example.net", &target("example.org", Some("bob"))));
	assert!(!scopes.refuses_sender("a@bad.example.net", &target("example.org", Some("alice"))));
	assert!(!scopes.refuses_sender("a@bad.example.net", &target("example.org", None)));
	assert!(scopes.refuses_recipient("x@a.example.net", &target("example.org", Some("bob"))));
	assert!(!scopes.refuses_recipient("x@a.example.net", &target("example.org", Some("alice"))));
}

#[test]
fn a_deny_at_any_scope_beats_an_allow_at_any_other() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\nallow = [\"x.spam.example.net\"]\n\
		 [[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.senders]\nallow = [\"*.spam.example.net\"]",
	);
	// The server denies `*.spam.example.net`; the domain and the account
	// allow it, and the deny still wins.
	let bob = target("example.org", Some("bob"));
	assert!(!scopes.favours_sender("a@x.spam.example.net", &bob));
	assert!(scopes.refuses_sender("a@x.spam.example.net", &bob));
}

#[test]
fn an_allow_of_a_narrower_scope_does_not_reach_other_recipients() {
	let scopes = scopes(
		"[[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\nallow = [\"friend.example.net\"]",
	);
	assert!(scopes.favours_sender("a@friend.example.net", &target("example.org", None)));
	assert!(!scopes.favours_sender("a@friend.example.net", &target("example.com", None)));
}

#[test]
fn a_domain_alias_resolves_to_the_domain_it_delivers_to() {
	let scopes = {
		use std::io::Write;
		let mut file = tempfile::NamedTempFile::new().expect("config file");
		write!(
			file,
			"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
			 domains = [\"example.org\"]\n[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n\
			 [[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.senders]\ndeny = [\"bad.example.net\"]\n"
		)
		.expect("write");
		Scopes::from_config(&Config::load(file.path()).expect("loads"))
	};
	assert!(scopes.refuses_sender("a@bad.example.net", &target("alias.example.org", None)));
}

#[test]
fn nothing_configured_is_inert() {
	let empty = Scopes::default();
	assert!(empty.is_inert());
	assert!(!empty.refuses_sender("a@example.com", &target("example.org", None)));
	assert!(!scopes("").is_inert());
}

#[test]
fn attachment_settings_merge_to_the_strictest_of_every_scope_in_reach() {
	let scopes = scopes(
		"[attachments]\nmode = \"flag\"\n\
		 [[antispam_scope]]\ndomain = \"example.org\"\n[antispam_scope.attachments]\nmode = \"quarantine\"\nblock_extensions = [\"docm\"]\nmax_attachment_bytes = 5000000\n\
		 [[antispam_scope]]\naccount = \"bob\"\n[antispam_scope.attachments]\nmode = \"reject\"\nmax_attachment_bytes = 1000000\nblock_mime_types = [\"image/*\"]",
	);
	let merged = scopes.attachment_overlay(&[target("example.org", Some("bob"))]);
	assert_eq!(merged.mode, Some(crate::config::AttachmentMode::Reject));
	assert_eq!(merged.max_attachment_bytes, Some(1_000_000));
	assert_eq!(merged.block_extensions, vec!["docm".to_string()]);
	assert_eq!(merged.block_mime_types, vec!["image/*".to_string()]);
	// A second recipient outside both scopes adds nothing but does not
	// loosen the first one.
	let both = scopes.attachment_overlay(&[
		target("example.org", Some("bob")),
		target("example.com", None),
	]);
	assert_eq!(both, merged);
	let other = scopes.attachment_overlay(&[target("example.com", None)]);
	assert!(other.is_empty());
}
