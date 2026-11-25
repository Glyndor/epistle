//! What `stack rollback` takes out of `mail.toml` for 0.14.0, proved against a
//! frozen list of what 0.14.0 accepts.

use std::collections::BTreeSet;

use super::super::check::{check_for_v014, refuse_unreadable_config};
use crate::config::{Api, ListenerKind};

const KNOWN: &str = include_str!("../testdata/config-v0.14.0-known.txt");

fn known(section: &str) -> BTreeSet<&'static str> {
	KNOWN
		.lines()
		.filter(|line| !line.starts_with('#'))
		.filter_map(|line| line.strip_prefix(section)?.strip_prefix(' '))
		.collect()
}

const WITH_THE_NEW_KEYS: &str = r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

# the mail
[[listeners]]
kind = "smtp"

[[listeners]]
kind = "api"
addr = "127.0.0.1"

[[listeners]]
kind = "jmap"

[[listeners]]
kind = "oauth"
port = 9000

[[listeners]]
kind = "scim"

[api]
admins = ["alice"]
surfaces = ["jmap"]
"#;

#[test]
fn a_configuration_with_the_new_options_is_refused_and_each_is_named() {
	let error = check_for_v014(WITH_THE_NEW_KEYS).expect_err("0.14.0 cannot read it");
	for named in [
		"a `jmap` listener",
		"a `oauth` listener",
		"a `scim` listener",
		"`[api] surfaces`",
	] {
		assert!(error.contains(named), "{named}: {error}");
	}
	assert!(error.contains("nothing was changed"), "{error}");
	assert!(
		!error.contains("a `api`"),
		"a listener 0.14.0 reads is not named: {error}"
	);
}

#[test]
fn every_new_option_is_refused_alone() {
	for kind in ["jmap", "scim", "oauth"] {
		let table = format!("[[listeners]]\nkind = \"{kind}\"\n");
		assert!(check_for_v014(&table).is_err(), "{kind} as a table");
		let inline = format!("listeners = [{{ kind = \"{kind}\" }}]\n");
		assert!(check_for_v014(&inline).is_err(), "{kind} inline");
	}
	for surfaces in ["surfaces = []", "surfaces = [\"scim\"]"] {
		let text = format!("[[listeners]]\nkind = \"api\"\n[api]\n{surfaces}\n");
		assert!(check_for_v014(&text).is_err(), "{surfaces}");
	}
}

#[test]
fn a_file_with_nothing_new_passes() {
	let old = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
	           [[listeners]]\nkind = \"api\"\n[api]\nadmins = []\n";
	assert_eq!(check_for_v014(old), Ok(()));
}

#[test]
fn a_file_that_does_not_parse_is_an_error() {
	assert!(check_for_v014("kind = [").is_err());
}

/// What `stack rollback` runs before it stops anything.
#[test]
fn the_rollback_stops_for_a_release_that_cannot_read_the_file_and_not_for_one_that_can() {
	for version in ["0.14.0", "0.13.2", "0.9.0", "nightly"] {
		let error = refuse_unreadable_config(version, WITH_THE_NEW_KEYS).expect_err(version);
		assert!(error.contains("nothing was changed"), "{version}: {error}");
	}
	for version in ["0.15.0", "0.15.1", "0.16.0", "1.0.0"] {
		assert_eq!(
			refuse_unreadable_config(version, WITH_THE_NEW_KEYS),
			Ok(()),
			"{version}"
		);
	}
	assert_eq!(
		refuse_unreadable_config("0.14.0", "hostname = \"h\"\n"),
		Ok(()),
		"a configuration without the options rolls back as before"
	);
}

/// Every listener kind the code has. The `match` has no wildcard, so adding a
/// kind stops the build here until its place in the rollback is decided.
fn every_kind() -> Vec<ListenerKind> {
	use ListenerKind::*;
	let all = [
		Smtp,
		Submission,
		Submissions,
		Api,
		Jmap,
		Scim,
		Oauth,
		Imaps,
		Imap,
		Pop3s,
		ManageSieve,
		Metrics,
		Acme,
		Autoconfig,
		Autoconfigs,
		WebDav,
	];
	for kind in all {
		match kind {
			Smtp | Submission | Submissions | Api | Jmap | Scim | Oauth | Imaps | Imap | Pop3s
			| ManageSieve | Metrics | Acme | Autoconfig | Autoconfigs | WebDav => {}
		}
	}
	all.to_vec()
}

/// The fixture is the other side of the rollback, so it must not drift: every
/// listener kind and `[api]` key the code has now is in it or is refused.
#[test]
fn every_current_kind_and_api_key_is_known_to_0_14_0_or_refused() {
	let kinds = known("kind");
	for kind in every_kind() {
		let name = kind.as_str();
		let text = format!("[[listeners]]\nkind = \"{name}\"\n");
		let refused = check_for_v014(&text).is_err();
		assert!(
			kinds.contains(name) || refused,
			"{name} is new since 0.14.0 and the rollback does not refuse it"
		);
		assert!(
			!kinds.contains(name) || !refused,
			"{name} is known to 0.14.0 and the rollback refuses it"
		);
	}
	// Every key `[api]` takes now is in the list, or is `surfaces`.
	let error = toml::from_str::<Api>("nothing = 1")
		.expect_err("unknown key")
		.to_string();
	let current: Vec<&str> = error
		.split("expected one of ")
		.nth(1)
		.expect("serde lists the fields")
		.lines()
		.next()
		.expect("a line")
		.split(", ")
		.map(|name| name.trim().trim_matches('`'))
		.collect();
	assert!(current.len() >= 8, "{current:?}");
	let keys = known("api");
	for key in current {
		assert!(
			keys.contains(key) || key == "surfaces",
			"[api] {key} is new since 0.14.0 and the rollback does not refuse it"
		);
	}
}
