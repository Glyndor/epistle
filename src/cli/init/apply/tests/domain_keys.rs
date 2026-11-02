//! `init` gives every domain after the first a DKIM key of its own, and a
//! second run neither adds nor takes away a domain's key.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::*;
use crate::cli::init::answers::Services;
use crate::config::Config;

fn answers(dir: &Path, domains: &[&str]) -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: dir.join("data"),
		config_path: dir.join("mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

fn written(answers: &Answers) -> Config {
	let outcome = apply(answers);
	assert!(outcome.error.is_none(), "{:?}", outcome.error);
	Config::load(&answers.config_path).expect("the written configuration loads")
}

fn public(file: &Path) -> String {
	crate::dkim::Signer::load("x", file)
		.expect("loads")
		.dns_record_value()
}

#[test]
fn the_first_domain_keeps_the_default_pair_and_the_others_get_their_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = written(&answers(
		dir.path(),
		&["a.example", "b.example", "c.example"],
	));
	let dkim = config.dkim.clone().expect("dkim");
	let names: Vec<_> = dkim.domain.iter().map(|d| d.name.as_str()).collect();
	assert_eq!(
		names,
		["b.example", "c.example"],
		"the first signs with [dkim]"
	);
	let b = dkim.override_for("b.example").expect("b");
	let c = dkim.override_for("c.example").expect("c");
	assert_ne!(public(&b.key_file), public(&c.key_file));
	assert_ne!(public(&b.key_file), public(&dkim.key_file));
	assert!(
		b.rsa_selector.is_some(),
		"the default pair has an RSA key, so do theirs"
	);
	assert!(
		dkim.shared_default_warning(&config.domains, &config.domain_aliases)
			.is_none(),
		"no key is shared"
	);
	assert_eq!(
		crate::dkim::sharing::shared_public_keys(&config),
		Ok(Vec::new())
	);
}

#[test]
fn one_domain_has_no_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = written(&answers(dir.path(), &["a.example"]));
	assert!(config.dkim.expect("dkim").domain.is_empty());
	assert!(!dir.path().join("data/keys/dkim").exists());
}

#[test]
fn running_it_again_keeps_the_keys_and_the_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = answers(dir.path(), &["a.example", "b.example"]);
	let first = written(&answers);
	let before = first.dkim.as_ref().expect("dkim").domain.clone();
	let key_before = public(&before[0].key_file);
	let second = written(&answers);
	let after = second.dkim.expect("dkim").domain;
	assert_eq!(after, before);
	assert_eq!(public(&after[0].key_file), key_before);
}

#[test]
fn an_existing_configuration_without_entries_gets_none() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = answers(dir.path(), &["a.example"]);
	written(&first);
	// The operator adds a domain by hand and runs init again: the install
	// keeps signing the way it did, with no entry and no new key.
	let mut second = answers(dir.path(), &["a.example", "b.example"]);
	second.config_path = first.config_path.clone();
	let config = written(&second);
	assert!(config.dkim.expect("dkim").domain.is_empty());
	assert!(!dir.path().join("data/keys/dkim").exists());
}

#[test]
fn an_entry_the_operator_has_survives_a_second_run() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers = answers(dir.path(), &["a.example", "b.example"]);
	written(&answers);
	// The operator moves b.example's entry to a key of their choosing.
	let text = std::fs::read_to_string(&answers.config_path).expect("read");
	let own = dir.path().join("b-own.pem");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(&own, pem).expect("write");
	let edited = text.replace(
		&dir.path()
			.join("data/keys/dkim/b.example/ed25519.pem")
			.display()
			.to_string(),
		&own.display().to_string(),
	);
	assert_ne!(edited, text, "the edit changed the key file");
	std::fs::write(&answers.config_path, edited).expect("write config");
	let config = written(&answers);
	let b = config
		.dkim
		.expect("dkim")
		.override_for("b.example")
		.cloned()
		.expect("the entry survived");
	assert_eq!(b.key_file, PathBuf::from(&own));
}
