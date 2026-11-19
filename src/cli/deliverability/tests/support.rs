//! A hosted `example.org` with one account, a fixed signing key and a healthy
//! resolver.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::cli::status::dns_fake::FakeDns;
use crate::config::Config;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::dkim::{PerDomainSigner, ReloadableSigner};
use crate::smtp::auth::tests::base::{fixture_password, hash};

/// The one address the tests send to, outside the hosted domain.
pub(super) const DESTINATION: &str = "check@mail-tester.example";

pub(super) fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\npublic_ipv4 = \"203.0.113.10\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

pub(super) fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| a.to_string()).collect(),
		password_hash: hash(fixture_password()),
		..DynamicAccount::default()
	}
}

/// A store holding `alice` with `alice@example.org`, and any `extra` account.
pub(super) fn store(
	data_dir: &std::path::Path,
	config: &Config,
	extra: Vec<DynamicAccount>,
) -> AccountStore {
	let store = AccountStore::open(
		data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store");
	store
		.add(account("alice", &["alice@example.org"]))
		.expect("add alice");
	for account in extra {
		store.add(account).expect("add account");
	}
	store
}

/// The signer every test signs with: a fixed key published by [`dns`].
pub(super) fn signer(dir: &std::path::Path) -> PerDomainSigner {
	PerDomainSigner::new(
		ReloadableSigner::new(Arc::new(crate::dkim::test_support::fixed_signer(dir))),
		Vec::new(),
	)
}

/// A healthy resolver that also publishes the signing key.
pub(super) fn dns() -> FakeDns {
	let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("seed");
	let public = ring::signature::KeyPair::public_key(&pair);
	let mut dns = FakeDns::healthy();
	dns.txt.insert(
		"sel._domainkey.example.org".into(),
		vec![format!("v=DKIM1; k=ed25519; p={}", STANDARD.encode(public))],
	);
	dns
}
