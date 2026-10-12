//! `epistle account catch-all add` follows the rules delivery applies:
//! the directory resolves a domain alias to its target before it looks a
//! catch-all up, and keeps one catch-all account per domain. A catch-all
//! the directory would never consult, or would silently take from
//! another account, is refused and leaves the store as it was.

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

/// A data dir with dynamic `bob` and `carol`, and a config serving
/// `example.org` with `alias.example` as its alias plus `extra`.
fn setup(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	use std::io::Write as _;
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\
		 [domain_aliases]\n\"alias.example\" = \"example.org\"\n\n{extra}",
		dir.path()
	)
	.expect("write config");
	let config = crate::config::Config::load(file.path()).expect("config loads");
	let store = open_store(&config);
	for name in ["bob", "carol"] {
		store
			.add(DynamicAccount {
				name: name.to_string(),
				addresses: vec![format!("{name}@example.org")],
				password_hash: crate::smtp::auth::tests::hash(
					crate::smtp::auth::tests::fixture_password(),
				),
				..DynamicAccount::default()
			})
			.expect("add account");
	}
	(dir, file)
}

fn open_store(config: &crate::config::Config) -> AccountStore {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store")
}

fn store_of(config: &tempfile::NamedTempFile) -> AccountStore {
	open_store(&crate::config::Config::load(config.path()).expect("config loads"))
}

fn catch_all(config: &tempfile::NamedTempFile, verb: &str, name: &str, domain: &str) -> ExitCode {
	Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		config.path().to_str().expect("utf8 path"),
		"catch-all",
		verb,
		name,
		domain,
	])
	.expect("parses")
	.run()
}

fn resolve(store: &AccountStore, address: &str) -> Resolution {
	let address = Address::parse(address).expect("address");
	store.handle().current().resolve(&address)
}

#[test]
fn catch_all_add_routes_unknown_users_of_the_domain() {
	let (_dir, config) = setup("");
	assert_eq!(
		catch_all(&config, "add", "bob", "EXAMPLE.org"),
		ExitCode::SUCCESS
	);
	let store = store_of(&config);
	assert_eq!(store.catch_alls("bob"), vec!["example.org".to_string()]);
	assert_eq!(
		resolve(&store, "nobody@example.org"),
		Resolution::Account("bob".to_string())
	);
}

#[test]
fn catch_all_add_refuses_a_domain_alias() {
	let (_dir, config) = setup("");
	assert_ne!(
		catch_all(&config, "add", "bob", "alias.example"),
		ExitCode::SUCCESS
	);
	let store = store_of(&config);
	assert!(store.catch_alls("bob").is_empty());
	// The refusal names the target, so the operator knows where it belongs.
	match store.add_catch_all("bob", "alias.example") {
		Err(crate::directory_store::StoreError::Invalid(message)) => assert_eq!(
			message,
			"alias.example is an alias of example.org; set the catch-all on example.org"
		),
		other => panic!("expected Invalid, got {other:?}"),
	}
}

#[test]
fn catch_all_add_refuses_a_domain_another_dynamic_account_catches() {
	let (_dir, config) = setup("");
	assert_eq!(
		catch_all(&config, "add", "carol", "example.org"),
		ExitCode::SUCCESS
	);
	assert_ne!(
		catch_all(&config, "add", "bob", "example.org"),
		ExitCode::SUCCESS
	);
	let store = store_of(&config);
	assert!(store.catch_alls("bob").is_empty());
	assert_eq!(
		resolve(&store, "nobody@example.org"),
		Resolution::Account("carol".to_string())
	);
}

#[test]
fn catch_all_add_refuses_a_domain_a_static_account_catches() {
	let (_dir, config) = setup(
		"[[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n\
		 catch_all = [\"example.org\"]\n",
	);
	assert_ne!(
		catch_all(&config, "add", "bob", "example.org"),
		ExitCode::SUCCESS
	);
	let store = store_of(&config);
	assert!(store.catch_alls("bob").is_empty());
	assert_eq!(
		resolve(&store, "nobody@example.org"),
		Resolution::Account("postmaster".to_string())
	);
}
