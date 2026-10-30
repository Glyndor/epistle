//! End-to-end tests for the `account forward` and `account catch-all`
//! resource subcommands and their backing store mutators.
//!
//! Sibling test module so `account_subcommand.rs` and the
//! other test files stay under the per-file code-line budget. Tests
//! here drive the store mutators directly (the path the CLI handlers
//! take) plus the full `Cli::run` for parser-shape validation.

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::directory_store::AccountStore;
use crate::smtp::auth::tests::base::{fixture_password, hash};

const DOMAIN: &str = "example.org";

fn write_config(data_dir: &std::path::Path, body: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	let full = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\"]\n\n{}",
		data_dir, body
	);
	use std::io::Write as _;
	file.write_all(full.as_bytes()).expect("write");
	file
}

fn open_store(data_dir: &std::path::Path) -> AccountStore {
	AccountStore::open(
		data_dir,
		vec![DOMAIN.to_string()],
		Default::default(),
		Vec::new(),
	)
	.expect("open store")
}

fn seed_bob(store: &AccountStore) {
	store
		.add(crate::directory_store::DynamicAccount {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: hash(fixture_password()),
			..crate::directory_store::DynamicAccount::default()
		})
		.expect("add bob");
}

#[test]
fn forward_resource_parser_maps_to_subcommand() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"forward",
		"add",
		"bob",
		"outsource@example.com",
	])
	.expect("account forward add parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::Forward(args) => match args.action {
				crate::cli::account::ForwardSubcommand::Add { name, address } => {
					assert_eq!(name, "bob");
					assert_eq!(address, "outsource@example.com");
				}
				other => panic!("expected ForwardSubcommand::Add, got {other:?}"),
			},
			other => panic!("expected Subcommand::Forward, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn catch_all_resource_parser_maps_to_subcommand() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		"/etc/mail.toml",
		"catch-all",
		"add",
		"bob",
		"example.org",
	])
	.expect("account catch-all add parses");
	match cli.command {
		Command::Account { action, .. } => match action {
			crate::cli::account::Subcommand::CatchAll(args) => match args.action {
				crate::cli::account::CatchAllSubcommand::Add { name, domain } => {
					assert_eq!(name, "bob");
					assert_eq!(domain, "example.org");
				}
				other => panic!("expected CatchAllSubcommand::Add, got {other:?}"),
			},
			other => panic!("expected Subcommand::CatchAll, got {other:?}"),
		},
		other => panic!("expected Command::Account, got {other:?}"),
	}
}

#[test]
fn forward_add_remove_round_trip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	// Round trip: add two forward targets, remove one, confirm one is left.
	store
		.add_forward("bob", "outside@example.com")
		.expect("add forward");
	store
		.add_forward("bob", "second@example.com")
		.expect("add second forward");
	let all = store.forwards("bob");
	assert!(
		all.contains(&"outside@example.com".to_string()),
		"first forward missing from the stored forwards"
	);
	assert!(
		all.contains(&"second@example.com".to_string()),
		"second forward missing from the stored forwards"
	);
	store
		.remove_forward("bob", "outside@example.com")
		.expect("remove forward");
	let after = store.forwards("bob");
	assert_eq!(after, vec!["second@example.com".to_string()]);
}

#[test]
fn forward_add_refuses_self_target() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	let err = store
		.add_forward("bob", "bob@example.org")
		.expect_err("forward to own address must fail");
	assert!(
		matches!(err, crate::directory_store::StoreError::Invalid(_)),
		"own-address self-forward should be Invalid, got {err:?}"
	);
}

#[test]
fn forward_add_refuses_duplicate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	store
		.add_forward("bob", "outside@example.com")
		.expect("first");
	let err = store
		.add_forward("bob", "OUTSIDE@example.com")
		.expect_err("duplicate must fail");
	assert!(
		matches!(err, crate::directory_store::StoreError::Duplicate(_)),
		"duplicate forward should be Duplicate, got {err:?}"
	);
}

#[test]
fn catch_all_add_requires_configured_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	let err = store
		.add_catch_all("bob", "not-configured.example")
		.expect_err("unconfigured domain must fail");
	assert!(
		matches!(err, crate::directory_store::StoreError::Invalid(_)),
		"unconfigured domain should be Invalid, got {err:?}"
	);
	// The configured one succeeds.
	store
		.add_catch_all("bob", "example.org")
		.expect("configured catch-all");
	let domains = store.catch_alls("bob");
	assert_eq!(domains, vec!["example.org".to_string()]);
}

#[test]
fn catch_all_remove_unknown_domain_is_invalid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	store
		.add_catch_all("bob", "example.org")
		.expect("add catch-all");
	let err = store
		.remove_catch_all("bob", "other.example")
		.expect_err("unknown must fail");
	assert!(
		matches!(err, crate::directory_store::StoreError::Invalid(_)),
		"unknown catch-all should be Invalid, got {err:?}"
	);
}

#[test]
fn forward_remove_unknown_target_is_invalid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	let err = store
		.remove_forward("bob", "never-set@example.com")
		.expect_err("missing must fail");
	assert!(
		matches!(err, crate::directory_store::StoreError::Invalid(_)),
		"missing forward should be Invalid, got {err:?}"
	);
}

#[test]
fn dynamic_forward_is_picked_up_by_directory_builder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	store
		.add_forward("bob", "outsource@example.com")
		.expect("add forward");
	let handle = store.handle();
	let dir_view = handle.current();
	let (targets, keep_local) = dir_view
		.forwards("bob")
		.expect("bob should have a forward entry");
	assert_eq!(targets, &["outsource@example.com".to_string()]);
	assert!(keep_local);
}

#[test]
fn dynamic_catch_all_is_picked_up_by_directory_builder() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = open_store(dir.path());
	seed_bob(&store);
	store
		.add_catch_all("bob", "example.org")
		.expect("add catch-all");
	let handle = store.handle();
	let dir_view = handle.current();
	// Catch-all is consulted at the lowest cost: any unknown address in
	// the domain should resolve to bob.
	let unknown = crate::smtp::address::Address::parse("nobody@example.org").expect("parse");
	let resolved = dir_view.resolve(&unknown);
	assert!(
		matches!(
			resolved,
			crate::smtp::directory::Resolution::Account(ref account) if account == "bob"
		),
		"an unknown local part on the catch-all domain must resolve to bob's account"
	);
}

#[test]
fn account_run_refuses_static_account_for_forward() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(
		dir.path(),
		"[[accounts]]\n\
		 name = \"static-alice\"\n\
		 addresses = [\"alice@example.org\"]\n",
	);
	let cli = Cli::try_parse_from([
		"epistle",
		"account",
		"--config",
		cfg.path().to_str().expect("utf8 path"),
		"forward",
		"add",
		"static-alice",
		"outsource@example.com",
	])
	.expect("parses");
	// The umbrella refuses a static account with the config-file hint
	// before the forward mutator runs: a refusal by policy, exit code 3.
	assert_eq!(cli.run(), ExitCode::from(3));
}
