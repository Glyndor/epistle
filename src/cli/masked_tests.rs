//! Tests for `epistle masked`. Each test drives the command against a temp
//! data dir, then reopens the store the way `serve` does and resolves the
//! address, so what is checked is delivery and not just file contents.

use super::*;
use crate::directory_store::AccountStore;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

const DOMAIN: &str = "example.org";

fn config(dir: &std::path::Path, extra: &str) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{DOMAIN}\", \"example.net\"]\n\
		 {extra}\n[[accounts]]\nname = \"alice\"\naddresses = [\"alice@{DOMAIN}\"]\n",
		dir
	);
	toml::from_str(&toml).expect("config parses")
}

/// Run an action and return the exit code, stdout and stderr.
fn exec(config: &Config, action: MaskedCli) -> (ExitCode, String, String) {
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = run(config, action, 1_700_000_000, &mut out, &mut err);
	(
		code,
		String::from_utf8(out).expect("utf8"),
		String::from_utf8(err).expect("utf8"),
	)
}

fn add(config: &Config, account: &str, label: &str, domain: Option<&str>) -> (ExitCode, String) {
	let (code, out, _) = exec(
		config,
		MaskedCli::Add {
			account: account.to_string(),
			label: label.to_string(),
			domain: domain.map(str::to_string),
		},
	);
	(code, out.trim().to_string())
}

/// What a store opened like the server's makes of a recipient.
fn resolve(config: &Config, address: &str) -> Resolution {
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store")
	.with_masked_max(config.masked_addresses_max);
	let address = Address::parse(address).expect("address parses");
	store.handle().current().resolve(&address)
}

#[test]
fn added_address_resolves_to_the_account_and_disable_stops_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (code, address) = add(&config, "alice", "Shop", None);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(address.starts_with("shop."), "{address}");
	assert!(address.ends_with("@example.org"), "{address}");
	assert_eq!(
		resolve(&config, &address),
		Resolution::Account("alice".to_string())
	);

	let disable = MaskedCli::Disable {
		account: "alice".to_string(),
		address: address.clone(),
	};
	assert_eq!(exec(&config, disable).0, ExitCode::SUCCESS);
	assert_eq!(resolve(&config, &address), Resolution::UnknownUser);

	let enable = MaskedCli::Enable {
		account: "alice".to_string(),
		address: address.clone(),
	};
	assert_eq!(exec(&config, enable).0, ExitCode::SUCCESS);
	assert_eq!(
		resolve(&config, &address),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn remove_deletes_the_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (_, address) = add(&config, "alice", "Shop", None);
	let remove = MaskedCli::Remove {
		account: "alice".to_string(),
		address: address.clone(),
	};
	let (code, out, _) = exec(&config, remove);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(out, format!("removed {address}\n"));
	assert_eq!(resolve(&config, &address), Resolution::UnknownUser);
}

#[test]
fn domain_flag_picks_the_domain_and_a_foreign_domain_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (code, address) = add(&config, "alice", "Shop", Some("EXAMPLE.net"));
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(address.ends_with("@example.net"), "{address}");

	let (code, out, err) = exec(
		&config,
		MaskedCli::Add {
			account: "alice".to_string(),
			label: "Shop".to_string(),
			domain: Some("elsewhere.test".to_string()),
		},
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty(), "nothing is printed on failure: {out}");
	assert!(err.contains("elsewhere.test"), "{err}");
}

#[test]
fn per_account_cap_applies() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "masked_addresses_max = 1");
	assert_eq!(add(&config, "alice", "one", None).0, ExitCode::SUCCESS);
	let (code, out) = add(&config, "alice", "two", None);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty(), "{out}");
	let listed = exec(
		&config,
		MaskedCli::List {
			account: "alice".to_string(),
			json: false,
		},
	);
	assert_eq!(listed.1.lines().count(), 1, "{}", listed.1);
}

#[test]
fn unknown_account_is_refused_and_nothing_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (code, out, err) = exec(
		&config,
		MaskedCli::Add {
			account: "nobody".to_string(),
			label: "Shop".to_string(),
			domain: None,
		},
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty(), "{out}");
	assert!(err.contains("no such account: nobody"), "{err}");
	assert!(!dir.path().join("masked.json").exists());
}

#[test]
fn another_accounts_address_cannot_be_touched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(
		dir.path(),
		"\n[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n",
	);
	let (_, address) = add(&config, "alice", "Shop", None);
	let (code, _, err) = exec(
		&config,
		MaskedCli::Remove {
			account: "bob".to_string(),
			address: address.clone(),
		},
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("no such masked address"), "{err}");
	assert_eq!(
		resolve(&config, &address),
		Resolution::Account("alice".to_string())
	);
}

#[test]
fn list_prints_text_and_json() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (_, address) = add(&config, "alice", "Shop", None);
	let disable = MaskedCli::Disable {
		account: "alice".to_string(),
		address: address.clone(),
	};
	exec(&config, disable);

	let (code, text, _) = exec(
		&config,
		MaskedCli::List {
			account: "alice".to_string(),
			json: false,
		},
	);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(text, format!("{address}\tShop\tdisabled\n"));

	let (_, json, _) = exec(
		&config,
		MaskedCli::List {
			account: "alice".to_string(),
			json: true,
		},
	);
	let rows: serde_json::Value = serde_json::from_str(&json).expect("json");
	assert_eq!(rows[0]["address"], address.as_str());
	assert_eq!(rows[0]["enabled"], false);
	assert_eq!(rows[0]["label"], "Shop");
	assert_eq!(rows.as_array().expect("array").len(), 1);
}

#[test]
fn list_of_unknown_account_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path(), "");
	let (code, out, err) = exec(
		&config,
		MaskedCli::List {
			account: "nobody".to_string(),
			json: false,
		},
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty(), "{out}");
	assert!(err.contains("no such account: nobody"), "{err}");
}

#[test]
fn parses_the_documented_shapes() {
	use clap::Parser;
	let cli = crate::cli::Cli::try_parse_from([
		"epistle",
		"masked",
		"add",
		"alice",
		"--label",
		"Shop",
		"--domain",
		"example.org",
	])
	.expect("add parses");
	assert!(matches!(
		cli.command,
		crate::cli::Command::Masked {
			action: MaskedCli::Add { .. },
			..
		}
	));
	assert!(
		crate::cli::Cli::try_parse_from(["epistle", "masked", "list", "alice", "--json"]).is_ok()
	);
	assert!(crate::cli::Cli::try_parse_from(["epistle", "masked", "remove", "alice"]).is_err());
}
