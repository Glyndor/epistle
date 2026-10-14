//! `epistle alias enable|disable`: round-trips through the dynamic
//! `aliases.json` store, never touches `mail.toml`.

use std::io::Write;
use std::path::Path;

use super::alias_writers::set_enabled;
use super::*;
use crate::config::Config;

fn fixture_with_alias(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

#[test]
fn set_enabled_persists_the_disabled_flag_and_does_not_touch_the_config() {
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	set_enabled(&config, "team@example.org", false, &mut out, &mut status)
		.expect("disable must succeed");
	assert!(
		String::from_utf8(status.clone())
			.unwrap()
			.contains("disabled"),
		"status must say disabled: {:?}",
		String::from_utf8(status).unwrap()
	);
	assert_eq!(
		std::fs::read_to_string(file.path()).unwrap(),
		before,
		"enable/disable must not rewrite mail.toml"
	);
	// aliases.json was created with the address listed.
	let aliases_path = config.data_dir.join("aliases.json");
	let json = std::fs::read_to_string(&aliases_path).unwrap();
	assert!(
		json.contains("team@example.org"),
		"aliases.json must contain the disabled address: {json}"
	);
}

#[test]
fn set_enabled_is_idempotent() {
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	set_enabled(&config, "team@example.org", false, &mut out, &mut status)
		.expect("first disable must succeed");
	out.clear();
	status.clear();
	set_enabled(&config, "team@example.org", false, &mut out, &mut status)
		.expect("second disable must succeed");
	assert!(
		String::from_utf8(status).unwrap().contains("already"),
		"idempotent disable must say already disabled"
	);
}

#[test]
fn enable_restores_a_disabled_alias() {
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	set_enabled(&config, "team@example.org", false, &mut out, &mut status)
		.expect("disable must succeed");
	out.clear();
	status.clear();
	set_enabled(&config, "team@example.org", true, &mut out, &mut status)
		.expect("enable must succeed");
	let aliases_path = config.data_dir.join("aliases.json");
	let json = std::fs::read_to_string(&aliases_path).unwrap();
	assert!(
		!json.contains("team@example.org"),
		"enabled alias must be absent from the disabled list: {json}"
	);
}

#[test]
fn list_reflects_the_disabled_flag() {
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	set_enabled(
		&config,
		"team@example.org",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("disable must succeed");
	let mut out: Vec<u8> = Vec::new();
	list(&config, false, &mut out).expect("list must succeed");
	let text = String::from_utf8(out).unwrap();
	assert!(
		text.contains("disabled"),
		"list must mark a disabled alias as such: {text}"
	);
}

#[test]
fn enable_refuses_an_alias_not_in_the_config() {
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	let err = set_enabled(
		&config,
		"missing@example.org",
		true,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert!(
		err.as_ref().contains("not found"),
		"unexpected message: {err}"
	);
}

/// What the running server sees: a store opened on the same data dir, as the
/// file watcher rebuilds it, stops routing a disabled alias and routes it
/// again after `enable`, all without touching mail.toml.
#[test]
fn a_disabled_alias_stops_resolving_for_the_server_and_enable_restores_it() {
	use crate::smtp::address::Address;
	use crate::smtp::directory::Resolution;
	let (_dir, file) = fixture_with_alias("");
	let config = load(file.path());
	let resolves_as_alias = || {
		let store = crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			config.domain_aliases.clone(),
			config.accounts.clone(),
		)
		.expect("open store")
		.with_aliases(config.alias.clone());
		matches!(
			store
				.handle()
				.current()
				.resolve(&Address::parse("team@example.org").expect("address")),
			Resolution::Alias(_)
		)
	};
	assert!(resolves_as_alias(), "an enabled alias must resolve");
	set_enabled(
		&config,
		"team@example.org",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("disable");
	assert!(!resolves_as_alias(), "a disabled alias must not resolve");
	set_enabled(
		&config,
		"team@example.org",
		true,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("enable");
	assert!(resolves_as_alias(), "enable must restore the alias");
}
