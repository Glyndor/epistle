//! Removal blockers: the operator cannot drop a domain while any
//! account (static or dynamic), alias, masked address or `domain_aliases`
//! entry still uses it; the error names every offender.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::config::Config;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn fixture_domains(
	domains_line: &str,
	extra: &str,
) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n{domains_line}\n{extra}\n",
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
fn removal_blockers_list_a_static_account() {
	let (_dir, file) = fixture(
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n",
	);
	let config = load(file.path());
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("still in use"));
	assert!(err.contains("alice@example.org"));
}

#[test]
fn removal_blockers_list_an_alias() {
	let (_dir, file) =
		fixture("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n");
	let config = load(file.path());
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("team@example.org"));
}

#[test]
fn removal_blockers_list_a_member_outside_the_alias_address() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"someone@other.example.org\"]\n",
	);
	let config = load(file.path());
	let err = removal_blockers(&config, "other.example.org").unwrap_err();
	assert!(
		err.contains("someone@other.example.org"),
		"members must be listed: {err}"
	);
}

#[test]
fn removal_blockers_list_a_sender_outside_the_alias_address() {
	let (_dir, file) = fixture(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\nsenders = [\"ceo@other.example.org\"]\n",
	);
	let config = load(file.path());
	let err = removal_blockers(&config, "other.example.org").unwrap_err();
	assert!(
		err.contains("ceo@other.example.org"),
		"senders must be listed: {err}"
	);
}

#[test]
fn removal_blockers_list_a_domain_alias_source_and_target() {
	let (_dir, file) = fixture_domains(
		"domains = [\"example.org\", \"target.example.org\"]",
		"[domain_aliases]\n\"alias.example.org\" = \"target.example.org\"\n",
	);
	let config = load(file.path());
	let err_source = removal_blockers(&config, "alias.example.org").unwrap_err();
	assert!(err_source.contains("alias.example.org -> target.example.org"));
	let err_target = removal_blockers(&config, "target.example.org").unwrap_err();
	assert!(err_target.contains("domain_aliases"));
}

#[test]
fn removal_blockers_passes_when_no_user_references_the_domain() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	assert!(removal_blockers(&config, "example.org").is_ok());
}

#[test]
fn removal_blockers_list_a_masked_address() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let masked = config.data_dir.join("masked.json");
	std::fs::write(
		&masked,
		r#"{"addresses":{"alice.label.x12345678@example.org":{"account":"alice","label":"alice","created_at":1,"enabled":true}}}"#,
	)
	.unwrap();
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(
		err.contains("alice.label.x12345678@example.org"),
		"masked addresses must be listed: {err}"
	);
}

#[test]
fn removal_blockers_list_a_dynamic_account_address() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let accounts = config.data_dir.join("accounts.toml");
	std::fs::write(
		&accounts,
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n",
	)
	.unwrap();
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(
		err.contains("dynamic account alice uses alice@example.org"),
		"dynamic account addresses must be listed: {err}"
	);
}

#[test]
fn removal_blockers_tolerate_unreadable_or_malformed_sidecars() {
	// An unreadable accounts.toml or masked.json must not crash the
	// removal check; the operator gets a clean error mentioning the
	// statically-known offenders.
	let (_dir, file) = fixture(
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n",
	);
	let config = load(file.path());
	let accounts = config.data_dir.join("accounts.toml");
	std::fs::write(&accounts, "this is not valid TOML").unwrap();
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("alice@example.org"));
}
