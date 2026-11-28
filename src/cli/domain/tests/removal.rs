//! Removal blockers: the operator cannot drop a domain while any
//! account (static or dynamic), alias, masked address or `domain_aliases`
//! entry still uses it; the error names every offender.

use std::io::Write;
use std::path::Path;

use crate::config::Config;
use crate::domain::state::blockers::removal_blockers;

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

/// An account file the check cannot read is a reason to keep the domain, not a
/// file with nobody in it.
#[test]
fn removal_blockers_refuse_when_the_dynamic_accounts_file_cannot_be_read() {
	let (dir, file) = fixture("");
	let config = load(file.path());
	std::fs::write(dir.path().join("accounts.toml"), "[[accounts]]\nname = ").unwrap();
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("cannot be read"), "{err}");
	std::fs::write(dir.path().join("accounts.toml"), [0xff, 0xfe, 0x00]).unwrap();
	assert!(removal_blockers(&config, "example.org").is_err());
	// No file at all is no dynamic accounts.
	std::fs::remove_file(dir.path().join("accounts.toml")).unwrap();
	assert!(removal_blockers(&config, "example.org").is_ok());
}

/// The largest quota a request may set still leaves the file readable, so the
/// account it belongs to still keeps its domain.
#[test]
fn a_largest_quota_leaves_the_account_listed_as_using_its_domain() {
	use crate::directory_store::{AccountStore, DynamicAccount};
	let (dir, file) = fixture("");
	let config = load(file.path());
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.unwrap();
	store
		.add(DynamicAccount {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: "$argon2id$stub".to_string(),
			..DynamicAccount::default()
		})
		.unwrap();
	let most = crate::util::quota_size::parse_quota_size("8388607T")
		.unwrap()
		.unwrap();
	store.set_quota_bytes("alice", Some(most)).unwrap();
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("alice@example.org"), "{err}");
	// What the file cannot hold is refused before it is written.
	assert!(store.set_quota_bytes("alice", Some(u64::MAX)).is_err());
	assert!(removal_blockers(&config, "example.org").is_err());
	let err = removal_blockers(&config, "example.org").unwrap_err();
	assert!(err.contains("alice@example.org"), "{err}");
}
