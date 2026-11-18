//! A new domain gets a DKIM key of its own and an SRS secret of its own.

use std::path::Path;

use super::super::super::file::StoredRole;
use super::super::super::tests::Fixture;
use super::super::add::{Signing, discard, prepare};
use super::*;

const NOW: u64 = 20_000 * 86_400;

fn with_dkim(extra: &str) -> Fixture {
	let fixture = Fixture::new("");
	let (pem, _) = crate::dkim::generate_key().unwrap();
	let default = fixture.data_dir.join("default.pem");
	std::fs::write(&default, pem).unwrap();
	fixture.write_config(
		"[\"example.org\"]",
		&format!("[dkim]\nselector = \"s1\"\nkey_file = {default:?}\n{extra}"),
	);
	fixture
}

fn public(file: &Path) -> String {
	crate::dkim::Signer::load("x", file)
		.expect("loads")
		.dns_record_value()
}

fn added(fixture: &Fixture, name: &str, signing: Signing) -> super::super::add::Prepared {
	let prepared = prepare(
		&fixture.load(),
		name,
		StoredRole::Full,
		(signing, false),
		NOW,
	)
	.unwrap();
	commit(&fixture.load(), &prepared.change).unwrap();
	prepared
}

#[test]
fn a_new_domain_gets_a_key_and_a_secret_of_its_own() {
	let fixture = with_dkim("");
	let first = added(&fixture, "a.example", Signing::OwnKey);
	let second = added(&fixture, "b.example", Signing::OwnKey);
	assert_eq!((first.created.len(), second.created.len()), (1, 1));
	let config = fixture.load();
	let dkim = config.dkim.as_ref().unwrap();
	let a = dkim.override_for("a.example").expect("an override");
	let b = dkim.override_for("b.example").expect("an override");
	assert!(a.selector.starts_with("own"), "{}", a.selector);
	assert_ne!(public(&a.key_file), public(&b.key_file));
	assert_ne!(
		public(&a.key_file),
		public(&fixture.data_dir.join("default.pem"))
	);
	let secret = |name| config.srs_domain(name).map(|entry| entry.secret.clone());
	assert!(secret("a.example").is_some());
	assert_ne!(secret("a.example"), secret("b.example"));
}

#[test]
fn dual_signing_gives_the_domain_an_rsa_key_too() {
	let rsa = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dkim/test_rsa_key.pem");
	let fixture = with_dkim(&format!(
		"rsa_selector = \"s2\"\nrsa_key_file = {:?}\n",
		rsa.display().to_string()
	));
	let prepared = added(&fixture, "a.example", Signing::OwnKey);
	assert_eq!(prepared.created.len(), 2);
	let config = fixture.load();
	let entry = config
		.dkim
		.as_ref()
		.unwrap()
		.override_for("a.example")
		.unwrap();
	assert!(
		entry
			.rsa_key_file
			.as_ref()
			.is_some_and(|file| file.is_file())
	);
	assert!(
		entry
			.rsa_selector
			.as_deref()
			.is_some_and(|s| s.starts_with("ownrsa"))
	);
}

#[test]
fn the_shared_key_and_a_server_without_dkim_make_no_key() {
	let fixture = with_dkim("");
	let shared = added(&fixture, "a.example", Signing::SharedKey);
	assert!(shared.created.is_empty());
	assert!(
		fixture
			.load()
			.dkim
			.unwrap()
			.override_for("a.example")
			.is_none()
	);
	let plain = Fixture::new("");
	let prepared = added(&plain, "a.example", Signing::OwnKey);
	assert!(prepared.created.is_empty());
	assert!(!plain.data_dir.join("keys").exists());
}

#[test]
fn a_dry_run_names_the_key_and_writes_no_file() {
	let fixture = with_dkim("");
	let prepared = prepare(
		&fixture.load(),
		"a.example",
		StoredRole::Full,
		(Signing::OwnKey, true),
		NOW,
	)
	.unwrap();
	assert!(prepared.created.is_empty());
	assert!(prepared.selector.is_some_and(|s| s.starts_with("own")));
	assert!(!fixture.data_dir.join("keys").exists());
}

#[test]
fn a_key_whose_entry_never_reached_the_file_is_removed() {
	let fixture = with_dkim("");
	let prepared = prepare(
		&fixture.load(),
		"a.example",
		StoredRole::Full,
		(Signing::OwnKey, false),
		NOW,
	)
	.unwrap();
	assert!(prepared.created.iter().all(|file| file.is_file()));
	discard(&prepared);
	assert!(prepared.created.iter().all(|file| !file.exists()));
}

#[test]
fn a_domain_the_configuration_file_already_keys_gets_no_second_key() {
	let fixture = with_dkim("");
	let (pem, _) = crate::dkim::generate_key().unwrap();
	let own = fixture.data_dir.join("own.pem");
	std::fs::write(&own, pem).unwrap();
	let default = fixture.data_dir.join("default.pem");
	fixture.write_config(
		"[\"example.org\", \"old.example\"]",
		&format!(
			"[dkim]\nselector = \"s1\"\nkey_file = {default:?}\n\
			 [[dkim.domain]]\nname = \"old.example\"\nselector = \"o1\"\nkey_file = {own:?}\n"
		),
	);
	commit(
		&fixture.load(),
		&Change::Remove {
			name: "old.example".into(),
		},
	)
	.unwrap();
	let again = added(&fixture, "old.example", Signing::OwnKey);
	assert!(again.created.is_empty(), "the configured key is used again");
	assert_eq!(
		fixture
			.load()
			.dkim
			.unwrap()
			.override_for("old.example")
			.unwrap()
			.selector,
		"o1"
	);
}
