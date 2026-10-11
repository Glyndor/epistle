//! `epistle antispam add|remove`: list membership for the three DNSBL
//! keys, leaving unrelated keys untouched.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::cli::config_edit::ConfigDocument;
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

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

fn open(path: &Path) -> ConfigDocument {
	ConfigDocument::open(path).expect("config document must open")
}

#[test]
fn add_appends_a_value_to_each_dnsbl_list() {
	for (key, field) in [
		(Key::DnsblZones, "dnsbl_zones"),
		(Key::DnsblDomainZones, "dnsbl_domain_zones"),
		(Key::DnsblUrlZones, "dnsbl_url_zones"),
	] {
		let (_dir, file) = fixture("");
		let mut document = open(file.path());
		apply_add(&mut document, key, "zen.spamhaus.org").expect("add must succeed");
		document.commit().expect("commit must succeed");
		let config = load(file.path());
		let list = match field {
			"dnsbl_zones" => &config.dnsbl_zones,
			"dnsbl_domain_zones" => &config.dnsbl_domain_zones,
			"dnsbl_url_zones" => &config.dnsbl_url_zones,
			_ => unreachable!(),
		};
		assert_eq!(list, &vec!["zen.spamhaus.org".to_string()], "{key:?}");
	}
}

#[test]
fn add_is_idempotent_and_reports_no_change() {
	let (_dir, file) = fixture("dnsbl_zones = [\"zen.spamhaus.org\"]\n");
	let mut document = open(file.path());
	apply_add(&mut document, Key::DnsblZones, "zen.spamhaus.org").expect("add must succeed");
	let outcome = document.commit().expect("commit must succeed");
	assert_eq!(outcome, crate::cli::config_edit::Outcome::Unchanged);
}

#[test]
fn remove_drops_only_the_matching_value() {
	let (_dir, file) = fixture(
		"dnsbl_zones = [\"a.example\", \"b.example\", \"c.example\"]\ndnsbl_domain_zones = [\"x.example\"]\n",
	);
	let mut document = open(file.path());
	apply_list_remove(&mut document, Key::DnsblZones, "b.example").expect("remove must succeed");
	document.commit().expect("commit must succeed");
	let config = load(file.path());
	assert_eq!(
		config.dnsbl_zones,
		vec!["a.example".to_string(), "c.example".to_string()]
	);
	assert_eq!(config.dnsbl_domain_zones, vec!["x.example".to_string()]);
}

#[test]
fn add_refuses_a_scalar_key() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	let err = apply_add(&mut document, Key::GreylistDelay, "10").unwrap_err();
	assert!(
		err.contains("not a list"),
		"the add path must reject scalar keys: {err}"
	);
}

#[test]
fn remove_refuses_a_scalar_key() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	let err = apply_list_remove(&mut document, Key::ClamdOnFound, "reject").unwrap_err();
	assert!(
		err.contains("not a list"),
		"the remove path must reject scalar keys: {err}"
	);
}

#[test]
fn unset_refuses_a_list_key() {
	let (_dir, file) = fixture("");
	let mut document = open(file.path());
	let err = apply_unset(&mut document, Key::DnsblZones).unwrap_err();
	assert!(
		err.contains("is a list"),
		"unset must refuse list keys: {err}"
	);
}
