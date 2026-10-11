//! `epistle domain alias add|remove`: edit the `domain_aliases` map.

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

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

#[test]
fn add_writes_a_new_domain_alias_entry() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	add_alias_map(&config, &mut document, "alias.example.org", "example.org")
		.expect("add must succeed");
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	super::domain_writers::commit_alias(
		document,
		"alias.example.org",
		"added",
		false,
		&mut out,
		&mut status,
	)
	.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		after.contains("alias.example.org"),
		"domain_aliases must contain the new entry: {after}"
	);
}

#[test]
fn add_refuses_an_unknown_target() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = add_alias_map(
		&config,
		&mut document,
		"alias.example.org",
		"missing.example.org",
	)
	.unwrap_err();
	assert!(
		err.contains("not a configured domain"),
		"unexpected message: {err}"
	);
}

#[test]
fn add_refuses_an_alias_that_collides_with_a_domain() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = add_alias_map(&config, &mut document, "example.org", "example.org").unwrap_err();
	assert!(
		err.contains("configured domain"),
		"unexpected message: {err}"
	);
}

#[test]
fn add_refuses_a_duplicate_alias_entry() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err =
		add_alias_map(&config, &mut document, "alias.example.org", "example.org").unwrap_err();
	assert!(
		err.contains("already declared"),
		"unexpected message: {err}"
	);
}

#[test]
fn add_refuses_a_malformed_alias_name() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = add_alias_map(&config, &mut document, "", "example.org").unwrap_err();
	assert!(
		err.contains("must not be empty"),
		"unexpected message: {err}"
	);
}

#[test]
fn remove_drops_an_existing_alias_entry() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	remove_alias_map(&config, &mut document, "alias.example.org").expect("remove must succeed");
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	super::domain_writers::commit_alias(
		document,
		"alias.example.org",
		"removed",
		false,
		&mut out,
		&mut status,
	)
	.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		!after.contains("alias.example.org"),
		"alias entry must be removed"
	);
}

#[test]
fn remove_refuses_an_unknown_alias_entry() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = remove_alias_map(&config, &mut document, "missing.example.org").unwrap_err();
	assert!(err.contains("not declared"), "unexpected message: {err}");
}
