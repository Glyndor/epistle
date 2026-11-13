//! `epistle domain add` and `remove` and the domain's own SRS secret.

use std::io::Write;

use super::writers::{commit_add, commit_remove};
use super::*;
use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;
use crate::test_support::fixtures::fresh_secret;

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

fn add(path: &std::path::Path, domain: &str) -> Config {
	let config = Config::load(path).unwrap();
	let mut document = ConfigDocument::open(path).unwrap();
	add_domain(&config, &mut document, domain).expect("add must succeed");
	let _ = commit_add(
		&config,
		document,
		domain,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit must succeed");
	Config::load(path).unwrap()
}

#[test]
fn a_new_domain_gets_a_secret_of_its_own_that_no_other_domain_has() {
	let global = fresh_secret();
	let (_dir, file) = fixture(&format!("srs_secret = \"{global}\""));
	let config = add(file.path(), "new.example.org");
	let entry = config.srs_domain("new.example.org").expect("an entry");
	assert_eq!(entry.secret.len(), 43, "a generated secret");
	assert_ne!(entry.secret, global);
	// A second domain gets another, and the file still loads.
	let config = add(file.path(), "third.example.org");
	let first = config.srs_domain("new.example.org").unwrap().secret.clone();
	let second = config
		.srs_domain("third.example.org")
		.unwrap()
		.secret
		.clone();
	assert_ne!(first, second, "two domains got the same secret");
}

#[test]
fn a_dry_run_add_prints_no_secret() {
	let (_dir, file) = fixture("");
	let config = Config::load(file.path()).unwrap();
	let mut document = ConfigDocument::open(file.path()).unwrap();
	add_domain(&config, &mut document, "new.example.org").unwrap();
	let diff = document.dry_run().unwrap();
	assert!(diff.contains("srs_domain"), "{diff}");
	let written = document.render();
	let secret = written
		.lines()
		.find_map(|line| line.strip_prefix("secret = \""))
		.and_then(|rest| rest.strip_suffix('"'))
		.expect("a secret was generated");
	assert!(!diff.contains(secret), "the dry run printed the secret");
}

#[test]
fn removing_a_domain_removes_its_secret() {
	let (_dir, file) = fixture("");
	add(file.path(), "other.example.org");
	let config = Config::load(file.path()).unwrap();
	assert!(config.srs_domain("other.example.org").is_some());
	let mut document = ConfigDocument::open(file.path()).unwrap();
	remove_domain(&config, &mut document, "other.example.org").expect("remove");
	let _ = commit_remove(
		document,
		"other.example.org",
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.expect("commit");
	let after = Config::load(file.path()).unwrap();
	assert!(after.srs_domain("other.example.org").is_none());
}
