//! `epistle domain`: list, show, add and remove flow on a fixture config.

use std::io::Write;
use std::path::Path;

use super::domain_blockers::address_domain_matches;
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

/// Same as `fixture` but lets the test supply its own `domains` line
/// instead of inheriting the bare `example.org` set.
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
fn list_writes_every_domain_with_alias_edges() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	let mut out: Vec<u8> = Vec::new();
	list(&config, false, &mut out).expect("list must succeed");
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("example.org"));
	assert!(text.contains("alias.example.org"));
}

#[test]
fn list_json_emits_an_array_with_alias_edges() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	let mut out: Vec<u8> = Vec::new();
	list(&config, true, &mut out).expect("list must succeed");
	let parsed: serde_json::Value = serde_json::from_slice(&out).expect("valid JSON");
	let rows = parsed.as_array().expect("array");
	assert_eq!(rows.len(), 1);
	let row = &rows[0];
	assert_eq!(row["domain"], "example.org");
	// aliases_from: domains this domain is the source of (empty here).
	let aliases_from = row["aliases_from"].as_array().expect("array");
	assert!(aliases_from.is_empty());
	// aliases_to: domains that point at this one, `alias.example.org`
	// targets `example.org`, so it appears here.
	let aliases_to = row["aliases_to"].as_array().expect("array");
	assert!(
		aliases_to
			.iter()
			.any(|v| v.as_str() == Some("alias.example.org")),
		"aliases_to must include the source: {row:?}"
	);
}

#[test]
fn show_prints_accounts_and_aliases_relying_on_the_domain() {
	let (_dir, file) = fixture(
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000\"\n\n[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n",
	);
	let config = load(file.path());
	let mut out: Vec<u8> = Vec::new();
	show(&config, "example.org", false, &mut out).expect("show must succeed");
	let text = String::from_utf8(out).unwrap();
	for needle in [
		"domain\texample.org",
		"accounts\talice@example.org",
		"aliases\tteam@example.org",
	] {
		assert!(
			text.contains(needle),
			"show must contain {needle:?}\n--- got ---\n{text}"
		);
	}
}

#[test]
fn show_refuses_an_unknown_domain() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let result = show(&config, "missing.example.org", false, &mut Vec::new());
	assert!(result.is_err(), "show must reject an unknown domain");
	let err = result.unwrap_err().to_string();
	assert!(err.contains("not configured"), "unexpected message: {err}");
}

#[test]
fn address_domain_matches_handles_malformed_addresses() {
	assert!(address_domain_matches("alice@example.org", "example.org"));
	assert!(!address_domain_matches("alice@example.org", "other.org"));
	assert!(!address_domain_matches("not-an-address", "example.org"));
}

#[test]
fn validate_domain_for_add_rejects_duplicates_and_alias_collisions() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	assert!(
		validate_domain_for_add(&config, "example.org")
			.unwrap_err()
			.contains("already configured")
	);
	assert!(
		validate_domain_for_add(&config, "alias.example.org")
			.unwrap_err()
			.contains("already declared")
	);
	assert!(validate_domain_for_add(&config, "new.example.org").is_ok());
	assert!(
		validate_domain_for_add(&config, "")
			.unwrap_err()
			.contains("must not be empty")
	);
}

#[test]
fn add_writes_the_new_domain_and_records_dns() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	add_domain(&config, &mut document, "new.example.org").expect("add must succeed");
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	commit_add(
		&config,
		document,
		"new.example.org",
		false,
		&mut out,
		&mut status,
	)
	.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		after.contains("new.example.org"),
		"file must list the new domain"
	);
	let out_text = String::from_utf8(out).unwrap();
	assert!(
		out_text.contains("new.example.org"),
		"add must print DNS records for the new domain: {out_text}"
	);
}

#[test]
fn add_refuses_a_duplicate_domain() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = add_domain(&config, &mut document, "example.org").unwrap_err();
	assert!(
		err.contains("already configured"),
		"unexpected message: {err}"
	);
}

#[test]
fn add_refuses_an_invalid_domain_name() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = add_domain(&config, &mut document, "").unwrap_err();
	assert!(
		err.contains("must not be empty"),
		"unexpected message: {err}"
	);
}

#[test]
fn remove_refuses_when_a_domain_alias_targets_the_domain() {
	let (_dir, file) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = remove_domain(&config, &mut document, "example.org").unwrap_err();
	assert!(err.contains("still in use"), "unexpected message: {err}");
}

#[test]
fn remove_succeeds_when_only_other_domains_point_at_the_target() {
	// `alias.example.org` points at `example.org`, but `other.example.org`
	// is independent; the operator should be able to drop it.
	let (_dir, file) = fixture_domains(
		"domains = [\"example.org\", \"other.example.org\"]",
		"[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n",
	);
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	remove_domain(&config, &mut document, "other.example.org").expect("remove must succeed");
	let mut out: Vec<u8> = Vec::new();
	let mut status: Vec<u8> = Vec::new();
	commit_remove(document, "other.example.org", false, &mut out, &mut status)
		.expect("commit must succeed");
	let after = std::fs::read_to_string(file.path()).unwrap();
	assert!(
		!after.contains("other.example.org"),
		"domain must be removed"
	);
	assert!(
		after.contains("example.org"),
		"the configured domain must survive"
	);
}

#[test]
fn remove_refuses_an_unknown_domain() {
	let (_dir, file) = fixture("");
	let config = load(file.path());
	let mut document = super::super::config_edit::ConfigDocument::open(file.path()).unwrap();
	let err = remove_domain(&config, &mut document, "missing.example.org").unwrap_err();
	assert!(err.contains("not configured"), "unexpected message: {err}");
}
