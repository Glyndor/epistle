//! `epistle domain`: list, show, add and remove flow on a fixture config.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::config::Config;
use crate::domain::state::blockers::address_domain_matches;

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
