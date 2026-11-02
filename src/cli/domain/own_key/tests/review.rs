//! Cases an independent review found: a new selector that collides with the
//! shared key's, keys deleted after the entry reached the file, and the
//! records printed for a domain that stays on a rotated key.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::cli::domain::writers::{add_commit, commit};

fn fixture(dkim_extra: &str, selector: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().canonicalize().unwrap();
	let (pem, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(data.join("default.pem"), pem).unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [\"example.org\"]\n\
		 [dkim]\nselector = \"{selector}\"\nkey_file = {:?}\n{dkim_extra}",
		data.join("default.pem")
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn today() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		/ 86_400
}

fn open(path: &Path) -> (Config, ConfigDocument) {
	(
		Config::load(path).expect("loads"),
		ConfigDocument::open(path).expect("opens"),
	)
}

#[test]
fn a_selector_the_shared_key_publishes_is_never_taken_for_the_new_key() {
	let shared = format!("own{}", today());
	let (_dir, file) = fixture("", &shared);
	let (config, mut document) = open(file.path());
	crate::cli::domain::add_domain(&config, &mut document, "new.example.org").unwrap();
	give(
		&config,
		&mut document,
		"new.example.org",
		(false, false),
		today() * 86_400,
	)
	.unwrap();
	let dkim = document.config().unwrap().dkim.unwrap();
	let entry = dkim.override_for("new.example.org").unwrap();
	assert_ne!(
		entry.selector, shared,
		"that record would replace the shared key's"
	);
	assert_eq!(entry.selector, format!("{shared}x2"));
}

#[test]
fn the_selector_a_rotation_put_in_service_is_reserved_too() {
	let (dir, file) = fixture("", "s1");
	let mut service = format!("own{}", today());
	service.push_str("");
	let (pem, _) = crate::dkim::generate_key().unwrap();
	let data = dir.path().canonicalize().unwrap();
	std::fs::write(data.join("dkim-service.key"), pem).unwrap();
	let state = serde_json::json!({
		"selector": service, "key_file": "dkim-service.key", "rotated_at": 1, "previous": null
	});
	std::fs::write(data.join("dkim-rotation.json"), state.to_string()).unwrap();
	let (config, mut document) = open(file.path());
	crate::cli::domain::add_domain(&config, &mut document, "new.example.org").unwrap();
	// A dry run names the same selector the real run would.
	give(
		&config,
		&mut document,
		"new.example.org",
		(false, true),
		today() * 86_400,
	)
	.unwrap();
	let dkim = document.config().unwrap().dkim.unwrap();
	assert_eq!(
		dkim.override_for("new.example.org").unwrap().selector,
		format!("{service}x2")
	);
}

/// A writer whose every write fails, like a closed pipe.
struct Broken;

impl Write for Broken {
	fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
		Err(std::io::Error::other("closed"))
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

#[test]
fn a_failure_after_the_entry_was_saved_leaves_the_keys_the_file_names() {
	let (_dir, file) = fixture("", "s1");
	let (config, mut document) = open(file.path());
	crate::cli::domain::add_domain(&config, &mut document, "new.example.org").unwrap();
	let created = give(&config, &mut document, "new.example.org", (false, false), 0).unwrap();
	assert_eq!(created.len(), 1);
	let mut status = Vec::new();
	let outcome = commit(
		document,
		add_commit("new.example.org"),
		(false, false),
		&mut Broken,
		&mut status,
	);
	assert!(
		outcome.is_err(),
		"printing the records failed after the save"
	);
	forget_unused(file.path(), "new.example.org", &created);
	assert!(
		created[0].is_file(),
		"the saved configuration still names this key"
	);
	let reloaded = Config::load(file.path()).expect("the configuration loads");
	assert!(
		reloaded
			.dkim
			.unwrap()
			.override_for("new.example.org")
			.is_some()
	);
}

#[test]
fn keys_made_for_an_edit_that_never_reached_the_file_are_removed() {
	let (_dir, file) = fixture("", "s1");
	let (config, mut document) = open(file.path());
	crate::cli::domain::add_domain(&config, &mut document, "new.example.org").unwrap();
	let created = give(&config, &mut document, "new.example.org", (false, false), 0).unwrap();
	// The document is dropped without a commit: the file never names the key.
	drop(document);
	forget_unused(file.path(), "new.example.org", &created);
	assert!(!created[0].exists());
}

#[test]
fn a_domain_left_on_the_shared_key_gets_the_records_of_the_key_in_service() {
	let rsa = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dkim/test_rsa_key.pem");
	let extra = format!(
		"rsa_selector = \"s2\"\nrsa_key_file = {:?}\n",
		rsa.display().to_string()
	);
	let (dir, file) = fixture(&extra, "s1");
	let data = dir.path().canonicalize().unwrap();
	let (ed, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(data.join("dkim-ed100.key"), ed).unwrap();
	std::fs::copy(&rsa, data.join("dkim-rsa100.key")).unwrap();
	let state = serde_json::json!({
		"selector": "ed100", "key_file": "dkim-ed100.key", "rotated_at": 1, "previous": null,
		"rsa": { "selector": "rsa100", "key_file": "dkim-rsa100.key" }
	});
	std::fs::write(data.join("dkim-rotation.json"), state.to_string()).unwrap();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	crate::cli::domain::writers::print_domain_records(&config, "new.example.org", &mut out)
		.unwrap();
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("ed100._domainkey.new.example.org"), "{text}");
	assert!(text.contains("rsa100._domainkey.new.example.org"), "{text}");
	assert!(!text.contains("s1._domainkey.new.example.org"), "{text}");
}
