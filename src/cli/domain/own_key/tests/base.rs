//! `domain add` gives the new domain a DKIM key of its own.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::dkim::Signer;

const NOW: u64 = 20_000 * 86_400;

/// A configuration with `example.org`, a default key file `DEFAULT` that
/// the tests refer to, and `dkim` appended.
fn fixture(dkim: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().canonicalize().unwrap();
	let (pem, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(data.join("default.pem"), pem).unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [\"example.org\"]\n{}",
		dkim.replace("DEFAULT", &data.join("default.pem").to_string_lossy())
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

const DKIM: &str = "[dkim]\nselector = \"s1\"\nkey_file = \"DEFAULT\"\n";

fn document(path: &Path) -> (Config, ConfigDocument) {
	let config = Config::load(path).expect("config loads");
	let document = ConfigDocument::open(path).expect("document opens");
	(config, document)
}

/// `domain add` as the dispatch runs it: the domain joins `domains`, then
/// gets its key.
fn add(
	config: &Config,
	document: &mut ConfigDocument,
	name: &str,
	mode: (bool, bool),
) -> Vec<std::path::PathBuf> {
	crate::cli::domain::add_domain(config, document, name).expect("the domain is added");
	give(config, document, name, mode, NOW).expect("the key is made")
}

/// The day the file was written: the day the selector is named after.
fn file_day(file: &Path) -> u64 {
	let modified = std::fs::metadata(file).unwrap().modified().unwrap();
	modified
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		/ 86_400
}

fn public(file: &Path) -> String {
	Signer::load("x", file).expect("loads").dns_record_value()
}

#[test]
fn a_new_domain_gets_a_key_of_its_own_and_an_entry_that_names_it() {
	let (dir, file) = fixture(DKIM);
	let (config, mut document) = document(file.path());
	let created = add(&config, &mut document, "New.Example.org", (false, false));
	assert_eq!(created.len(), 1, "one key file is made");
	let dkim = document
		.config()
		.expect("the edit validates")
		.dkim
		.expect("dkim");
	let entry = dkim.override_for("new.example.org").expect("an entry");
	assert_eq!(entry.selector, format!("own{}", file_day(&entry.key_file)));
	assert_ne!(
		public(&entry.key_file),
		public(&dir.path().canonicalize().unwrap().join("default.pem")),
		"the key is not the default one"
	);
	assert!(entry.rsa_selector.is_none(), "no RSA without dual signing");
}

#[test]
fn dual_signing_defaults_get_an_rsa_key_for_the_domain_too() {
	// The default RSA key is a fixture file of the crate.
	let rsa = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dkim/test_rsa_key.pem");
	let (_dir, file) = fixture(&format!(
		"{DKIM}rsa_selector = \"s2\"\nrsa_key_file = {:?}\n",
		rsa.display().to_string()
	));
	let (config, mut document) = document(file.path());
	add(&config, &mut document, "new.example.org", (false, false));
	let dkim = document
		.config()
		.expect("the edit validates")
		.dkim
		.expect("dkim");
	let entry = dkim.override_for("new.example.org").expect("an entry");
	let rsa_file = entry.rsa_key_file.as_ref().expect("rsa file");
	assert!(rsa_file.is_file());
	assert_eq!(
		entry.rsa_selector.as_deref(),
		Some(format!("ownrsa{}", file_day(rsa_file)).as_str())
	);
}

#[test]
fn the_shared_flag_leaves_the_domain_on_the_default_key() {
	let (dir, file) = fixture(DKIM);
	let (config, mut document) = document(file.path());
	let created = add(&config, &mut document, "new.example.org", (true, false));
	assert!(created.is_empty());
	let dkim = document.config().expect("valid").dkim.expect("dkim");
	assert!(dkim.domain.is_empty(), "no entry");
	assert!(!dir.path().join("keys").exists(), "no key directory");
}

#[test]
fn without_dkim_nothing_is_made() {
	let (dir, file) = fixture("");
	let (config, mut document) = document(file.path());
	let created = add(&config, &mut document, "new.example.org", (false, false));
	assert!(created.is_empty());
	assert!(!dir.path().join("keys").exists());
}

#[test]
fn a_dry_run_names_the_key_and_writes_nothing() {
	let (dir, file) = fixture(DKIM);
	let (config, mut document) = document(file.path());
	let created = add(&config, &mut document, "new.example.org", (false, true));
	assert!(created.is_empty(), "a dry run writes no file");
	assert!(
		!dir.path().join("keys").exists(),
		"and creates no directory"
	);
	let diff = document.dry_run().expect("the diff");
	assert!(diff.contains("[[dkim.domain]]"), "{diff}");
	assert!(diff.contains("own20000"), "{diff}");
}

#[test]
fn two_domains_added_one_after_the_other_never_share_a_key() {
	let (_dir, file) = fixture(DKIM);
	let (config, mut document) = document(file.path());
	add(&config, &mut document, "a.example.org", (false, false));
	// The second `add_domain` reads the domains from the config it is given.
	let config = Config::parse_text(&document.render(), file.path()).expect("valid");
	add(&config, &mut document, "b.example.org", (false, false));
	let dkim = document.config().expect("valid").dkim.expect("dkim");
	let a = dkim.override_for("a.example.org").expect("a entry");
	let b = dkim.override_for("b.example.org").expect("b entry");
	assert_ne!(public(&a.key_file), public(&b.key_file));
}
