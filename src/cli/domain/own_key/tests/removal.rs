//! Removing a domain, or an alias, takes its `[[dkim.domain]]` entry with it,
//! and leaves the other domains' entries and the key files alone.

use std::io::Write;
use std::path::Path;

use super::*;

fn fixture(dir: &Path, extra: &str) -> tempfile::NamedTempFile {
	let data = dir.canonicalize().unwrap();
	for name in ["default.pem", "other.pem", "alias.pem"] {
		let (pem, _) = crate::dkim::generate_key().unwrap();
		std::fs::write(data.join(name), pem).unwrap();
	}
	let mut file = tempfile::NamedTempFile::new_in(dir).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\n\
		 domains = [\"example.org\", \"other.example.org\"]\n\
		 [domain_aliases]\n\"alias.example.org\" = \"example.org\"\n\
		 [dkim]\nselector = \"s1\"\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = \"other.example.org\"\nselector = \"o1\"\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = \"alias.example.org\"\nselector = \"a1\"\nkey_file = {:?}\n{extra}",
		data.join("default.pem"),
		data.join("other.pem"),
		data.join("alias.pem"),
	)
	.unwrap();
	file.flush().unwrap();
	file
}

fn names(document: &ConfigDocument) -> Vec<String> {
	let dkim = document.config().expect("valid").dkim.expect("dkim");
	dkim.domain.iter().map(|d| d.name.clone()).collect()
}

#[test]
fn removing_a_domain_drops_only_its_entry() {
	let dir = tempfile::tempdir().unwrap();
	let file = fixture(dir.path(), "");
	let config = Config::load(file.path()).unwrap();
	let mut document = ConfigDocument::open(file.path()).unwrap();
	crate::cli::domain::remove_domain(&config, &mut document, "Other.example.org")
		.expect("the domain is removed");
	assert_eq!(names(&document), vec!["alias.example.org"]);
	assert!(dir.path().join("other.pem").exists(), "the key file stays");
}

#[test]
fn removing_an_alias_drops_only_its_entry() {
	let dir = tempfile::tempdir().unwrap();
	let file = fixture(dir.path(), "");
	let config = Config::load(file.path()).unwrap();
	let mut document = ConfigDocument::open(file.path()).unwrap();
	crate::cli::domain::remove_alias_map(&config, &mut document, "alias.example.org")
		.expect("the alias is removed");
	assert_eq!(names(&document), vec!["other.example.org"]);
}

#[test]
fn a_domain_without_an_entry_removes_nothing_else() {
	let dir = tempfile::tempdir().unwrap();
	let file = fixture(dir.path(), "");
	let mut document = ConfigDocument::open(file.path()).unwrap();
	drop_entry(&mut document, "nobody.example.org").expect("nothing to drop");
	assert_eq!(names(&document).len(), 2);
}
