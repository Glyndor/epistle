//! The role of a domain: how `domain add --send-only` and `domain set
//! --send-only|--full` write it, and how `list`, `show` and the printed
//! records show it.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::cli::Cli;
use crate::config::Config;
use crate::dns::skip::DomainRole;

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\", \"example.net\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn document(path: &Path) -> ConfigDocument {
	ConfigDocument::open(path).expect("document opens")
}

fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
	let mut full = vec!["epistle", "domain"];
	full.extend_from_slice(argv);
	<Cli as clap::Parser>::try_parse_from(full)
}

#[test]
fn a_domain_is_full_unless_the_file_says_otherwise() {
	let (_dir, file) = fixture("");
	let config = Config::load(file.path()).expect("config");
	assert_eq!(config.domain_role("example.org"), DomainRole::Full);
}

#[test]
fn set_send_only_writes_the_role_and_set_full_takes_it_back() {
	let (_dir, file) = fixture("");
	let mut doc = document(file.path());
	set::Change::parse((None, false), (None, false))
		.unwrap()
		.with_role(Some(DomainRole::SendOnly))
		.apply(&mut doc, "example.net")
		.unwrap();
	let config = doc.config().expect("valid");
	assert_eq!(config.domain_role("example.net"), DomainRole::SendOnly);
	assert_eq!(config.domain_role("example.org"), DomainRole::Full);
	set::Change::parse((None, false), (None, false))
		.unwrap()
		.with_role(Some(DomainRole::Full))
		.apply(&mut doc, "example.net")
		.unwrap();
	assert_eq!(
		doc.config().unwrap().domain_role("example.net"),
		DomainRole::Full
	);
}

#[test]
fn set_without_a_role_leaves_it_alone() {
	let (_dir, file) = fixture("send_only_domains = [\"example.net\"]");
	let mut doc = document(file.path());
	set::Change::parse((Some("1G"), false), (None, false))
		.unwrap()
		.apply(&mut doc, "example.net")
		.unwrap();
	assert_eq!(
		doc.config().unwrap().domain_role("example.net"),
		DomainRole::SendOnly
	);
}

#[test]
fn removing_a_domain_drops_its_role() {
	let (_dir, file) = fixture("send_only_domains = [\"example.net\"]");
	let config = Config::load(file.path()).expect("config");
	let mut doc = document(file.path());
	remove_domain(&config, &mut doc, "example.net").expect("removable");
	let after = doc.config().expect("still valid");
	assert!(after.send_only_domains.is_empty());
}

#[test]
fn the_commit_of_set_names_the_role() {
	let change = set::Change::parse((None, false), (None, false))
		.unwrap()
		.with_role(Some(DomainRole::SendOnly));
	assert_eq!(
		set::commit("example.net", &change).fields["role"],
		"send-only"
	);
}

#[test]
fn list_and_show_say_the_role() {
	let (_dir, file) = fixture("send_only_domains = [\"example.net\"]");
	let config = Config::load(file.path()).expect("config");
	let mut out = Vec::new();
	list(&config, true, &mut out).unwrap();
	let rows: serde_json::Value = serde_json::from_slice(&out).unwrap();
	assert_eq!(rows[0]["role"], "full");
	assert_eq!(rows[1]["role"], "send-only");
	let mut out = Vec::new();
	list(&config, false, &mut out).unwrap();
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("ROLE"), "{text}");
	assert!(text.contains("send-only"), "{text}");
	let mut out = Vec::new();
	show(&config, "example.net", false, &mut out).unwrap();
	assert!(
		String::from_utf8(out).unwrap().contains("role\tsend-only"),
		"show names the role"
	);
}

#[test]
fn the_records_printed_for_a_send_only_domain_are_the_core_ones() {
	let (_dir, file) = fixture("send_only_domains = [\"example.net\"]");
	let config = Config::load(file.path()).expect("config");
	let mut out = Vec::new();
	writers::print_domain_records(&config, "example.net", &mut out).unwrap();
	let text = String::from_utf8(out).unwrap();
	for kept in ["example.net 3600 IN MX", "_dmarc.example.net", "v=spf1"] {
		assert!(text.contains(kept), "{kept}: {text}");
	}
	for left_out in [
		"_mta-sts",
		"_smtp._tls",
		"autoconfig",
		"autodiscover",
		"SRV",
	] {
		assert!(!text.contains(left_out), "{left_out}: {text}");
	}
}

#[test]
fn the_flags_parse_and_set_needs_something_to_change() {
	assert!(parse(&["add", "example.com", "--send-only"]).is_ok());
	assert!(parse(&["set", "example.com", "--send-only"]).is_ok());
	assert!(parse(&["set", "example.com", "--full"]).is_ok());
	assert!(parse(&["set", "example.com", "--send-only", "--full"]).is_err());
	assert!(parse(&["set", "example.com"]).is_err());
}
