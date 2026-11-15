//! The DANE association is published only when the certificate it names is
//! the one that stays in service, and only in a zone the operator says is
//! signed (`[dns_publish] dane`).

use std::path::Path;

use super::*;
use crate::dns::provider::RecordKind;
use crate::dns::skip::SkipGroup;

/// Write a certificate and its key; return the TLSA value of the leaf.
fn write_pair(cert: &Path, key: &Path, name: &str) -> String {
	std::fs::create_dir_all(cert.parent().expect("parent")).expect("directory");
	let certified = rcgen::generate_simple_self_signed(vec![name.to_string()]).expect("pair");
	let pem = certified.cert.pem();
	std::fs::write(cert, &pem).expect("cert");
	std::fs::write(key, certified.signing_key.serialize_pem()).expect("key");
	crate::dns::records::tlsa_full_cert(&pem).expect("association")
}

fn config(dir: &Path, extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{extra}",
		dir
	))
	.expect("config")
}

/// A configuration with the `[tls]` pair at `keys/` and, when `acme`, the
/// `[acme]` section; returns it with the TLSA value of the `[tls]` pair.
fn with_static_pair(dir: &Path, acme: bool, dane: &str) -> (Config, String) {
	let cert = dir.join("keys/cert.pem");
	let value = write_pair(&cert, &dir.join("keys/key.pem"), "mail.example.org");
	let mut extra = format!(
		"[tls]\ncert_file = {cert:?}\nkey_file = {:?}\n{dane}",
		dir.join("keys/key.pem")
	);
	if acme {
		extra.push_str(
			"[acme]\ndirectory_url = 'https://acme.example/dir'\ndomains = ['mail.example.org']\n",
		);
	}
	(config(dir, &extra), value)
}

fn tlsa(desired: &Desired) -> Vec<String> {
	desired
		.records
		.iter()
		.filter(|r| r.record.kind == RecordKind::Tlsa)
		.map(|r| r.record.value.clone())
		.collect()
}

const DANE: &str = "[dns_publish]\ndane = true\n";

#[test]
fn without_acme_the_association_names_the_tls_pair() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, value) = with_static_pair(dir.path(), false, DANE);
	let desired = from_config(&config).expect("set");
	assert_eq!(tlsa(&desired), vec![value]);
	assert_eq!(desired.incomplete(), None);
}

#[test]
fn with_acme_the_association_names_the_issued_certificate() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, bootstrap) = with_static_pair(dir.path(), true, DANE);
	let issued = write_pair(
		&crate::acme::renew::cert_path(dir.path()),
		&crate::acme::renew::key_path(dir.path()),
		"mail.example.org",
	);
	assert_ne!(issued, bootstrap);
	let desired = from_config(&config).expect("set");
	assert_eq!(tlsa(&desired), vec![issued]);
	assert_eq!(desired.incomplete(), None);
}

#[test]
fn with_acme_and_only_the_bootstrap_pair_there_is_no_association_and_a_warning() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, _) = with_static_pair(dir.path(), true, DANE);
	let desired = from_config(&config).expect("set");
	assert!(tlsa(&desired).is_empty());
	let why = desired.incomplete().expect("the set is incomplete");
	assert!(why.contains("issued certificate"), "{why}");
}

#[test]
fn a_zone_not_declared_signed_does_not_hold_the_set_back_while_waiting_for_the_authority() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, _) = with_static_pair(dir.path(), true, "");
	let desired = from_config(&config).expect("set");
	assert!(tlsa(&desired).is_empty());
	assert_eq!(desired.incomplete(), None);
}

#[test]
fn an_unreadable_certificate_and_one_without_a_certificate_warn_and_give_no_association() {
	let dir = tempfile::tempdir().expect("directory");
	let cert = dir.path().join("cert.pem");
	let tls = |cert: &Path| {
		format!(
			"{DANE}[tls]\ncert_file = {cert:?}\nkey_file = {:?}\n",
			dir.path().join("key.pem")
		)
	};
	std::fs::write(&cert, "not a certificate").expect("cert");
	let desired = from_config(&config(dir.path(), &tls(&cert))).expect("set");
	assert!(tlsa(&desired).is_empty());
	assert!(desired.incomplete().expect("incomplete").contains("TLSA"));
	let missing = dir.path().join("absent.pem");
	let desired = from_config(&config(dir.path(), &tls(&missing))).expect("set");
	assert!(tlsa(&desired).is_empty());
	assert!(
		desired
			.incomplete()
			.expect("incomplete")
			.contains("cannot read certificate")
	);
}

#[test]
fn dane_off_keeps_the_record_out_and_reports_the_group_as_skipped() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, value) = with_static_pair(dir.path(), false, "");
	let desired = from_config(&config).expect("set");
	assert!(tlsa(&desired).is_empty());
	let group = desired
		.skipped
		.iter()
		.find(|s| s.group == SkipGroup::Tlsa)
		.expect("the tlsa group is reported apart");
	assert_eq!(group.records.len(), 1);
	assert_eq!(group.records[0].record.value, value);
}

#[test]
fn dane_on_puts_the_record_in_the_wanted_set() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, _) = with_static_pair(dir.path(), false, DANE);
	let desired = from_config(&config).expect("set");
	assert_eq!(tlsa(&desired).len(), 1);
	assert!(desired.skipped.iter().all(|s| s.group != SkipGroup::Tlsa));
}

#[test]
fn an_explicit_skip_of_tlsa_wins_over_dane() {
	let dir = tempfile::tempdir().expect("directory");
	let (config, _) = with_static_pair(
		dir.path(),
		false,
		"[dns_publish]\ndane = true\nskip = ['tlsa']\n",
	);
	let desired = from_config(&config).expect("set");
	assert!(tlsa(&desired).is_empty());
	assert!(desired.skipped.iter().any(|s| s.group == SkipGroup::Tlsa));
}
