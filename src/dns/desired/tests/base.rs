//! The record set is computed once, from the configuration, and the
//! publisher reads the same set `dns-records` prints.

use super::*;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

fn names(desired: &Desired) -> Vec<String> {
	desired
		.records
		.iter()
		.map(|r| format!("{} {}", r.record.name, r.record.kind.as_str()))
		.collect()
}

#[test]
fn a_service_that_is_off_gets_no_locator_in_the_set() {
	let desired =
		from_config(&config("[[listeners]]\nkind = 'imaps'\n")).expect("the set is computed");
	let names = names(&desired);
	assert!(names.contains(&"_imaps._tcp.example.org SRV".to_string()));
	for absent in ["_pop3s", "_sieve", "_jmap", "_caldavs", "_carddavs"] {
		assert!(
			!names.iter().any(|n| n.starts_with(absent)),
			"{absent} is off and must have no locator: {names:?}"
		);
	}
}

#[test]
fn every_hosted_domain_gets_its_mail_records() {
	let desired = from_config(&config("")).expect("the set is computed");
	let names = names(&desired);
	for needed in [
		"example.org MX",
		"example.org TXT",
		"_dmarc.example.org TXT",
		"_mta-sts.example.org TXT",
		"_smtp._tls.example.org TXT",
		"mta-sts.example.org CNAME",
	] {
		assert!(
			names.contains(&needed.to_string()),
			"{needed} missing: {names:?}"
		);
	}
	assert!(desired.warnings.is_empty());
}

#[test]
fn a_rotation_state_that_cannot_be_read_stops_the_set() {
	let dir = tempfile::tempdir().expect("directory");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("original.key"), pem).expect("key file");
	std::fs::write(dir.path().join("dkim-rotation.json"), "invalid JSON").expect("state");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[dkim]\nselector = 'original'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("original.key")
	))
	.expect("config");
	let errors = from_config(&config).expect_err("a broken state must not fall back");
	assert_eq!(errors.len(), 1);
}
