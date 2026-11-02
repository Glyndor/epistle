//! The `dns` step of automatic mode publishes through the reconcile run and
//! never undoes the install when it cannot.

use std::sync::Arc;

use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::{DnsRecord, RecordKind};

const CONFIG: &str = "hostname = 'mail.example.org'\ndata_dir = {DIR}\ndomains = ['example.org']\n\
	[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_env = 'EPISTLE_TEST_UNSET_TOKEN'\n";

fn written(dir: &std::path::Path) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(&path, CONFIG.replace("{DIR}", &format!("{dir:?}"))).expect("config");
	// `Config::load` refuses a configuration others can read.
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
	path
}

#[test]
fn automatic_mode_publishes_the_records_and_keeps_the_ledger() {
	let dir = tempfile::tempdir().expect("directory");
	let path = written(dir.path());
	let zone = Arc::new(Zone::default());
	let provider = zone.clone();
	let lines = publish(
		&path,
		&|_: &Config| Some(provider.clone() as Arc<dyn DnsProvider>),
		1,
	);
	assert!(lines[0].starts_with("dns: "), "{lines:?}");
	let spf = DnsRecord::new("example.org", RecordKind::Txt, "v=spf1 mx -all", 3600);
	assert!(
		zone.snapshot()
			.iter()
			.any(|r| crate::dns::rrset::same_record(r, &spf)),
		"{lines:?}"
	);
	let ledger = store::load(dir.path(), "example.org").expect("ledger");
	assert!(ledger.owns(&spf));
}

#[test]
fn a_credential_that_cannot_be_read_leaves_the_install_and_says_what_to_run() {
	let dir = tempfile::tempdir().expect("directory");
	let path = written(dir.path());
	let lines = publish(&path, &|_: &Config| None, 1);
	assert_eq!(lines.len(), 1);
	assert!(lines[0].contains("epistle dns publish"), "{lines:?}");
}

#[test]
fn a_conflict_is_reported_and_the_foreign_record_stays() {
	let dir = tempfile::tempdir().expect("directory");
	let path = written(dir.path());
	let theirs = DnsRecord::new(
		"example.org",
		RecordKind::Txt,
		"v=spf1 include:_spf.example.net -all",
		3600,
	);
	let zone = Arc::new(Zone::with(vec![theirs.clone()]));
	let provider = zone.clone();
	let lines = publish(
		&path,
		&|_: &Config| Some(provider.clone() as Arc<dyn DnsProvider>),
		1,
	);
	assert!(
		lines
			.iter()
			.any(|l| l.starts_with("dns: conflict in example.org")),
		"{lines:?}"
	);
	assert!(zone.snapshot().contains(&theirs));
}
