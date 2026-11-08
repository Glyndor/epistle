//! `epistle dkim cleanup` with the certificates container on: the process
//! that holds the DKIM keys holds no DNS credential, so it cannot read the
//! zone. The TXT records are not checked, and the command says so and fails
//! instead of promising a removal that will not happen.

use super::*;
use std::pin::Pin;

use crate::dkim::rotate::{CLEANUP_FILE, RotationState, STATE_FILE};
use crate::dns::handoff::{HandoffProvider, Writer};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A zone the operator's own credential reads: the records it holds.
struct Listed(Vec<&'static str>);

impl DnsProvider for Listed {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim cleanup must not publish anything")
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim cleanup must leave removal to the server")
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		let records = self
			.0
			.iter()
			.map(|name| DnsRecord {
				name: (*name).to_string(),
				kind: RecordKind::Txt,
				value: "v=DKIM1; k=ed25519; p=AAAA".into(),
				ttl: 300,
				proxied: None,
			})
			.collect();
		Box::pin(async move { Ok(records) })
	}
}

/// A configuration with one orphan key file and one orphan TXT record.
fn config(dir: &std::path::Path) -> Config {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.join("dkim-ed100.key"), &pem).expect("active key");
	std::fs::write(dir.join("dkim-ed5.key"), &pem).expect("orphan key");
	let state = RotationState {
		selector: "ed100".into(),
		key_file: dir.join("dkim-ed100.key"),
		rotated_at: 1,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		dir.join(STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("state");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n\
		 [dkim]\nselector = 's1'\nkey_file = {:?}\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'secret'\n",
		dir.join("configured.key")
	))
	.expect("config")
}

/// The provider the server that removes the leftovers holds when the
/// certificates container runs: the hand-off, which cannot read the zone.
fn handoff_provider(data_dir: &std::path::Path) -> (HandoffProvider, std::path::PathBuf) {
	let dir = crate::dns::handoff::dir(data_dir);
	(HandoffProvider::new(Writer::at(dir.clone())), dir)
}

#[test]
fn the_txt_records_are_not_checked_and_the_command_fails() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let (provider, handoff) = handoff_provider(&config.data_dir);
	let mut out = Vec::new();
	let code = cleanup_with(
		&config,
		&DnsWrite::Handoff(handoff),
		Some(&provider),
		false,
		true,
		false,
		&mut out,
	);
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(code, ExitCode::FAILURE, "{text}");
	assert!(
		text.contains("TXT records not checked"),
		"the operator is told the records were not checked: {text}"
	);
	assert!(
		!text.contains("the running server removes what is still unused"),
		"nothing is promised that cannot happen: {text}"
	);
	// The key files are still queued: the server removes them.
	assert!(
		dir.path().join(CLEANUP_FILE).exists(),
		"the cleanup request is written"
	);
}

#[test]
fn the_json_says_the_records_were_not_checked() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let (provider, handoff) = handoff_provider(&config.data_dir);
	let mut out = Vec::new();
	let code = cleanup_with(
		&config,
		&DnsWrite::Handoff(handoff),
		Some(&provider),
		false,
		true,
		true,
		&mut out,
	);
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(text.lines().count(), 1, "not one line of JSON: {text}");
	let json: serde_json::Value = serde_json::from_str(&text).expect("json");
	assert_eq!(code, ExitCode::FAILURE, "{text}");
	assert_eq!(json["result"], "failed", "{text}");
	assert!(
		json["records_unchecked"]
			.as_str()
			.is_some_and(|reason| reason.contains("no DNS credential")),
		"the field says why the records were not checked: {text}"
	);
	assert_eq!(json["records"], serde_json::json!([]), "{text}");
	assert_eq!(
		json["key_files"],
		serde_json::json!([dir.path().join("dkim-ed5.key").display().to_string()]),
		"{text}"
	);
}

#[test]
fn a_dry_run_says_the_records_were_not_checked_too() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let (provider, handoff) = handoff_provider(&config.data_dir);
	let mut out = Vec::new();
	let code = cleanup_with(
		&config,
		&DnsWrite::Handoff(handoff),
		Some(&provider),
		true,
		true,
		false,
		&mut out,
	);
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(code, ExitCode::FAILURE, "{text}");
	assert!(text.contains("TXT records not checked"), "{text}");
	assert!(!dir.path().join(CLEANUP_FILE).exists(), "nothing changed");
}

/// The same installation without the split: the zone is read, the records
/// are found, and the command queues their removal.
#[test]
fn without_the_split_the_records_are_checked_and_queued() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let zone = vec![
		"ed100._domainkey.example.org.",
		"ed5._domainkey.example.org.",
		"s1._domainkey.example.org.",
	];
	let mut out = Vec::new();
	let code = cleanup_with(
		&config,
		&DnsWrite::Direct,
		Some(&Listed(zone)),
		false,
		true,
		false,
		&mut out,
	);
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(code, ExitCode::SUCCESS, "{text}");
	assert!(
		text.contains("delete TXT ed5._domainkey.example.org"),
		"{text}"
	);
	assert!(!text.contains("TXT records not checked"), "{text}");
	assert!(dir.path().join(CLEANUP_FILE).exists());
}
