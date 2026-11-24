//! `epistle dkim cleanup` asks before it queues the removal of keys and
//! records: `--yes` skips the question, a run with nobody to ask is refused,
//! and a dry run never asks.

use super::*;
use std::pin::Pin;

use crate::cli::prompt::script::scripted;
use crate::dkim::rotate::{CLEANUP_FILE, RotationState, STATE_FILE};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A zone that lists the DKIM records of the active key and of an old one.
struct Zone;

impl DnsProvider for Zone {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim cleanup must not publish anything")
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim cleanup must leave removal to the server")
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		let records = [
			"ed100._domainkey.example.org.",
			"ed5._domainkey.example.org.",
		]
		.into_iter()
		.map(|name| DnsRecord {
			name: name.to_string(),
			kind: RecordKind::Txt,
			value: "v=DKIM1; k=ed25519; p=AAAA".into(),
			ttl: 300,
			proxied: None,
		})
		.collect();
		Box::pin(async move { Ok(records) })
	}
}

/// A configuration whose active key is `ed100` and which also holds an
/// unused `ed5` key file and record.
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
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n[dkim]\nselector = 's1'\nkey_file = {:?}\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'secret'\n",
		dir.join("configured.key")
	))
	.expect("config")
}

fn run(config: &Config, dry_run: bool, yes: bool) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = cleanup_with(
		config,
		&DnsWrite::Direct,
		Some(&Zone),
		dry_run,
		yes,
		false,
		&mut out,
	);
	(code, String::from_utf8(out).expect("utf-8"))
}

#[test]
fn off_a_terminal_without_yes_nothing_is_queued() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let (code, text) = run(&config, false, false);
	assert_eq!(code, ExitCode::from(2), "{text}");
	assert!(!dir.path().join(CLEANUP_FILE).exists());
	assert!(dir.path().join("dkim-ed5.key").exists());
}

#[test]
fn a_no_at_the_question_queues_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let run = scripted(true, None, "n\n", || run(&config, false, false));
	assert_ne!(run.value.0, ExitCode::SUCCESS);
	assert!(run.stderr.contains("cancelled"), "{}", run.stderr);
	assert!(!dir.path().join(CLEANUP_FILE).exists());
}

#[test]
fn a_yes_at_the_question_queues_the_request() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let run = scripted(true, None, "y\n", || run(&config, false, false));
	assert_eq!(run.value.0, ExitCode::SUCCESS, "{}", run.value.1);
	assert!(
		run.stderr
			.contains("Ask the server to remove 1 key file(s) and 1 TXT record(s)?"),
		"{}",
		run.stderr
	);
	assert!(dir.path().join(CLEANUP_FILE).exists());
	assert!(
		dir.path().join("dkim-ed5.key").exists(),
		"the server removes it"
	);
}

#[test]
fn a_dry_run_does_not_ask_and_queues_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let run = scripted(true, None, "", || run(&config, true, false));
	assert_eq!(run.value.0, ExitCode::SUCCESS);
	assert!(run.stderr.is_empty(), "{}", run.stderr);
	assert!(!dir.path().join(CLEANUP_FILE).exists());
}
