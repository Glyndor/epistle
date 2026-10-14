//! Tests for `epistle dkim cleanup`: it lists what no rotation uses and
//! only queues the removal for the server.

use super::*;
use std::pin::Pin;

use crate::dkim::rotate::{CLEANUP_FILE, RotationState, STATE_FILE};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A zone that lists DKIM records under the given names and refuses writes:
/// the CLI must never write.
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
			})
			.collect();
		Box::pin(async move { Ok(records) })
	}
}

fn config(dir: &std::path::Path, dns: bool) -> Config {
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
	let dns = if dns {
		"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'secret'\n"
	} else {
		""
	};
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n[dkim]\nselector = 's1'\nkey_file = {:?}\n{dns}",
		dir.join("configured.key")
	))
	.expect("config")
}

const ZONE: [&str; 3] = [
	"ed100._domainkey.example.org.",
	"ed5._domainkey.example.org.",
	"s1._domainkey.example.org.",
];

fn run(config: &Config, provider: Option<&dyn DnsProvider>, dry_run: bool) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = cleanup_with(config, provider, dry_run, true, &mut out);
	(code, String::from_utf8(out).expect("utf-8"))
}

#[test]
fn dry_run_lists_only_what_no_rotation_uses() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), true);
	let (code, text) = run(&config, Some(&Listed(ZONE.to_vec())), true);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		text,
		format!(
			"remove key file {}\ndelete TXT ed5._domainkey.example.org\ndry run: nothing changed\n",
			dir.path().join("dkim-ed5.key").display()
		)
	);
	assert!(!dir.path().join(CLEANUP_FILE).exists());
	assert!(dir.path().join("dkim-ed5.key").exists());
}

#[test]
fn confirmed_cleanup_queues_a_request_and_removes_nothing_itself() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), true);
	let (code, text) = run(&config, Some(&Listed(ZONE.to_vec())), false);
	assert_eq!(code, ExitCode::SUCCESS, "{text}");
	assert!(text.contains("queued"), "{text}");
	assert!(dir.path().join(CLEANUP_FILE).exists());
	assert!(
		dir.path().join("dkim-ed5.key").exists(),
		"the server removes it"
	);
}

#[test]
fn nothing_unused_queues_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), true);
	std::fs::remove_file(dir.path().join("dkim-ed5.key")).expect("remove");
	let (code, text) = run(&config, Some(&Listed(vec![ZONE[0]])), false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(text, "nothing to clean up\n");
	assert!(!dir.path().join(CLEANUP_FILE).exists());
}

#[test]
fn without_a_provider_the_server_cannot_serve_it_so_nothing_is_queued() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), false);
	let (code, text) = run(&config, None, false);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		text.contains("TXT records not checked") && text.contains("dkim-ed5.key"),
		"{text}"
	);
	assert!(!dir.path().join(CLEANUP_FILE).exists());
}

#[test]
fn an_unreadable_state_refuses_to_guess() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), true);
	std::fs::write(dir.path().join(STATE_FILE), "{").expect("tear");
	let (code, text) = run(&config, Some(&Listed(ZONE.to_vec())), true);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(text.is_empty(), "{text}");
}
