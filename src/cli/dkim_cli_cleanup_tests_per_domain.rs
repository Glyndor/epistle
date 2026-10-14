//! `epistle dkim cleanup` with a `[[dkim.domain]]` override: the override
//! is never rotated, so nothing in the rotation state names it, and its key
//! file and TXT record must still never be offered for removal.

use super::*;
use std::pin::Pin;

use crate::dkim::rotate::{RotationState, STATE_FILE};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

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

/// The default rotated to `ed100`; `example.net` signs with an override
/// whose key the operator kept from an earlier rotation (`ed5`), and
/// `ed7` is a real leftover.
fn config(dir: &std::path::Path) -> Config {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	for name in ["dkim-ed100.key", "dkim-ed5.key", "dkim-ed7.key"] {
		std::fs::write(dir.join(name), &pem).expect("key file");
	}
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
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 's1'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.net'\nselector = 'ed5'\nkey_file = {:?}\n\
		 [dns]\nprovider = 'cloudflare'\nzone = 'example.org'\n",
		dir.join("configured.key"),
		dir.join("dkim-ed5.key"),
	))
	.expect("config")
}

#[test]
fn an_override_key_and_record_are_never_offered_for_removal() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let zone = vec![
		"ed100._domainkey.example.org.",
		"ed7._domainkey.example.org.",
		"ed5._domainkey.example.net.",
	];
	let mut out = Vec::new();
	let code = cleanup_with(&config, Some(&Listed(zone)), true, true, &mut out);
	let text = String::from_utf8(out).expect("utf-8");
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		text,
		format!(
			"remove key file {}\ndelete TXT ed7._domainkey.example.org\ndry run: nothing changed\n",
			dir.path().join("dkim-ed7.key").display()
		)
	);
}
