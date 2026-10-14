//! Per-domain DKIM signing through the routing sink: mail whose `d=` has a
//! `[[dkim.domain]]` override is signed with that override's key, every
//! other domain with the default, and the signature verifies only against
//! the key of the domain it names.

use super::*;
use std::sync::Arc;

use crate::dkim::test_support::{KeyDns, signature_fields};
use crate::dkim::{DkimOutcome, DomainSigner, PerDomainSigner, ReloadableSigner, Signer};

/// The relayed copy of a message from `envelope` with `From: from`, signed
/// by a sink whose default key uses selector `mail` and whose override for
/// `example.org` uses the same selector name with its own key. Returns the
/// spooled message and the default's and the override's TXT values.
fn relayed(envelope: &str, from: &str) -> (Vec<u8>, String, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (default_pem, default_txt) = crate::dkim::generate_key().expect("key");
	let (override_pem, override_txt) = crate::dkim::generate_key().expect("key");
	let default_key = dir.path().join("default.key");
	let override_key = dir.path().join("override.key");
	std::fs::write(&default_key, default_pem).expect("write default");
	std::fs::write(&override_key, override_pem).expect("write override");
	let default = Signer::load("mail", &default_key).expect("load default");
	let override_signer = Signer::load("mail", &override_key).expect("load override");
	let signer = PerDomainSigner::new(
		ReloadableSigner::new(Arc::new(default)),
		vec![DomainSigner {
			domain: "example.org".to_string(),
			signer: Arc::new(override_signer),
		}],
	);
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string(), "fallback.example".to_string()],
		[(envelope.to_string(), "alice".to_string())],
	));
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(signer);
	split
		.deliver(AcceptedMessage {
			reverse_path: envelope.to_string(),
			recipients: vec!["bob@elsewhere.net".into()],
			data: format!("From: Alice <{from}>\r\nSubject: hi\r\n\r\nHello\r\n").into_bytes(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("ids")[0];
	(
		spool.load(id).expect("load").data,
		default_txt,
		override_txt,
	)
}

/// The `d=` of the only signature, and whether it verifies when `record` is
/// what that domain publishes under the selector.
fn verifies(data: &[u8], record: &str) -> (String, bool) {
	let fields = signature_fields(data);
	assert_eq!(fields.len(), 1, "one signature per message");
	let (selector, domain, _) = &fields[0];
	let dns = KeyDns(
		[(
			format!("{selector}._domainkey.{domain}"),
			vec![record.to_string()],
		)]
		.into(),
	);
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let results = runtime.block_on(crate::dkim::verify_message(&dns, data));
	let pass = results.iter().all(|r| r.outcome == DkimOutcome::Pass);
	(domain.clone(), pass)
}

#[test]
fn a_domain_with_an_override_signs_with_its_own_key() {
	let (data, default_txt, override_txt) = relayed("alice@example.org", "alice@example.org");
	assert_eq!(verifies(&data, &override_txt), ("example.org".into(), true));
	assert_eq!(
		verifies(&data, &default_txt),
		("example.org".into(), false),
		"the default key must not sign for example.org"
	);
}

#[test]
fn a_domain_without_an_override_signs_with_the_default() {
	let (data, default_txt, override_txt) =
		relayed("alice@fallback.example", "alice@fallback.example");
	assert_eq!(
		verifies(&data, &default_txt),
		("fallback.example".into(), true)
	);
	assert_eq!(
		verifies(&data, &override_txt),
		("fallback.example".into(), false),
		"example.org's key must not sign for another domain"
	);
}

#[test]
fn the_from_domain_is_signed_with_its_own_key_whatever_the_envelope() {
	// The envelope is example.org, which has an override, but d= is the
	// hosted From domain, so the key is that domain's (the default).
	let (data, default_txt, _) = relayed("alice@example.org", "alice@fallback.example");
	assert_eq!(
		verifies(&data, &default_txt),
		("fallback.example".into(), true)
	);
}

#[test]
fn an_unhosted_from_domain_is_never_signed_for() {
	// An unhosted From falls back to the envelope domain, as without
	// overrides, and that domain's override signs.
	let (data, _, override_txt) = relayed("alice@example.org", "alice@unhosted.example");
	assert_eq!(verifies(&data, &override_txt), ("example.org".into(), true));
}
