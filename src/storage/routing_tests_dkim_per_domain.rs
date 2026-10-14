//! Per-domain DKIM signing: the routing sink signs mail whose `d=` is
//! in `[dkim.domain]` with the override's selector, and falls back to
//! the default for every other hosted domain.

use super::*;
use std::sync::Arc;

use crate::dkim::test_support::signature_fields;
use crate::dkim::{PerDomainSigner, ReloadableSigner, Signer};

#[test]
fn a_listed_domain_signs_with_its_own_selector() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (default_pem, _) = crate::dkim::generate_key().expect("key");
	let (override_pem, _) = crate::dkim::generate_key().expect("key");
	let default_key = dir.path().join("default.key");
	let override_key = dir.path().join("override.key");
	std::fs::write(&default_key, default_pem).expect("write default");
	std::fs::write(&override_key, override_pem).expect("write override");
	let default_signer = ReloadableSigner::new(Arc::new(
		Signer::load("default-sel", &default_key).expect("load"),
	));
	let override_signer = Arc::new(Signer::load("per-sel", &override_key).expect("load"));
	let per_domain = PerDomainSigner::new(
		default_signer,
		vec![crate::dkim::DomainSigner {
			domain: "example.org".to_string(),
			signer: override_signer,
		}],
	);
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string(), "fallback.example".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(per_domain);
	split
		.deliver(AcceptedMessage {
			reverse_path: "alice@example.org".to_string(),
			recipients: vec!["bob@elsewhere.net".into()],
			data: b"From: Alice <alice@example.org>\r\nSubject: hi\r\n\r\nHello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("ids")[0];
	let data = spool.load(id).expect("load").data;
	let fields = signature_fields(&data);
	assert_eq!(fields.len(), 1, "one signature per message");
	assert_eq!(
		fields[0].0, "per-sel",
		"listed domain must use its override selector"
	);
	assert_eq!(
		fields[0].1, "example.org",
		"the signature's d= is the From domain"
	);
}

#[test]
fn an_unlisted_domain_falls_back_to_the_default() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (default_pem, _) = crate::dkim::generate_key().expect("key");
	let (override_pem, _) = crate::dkim::generate_key().expect("key");
	let default_key = dir.path().join("default.key");
	let override_key = dir.path().join("override.key");
	std::fs::write(&default_key, default_pem).expect("write default");
	std::fs::write(&override_key, override_pem).expect("write override");
	let default_signer = ReloadableSigner::new(Arc::new(
		Signer::load("default-sel", &default_key).expect("load"),
	));
	let override_signer = Arc::new(Signer::load("per-sel", &override_key).expect("load"));
	let per_domain = PerDomainSigner::new(
		default_signer,
		vec![crate::dkim::DomainSigner {
			domain: "example.org".to_string(),
			signer: override_signer,
		}],
	);
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string(), "fallback.example".to_string()],
		[("alice@fallback.example".to_string(), "alice".to_string())],
	));
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(per_domain);
	split
		.deliver(AcceptedMessage {
			reverse_path: "alice@fallback.example".to_string(),
			recipients: vec!["bob@elsewhere.net".into()],
			data: b"From: Alice <alice@fallback.example>\r\nSubject: hi\r\n\r\nHello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("ids")[0];
	let data = spool.load(id).expect("load").data;
	let fields = signature_fields(&data);
	assert_eq!(fields.len(), 1, "one signature per message");
	assert_eq!(
		fields[0].0, "default-sel",
		"unlisted domain must use the default selector"
	);
	assert_eq!(
		fields[0].1, "fallback.example",
		"the signature's d= is the From domain"
	);
}
