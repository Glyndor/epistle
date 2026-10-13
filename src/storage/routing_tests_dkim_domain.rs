//! The DKIM `d=` is the domain of the single, checked From header when
//! the server signs for it, so DMARC aligns for an account writing from
//! its address in a second hosted domain. Only a From domain the server
//! holds no key for falls back to the envelope domain.

use super::*;
use std::collections::HashMap;

use crate::dkim::test_support::{KeyDns, signature_fields};
use crate::dkim::{ReloadableSigner, Signer};

/// Deliver `from` / `reverse_path` to a remote recipient; return the
/// queued message and the signer's DNS record.
fn queued(reverse_path: &str, from: &str) -> (Vec<u8>, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key_file = dir.path().join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("alice@b.example".to_string(), "alice".to_string()),
		],
	));
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(signer);
	split
		.deliver(AcceptedMessage {
			reverse_path: reverse_path.to_string(),
			recipients: vec!["bob@elsewhere.net".into()],
			data: format!("From: {from}\r\nSubject: hi\r\n\r\nHello\r\n").into_bytes(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("ids")[0];
	(spool.load(id).expect("load").data, record)
}

#[tokio::test]
async fn a_from_in_a_second_hosted_domain_signs_for_that_domain_and_passes_dmarc() {
	let (data, record) = queued("alice@a.example", "Alice <alice@b.example>");
	let fields = signature_fields(&data);
	assert_eq!(fields.len(), 1);
	assert_eq!(fields[0].1, "b.example", "d= must be the From domain");

	let dns = KeyDns(HashMap::from([
		("sel._domainkey.b.example".to_string(), vec![record]),
		(
			"_dmarc.b.example".to_string(),
			vec!["v=DMARC1; p=reject".to_string()],
		),
	]));
	let dkim = crate::dkim::verify_message(&dns, &data).await;
	let dmarc = crate::dmarc::evaluate(
		&dns,
		"b.example",
		(crate::spf::SpfOutcome::None, Some("a.example")),
		&dkim,
	)
	.await;
	assert_eq!(dmarc, crate::dmarc::DmarcOutcome::Pass);
}

#[test]
fn a_from_domain_without_a_key_falls_back_to_the_envelope_domain() {
	let (data, _) = queued("alice@a.example", "someone@elsewhere.example");
	assert_eq!(signature_fields(&data)[0].1, "a.example");
}
