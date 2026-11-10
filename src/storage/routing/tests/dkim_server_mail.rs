//! Mail the server writes from its own host name (DMARC and TLS-RPT
//! reports) is signed for the hosted domain above the host name, where the
//! key is published, and so passes DKIM and aligns with its From.

use super::*;
use std::collections::HashMap;

use crate::dkim::test_support::{KeyDns, signature_fields};
use crate::dkim::{ReloadableSigner, Signer};

/// Deliver a message from `postmaster@<host>` with that same From to a
/// remote recipient; return the queued bytes and the signer's DNS record.
fn queued_from_host(host: &str) -> (Vec<u8>, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key_file = dir.path().join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let default = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let signer = crate::dkim::PerDomainSigner::new(default, Vec::new());
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(signer);
	split
		.deliver(AcceptedMessage {
			reverse_path: format!("postmaster@{host}"),
			recipients: vec!["rua@elsewhere.net".into()],
			data: format!("From: postmaster@{host}\r\nSubject: report\r\n\r\nbody\r\n")
				.into_bytes(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			sender_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let id = spool.list().expect("ids")[0];
	(spool.load(id).expect("load").data, record)
}

#[tokio::test]
async fn a_report_from_the_host_name_is_signed_for_the_hosted_parent_and_aligns() {
	let (data, record) = queued_from_host("mail.example.org");
	assert_eq!(signature_fields(&data)[0].1, "example.org");
	let dns = KeyDns(HashMap::from([
		("sel._domainkey.example.org".to_string(), vec![record]),
		(
			"_dmarc.mail.example.org".to_string(),
			vec!["v=DMARC1; p=reject".to_string()],
		),
		(
			"_dmarc.example.org".to_string(),
			vec!["v=DMARC1; p=reject".to_string()],
		),
	]));
	let dkim = crate::dkim::verify_message(&dns, &data).await;
	assert_eq!(dkim[0].outcome, crate::dkim::DkimOutcome::Pass);
	let dmarc = crate::dmarc::evaluate(
		&dns,
		"mail.example.org",
		(crate::spf::SpfOutcome::None, None),
		&dkim,
	)
	.await;
	assert_eq!(dmarc, crate::dmarc::DmarcOutcome::Pass);
}

#[test]
fn a_host_name_with_no_hosted_parent_keeps_the_envelope_domain() {
	let (data, _) = queued_from_host("mail.unrelated.net");
	assert_eq!(signature_fields(&data)[0].1, "mail.unrelated.net");
}
