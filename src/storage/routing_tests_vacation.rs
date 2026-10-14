//! A vacation reply leaves through the same outbound path as any other
//! message from the server: queued to the spool and DKIM-signed for the
//! domain in its From, so a receiver can tell it from a forged auto-reply.

use super::*;
use std::collections::HashMap;

use crate::dkim::test_support::{KeyDns, signature_fields};
use crate::dkim::{DkimOutcome, ReloadableSigner, Signer};
use crate::storage::vacation_store::{VacationSetting, write as write_setting};

#[tokio::test]
async fn a_jmap_vacation_reply_is_queued_and_dkim_signed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key_file = dir.path().join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let setting = VacationSetting {
		is_enabled: true,
		from_date: None,
		to_date: None,
		subject: Some("Away".to_string()),
		text_body: Some("Back on Monday.".to_string()),
		html_body: None,
	};
	write_setting(dir.path(), "alice", &setting).expect("write setting");
	let split = SplitDelivery::new(dir.path(), directory)
		.expect("sink")
		.with_signer(signer);
	split
		.deliver(AcceptedMessage {
			reverse_path: "carol@example.net".into(),
			recipients: vec!["alice@example.org".into()],
			data: b"From: carol@example.net\r\nSubject: hi\r\n\r\nHello\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		})
		.expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("ids");
	assert_eq!(ids.len(), 1, "one reply queued");
	let queued = spool.load(ids[0]).expect("load");
	assert!(queued.envelope.reverse_path.is_empty(), "null sender");
	assert_eq!(queued.envelope.recipients, vec!["carol@example.net"]);
	let fields = signature_fields(&queued.data);
	assert_eq!(fields.len(), 1, "the reply carries one DKIM signature");
	assert_eq!(fields[0].1, "example.org");
	let dns = KeyDns(HashMap::from([(
		"sel._domainkey.example.org".to_string(),
		vec![record],
	)]));
	let results = crate::dkim::verify_message(&dns, &queued.data).await;
	assert!(
		results.iter().any(|r| r.outcome == DkimOutcome::Pass),
		"the signature verifies"
	);
}
