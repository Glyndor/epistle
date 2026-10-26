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
	queued_with_ending(reverse_path, from, "\r\n", true, true)
}

fn queued_with_ending(
	reverse_path: &str,
	from: &str,
	ending: &str,
	signed: bool,
	terminated: bool,
) -> (Vec<u8>, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key_file = dir.path().join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let default = ReloadableSigner::new(Arc::new(Signer::load("sel", &key_file).expect("load")));
	let signer = crate::dkim::PerDomainSigner::new(default, Vec::new());
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["a.example".to_string(), "b.example".to_string()],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("alice@b.example".to_string(), "alice".to_string()),
		],
	));
	let mut split = SplitDelivery::new(dir.path(), directory).expect("sink");
	if signed {
		split = split.with_signer(signer);
	}
	let terminal = if terminated { ending } else { "" };
	split
		.deliver(AcceptedMessage {
			reverse_path: reverse_path.to_string(),
			recipients: vec!["bob@elsewhere.net".into()],
			data: format!(
				"From: {from}{ending}Subject: hi{ending}{ending}Hello{ending}.dot{ending}caf\u{e9}{terminal}"
			)
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

#[tokio::test]
async fn lf_only_outbound_bytes_are_crlf_before_signing_and_queueing() {
	for (ending, terminated, signed) in [
		("\n", true, false),
		("\n", true, true),
		("\n", false, false),
		("\n", false, true),
		("\r\n", false, false),
		("\r\n", false, true),
	] {
		let (data, record) = queued_with_ending(
			"alice@a.example",
			"alice@a.example",
			ending,
			signed,
			terminated,
		);
		for (index, byte) in data.iter().enumerate() {
			if *byte == b'\n' {
				assert!(
					index > 0 && data[index - 1] == b'\r',
					"I found a bare LF in queued bytes"
				);
			}
		}
		let received = transmitted(&data).await;
		assert!(
			received.ends_with(&data),
			"I expect SMTP to transmit the queued bytes unchanged"
		);
		let text = std::str::from_utf8(&received).expect("UTF-8 message");
		let (_, body) = text
			.split_once("\r\n\r\n")
			.expect("independent wire boundary");
		assert_eq!(body, "Hello\r\n.dot\r\ncaf\u{e9}\r\n");
		if signed {
			use base64::Engine;
			let expected = base64::engine::general_purpose::STANDARD
				.encode(ring::digest::digest(&ring::digest::SHA256, body.as_bytes()));
			assert!(text.contains(&format!("bh={expected}")));
			let dns = KeyDns(HashMap::from([(
				"sel._domainkey.a.example".into(),
				vec![record],
			)]));
			let results = crate::dkim::verify_message(&dns, &received).await;
			assert_eq!(results.len(), 1);
			assert_eq!(results[0].outcome, crate::dkim::DkimOutcome::Pass);
		}
	}
}

async fn transmitted(data: &[u8]) -> Vec<u8> {
	use crate::smtp::sink::MemorySink;
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(crate::smtp::directory::Directory::new(
		["elsewhere.net".to_string()],
		[("bob@elsewhere.net".to_string(), "bob".to_string())],
	));
	let server = crate::smtp::server::Server::new("mx.elsewhere.net", sink.clone())
		.with_directory(directory);
	let (client, receiver) = tokio::io::duplex(64 * 1024);
	let task = tokio::spawn(async move { server.handle(receiver, None).await });
	let result = crate::queue::client::deliver(
		client,
		"mx.elsewhere.net",
		"mail.a.example",
		"alice@a.example",
		&["bob@elsewhere.net".to_string()],
		data,
		false,
		None,
		&crate::dane::rrset::TlsaRrset::Absent,
		crate::config::OutboundTls::Strict,
		&mut None,
	)
	.await;
	task.abort();
	let _ = task.await;
	result.expect("I expect the strict SMTP line decoder to accept the outgoing bytes");
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	messages[0].data.clone()
}
