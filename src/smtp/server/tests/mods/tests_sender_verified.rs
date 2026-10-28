//! `AcceptedMessage::sender_verified` comes from the server's own SPF and
//! DKIM checks on the inbound hop: an SPF pass for the envelope sender's
//! domain, or a DKIM pass for the envelope or From domain. Headers in the
//! message, which the sender writes, never set it.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::dkim::Signer;
use crate::dkim::test_support::KeyDns;
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::MemorySink;

const SOFTFAIL: &str = "v=spf1 ~all";
const PASS: &str = "v=spf1 ip4:192.0.2.0/24 -all";

/// A message signed for `domain` and the DNS record of its key.
fn signed(domain: &str, message: &str) -> (String, (String, String)) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key_file = dir.path().join("sel.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = Signer::load("sel", &key_file).expect("load");
	let header = signer.sign(domain, message.as_bytes()).expect("signature");
	(
		format!("{header}{message}"),
		(format!("sel._domainkey.{domain}"), record),
	)
}

/// Deliver `data` from `eve@sender.example` at 192.0.2.7, with `spf` as
/// the domain's SPF record and `keys` as further TXT records.
async fn deliver(spf: &str, keys: &[(String, String)], data: &str) -> AcceptedMessage {
	let script = format!(
		"EHLO client.example.org\r\nMAIL FROM:<eve@sender.example>\r\n\
		 RCPT TO:<bob@example.org>\r\nDATA\r\n{data}.\r\nQUIT\r\n"
	);
	let mut messages = converse(spf, keys, &script).await;
	assert_eq!(messages.len(), 1);
	messages.remove(0)
}

/// Run `script` from 192.0.2.7 and return what was delivered.
async fn converse(spf: &str, keys: &[(String, String)], script: &str) -> Vec<AcceptedMessage> {
	let mut records = HashMap::from([("sender.example".to_string(), vec![spf.to_string()])]);
	for (name, record) in keys {
		records.insert(name.clone(), vec![record.clone()]);
	}
	let sink = Arc::new(MemorySink::new());
	let directory = DirectoryHandle::new(Directory::new(
		["example.org".to_string()],
		[("bob@example.org".to_string(), "bob".to_string())],
	));
	let server = Server::new("mail.example.org", sink.clone() as Arc<dyn MessageSink>)
		.with_directory(directory)
		.with_spf(Arc::new(KeyDns(records)));
	let (client, server_stream) = tokio::io::duplex(256 * 1024);
	let peer = Some("192.0.2.7".parse().expect("ip"));
	let task = tokio::spawn(async move { server.handle(server_stream, peer).await });
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = Vec::new();
	read.read_to_end(&mut output).await.expect("read");
	task.await.expect("task").expect("server result");
	assert!(!output.is_empty());
	sink.messages()
}

const PLAIN: &str =
	"From: eve@sender.example\r\nTo: bob@example.org\r\nSubject: hi\r\n\r\nhello\r\n";

#[tokio::test]
async fn an_spf_pass_verifies_the_sender() {
	assert!(deliver(PASS, &[], PLAIN).await.sender_verified);
}

#[tokio::test]
async fn a_softfail_without_dkim_does_not() {
	assert!(!deliver(SOFTFAIL, &[], PLAIN).await.sender_verified);
}

#[tokio::test]
async fn results_written_into_the_message_are_not_believed() {
	let forged = format!(
		"Authentication-Results: mail.example.org; spf=pass smtp.mailfrom=sender.example;\r\n \
		 dkim=pass header.d=sender.example\r\nReceived-SPF: pass\r\n{PLAIN}"
	);
	assert!(!deliver(SOFTFAIL, &[], &forged).await.sender_verified);
}

#[tokio::test]
async fn a_dkim_pass_for_the_sender_domain_verifies_it() {
	let (data, key) = signed("sender.example", PLAIN);
	assert!(deliver(SOFTFAIL, &[key], &data).await.sender_verified);
}

#[tokio::test]
async fn a_dkim_pass_for_a_subdomain_of_the_sender_verifies_it() {
	let (data, key) = signed("mail.sender.example", PLAIN);
	assert!(deliver(SOFTFAIL, &[key], &data).await.sender_verified);
}

/// The reply goes to the envelope sender, so a signature by the From
/// domain proves nothing about it: anyone can sign mail From their own
/// domain and put a victim in MAIL FROM.
#[tokio::test]
async fn a_dkim_pass_for_a_from_domain_unrelated_to_the_envelope_does_not() {
	let message = PLAIN.replace("From: eve@sender.example", "From: eve@author.example");
	let (data, key) = signed("author.example", &message);
	assert!(!deliver(SOFTFAIL, &[key], &data).await.sender_verified);
}

#[tokio::test]
async fn a_dkim_pass_for_a_from_domain_aligned_with_the_envelope_verifies_it() {
	let message = PLAIN.replace("From: eve@sender.example", "From: eve@news.sender.example");
	let (data, key) = signed("news.sender.example", &message);
	assert!(deliver(SOFTFAIL, &[key], &data).await.sender_verified);
}

/// Two transactions on one connection: a pass for the first sender does
/// not carry over to the second, whose domain has no SPF record.
#[tokio::test]
async fn a_pass_does_not_carry_over_to_the_next_transaction() {
	let script = format!(
		"EHLO client.example.org\r\n\
		 MAIL FROM:<eve@sender.example>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n{PLAIN}.\r\n\
		 MAIL FROM:<mallory@other.example>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n{PLAIN}.\r\n\
		 QUIT\r\n"
	);
	let messages = converse(PASS, &[], &script).await;
	assert_eq!(messages.len(), 2);
	assert!(messages[0].sender_verified, "eve passed SPF");
	assert!(!messages[1].sender_verified, "mallory did not");
}

#[tokio::test]
async fn a_pass_does_not_survive_rset() {
	let script = format!(
		"EHLO client.example.org\r\n\
		 MAIL FROM:<eve@sender.example>\r\nRSET\r\n\
		 MAIL FROM:<mallory@other.example>\r\nRCPT TO:<bob@example.org>\r\nDATA\r\n{PLAIN}.\r\n\
		 QUIT\r\n"
	);
	let messages = converse(PASS, &[], &script).await;
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].reverse_path, "mallory@other.example");
	assert!(!messages[0].sender_verified);
}

#[tokio::test]
async fn a_dkim_pass_for_an_unrelated_domain_does_not() {
	let (data, key) = signed("third.example", PLAIN);
	assert!(!deliver(SOFTFAIL, &[key], &data).await.sender_verified);
}
