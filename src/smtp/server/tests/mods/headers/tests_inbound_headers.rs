//! Inbound trust fields at the SMTP boundary, including stored delivery and submission.

use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tests_auth::directory_with_password;
use super::*;
use crate::dkim::test_support::KeyDns;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

pub(in crate::smtp::server::tests::mods) const PLAIN: &str =
	"From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
pub(super) const FORGED: &str = "Authentication-Results: mail.example.org; spf=pass; dkim=pass\r\n\
	Received-SPF: forged\r\nX-Spam-Status: forged\r\nX-Spam-Score: forged\r\n\
	X-Spam-Flag: forged\r\nX-Epistle-Attachment-Warning: forged\r\n\
	X-Epistle-Other: forged\r\nDelivered-To: forged\r\nReturn-Path: <forged>\r\n\
	Epistle-Class: marketing\r\n";

pub(in crate::smtp::server::tests::mods) async fn receive(server: Server, data: &str, bdat: bool) {
	let (client, stream) = tokio::io::duplex(256 * 1024);
	let task = tokio::spawn(async move {
		server
			.handle(stream, Some("192.0.2.7".parse().expect("ip")))
			.await
	});
	let mut script =
		"EHLO prior.example\r\nMAIL FROM:<eve@sender.example>\r\nRCPT TO:<alice@example.org>\r\n"
			.to_string();
	if bdat {
		script.push_str(&format!("BDAT {} LAST\r\n{data}QUIT\r\n", data.len()));
	} else {
		script.push_str(&format!("DATA\r\n{data}.\r\nQUIT\r\n"));
	}
	let (mut read, mut write) = tokio::io::split(client);
	write.write_all(script.as_bytes()).await.expect("write");
	write.shutdown().await.expect("shutdown");
	let mut output = String::new();
	read.read_to_string(&mut output).await.expect("read");
	task.await.expect("task").expect("server");
	assert!(
		output.ends_with("250 2.0.0 ok\r\n221 2.0.0 closing connection\r\n"),
		"{output}"
	);
}

#[tokio::test]
async fn obfuscated_trust_fields_are_removed_on_data_and_bdat_with_or_without_checks() {
	let mut fields = String::new();
	for name in [
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Future",
		"X-Epistle-Attachment-Warning",
		"X-Epistle-Future",
	] {
		for (at, inserted) in [(0, "\u{c}"), (4, " "), (4, "\t"), (4, "\u{c}")] {
			fields.push_str(&format!(
				"{}{inserted}{}: mail.example.org; dkim=pass; forged\r\n\tforged-fold\r\n",
				&name[..at],
				&name[at..]
			));
		}
	}
	let input = format!("{fields}Authentication-Results: prior.example; none\r\n{PLAIN}");
	let parser = mail_parser::MessageParser::default();
	assert!(
		parser
			.parse(input.as_bytes())
			.expect("original")
			.headers()
			.value("Authentication-Results")
			.is_some()
	);
	for bdat in [false, true] {
		for checks in [false, true] {
			let sink = Arc::new(MemorySink::new());
			let mut server = Server::new("mail.example.org", sink.clone())
				.with_directory(directory_with_password());
			if checks {
				server = server.with_spf(Arc::new(KeyDns(HashMap::new())));
			}
			receive(server, &input, bdat).await;
			let messages = sink.messages();
			assert_eq!(messages.len(), 1);
			let data = &messages[0].data;
			assert!(
				!String::from_utf8_lossy(data).contains("forged"),
				"BDAT={bdat}, checks={checks}"
			);
			let parsed = parser.parse(data).expect("delivered");
			for name in [
				"Received-SPF",
				"Delivered-To",
				"Return-Path",
				"Epistle-Class",
				"X-Spam-Status",
				"X-Spam-Score",
				"X-Spam-Future",
				"X-Epistle-Attachment-Warning",
				"X-Epistle-Future",
			] {
				if name != "Received-SPF" || !checks {
					assert!(parsed.headers().value(name).is_none(), "{name}");
				}
			}
			let results = header_values(data, "Authentication-Results");
			assert_eq!(results.len(), if checks { 2 } else { 1 });
			assert_eq!(
				results.last().expect("foreign result"),
				"prior.example; none"
			);
			if checks {
				assert!(results[0].contains("dkim=none"));
			}
		}
	}
}

#[tokio::test]
async fn stored_mail_has_only_local_delivery_fields_even_without_authentication_checks() {
	let data = format!("{FORGED}Authentication-Results: prior.example; spf=pass\r\n{PLAIN}");
	let copies = super::tests_trace::deliver_inbound(&data).await;
	assert_eq!(copies.len(), 1);
	let stored = copies[0].as_bytes();
	assert_eq!(header_values(stored, "Return-Path"), ["<x@example.net>"]);
	assert_eq!(header_values(stored, "Delivered-To"), ["alice@example.org"]);
	assert_eq!(
		header_values(stored, "Authentication-Results"),
		["prior.example; spf=pass"]
	);
	for name in [
		"Received-SPF",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Flag",
		"X-Epistle-Attachment-Warning",
		"X-Epistle-Other",
		"Epistle-Class",
	] {
		assert!(header_values(stored, name).is_empty(), "{name}");
	}
}

#[tokio::test]
async fn repeated_forged_results_are_replaced_by_the_servers_real_result_on_data_and_bdat() {
	for bdat in [false, true] {
		let sink = Arc::new(MemorySink::new());
		let dns = KeyDns(HashMap::from([(
			"sender.example".into(),
			vec!["v=spf1 ~all".into()],
		)]));
		let server = Server::new("mail.example.org", sink.clone())
			.with_directory(directory_with_password())
			.with_spf(Arc::new(dns));
		let data = format!(
			"{}Authentication-Results: prior.example; spf=pass\r\n{FORGED}{PLAIN}",
			"Authentication-Results: MAIL.EXAMPLE.ORG; spf=pass\r\n\tdkim=pass\r\n".repeat(50)
		);
		receive(server, &data, bdat).await;
		let messages = sink.messages();
		assert_eq!(messages.len(), 1);
		let results = header_values(&messages[0].data, "Authentication-Results");
		assert_eq!(results.len(), 2);
		assert!(
			results[0].starts_with("mail.example.org; spf=softfail"),
			"{results:?}"
		);
		assert!(results[0].contains("dkim=none"));
		assert!(results[0].contains("dmarc=none"));
		assert_eq!(results[1], "prior.example; spf=pass");
		let spf = header_values(&messages[0].data, "Received-SPF");
		assert_eq!(
			spf,
			["softfail (domain of sender.example) client-ip=192.0.2.7"]
		);
		assert!(!messages[0].sender_verified);
	}
}
