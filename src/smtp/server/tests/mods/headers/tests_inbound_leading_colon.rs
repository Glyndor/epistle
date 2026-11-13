//! Trust fields with a leading colon or odd spacing are removed on DATA and BDAT.

use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tests_auth::directory_with_password;
use super::tests_inbound_headers::PLAIN;
use super::*;
use crate::dkim::test_support::KeyDns;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

/// Helper that sends a payload and reads back the SMTP reply stream.
async fn send_and_capture(server: Server, data: &str, bdat: bool) -> String {
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
	output
}

/// mail-parser 0.11.9 folds a leading `:` (and any ASCII whitespace)
/// before the header name, so `:Authentication-Results: x` reads as
/// the canonical name. The stripper now mirrors that fold and removes
/// the line on DATA and on BDAT, both with and without SPF/DKIM checks.
/// mail-parser 1.0 keeps the aliases distinct. The input still carries
/// every forged value, and delivery must remove them all byte for byte.
#[tokio::test]
async fn leading_colon_trust_fields_are_removed_on_data_and_bdat() {
	let names = [
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Epistle-Attachment-Warning",
	];
	let mut payload = String::new();
	for name in names {
		for prefix in [":", "::", ": ", " :"] {
			let value = if name == "Authentication-Results" {
				"mail.example.org; dkim=pass; forged"
			} else {
				"forged"
			};
			payload.push_str(&format!("{prefix}{name}: {value}\r\n"));
		}
	}
	// A foreign, parseable Authentication-Results survives as untrusted
	// info; the canonical-name assertion below should not see it.
	payload.push_str("Authentication-Results: prior.example; none\r\n");
	payload.push_str(PLAIN);
	let pre = mail_parser::MessageParser::default()
		.parse(payload.as_bytes())
		.expect("parses");
	for name in names {
		let count = pre.headers().all(name).count();
		assert_eq!(
			count,
			usize::from(name == "Authentication-Results"),
			"only the ordinary foreign field may have the canonical name: {name}"
		);
		assert!(
			payload.contains(&format!(":{name}:")),
			"the forged alias must be present"
		);
	}
	for bdat in [false, true] {
		for checks in [false, true] {
			let sink = Arc::new(MemorySink::new());
			let mut server = Server::new("mail.example.org", sink.clone())
				.with_directory(directory_with_password());
			if checks {
				server = server.with_spf(Arc::new(KeyDns(HashMap::new())));
			}
			let output = send_and_capture(server, &payload, bdat).await;
			assert!(
				output.contains("250 2.0.0 ok\r\n221"),
				"BDAT={bdat}, checks={checks}: {output}"
			);
			let messages = sink.messages();
			assert_eq!(messages.len(), 1, "BDAT={bdat}, checks={checks}");
			let data = &messages[0].data;
			let parsed = mail_parser::MessageParser::default()
				.parse(data)
				.expect("delivered parses");
			for name in names {
				if name == "Received-SPF" && checks {
					// The server emits its own Received-SPF; check the
					// forged one is not the source.
					continue;
				}
				if name == "Authentication-Results" {
					continue;
				}
				assert!(
					parsed.headers().value(name).is_none(),
					"BDAT={bdat}, checks={checks}, {name}"
				);
			}
			// Only the foreign Authentication-Results remains, plus the
			// server's own stamp when checks are on; the forged values
			// must be gone.
			let results = header_values(data, "Authentication-Results");
			assert!(
				results.iter().any(|r| r == "prior.example; none"),
				"BDAT={bdat}, checks={checks}: {results:?}"
			);
			assert!(
				!results.iter().any(|r| r.contains("forged")),
				"BDAT={bdat}, checks={checks}: {results:?}"
			);
			// The forged X-Spam-* / X-Epistle-* values are also gone
			// (mail-parser reads them with the canonical name).
			for name in [
				"X-Spam-Status",
				"X-Spam-Score",
				"X-Epistle-Attachment-Warning",
			] {
				let values = header_values(data, name);
				assert!(
					values.is_empty() || !values.iter().any(|v| v.contains("forged")),
					"BDAT={bdat}, checks={checks}, {name}: {values:?}"
				);
			}
		}
	}
}

/// If strip fails to remove a reserved header (simulated by swapping in
/// the buggy stripper that does not fold the leader), the safety net
/// must still refuse the message with `550 5.7.1`. This is the test
/// the second review asked for: any leak in strip turns into a refusal
/// in the second pass, not into a forged header delivered.
#[tokio::test]
async fn safety_net_trusts_a_hypothetical_hole_in_strip() {
	let names = [
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
		"X-Epistle",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Epistle-Attachment-Warning",
	];
	for name in names {
		let value = if name == "Authentication-Results" {
			"mail.example.org; dkim=pass"
		} else {
			"forged"
		};
		let payload = format!(":{name}: {value}\r\n{PLAIN}");
		for bdat in [false, true] {
			let sink = Arc::new(MemorySink::new());
			let server = Server::new("mail.example.org", sink.clone())
				.with_directory(directory_with_password())
				.with_strip_for_test(crate::smtp::inbound_headers::strip_buggy);
			let output = send_and_capture(server, &payload, bdat).await;
			assert!(
				output.contains("550 5.7.1"),
				"BDAT={bdat}, {name}: {output}"
			);
			assert!(
				output.ends_with("221 2.0.0 closing connection\r\n"),
				"BDAT={bdat}, {name}: {output}"
			);
			assert!(
				!output.contains("250 2.0.0 ok\r\n221"),
				"BDAT={bdat}, {name}: a refused message must not be queued: {output}"
			);
			assert_eq!(
				sink.messages().len(),
				0,
				"BDAT={bdat}, {name}: refused message must not reach the sink"
			);
		}
	}
}

// See `tests_inbound_headers_unicode.rs` for the
// `unicode_whitespace_after_a_reserved_field_is_removed_on_data_and_bdat`
// test that exercises the 95-alias matrix through DATA and BDAT.
