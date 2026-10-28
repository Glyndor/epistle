//! Inbound trust fields at the SMTP boundary, including stored delivery and submission.

use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tests_auth::directory_with_password;
use super::*;
use crate::dkim::test_support::KeyDns;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

pub(super) const PLAIN: &str =
	"From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
const FORGED: &str = "Authentication-Results: mail.example.org; spf=pass; dkim=pass\r\n\
	Received-SPF: forged\r\nX-Spam-Status: forged\r\nX-Spam-Score: forged\r\n\
	X-Spam-Flag: forged\r\nX-Epistle-Attachment-Warning: forged\r\n\
	X-Epistle-Other: forged\r\nDelivered-To: forged\r\nReturn-Path: <forged>\r\n\
	Epistle-Class: marketing\r\n";

pub(super) async fn receive(server: Server, data: &str, bdat: bool) {
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
			.header("Authentication-Results")
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
					assert!(parsed.header(name).is_none(), "{name}");
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

struct Junk;
impl crate::antispam::corpus::BayesScorer for Junk {
	fn score<'a>(
		&'a self,
		_scope: &'a str,
		_text: &'a str,
	) -> crate::antispam::trainer::TrainerFuture<'a, Result<f64, sqlx::Error>> {
		Box::pin(async { Ok(0.97) })
	}
	fn score_for_account<'a>(
		&'a self,
		_account: &'a str,
		_text: &'a [u8],
	) -> crate::antispam::trainer::TrainerFuture<'a, Option<f64>> {
		Box::pin(async { Some(0.97) })
	}
}

#[tokio::test]
async fn local_spam_and_attachment_verdicts_replace_sender_supplied_fields() {
	let sink = Arc::new(MemorySink::new());
	let section = crate::config::Attachments {
		mode: crate::config::AttachmentMode::Flag,
		..Default::default()
	};
	let policy = crate::antispam::attachments::policy::Policy::from_config(&section, 1 << 20)
		.expect("policy");
	let server = Server::new("mail.example.org", sink.clone())
		.with_directory(directory_with_password())
		.with_attachment_policy(Arc::new(policy))
		.with_bayes(Arc::new(Junk))
		.with_bayes_thresholds(0.95, None);
	let executable = "From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: photo\r\n\
		MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: text/plain\r\n\r\nattached\r\n--b\r\n\
		Content-Type: image/jpeg; name=holiday.jpg\r\nContent-Transfer-Encoding: base64\r\n\r\n\
		TVqQAAMAAAAEAAAA\r\n--b--\r\n";
	receive(server, &format!("{FORGED}{executable}"), false).await;
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = &messages[0].data;
	assert_eq!(header_values(data, "X-Spam-Status"), ["Yes"]);
	assert_eq!(header_values(data, "X-Spam-Score"), ["0.970000"]);
	assert_eq!(
		header_values(data, "X-Epistle-Attachment-Warning"),
		["executable-content, type-mismatch"]
	);
	assert!(header_values(data, "X-Spam-Flag").is_empty());
	assert!(header_values(data, "X-Epistle-Other").is_empty());
}

#[tokio::test]
async fn authenticated_submission_keeps_its_existing_header_policy() {
	let sink = Arc::new(MemorySink::new());
	let data = format!(
		"{FORGED}Bcc: hidden@example.net\r\n\
		 Received: from forged.example\r\n{}",
		PLAIN.replace("eve@sender.example", "alice@example.org")
	);
	let answer = super::tests_virus::submit(sink.clone(), &data).await;
	assert!(answer.starts_with("250 "), "{answer}");
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let data = &messages[0].data;
	for name in [
		"Received-SPF",
		"X-Spam-Status",
		"X-Spam-Score",
		"X-Spam-Flag",
		"Delivered-To",
		"Return-Path",
	] {
		assert!(!header_values(data, name).is_empty(), "{name}");
	}
	assert!(header_values(data, "Epistle-Class").is_empty());
	assert!(header_values(data, "Bcc").is_empty());
	assert_eq!(header_values(data, "Message-ID").len(), 1);
	assert_eq!(header_values(data, "Date").len(), 1);
	// The client's own view of the path does not survive: this hop wrote
	// one trace header, one set of authentication results and no local
	// verdicts, and none of the fields above is one of ours to speak for.
	assert_eq!(header_values(data, "Received").len(), 1);
	assert!(header_values(data, "Received")[0].contains("mail.example.org"));
	assert!(header_values(data, "Authentication-Results").is_empty());
	assert!(header_values(data, "X-Epistle-Other").is_empty());
}

#[tokio::test]
async fn dkim_and_the_prior_arc_chain_survive_with_a_valid_local_seal() {
	use crate::arc::chain::ChainValidation;
	use crate::arc::sealer::ArcSealer;
	use base64::Engine;
	use ring::signature::{Ed25519KeyPair, KeyPair};
	let rng = ring::rand::SystemRandom::new();
	let make_key = || {
		let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key");
		Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair")
	};
	let prior_key = make_key();
	let local_key = make_key();
	let record = |key: &Ed25519KeyPair| {
		format!(
			"v=DKIM1; k=ed25519; p={}",
			base64::engine::general_purpose::STANDARD.encode(key.public_key().as_ref())
		)
	};
	let mut records = HashMap::from([
		("sender.example".into(), vec!["v=spf1 ~all".into()]),
		(
			"arc._domainkey.prior.example".into(),
			vec![record(&prior_key)],
		),
		(
			"arc._domainkey.mail.example.org".into(),
			vec![record(&local_key)],
		),
	]);
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, public) = crate::dkim::generate_key().expect("dkim key");
	let path = dir.path().join("key");
	std::fs::write(&path, pem).expect("write key");
	let signer = crate::dkim::Signer::load("dkim", &path).expect("signer");
	let signature = signer
		.sign("sender.example", PLAIN.as_bytes())
		.expect("signature");
	records.insert("dkim._domainkey.sender.example".into(), vec![public]);
	let original = format!("Received: from original.example\r\n{signature}{FORGED}{PLAIN}");
	let prior = ArcSealer::new(prior_key, "prior.example", "arc")
		.seal(original.as_bytes(), "spf=pass", &[], ChainValidation::None)
		.expect("prior seal");
	let dns = Arc::new(KeyDns(records));
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone())
		.with_directory(directory_with_password())
		.with_spf(dns.clone())
		.with_arc_sealer(Arc::new(ArcSealer::new(
			local_key,
			"mail.example.org",
			"arc",
		)));
	receive(server, &format!("{prior}{original}"), false).await;
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let message = &messages[0];
	let text = std::str::from_utf8(&message.data).expect("text");
	assert!(text.contains(&signature));
	assert!(text.contains(&prior));
	assert_eq!(header_values(&message.data, "Received").len(), 2);
	assert!(text.contains("Received: from original.example\r\n"));
	let results = header_values(&message.data, "Authentication-Results");
	assert_eq!(results.len(), 1);
	assert!(
		results[0].contains("dkim=pass header.d=sender.example"),
		"{results:?}"
	);
	assert_eq!(
		crate::arc::chain::extract(&message.data)
			.expect("chain")
			.expect("present")
			.len(),
		2
	);
	assert_eq!(
		crate::arc::validate::validate(dns.as_ref(), &message.data).await,
		ChainValidation::Pass
	);
}

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
/// Each test asserts that mail-parser sees the canonical name BEFORE
/// strip is exercised, so a no-op strip cannot make the assertion pass.
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
		assert!(
			pre.header(name).is_some(),
			"mail-parser must see it before strip: {name}"
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
					parsed.header(name).is_none(),
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
