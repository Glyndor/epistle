//! Local spam and attachment verdicts, and the header policy of authenticated submission.

use super::tests_auth::directory_with_password;
use super::tests_inbound_headers::{FORGED, PLAIN, receive};
use super::*;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

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
	let answer = super::super::scanning::tests_virus::submit(sink.clone(), &data).await;
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
