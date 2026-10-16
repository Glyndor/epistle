//! A submission the scan or the attachment policy refuses is not in the
//! sender's `Sent` folder: the copy is stored only once the message was
//! accepted, as the API already does.

use super::tests_auth::directory_with_password;
use super::tests_virus::submit_to;
use super::*;
use crate::antispam::attachments::policy::Policy;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::fake::{FakeClamd, eicar};
use crate::antispam::submission_scan::ScanningSink;
use crate::config::{AttachmentMode, Attachments, ClamdOnError};
use crate::imap::mailbox;
use crate::smtp::sink::MemorySink;

const EXE_AS_PDF: &str = "From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: s\r\n\
	MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
	Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\n\
	Content-Type: application/pdf; name=invoice.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n\
	TVqQAAMAAAAEAAAA\r\n--b--\r\n";

fn message(body: &str) -> String {
	format!("From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: s\r\n\r\n{body}\r\n")
}

/// Submit `data` as alice through `sink`, with alice's `Sent` folder under
/// `dir`; the reply to the end of DATA and how many copies `Sent` holds.
async fn submit_and_count(
	dir: &std::path::Path,
	sink: Arc<dyn MessageSink>,
	data: &str,
) -> (String, usize) {
	let server = Server::new("mail.example.org", sink)
		.with_directory(directory_with_password())
		.with_data_dir(dir.to_path_buf());
	let answer = submit_to(server, data).await;
	let copies = if mailbox::exists(dir, "alice", "Sent") {
		mailbox::Snapshot::open(
			dir,
			"alice",
			"Sent",
			&crate::storage::MessageCrypto::disabled(),
		)
		.expect("open Sent")
		.messages()
		.count()
	} else {
		0
	};
	(answer, copies)
}

fn with_clamd(clamd: Arc<ClamdHook>) -> Arc<dyn MessageSink> {
	ScanningSink::wrap(true, Arc::new(MemorySink::new()), Some(clamd), None, None).expect("sink")
}

#[tokio::test]
async fn an_accepted_submission_is_saved_to_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = FakeClamd::start();
	let sink = with_clamd(Arc::new(ClamdHook::new(clamd.socket.clone())));
	let (answer, copies) = submit_and_count(dir.path(), sink, &message("hello")).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(copies, 1);
}

#[tokio::test]
async fn a_submission_refused_for_a_virus_is_not_saved_to_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = FakeClamd::start();
	let sink = with_clamd(Arc::new(ClamdHook::new(clamd.socket.clone())));
	let (answer, copies) = submit_and_count(dir.path(), sink, &message(&eicar())).await;
	assert!(answer.starts_with("554 5.7.1 "), "{answer}");
	assert_eq!(copies, 0, "a refused message was never sent");
}

#[tokio::test]
async fn a_submission_deferred_by_the_scan_is_not_saved_to_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = ClamdHook::new(dir.path().join("no-clamd.sock")).with_on_error(ClamdOnError::Defer);
	let sink = with_clamd(Arc::new(clamd));
	let (answer, copies) = submit_and_count(dir.path(), sink, &message("hello")).await;
	assert_eq!(
		answer,
		"451 4.7.1 content scan unavailable, try again later\r\n"
	);
	assert_eq!(copies, 0, "the retry will be saved, not this attempt");
}

#[tokio::test]
async fn a_submission_refused_by_the_attachment_policy_is_not_saved_to_sent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let section = Attachments {
		mode: AttachmentMode::Quarantine,
		..Attachments::default()
	};
	let policy = Arc::new(Policy::from_config(&section, 1 << 20).expect("policy"));
	let sink = ScanningSink::wrap_with_attachments(
		true,
		Arc::new(MemorySink::new()),
		None,
		Some(policy),
		None,
		None,
	)
	.expect("sink");
	let (answer, copies) = submit_and_count(dir.path(), sink, EXE_AS_PDF).await;
	assert_eq!(answer, "550 5.7.1 attachment type not accepted\r\n");
	assert_eq!(copies, 0, "a refused message was never sent");
}
