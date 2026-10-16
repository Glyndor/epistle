//! `clamd_on_error` on submissions: with `defer`, a scan that could not run
//! asks the client to retry instead of sending the message unscanned.


use super::*;
use crate::config::ClamdOnError;
use crate::smtp::sink::MemorySink;

fn message() -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "alice@example.org".into(),
		recipients: vec!["bob@elsewhere.example".into()],
		data: b"From: alice@example.org\r\nSubject: s\r\n\r\nhello\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

/// Submit one message through a scanning sink whose clamd socket does not
/// exist; what the sink answered and how many messages were handed on.
fn submit_with_clamd_down(on_error: ClamdOnError) -> (Result<(), String>, usize) {
	let dir = tempfile::tempdir().expect("tempdir");
	let inner = Arc::new(MemorySink::new());
	let clamd = Arc::new(ClamdHook::new(dir.path().join("clamd.sock")).with_on_error(on_error));
	let sink = ScanningSink::wrap(true, inner.clone(), Some(clamd), None, None).expect("sink");
	let outcome = sink
		.submit(
			message(),
			uuid::Uuid::now_v7(),
			"alice",
			&crate::smtp::sink::Submission::default(),
		)
		.map_err(|error| error.smtp_reply().to_string());
	(outcome, inner.messages().len())
}

#[test]
fn defer_asks_the_client_to_retry_a_submission_clamd_could_not_scan() {
	let (outcome, handed_on) = submit_with_clamd_down(ClamdOnError::Defer);
	assert_eq!(
		outcome,
		Err("451 4.7.1 content scan unavailable, try again later\r\n".to_string())
	);
	assert_eq!(handed_on, 0, "nothing left unscanned");
}

#[test]
fn accept_sends_the_same_submission_unscanned() {
	let (outcome, handed_on) = submit_with_clamd_down(ClamdOnError::Accept);
	assert_eq!(outcome, Ok(()));
	assert_eq!(handed_on, 1);
}

/// Submit [`message`] through a sink whose clamd cannot take it.
fn submit_too_large(on_error: ClamdOnError, clamd: ClamdHook) -> (Result<(), String>, usize) {
	let inner = Arc::new(MemorySink::new());
	let clamd = Arc::new(clamd.with_on_error(on_error));
	let sink = ScanningSink::wrap(true, inner.clone(), Some(clamd), None, None).expect("sink");
	let outcome = sink
		.submit(
			message(),
			uuid::Uuid::now_v7(),
			"alice",
			&crate::smtp::sink::Submission::default(),
		)
		.map_err(|error| error.smtp_reply().to_string());
	(outcome, inner.messages().len())
}

const TOO_LARGE: &str = "552 5.3.4 message too large for the content scan\r\n";

#[test]
fn defer_refuses_a_submission_over_clamd_max_bytes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = ClamdHook::new(dir.path().join("clamd.sock")).with_max_bytes(4);
	let (outcome, handed_on) = submit_too_large(ClamdOnError::Defer, clamd);
	assert_eq!(outcome, Err(TOO_LARGE.to_string()));
	assert_eq!(handed_on, 0, "nothing left unscanned");
}

#[test]
fn accept_sends_a_submission_over_clamd_max_bytes_unscanned() {
	let dir = tempfile::tempdir().expect("tempdir");
	let clamd = ClamdHook::new(dir.path().join("clamd.sock")).with_max_bytes(4);
	let (outcome, handed_on) = submit_too_large(ClamdOnError::Accept, clamd);
	assert_eq!(outcome, Ok(()));
	assert_eq!(handed_on, 1);
}

#[test]
fn defer_refuses_a_submission_clamd_says_is_over_its_stream_limit() {
	let fake = crate::antispam::clamd::fake::FakeClamd::start_replying(
		"INSTREAM size limit exceeded. ERROR",
	);
	let (outcome, handed_on) =
		submit_too_large(ClamdOnError::Defer, ClamdHook::new(fake.socket.clone()));
	assert_eq!(outcome, Err(TOO_LARGE.to_string()));
	assert_eq!(handed_on, 0);
}
