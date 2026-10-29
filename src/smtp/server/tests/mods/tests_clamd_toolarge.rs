//! `clamd_on_error = "defer"` over SMTP with a message clamd cannot take:
//! it is refused for good at the end of DATA, never delivered unscanned,
//! and never left to retry. Accept keeps letting it through.

use super::tests_clamd_defer::{INBOUND, deliver, down};
use super::*;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::tests::fake::FakeClamd;
use crate::config::ClamdOnError;

const TOO_LARGE: &str = "552 5.3.4 message too large for the content scan\r\n";

#[tokio::test]
async fn inbound_mail_over_clamd_max_bytes_is_refused_with_defer() {
	let dir = tempfile::tempdir().expect("tempdir");
	let hook = Arc::new(
		ClamdHook::new(dir.path().join("clamd.sock"))
			.with_on_error(ClamdOnError::Defer)
			.with_max_bytes(4),
	);
	let (answer, delivered) = deliver(hook).await;
	assert_eq!(answer, TOO_LARGE);
	assert_eq!(delivered, 0, "nothing delivered unscanned");
}

#[tokio::test]
async fn inbound_mail_over_clamd_max_bytes_is_accepted_by_default() {
	let dir = tempfile::tempdir().expect("tempdir");
	let hook = Arc::new(ClamdHook::new(dir.path().join("clamd.sock")).with_max_bytes(4));
	let (answer, delivered) = deliver(hook).await;
	assert!(answer.starts_with("250 "), "{answer}");
	assert_eq!(delivered, 1);
}

#[tokio::test]
async fn a_message_at_the_limit_is_not_delivered_unscanned_once_the_server_stamps_it() {
	// The message is exactly clamd_max_bytes as the client sent it; the
	// trace and authentication headers added before the scan push it over,
	// and a healthy clamd never sees it.
	let clamd = FakeClamd::start();
	let hook = Arc::new(
		ClamdHook::new(clamd.socket.clone())
			.with_on_error(ClamdOnError::Defer)
			.with_max_bytes(INBOUND.len()),
	);
	let (answer, delivered) = deliver(hook).await;
	assert_eq!(answer, TOO_LARGE);
	assert_eq!(delivered, 0);
	assert_eq!(clamd.scans(), 0);
}

#[tokio::test]
async fn a_stream_limit_reply_from_a_healthy_clamd_is_refused_with_defer() {
	let clamd = FakeClamd::start_replying("INSTREAM size limit exceeded. ERROR");
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()).with_on_error(ClamdOnError::Defer));
	let (answer, delivered) = deliver(hook).await;
	assert_eq!(answer, TOO_LARGE);
	assert_eq!(delivered, 0);
}

#[tokio::test]
async fn a_failing_clamd_still_defers_instead_of_refusing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (answer, _) = deliver(down(dir.path(), ClamdOnError::Defer)).await;
	assert!(answer.starts_with("451 "), "{answer}");
}
