//! A message clamd cannot take, with `clamd_on_error = "defer"`: the API and
//! JMAP refuse it for good (retrying cannot help) and nothing is queued.

use std::sync::Arc;

use super::router;
use super::send_tests_virus::{api_send, draft, jmap_submit, queued};
use super::tests::test_state;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::fake::FakeClamd;
use crate::antispam::submission_scan::ScanningSink;
use crate::config::ClamdOnError;
use crate::storage::SplitDelivery;
use axum::http::StatusCode;

fn deferring_state(dir: &std::path::Path, clamd: &FakeClamd) -> super::state::ApiState {
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let split = SplitDelivery::new(dir, directory).expect("sink");
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()).with_on_error(ClamdOnError::Defer));
	let sink = ScanningSink::wrap(true, Arc::new(split), Some(hook), None, None).expect("sink");
	test_state(dir, 0).with_outbound(sink)
}

#[tokio::test]
async fn api_send_too_large_for_clamd_is_refused_with_413() {
	let clamd = FakeClamd::start_replying("INSTREAM size limit exceeded. ERROR");
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(deferring_state(dir.path(), &clamd));
	let (status, body) = api_send(&app, "bob@elsewhere.example", "hello").await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
	assert_eq!(body["error"]["code"], "scan_too_large", "{body}");
	assert_eq!(queued(dir.path()), 0, "nothing queued");
}

#[tokio::test]
async fn jmap_submission_too_large_for_clamd_is_forbidden_to_send() {
	let clamd = FakeClamd::start_replying("INSTREAM size limit exceeded. ERROR");
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(deferring_state(dir.path(), &clamd));
	let response = jmap_submit(&app, dir.path(), &draft("hello")).await;
	let refusal = &response["notCreated"]["s"];
	assert_eq!(refusal["type"], "forbiddenToSend", "{response}");
	assert_eq!(
		refusal["description"], "message too large for the content scan",
		"{response}"
	);
	assert_eq!(queued(dir.path()), 0);
}
