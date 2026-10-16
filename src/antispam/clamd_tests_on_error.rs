//! `clamd_on_error`: what a scan that could not run does to the message.

use super::fake::{FakeClamd, eicar};
use super::*;

/// A socket path in an empty directory: connecting to it fails at once.
fn missing_socket(dir: &std::path::Path) -> PathBuf {
	dir.join("clamd.sock")
}

async fn verdict(hook: &ClamdHook, raw: &[u8]) -> HookVerdict {
	tokio::time::timeout(Duration::from_secs(5), hook.scan(raw))
		.await
		.expect("scan exceeded test deadline")
}

fn counters(metrics: &Metrics) -> (Option<u64>, Option<u64>) {
	let snapshot = metrics.snapshot();
	(
		snapshot.get("scanner_clamd_failed").copied(),
		snapshot.get("scanner_clamd_skipped").copied(),
	)
}

#[tokio::test]
async fn defer_holds_back_a_message_clamd_could_not_scan() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(missing_socket(dir.path()))
		.with_on_error(ClamdOnError::Defer)
		.with_metrics(metrics.clone());
	assert_eq!(
		verdict(&hook, b"Subject: s\r\n\r\nhi\r\n").await,
		HookVerdict::Defer
	);
	assert_eq!(counters(&metrics), (Some(1), Some(0)));
}

#[tokio::test]
async fn accept_lets_the_same_message_through_unscanned() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(missing_socket(dir.path())).with_metrics(metrics.clone());
	assert_eq!(hook.on_error(), ClamdOnError::Accept, "the default");
	assert_eq!(
		verdict(&hook, b"Subject: s\r\n\r\nhi\r\n").await,
		HookVerdict::Accept
	);
	assert_eq!(counters(&metrics), (Some(1), Some(0)));
}

#[tokio::test]
async fn defer_also_covers_a_clamd_that_does_not_answer_in_time() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = missing_socket(dir.path());
	// Accepts the connection and never reads or answers.
	let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
	let hook = ClamdHook::new(socket)
		.with_on_error(ClamdOnError::Defer)
		.with_timeout(Duration::from_millis(200));
	assert_eq!(verdict(&hook, b"x").await, HookVerdict::Defer);
	drop(listener);
}

#[tokio::test]
async fn defer_refuses_for_good_a_message_over_the_size_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(missing_socket(dir.path()))
		.with_on_error(ClamdOnError::Defer)
		.with_max_bytes(4)
		.with_metrics(metrics.clone());
	// A retry would be just as large, and nothing may pass unscanned: the
	// sender is told now instead of after days of retries.
	assert_eq!(verdict(&hook, b"12345").await, HookVerdict::Refuse);
	assert_eq!(counters(&metrics), (Some(0), Some(1)));
	assert_eq!(hook.inspect(b"12345").await, Inspection::Skipped);
}

#[tokio::test]
async fn accept_still_lets_a_message_over_the_size_limit_through() {
	let dir = tempfile::tempdir().expect("tempdir");
	let hook = ClamdHook::new(missing_socket(dir.path())).with_max_bytes(4);
	assert_eq!(verdict(&hook, b"12345").await, HookVerdict::Accept);
}

const STREAM_LIMIT: &str = "INSTREAM size limit exceeded. ERROR";

#[tokio::test]
async fn defer_refuses_for_good_what_clamd_says_is_over_its_stream_limit() {
	let clamd = FakeClamd::start_replying(STREAM_LIMIT);
	let metrics = Arc::new(Metrics::new());
	let hook = ClamdHook::new(clamd.socket.clone())
		.with_on_error(ClamdOnError::Defer)
		.with_metrics(metrics.clone());
	assert_eq!(
		verdict(&hook, b"Subject: s\r\n\r\nhi\r\n").await,
		HookVerdict::Refuse
	);
	// clamd answered: this is not a failure of clamd to count or retry.
	assert_eq!(counters(&metrics), (Some(0), Some(1)));
	assert_eq!(
		hook.inspect(b"Subject: s\r\n\r\nhi\r\n").await,
		Inspection::Skipped
	);
}

#[tokio::test]
async fn accept_lets_through_what_clamd_says_is_over_its_stream_limit() {
	let clamd = FakeClamd::start_replying(STREAM_LIMIT);
	let hook = ClamdHook::new(clamd.socket.clone());
	assert_eq!(verdict(&hook, b"x").await, HookVerdict::Accept);
}

#[tokio::test]
async fn defer_keeps_retrying_an_error_that_may_pass() {
	// Another clamd error can be transient (a reload, a full disk): defer.
	let clamd = FakeClamd::start_replying("stream: lstat() failed. ERROR");
	let hook = ClamdHook::new(clamd.socket.clone()).with_on_error(ClamdOnError::Defer);
	assert_eq!(verdict(&hook, b"x").await, HookVerdict::Defer);
}

#[tokio::test]
async fn defer_changes_nothing_when_clamd_answers() {
	let clamd = FakeClamd::start();
	let hook = ClamdHook::new(clamd.socket.clone())
		.with_on_error(ClamdOnError::Defer)
		.with_on_found(HookVerdict::Reject);
	assert_eq!(
		verdict(&hook, b"Subject: s\r\n\r\nclean\r\n").await,
		HookVerdict::Accept
	);
	assert_eq!(
		verdict(&hook, eicar().as_bytes()).await,
		HookVerdict::Reject
	);
	assert_eq!(clamd.scans(), 2);
}
