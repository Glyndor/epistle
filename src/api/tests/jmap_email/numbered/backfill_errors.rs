//! The blob-ownership backfill says which blobs failed and why, and logs a
//! run with errors as a warning (a clean run stays at info).

use crate::api::jmap::{LISTED_FAILURES, backfill_blob_ownership};
use crate::cli::trace::capture::{Capture, CapturedEvent};
use tracing_subscriber::layer::SubscriberExt;

/// Run `f` with a subscriber that records every event.
fn capture<F: FnOnce()>(f: F) -> Vec<CapturedEvent> {
	crate::cli::trace::capture::keep_callsites_live();
	let capture = Capture::default();
	let events = capture.events.clone();
	let _guard =
		tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
	f();
	std::mem::take(&mut *events.lock().expect("capture"))
}

/// A data directory where alice owns `count` stored messages whose `.owner`
/// sidecar cannot be read (it is a directory), so each one is an error.
fn unreadable_blobs(path: &std::path::Path, count: usize) -> Vec<uuid::Uuid> {
	let inbox = path.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir inbox");
	std::fs::create_dir_all(path.join("blobs")).expect("mkdir blobs");
	(0..count)
		.map(|_| {
			let id = uuid::Uuid::now_v7();
			std::fs::write(inbox.join(format!("{id}.eml")), b"m").expect("write message");
			std::fs::write(path.join("blobs").join(id.to_string()), b"p").expect("write payload");
			let sidecar = crate::api::jmap::blob_path::read_path(path, id, ".owner");
			std::fs::create_dir_all(&sidecar).expect("sidecar as directory");
			id
		})
		.collect()
}

fn warnings(events: &[CapturedEvent]) -> Vec<&CapturedEvent> {
	events
		.iter()
		.filter(|event| event.level == tracing::Level::WARN)
		.collect()
}

#[test]
fn an_unreadable_blob_is_listed_with_its_account_blob_and_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ids = unreadable_blobs(dir.path(), 1);
	let stats = backfill_blob_ownership(dir.path(), &["alice".to_string()]);
	assert_eq!(stats.errors, 1);
	assert_eq!(stats.failures.len(), 1);
	let failure = &stats.failures[0];
	assert_eq!(failure.account, "alice");
	assert_eq!(failure.blob.as_deref(), Some(ids[0].to_string().as_str()));
	assert!(
		failure.reason.contains("owner sidecar"),
		"reason must say what failed, got {:?}",
		failure.reason
	);
}

#[test]
fn errors_are_listed_up_to_the_bound_and_the_rest_counted() {
	let dir = tempfile::tempdir().expect("tempdir");
	unreadable_blobs(dir.path(), LISTED_FAILURES + 3);
	let stats = backfill_blob_ownership(dir.path(), &["alice".to_string()]);
	assert_eq!(stats.errors as usize, LISTED_FAILURES + 3);
	assert_eq!(stats.failures.len(), LISTED_FAILURES);
	let events = capture(|| stats.log());
	let warned = warnings(&events);
	let lines = events
		.iter()
		.filter(|event| {
			event.fields.get("message").map(String::as_str)
				== Some("jmap blob-ownership backfill error")
		})
		.count();
	assert_eq!(lines, LISTED_FAILURES, "one warn line per listed error");
	let unlisted = warned
		.iter()
		.find(|event| event.fields.contains_key("unlisted"))
		.expect("a line counts the errors past the bound");
	assert_eq!(unlisted.fields["unlisted"], "3");
}

#[test]
fn a_run_with_errors_summarises_at_warn() {
	let dir = tempfile::tempdir().expect("tempdir");
	unreadable_blobs(dir.path(), 1);
	let stats = backfill_blob_ownership(dir.path(), &["alice".to_string()]);
	let events = capture(|| stats.log());
	let summary = events
		.iter()
		.find(|event| event.fields.get("errors").map(String::as_str) == Some("1"))
		.expect("a summary line");
	assert_eq!(summary.level, tracing::Level::WARN);
}

#[test]
fn a_clean_run_stays_at_info() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir inbox");
	std::fs::create_dir_all(dir.path().join("blobs")).expect("mkdir blobs");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), b"m").expect("write message");
	std::fs::write(dir.path().join("blobs").join(id.to_string()), b"p").expect("write payload");
	let stats = backfill_blob_ownership(dir.path(), &["alice".to_string()]);
	assert_eq!((stats.written, stats.errors), (1, 0));
	let events = capture(|| stats.log());
	assert!(warnings(&events).is_empty(), "a clean run must not warn");
	let summary = events
		.iter()
		.find(|event| event.fields.contains_key("scanned"))
		.expect("a summary line");
	assert_eq!(summary.level, tracing::Level::INFO);
}
