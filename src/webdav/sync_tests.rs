use super::{CHANGELOG, Change, MAX_ENTRIES, current, parse_token, record, record_many, since};
use std::path::Path;

fn empty_collection() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	let coll = dir.path().join("coll");
	std::fs::create_dir(&coll).expect("mkdir");
	dir
}

#[tokio::test]
async fn empty_collection_has_sequence_zero() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	let state = current(&coll).await;
	assert_eq!(state.sequence, 0);
	assert_eq!(state.token, "urn:epistle:sync:0");
}

#[tokio::test]
async fn record_increments_sequence() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	let state = current(&coll).await;
	assert_eq!(state.sequence, 1);
	assert_eq!(state.token, "urn:epistle:sync:1");
	record(&coll, "b.ics", false).await;
	let state = current(&coll).await;
	assert_eq!(state.sequence, 2);
}

#[tokio::test]
async fn record_writes_log_line() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	record(&coll, "b.ics", true).await;
	let text = std::fs::read_to_string(coll.join(CHANGELOG)).expect("log");
	assert!(text.contains("1\ta.ics\tfalse"));
	assert!(text.contains("2\tb.ics\ttrue"));
}

#[tokio::test]
async fn since_returns_only_strictly_newer_entries() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	record(&coll, "b.ics", false).await;
	record(&coll, "c.ics", true).await;
	let entries: Vec<Change> = since(&coll, 1).await;
	assert_eq!(entries.len(), 2);
	assert_eq!(entries[0].href, "b.ics");
	assert!(!entries[0].deleted);
	assert_eq!(entries[1].href, "c.ics");
	assert!(entries[1].deleted);
}

#[tokio::test]
async fn since_zero_returns_all() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	record(&coll, "b.ics", false).await;
	let entries = since(&coll, 0).await;
	assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn since_at_or_above_highest_returns_empty() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	record(&coll, "b.ics", false).await;
	let entries = since(&coll, 2).await;
	assert!(entries.is_empty());
}

#[tokio::test]
async fn parse_token_recognises_issued_tokens() {
	assert_eq!(parse_token("urn:epistle:sync:7"), Some(7));
	assert_eq!(parse_token("urn:epistle:sync:0"), Some(0));
	assert_eq!(parse_token("urn:epistle:sync:999999"), Some(999_999));
}

#[tokio::test]
async fn parse_token_rejects_garbage() {
	assert_eq!(parse_token("urn:example:sync:7"), None);
	assert_eq!(parse_token("urn:epistle:sync:"), None);
	assert_eq!(parse_token("urn:epistle:sync:abc"), None);
	assert_eq!(parse_token(""), None);
	assert_eq!(parse_token("7"), None);
}

#[tokio::test]
async fn record_many_shares_one_sequence_run() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	record_many(
		&coll,
		&[("b.ics".to_string(), false), ("c.ics".to_string(), true)],
	)
	.await;
	let entries = since(&coll, 0).await;
	assert_eq!(entries.len(), 3);
	assert_eq!(entries[1].sequence, 2);
	assert_eq!(entries[2].sequence, 3);
}

#[tokio::test]
async fn record_many_with_no_entries_is_a_noop() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record_many(&coll, &[]).await;
	let state = current(&coll).await;
	assert_eq!(state.sequence, 0);
	assert!(!coll.join(CHANGELOG).exists());
}

#[tokio::test]
async fn trim_keeps_only_the_most_recent_entries() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	// Exceed the cap by a wide margin so the trim has work to do.
	let total = MAX_ENTRIES + 25;
	for i in 0..total {
		record(&coll, &format!("{i:04}.ics"), false).await;
	}
	let text = std::fs::read_to_string(coll.join(CHANGELOG)).expect("log");
	let lines: Vec<&str> = text.lines().collect();
	assert_eq!(lines.len(), MAX_ENTRIES);
	// The first retained line is the (total - MAX_ENTRIES + 1)-th change.
	let first_seq: u64 = lines[0]
		.split('\t')
		.next()
		.and_then(|s| s.parse().ok())
		.expect("first seq");
	let expected_first = (total - MAX_ENTRIES + 1) as u64;
	assert_eq!(first_seq, expected_first);
}

#[tokio::test]
async fn since_below_oldest_returns_everything_kept() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	// Push past the cap.
	let total = MAX_ENTRIES + 10;
	for i in 0..total {
		record(&coll, &format!("{i:04}.ics"), false).await;
	}
	let entries = since(&coll, 0).await;
	assert_eq!(entries.len(), MAX_ENTRIES);
}

#[tokio::test]
async fn record_appends_atomically_when_log_is_missing() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	// No prior log file: the create-new fallback path runs.
	record(&coll, "x.ics", false).await;
	assert!(coll.join(CHANGELOG).is_file());
	let text = std::fs::read_to_string(coll.join(CHANGELOG)).expect("log");
	assert!(text.starts_with("1\tx.ics\tfalse"));
}

#[tokio::test]
async fn changelog_path_is_inside_collection() {
	let dir = empty_collection();
	let coll = dir.path().join("coll");
	record(&coll, "a.ics", false).await;
	let log = coll.join(CHANGELOG);
	assert!(log.starts_with(coll.as_path()));
	// And nothing else was touched in the parent.
	assert!(
		std::fs::read_dir(dir.path())
			.expect("read parent")
			.flatten()
			.all(|entry| entry.path() == coll
				|| entry.path() == log
				|| entry.path() == coll.join("coll"))
	);
	let _ = Path::new("unused");
}
