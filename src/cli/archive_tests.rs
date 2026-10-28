//! Placeholder tests for the archive CLI. The behaviour is covered by
//! `imap::archive::tests` (the underlying module) and `api::v1::archive::tests`
//! (the HTTP surface); the CLI is a thin wrapper that the dispatch logic
//! delegates to. Real CLI integration tests would invoke the binary end-to-end
//! through the `Command` enum in `cli::tests`, which already covers every
//! other subcommand.
//!
//! What is checked here is the shape of the listing the CLI prints, which no
//! other test covers.

use super::*;

#[test]
fn the_listing_shows_the_time_as_an_rfc3339_instant() {
	let entries = vec![ArchivedMessage {
		id: Uuid::now_v7(),
		mailbox: "INBOX".into(),
		deleted_at: 1_700_000_000,
	}];
	let mut out = Vec::new();
	render_entries(&entries, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("2023-11-14T22:13:20Z"),
		"the time must be readable at a glance: {text}"
	);
	assert!(
		!text.contains("1700000000"),
		"the listing must not print the epoch: {text}"
	);
}
