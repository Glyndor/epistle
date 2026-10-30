//! Tests for the per-account Message-ID guard that backs `save_sent`.

use super::{Entry, Guard, MAX_ENTRIES};
use crate::util::path_component::{AccountName, FixedDir};
use std::fs;

fn temp_data_dir() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

fn ensure_account(data_dir: &std::path::Path, account: &str) {
	let name = AccountName::new(account).expect("valid account");
	let root = name.root(data_dir).expect("root");
	fs::create_dir_all(root.child(FixedDir::New).unwrap()).unwrap();
	fs::create_dir_all(root.child(FixedDir::Tmp).unwrap()).unwrap();
}

#[test]
fn a_missing_file_yields_an_empty_guard() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	let (count, last) = guard.count_entries().expect("count");
	assert_eq!(count, 0, "fresh guard has no entries");
	assert!(last.is_none(), "fresh guard has no last entry");
}

#[test]
fn record_then_recent_round_trip() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	guard.record("<a@x>").expect("record");
	let recent = guard
		.is_recent("<a@x>")
		.expect("is_recent")
		.expect("is present");
	assert_eq!(recent.message_id, "<a@x>");
	assert!(recent.stored_at > 0);
}

#[test]
fn record_dedupes_when_the_same_message_id_is_added_twice() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	guard.record("<a@x>").expect("first record");
	guard.record("<a@x>").expect("second record");
	let (count, _) = guard.count_entries().expect("count");
	assert_eq!(
		count, 1,
		"duplicate record bumps the timestamp, not the count"
	);
}

#[test]
fn a_full_file_drops_the_oldest_entry() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	for index in 0..MAX_ENTRIES + 5 {
		guard
			.record(&format!("<m{index}@x>"))
			.expect("record fills the file past the cap");
	}
	let (count, _) = guard.count_entries().expect("count");
	assert_eq!(count, MAX_ENTRIES, "file stays bounded");
	assert!(
		guard.is_recent("<m0@x>").expect("recent").is_none(),
		"oldest entry was evicted when the bound was crossed"
	);
	assert!(
		guard
			.is_recent(&format!("<m{}@x>", MAX_ENTRIES + 4))
			.expect("recent")
			.is_some(),
		"the freshest entry is kept"
	);
}

#[test]
fn pruning_drops_entries_older_than_the_window() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	// Forge an entry that is older than the freshness window.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let long_ago = now.saturating_sub(Guard::window_secs() * 2);
	let stale = vec![Entry {
		message_id: "<old@x>".to_string(),
		stored_at: long_ago,
	}];
	let serialised = serde_json::to_string(&stale).unwrap();
	fs::write(guard.path(), serialised).expect("write stale entry");
	guard.prune().expect("prune");
	let (count, last) = guard.count_entries().expect("count");
	assert_eq!(count, 0, "stale entry pruned");
	assert!(last.is_none());
}

#[test]
fn pruning_keeps_entries_within_the_window() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	guard.record("<fresh@x>").expect("record");
	guard.prune().expect("prune");
	let (count, _) = guard.count_entries().expect("count");
	assert_eq!(count, 1, "fresh entry survives a prune");
}

#[test]
fn is_recent_returns_none_for_an_unrecorded_message_id() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	guard.record("<known@x>").expect("record");
	assert!(guard.is_recent("<other@x>").expect("recent").is_none());
}

#[test]
fn separate_accounts_keep_independent_files() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	ensure_account(dir.path(), "bob");
	let alice = Guard::open(dir.path(), "alice").expect("alice");
	let bob = Guard::open(dir.path(), "bob").expect("bob");
	alice.record("<a@x>").expect("alice record");
	assert!(alice.is_recent("<a@x>").expect("alice").is_some());
	assert!(bob.is_recent("<a@x>").expect("bob").is_none());
	assert_ne!(alice.path(), bob.path());
}

#[test]
fn raw_entries_lists_every_recorded_message_id() {
	let dir = temp_data_dir();
	ensure_account(dir.path(), "alice");
	let guard = Guard::open(dir.path(), "alice").expect("guard opens");
	guard.record("<a@x>").expect("record a");
	guard.record("<b@x>").expect("record b");
	let entries = guard.raw_entries().expect("raw entries");
	let ids: Vec<&str> = entries.iter().map(|e| e.message_id.as_str()).collect();
	assert!(ids.contains(&"<a@x>"));
	assert!(ids.contains(&"<b@x>"));
	assert_eq!(entries.len(), 2);
}
