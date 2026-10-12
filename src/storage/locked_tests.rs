//! Tests for the [`super`] read-mutate-write helper shared by the
//! four dynamic stores.

use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::locked::{EditError, edit, lock_path};

/// Simple struct used by the round-trip fixtures so TOML has a table
/// to anchor the values in (TOML lacks a top-level array-of-strings,
/// which is what the test fixture would otherwise default to).
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct TaggedItems {
	#[serde(default)]
	items: Vec<String>,
}

/// Edit on a missing file uses `default()`, applies the mutation, and
/// writes the serialised result atomically. A subsequent reopen reads
/// back the change.
#[test]
fn edit_applies_to_missing_file_and_persists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("state.toml");
	let state = edit(
		&path,
		|text| toml::from_str::<TaggedItems>(text).map_err(io_err),
		|state| toml::to_string_pretty(state).map_err(io_err),
		TaggedItems::default,
		|state| -> Result<(), &str> {
			state.items.push("alpha".into());
			state.items.push("bravo".into());
			Ok(())
		},
	)
	.expect("edit");
	assert_eq!(
		state,
		TaggedItems {
			items: vec!["alpha".to_string(), "bravo".to_string()]
		}
	);

	let text = std::fs::read_to_string(&path).expect("read back");
	let parsed: TaggedItems = toml::from_str(&text).expect("parse back");
	assert_eq!(parsed, state);
}

/// Edit re-reads the file from disk before applying the closure. A
/// mutation written between two consecutive edits is preserved across
/// the second one — this is the property that defeats lost updates.
#[test]
fn edit_reflects_a_writers_update_between_calls() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("state.toml");

	// Seed the file as if another process wrote it.
	crate::storage::write_secret(&path, br#"items = ["alpha"]"#).expect("seed");

	let state = edit(
		&path,
		|text| toml::from_str::<TaggedItems>(text).map_err(io_err),
		|state| toml::to_string_pretty(state).map_err(io_err),
		TaggedItems::default,
		|state| -> Result<(), &str> {
			// Without the re-read, this closure would see the empty
			// default the helper constructed on first call.
			assert_eq!(
				state.items,
				vec!["alpha".to_string()],
				"must read fresh from disk"
			);
			state.items.push("bravo".into());
			Ok(())
		},
	)
	.expect("edit");
	assert_eq!(state.items, vec!["alpha".to_string(), "bravo".to_string()]);
}

/// A mutation whose closure returns `Err` does not write the file or
/// release the lock prematurely — the file's mtime stays identical
/// after the rejection, and the next caller still reads the previous
/// on-disk content.
#[test]
fn edit_rejects_without_writing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("state.toml");
	crate::storage::write_secret(&path, b"").expect("seed empty");

	let mtime_before = std::fs::metadata(&path)
		.expect("stat")
		.modified()
		.expect("mtime");
	let result = edit(
		&path,
		|text| toml::from_str::<TaggedItems>(text).map_err(io_err),
		|state| toml::to_string_pretty(state).map_err(io_err),
		TaggedItems::default,
		|state| {
			state.items.push("alpha".into());
			Err::<(), &'static str>("rejected by the closure")
		},
	);
	assert!(matches!(
		result,
		Err(EditError::Mutate("rejected by the closure"))
	));
	let mtime_after_reject = std::fs::metadata(&path)
		.expect("stat")
		.modified()
		.expect("mtime");
	assert_eq!(
		mtime_before, mtime_after_reject,
		"a rejected edit must not rewrite the file",
	);

	// A subsequent edit that succeeds does write, of course, and that
	// is the path the caller sees on the next read. Some filesystems
	// report mtime at second granularity; sleep past one tick before
	// stat so the comparison is meaningful on those mounts.
	thread::sleep(Duration::from_millis(1100));
	let next = edit(
		&path,
		|text| toml::from_str::<TaggedItems>(text).map_err(io_err),
		|state| toml::to_string_pretty(state).map_err(io_err),
		TaggedItems::default,
		|state| -> Result<(), &str> {
			state.items.push("bravo".into());
			Ok(())
		},
	)
	.expect("second edit");
	assert_eq!(next.items, vec!["bravo".to_string()]);
	let mtime_after_success = std::fs::metadata(&path)
		.expect("stat")
		.modified()
		.expect("mtime");
	assert!(
		mtime_after_success > mtime_after_reject,
		"a successful edit must rewrite the file",
	);
}

/// Two `edit` calls that race through the lock primitive on the same
/// file both succeed and both mutations survive. Every writer's
/// addition reaches the file, regardless of how the threads interleaved
/// on the lock: a thread that ran first must see prior writes from the
/// other threads (because the helper re-reads from disk under the
/// lock), so a fresh-open at the end sees the union of contributions.
#[test]
fn concurrent_edits_do_not_lose_either_mutation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("state.toml");

	let count = 8usize;
	let barrier = Arc::new(Barrier::new(count));
	let path_a = path.clone();
	let path_b = path.clone();
	let handles: Vec<_> = (0..count)
		.map(|index| {
			let barrier = Arc::clone(&barrier);
			let path_a = path_a.clone();
			let path_b = path_b.clone();
			thread::spawn(move || {
				barrier.wait();
				edit(
					if index % 2 == 0 { &path_a } else { &path_b },
					|text| toml::from_str::<TaggedItems>(text).map_err(io_err),
					|state| toml::to_string_pretty(state).map_err(io_err),
					TaggedItems::default,
					|state| -> Result<(), &str> {
						state.items.push(format!("writer-{index}"));
						Ok(())
					},
				)
				.expect("edit")
			})
		})
		.collect();

	for handle in handles {
		handle.join().expect("thread");
	}

	let text = std::fs::read_to_string(&path).expect("read final state");
	let parsed: TaggedItems = toml::from_str(&text).expect("parse final state");
	let mut parsed_items = parsed.items;
	parsed_items.sort_unstable();
	let mut expected: Vec<String> = (0..count).map(|i| format!("writer-{i}")).collect();
	expected.sort_unstable();
	assert_eq!(
		parsed_items, expected,
		"every concurrent edit's contribution must reach the file",
	);
}

/// The lock path lives next to the data file (`.<name>.lock`) in the
/// same directory, so the lock inherits the data file's lifetime and
/// cannot outlive it as `cache.db-wal` patterns so often do.
#[test]
fn lock_path_lives_alongside_the_data_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("accounts.toml");
	assert_eq!(
		lock_path(&path),
		dir.path().join(".accounts.toml.lock"),
		"the lock must sit next to the data file with a leading dot",
	);
	// Top-level path with no parent falls back to ".".
	let top = Path::new("relative.toml");
	assert_eq!(lock_path(top), Path::new(".").join(".relative.toml.lock"));
}

fn io_err<E: std::fmt::Display>(error: E) -> std::io::Error {
	std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}
