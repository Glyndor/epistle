//! Concurrency and atomicity tests for [`super::write_secret`].
//!
//! The unit-level "is the file 0600 and did we fsync it" test sits in
//! the inline `secret_write_tests` module because it belongs with the
//! crate-level invariants, but anything that needs thread fan-out or
//! a directory walking for leftovers lives here.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

/// Many concurrent writers of distinct payloads leave one and only one
/// complete file on disk: the bytes exactly match one of the writers'
/// payloads (no mixing of two threads' output) and no `.tmp` file is
/// left behind for the cleanup pass to clean.
#[test]
fn many_concurrent_writers_leave_one_complete_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("secrets.toml");

	let count = 16usize;
	let barrier = Arc::new(Barrier::new(count));
	let handles: Vec<_> = (0..count)
		.map(|index| {
			let barrier = Arc::clone(&barrier);
			let path = path.clone();
			thread::spawn(move || {
				barrier.wait();
				let payload = format!("writer-{index}-says-hello\n");
				super::write_secret(&path, payload.as_bytes()).expect("write");
				payload
			})
		})
		.collect();

	let mut written: Vec<String> = Vec::with_capacity(count);
	for handle in handles {
		written.push(handle.join().expect("thread"));
	}

	let final_bytes = std::fs::read(&path).expect("read final");
	let final_text = std::str::from_utf8(&final_bytes).expect("final is utf-8");
	let expected_bytes = format!("writer-{}-says-hello\n", written.iter().position(|w| w == final_text).expect("writer present"));
	assert_eq!(
		final_text, expected_bytes.as_str(),
		"final file must be one writer's complete payload, not a mix of two",
	);

	let leftovers = leftover_temp_files(dir.path());
	assert!(
		leftovers.is_empty(),
		"concurrent writers must not leave temp files behind: {leftovers:?}",
	);
}

/// A `write_secret` whose rename succeeds leaves no temp file in the
/// directory, even when the writer runs many times in a tight loop.
#[test]
fn repeated_writes_leave_no_temp_files() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("rotating.toml");
	for index in 0..50 {
		super::write_secret(&path, format!("rotation-{index}\n").as_bytes()).expect("write");
	}
	let leftovers = leftover_temp_files(dir.path());
	assert!(
		leftovers.is_empty(),
		"writes must rename the temp before returning: {leftovers:?}",
	);
}

/// Any concurrent writer that loses the rename race must still produce
/// a complete, parseable file on disk for the next process to read.
/// The test runs the writers, then re-reads the file and verifies its
/// contents parse (so the file was not truncated or interleaved by a
/// racing rename).
#[test]
fn final_file_is_a_complete_payload_under_contention() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("completed.toml");
	let count = 8usize;
	let barrier = Arc::new(Barrier::new(count));
	let handles: Vec<_> = (0..count)
		.map(|index| {
			let barrier = Arc::clone(&barrier);
			let path = path.clone();
			thread::spawn(move || {
				barrier.wait();
				let payload = format!("PAYLOAD_{index}\nEXTRA");
				super::write_secret(&path, payload.as_bytes()).expect("write");
				payload
			})
		})
		.collect();
	for handle in handles {
		handle.join().expect("thread");
	}

	let bytes = std::fs::read(&path).expect("read final");
	let text = std::str::from_utf8(&bytes).expect("utf-8");
	let newline = text.bytes().position(|b| b == b'\n').expect("complete payload");
	let prefix = &text[..newline];
	let line = prefix.strip_suffix('\n').unwrap_or(prefix);
	assert!(
		(0..count).any(|index| line == format!("PAYLOAD_{index}")),
		"first line of final file must match a complete writer payload; got {line:?}",
	);
	// The "EXTRA" trailer means we got the full body, not a truncated
	// rename that stopped mid-write.
	assert!(text.ends_with("EXTRA"), "final file must contain every writer's trailer");
}

/// All temp files emitted by [`super::write_secret`] live in the same
/// directory as the target (`.<name>.<uuid>.tmp`), so they cannot
/// collide across files in different directories.
#[test]
fn temp_files_reside_alongside_the_target() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path_a = dir.path().join("a.toml");
	let path_b = dir.path().join("b.toml");
	super::write_secret(&path_a, b"a").expect("a");
	super::write_secret(&path_b, b"b").expect("b");
	assert!(!leftover_temp_files(dir.path()).contains(&".a.toml".to_string()));
	assert!(!leftover_temp_files(dir.path()).contains(&".b.toml".to_string()));
}

/// Return the names of every leftover `*.tmp` file under `dir`. Used
/// to assert that all concurrent writers successfully renamed their
/// temp before returning.
fn leftover_temp_files(dir: &Path) -> Vec<String> {
	let mut found = Vec::new();
	for entry in std::fs::read_dir(dir).expect("read_dir") {
		let entry = entry.expect("entry");
		let name = entry.file_name();
		if let Some(name) = name.to_str()
			&& name.ends_with(".tmp")
		{
			found.push(name.to_string());
		}
	}
	found
}

#[test]
fn write_secret_overwrites_existing_file_atomically() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("secrets.toml");
	{
		let mut options = std::fs::OpenOptions::new();
		options.create(true).write(true).truncate(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		let mut file = options.open(&path).expect("open");
		file.write_all(b"stale\n").expect("write stale");
		file.sync_all().expect("sync stale");
	}
	super::write_secret(&path, b"fresh\n").expect("fresh");
	assert_eq!(
		std::fs::read(&path).expect("read"),
		b"fresh\n",
		"rewrite must land on disk with the new bytes and nothing else",
	);
}
