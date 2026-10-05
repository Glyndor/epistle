//! Tests for the staging-file retry loop and the `StagingGuard`
//! that removes the staging file on a write failure. Lifted into a
//! sibling so `apply_failures_tests_c.rs` stays under the per-file
//! line limit. Production uses `create_unique_staging` (the real
//! CSPRNG plus the real `write_all` and `sync_all` step); these
//! tests drive `create_unique_staging_with`, the seam that injects
//! the suffix source and the write step so a controlled collision
//! sequence and a forced write failure can be exercised.

use super::*;
use super::tests_failures::apply_error_name;

#[cfg(unix)]
fn real_write(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
	use std::io::Write;
	file.write_all(bytes)?;
	file.sync_all()
}

fn write_fails_injected(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
	let _ = (file, bytes);
	Err(std::io::Error::other("injected"))
}

/// A pre-existing sibling at the suffix the loop would draw first
/// must not stop the call from succeeding: the retry loop draws a
/// fresh suffix on each attempt, so the next candidate wins. The
/// pre-existing sibling keeps its original bytes; the operator's
/// file is not the staging step's to lose.
#[cfg(unix)]
#[test]
fn retry_draws_a_fresh_suffix_on_each_attempt() {
	let dir = tempfile::tempdir().expect("tempdir");
	let parent = dir.path();
	let staging_pre = parent.join("mail.toml.config.tmp.aaaa");
	let original_bytes = b"operator-owned file";
	std::fs::write(&staging_pre, original_bytes).expect("write pre-existing sibling");
	let body = "hostname = \"mail.example.org\"\n";
	let mut counter = 0u32;
	let result = apply_config::create_unique_staging_with(
		parent,
		"mail.toml",
		body,
		&mut || {
			counter += 1;
			if counter == 1 {
				"aaaa".to_string()
			} else {
				"bbbb".to_string()
			}
		},
		real_write,
	);
	let (_, staging) = result.expect("retry must find a fresh candidate on the second draw");
	assert!(
		staging.ends_with("mail.toml.config.tmp.bbbb"),
		"the returned staging path must carry the fresh suffix: {}",
		staging.display()
	);
	let still = std::fs::read(&staging_pre).expect("read pre-existing sibling");
	assert_eq!(
		still, original_bytes,
		"the pre-existing sibling at the colliding suffix must keep its bytes"
	);
}

/// Sixteen attempts that all collide with an existing file must
/// surface as `ApplyError::ConfigWrite`, and the suffix source must
/// be called exactly sixteen times: the retry budget is the safety
/// bound, and the test pins both the budget and the exhaustion path.
#[cfg(unix)]
#[test]
fn retry_gives_up_after_sixteen_collisions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let parent = dir.path();
	let staging_pre = parent.join("mail.toml.config.tmp.aaaa");
	std::fs::write(&staging_pre, b"operator-owned file").expect("write pre-existing sibling");
	let mut counter = 0u32;
	let result = apply_config::create_unique_staging_with(
		parent,
		"mail.toml",
		"hostname = \"x\"\n",
		&mut || {
			counter += 1;
			"aaaa".to_string()
		},
		real_write,
	);
	let err = result.expect_err("sixteen collisions must surface as ConfigWrite");
	let ApplyError::ConfigWrite(_path, io) = &err else {
		panic!("expected ConfigWrite, got {}", apply_error_name(&err));
	};
	assert_eq!(
		counter, 16,
		"the suffix source must be called exactly sixteen times, got {counter}"
	);
	assert!(
		io.to_string().contains("16 attempts"),
		"the diagnostic must name the budget: {io}"
	);
}

/// A write failure inside the staging step must leave no staging
/// file behind on disk: the `StagingGuard` unlinks it on every
/// error path so a partial payload never blocks the next run on
/// its own `O_EXCL` blocker.
#[cfg(unix)]
#[test]
fn staging_file_is_removed_when_the_write_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let parent = dir.path();
	let mut counter = 0u32;
	let result = apply_config::create_unique_staging_with(
		parent,
		"mail.toml",
		"hostname = \"x\"\n",
		&mut || {
			counter += 1;
			format!("suffix{counter:08x}")
		},
		write_fails_injected,
	);
	let err = result.expect_err("a write failure must surface as ConfigWrite");
	let ApplyError::ConfigWrite(_path, io) = &err else {
		panic!("expected ConfigWrite, got {}", apply_error_name(&err));
	};
	assert!(
		io.to_string().contains("injected"),
		"the diagnostic must carry the injected message: {io}"
	);
	let mut leftovers: Vec<std::path::PathBuf> = Vec::new();
	for entry in std::fs::read_dir(parent).expect("read_dir") {
		let entry = entry.expect("dir entry");
		let name = entry.file_name();
		let s = name.to_string_lossy();
		if s.starts_with("mail.toml.config.tmp.") {
			leftovers.push(entry.path());
		}
	}
	assert!(
		leftovers.is_empty(),
		"no staging file may survive a write failure: {leftovers:?}"
	);
}

/// Acceptance half of the write-failure pair: when the write step
/// succeeds, the staging file is on disk with the exact bytes the
/// caller passed in, ready for the rename onto `config_path`. A
/// guard that armed itself on the success path would unlink a file
/// the rename needs to move.
#[cfg(unix)]
#[test]
fn staging_file_is_kept_for_the_caller_when_the_write_succeeds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let parent = dir.path();
	let body = "hostname = \"x\"\n";
	let mut counter = 0u32;
	let result = apply_config::create_unique_staging_with(
		parent,
		"mail.toml",
		body,
		&mut || {
			counter += 1;
			format!("aaaa{counter:08x}")
		},
		real_write,
	);
	let (_, staging) = result.expect("a successful write must return the staging path");
	let bytes = std::fs::read(&staging).expect("read staging");
	assert_eq!(
		bytes,
		body.as_bytes(),
		"the staging file must hold the exact bytes the caller passed in"
	);
}
