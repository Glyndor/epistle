//! Tests for the retry loop of `write_with_replace`. Split out of
//! `layout_tests.rs` so the main layout test file stays under the
//! 500-line cap and the seam-driven tests live next to each other.

use super::test_support::{fresh_dir, local_error_name};
use super::{LocalError, layout};

/// Pin: `write_with_replace` recovers from a stale sibling temp left
/// over from a previous crash. The counter advances on every attempt,
/// so the first attempt hits `AlreadyExists` on the seeded file and
/// the retry hits the next slot, which is free. Without the retry
/// loop the test fails with the seeded `AlreadyExists` because the
/// exclusive `create_new(true)` on the first attempt refuses to
/// reuse the name.
///
/// The counter is driven by an injected `FnMut` rather than the
/// process-wide atomic. The lib suite runs tests in parallel: another
/// test calling `write_with_replace` between this one's seed and
/// `write_with_replace_using` would steal the slot the seeded file
/// was meant to collide on, and the test would pass without the retry
/// ever running. The seam is what makes the assertion about the retry
/// actually load-bearing.
#[cfg(unix)]
#[test]
fn write_with_replace_recovers_from_stale_sibling_temp() {
	let dir = fresh_dir("replace-stale-temp");
	let target = dir.path().join("mail.toml");
	let pid = std::process::id();

	// Seed the stale temp that the first attempt will collide on.
	// The counter the seam draws is 7, so the file we leave on disk
	// is `<dir>/.mail.toml-<pid>-7.tmp`.
	let stale = dir.path().join(format!(".mail.toml-{pid}-7.tmp"));
	let original = b"stale from a previous crash";
	std::fs::write(&stale, original).expect("seed stale temp");

	let calls: std::cell::RefCell<Vec<u64>> = std::cell::RefCell::new(Vec::new());
	{
		let mut counter: u64 = 0;
		let sequence = [7u64, 8];
		let mut next = || -> u64 {
			let n = sequence[counter as usize];
			counter += 1;
			calls.borrow_mut().push(n);
			n
		};
		layout::write_with_replace_using(&target, b"new contents", 0o600, &mut next)
			.expect("retry succeeds");
	}
	let calls = calls.into_inner();

	assert_eq!(
		std::fs::read(&target).expect("read target"),
		b"new contents",
		"target must hold the new contents after the retry"
	);
	assert_eq!(
		std::fs::read(&stale).expect("read stale"),
		original,
		"the seeded stale file must be untouched; the retry moved past it"
	);
	assert_eq!(
		calls,
		vec![7u64, 8],
		"next must be called exactly twice (the seeded collision, then the free slot)"
	);

	// The seeded stale file is what the retry skipped past; it stays
	// on disk because nothing in the success path unlinks it. What
	// the success path guarantees is that no temp file other than the
	// stale one we seeded survives: the retry's own temp is unlinked
	// by the rename.
	let leftover: Vec<std::path::PathBuf> = std::fs::read_dir(dir.path())
		.expect("readdir")
		.flatten()
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.map(|entry| entry.path())
		.collect();
	assert_eq!(
		leftover,
		vec![stale.clone()],
		"only the seeded stale temp may remain, found {leftover:?}"
	);
}

/// Pin: the retry loop gives up after exhausting its budget. With
/// every attempt colliding, the loop runs the initial attempt plus the
/// ten retries (`1 + MAX_RETRIES = 11` total) and surfaces the first
/// `AlreadyExists` error so the operator sees the real reason the
/// rename never happened.
#[cfg(unix)]
#[test]
fn replace_gives_up_after_the_retry_budget() {
	let dir = fresh_dir("replace-retry-budget");
	let target = dir.path().join("mail.toml");
	let pid = std::process::id();

	// Seed every slot the loop will draw so each attempt collides on
	// `create_new(true)` and the budget is exhausted without a
	// rename ever succeeding.
	for n in 0..=10u64 {
		let path = dir.path().join(format!(".mail.toml-{pid}-{n}.tmp"));
		std::fs::write(&path, b"collision").expect("seed collision");
	}

	let calls: std::cell::RefCell<Vec<u64>> = std::cell::RefCell::new(Vec::new());
	let result = {
		let mut counter: u64 = 0;
		let mut next = || -> u64 {
			let n = counter;
			counter += 1;
			calls.borrow_mut().push(n);
			n
		};
		layout::write_with_replace_using(&target, b"new", 0o600, &mut next)
	};
	let calls = calls.into_inner();

	let err = result.expect_err("every attempt collides, must give up");
	match err {
		LocalError::Io(io) => assert_eq!(
			io.kind(),
			std::io::ErrorKind::AlreadyExists,
			"the surfaced error must name AlreadyExists, got {io:?}"
		),
		other => panic!(
			"expected LocalError::Io(AlreadyExists), got {}",
			local_error_name(&other)
		),
	}
	assert_eq!(
		calls,
		(0..=10u64).collect::<Vec<_>>(),
		"next must be called once per attempt: 1 + MAX_RETRIES = 11"
	);
}

/// Pin: `write_with_replace` cleans up its sibling temporary when the
/// rename fails. The failure mode is forced by creating a non-empty
/// directory at the target path: `rename(2)` of a regular file over a
/// non-empty directory fails for every uid, and the failure path must
/// remove the sibling temp explicitly because the rename itself only
/// unlinks on success. Without the cleanup line the failure path leaves
/// a stale `<dir>/.mail.toml-*.tmp` behind that the next run would have
/// to retry past. This is the test that pins the rename-failure arm of
/// `write_with_replace_using` (the retry loop is covered by the two
/// tests above).
#[cfg(unix)]
#[test]
fn replace_rename_into_non_empty_directory_errors_and_leaves_no_temp() {
	let dir = fresh_dir("replace-dir-target");
	let target = dir.path().join("mail.toml");

	// Non-empty directory at the target path. `rename(file, dir)`
	// fails with EISDIR because the new path is itself a directory.
	std::fs::create_dir(&target).expect("create target dir");
	std::fs::write(target.join("contents"), b"x").expect("fill target dir");

	let result = layout::write_with_replace(&target, b"new", 0o600);
	assert!(
		result.is_err(),
		"rename over a non-empty directory must error, got {result:?}"
	);

	// No `.tmp` left in the parent. The sibling temp was created in
	// `dir.path()`, not in the non-empty target directory, so a
	// successful rename would have moved it onto the target and the
	// failed-rename path must unlink it explicitly.
	let leftover: Vec<std::path::PathBuf> = std::fs::read_dir(dir.path())
		.expect("readdir parent")
		.flatten()
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.map(|entry| entry.path())
		.collect();
	assert!(
		leftover.is_empty(),
		"no sibling temp may remain after a failed rename, found {leftover:?}"
	);

	// The non-empty target directory survives the failure untouched:
	// the rename refused before it could touch the directory's
	// contents.
	assert!(target.is_dir(), "target directory must remain a directory");
	assert!(
		target.join("contents").exists(),
		"target directory's contents must remain after the failed rename"
	);
}

/// Pin: the same `write_with_replace` call over a regular file target
/// succeeds and leaves no `.tmp` behind. Pairs
/// `replace_rename_into_non_empty_directory_errors_and_leaves_no_temp`:
/// the rejection case exercises the rename-failure cleanup, the
/// acceptance case exercises the rename's own temp unlink on success.
#[cfg(unix)]
#[test]
fn replace_rename_over_regular_file_succeeds_and_leaves_no_temp() {
	let dir = fresh_dir("replace-file-target");
	let target = dir.path().join("mail.toml");
	std::fs::write(&target, b"old").expect("write old");

	layout::write_with_replace(&target, b"new", 0o600).expect("replace");

	assert_eq!(
		std::fs::read(&target).expect("read target"),
		b"new",
		"target must hold the new contents"
	);

	let leftover: Vec<std::path::PathBuf> = std::fs::read_dir(dir.path())
		.expect("readdir parent")
		.flatten()
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.map(|entry| entry.path())
		.collect();
	assert!(
		leftover.is_empty(),
		"no sibling temp may remain after a successful replace, found {leftover:?}"
	);
}
