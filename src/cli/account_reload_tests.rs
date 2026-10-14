//! `epistle account …` waits for the running server to have reloaded
//! the just-written file before returning. The test writes a fake
//! reload acknowledgement out of band: a thread simulates the
//! server's file-watcher by rewriting the reload status to the
//! fingerprint the CLI just produced. The CLI must observe the
//! match within the wait window and return at once; if the
//! acknowledgement never lands, the CLI prints the one-line note
//! and exits non-zero.
//!
//! Lives in a sibling so `account_reload.rs` stays under the
//! per-file code-line budget.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::cli::exit;
use crate::directory_store::file_watcher::Fingerprint;
use crate::directory_store::{read_reload_status, reload_fingerprint, wait_for_reload};

fn fixture() -> tempfile::TempDir {
	let dir = tempfile::tempdir().expect("tempdir");
	// Pre-existing accounts.toml so the watcher has a real file to
	// fingerprint and the CLI's wait is a meaningful operation.
	std::fs::write(
		dir.path().join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n",
	)
	.expect("write");
	dir
}

#[test]
fn missing_status_file_returns_immediately_as_no_server() {
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	// No status file, so the wait should return Ok(()) at once.
	let start = Instant::now();
	let result = wait_for_reload(
		dir.path(),
		&path,
		reload_fingerprint(&path),
		Duration::from_secs(1),
	);
	assert!(result.is_ok(), "no status file means no server: {result:?}");
	assert!(
		start.elapsed() < Duration::from_millis(50),
		"the no-server path must not block"
	);
}

#[test]
fn matching_status_file_returns_at_once() {
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let target = reload_fingerprint(&path);
	// Drop a status file with the just-written fingerprint; the
	// watcher would do this on its next poll.
	std::fs::write(
		dir.path().join("reload.status"),
		serde_json::to_string_pretty(&serde_json::json!({
			"accounts.toml": target,
		}))
		.expect("serialise"),
	)
	.expect("write status");
	let result = wait_for_reload(dir.path(), &path, target, Duration::from_secs(1));
	assert!(result.is_ok(), "matching status must return Ok: {result:?}");
}

#[test]
fn stale_status_file_waits_for_a_match() {
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let stale = Fingerprint {
		mtime_secs: 1,
		len: 1,
		ino: 1,
	};
	std::fs::write(
		dir.path().join("reload.status"),
		serde_json::to_string_pretty(&serde_json::json!({
			"accounts.toml": stale,
		}))
		.expect("serialise"),
	)
	.expect("write status");

	// The CLI's wait runs on the main thread; the simulated server
	// posts the matching fingerprint after 200 ms. The wait must
	// observe the change and return Ok.
	let target = reload_fingerprint(&path);
	let dir_path = dir.path().to_path_buf();
	let poster = std::thread::spawn(move || {
		std::thread::sleep(Duration::from_millis(200));
		std::fs::write(
			dir_path.join("reload.status"),
			serde_json::to_string_pretty(&serde_json::json!({
				"accounts.toml": target,
			}))
			.expect("serialise"),
		)
		.expect("write status");
	});
	let result = wait_for_reload(dir.path(), &path, target, Duration::from_secs(2));
	poster.join().expect("poster join");
	assert!(
		result.is_ok(),
		"stale status must wait for the new fingerprint: {result:?}"
	);
}

#[test]
fn stale_status_times_out() {
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let stale = Fingerprint {
		mtime_secs: 1,
		len: 1,
		ino: 1,
	};
	std::fs::write(
		dir.path().join("reload.status"),
		serde_json::to_string_pretty(&serde_json::json!({
			"accounts.toml": stale,
		}))
		.expect("serialise"),
	)
	.expect("write status");

	// The target the CLI is waiting for differs from the stale
	// status; the watcher never catches up, so the wait must
	// time out.
	let target = Fingerprint {
		mtime_secs: 9_999,
		len: 9_999,
		ino: 9_999,
	};
	let result = wait_for_reload(dir.path(), &path, Some(target), Duration::from_millis(150));
	assert!(matches!(
		result,
		Err(crate::directory_store::WaitError::Timeout)
	));
}

#[test]
fn read_status_round_trip() {
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let fp = reload_fingerprint(&path).expect("file has a fingerprint");
	std::fs::write(
		dir.path().join("reload.status"),
		serde_json::to_string_pretty(&serde_json::json!({
			"accounts.toml": fp,
		}))
		.expect("serialise"),
	)
	.expect("write");
	let status = read_reload_status(dir.path()).expect("read status");
	assert!(status.matches("accounts.toml", Some(fp)));
}

#[test]
fn wait_helper_succeeds_when_status_file_arrives() {
	// Drive the public `wait_for_reload_or_warn` wrapper with a
	// background thread that posts the matching status 200 ms in.
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let target = reload_fingerprint(&path);
	let dir_path = dir.path().to_path_buf();
	let target_for_thread = target;
	let poster = std::thread::spawn(move || {
		std::thread::sleep(Duration::from_millis(200));
		std::fs::write(
			dir_path.join("reload.status"),
			serde_json::to_string_pretty(&serde_json::json!({
				"accounts.toml": target_for_thread,
			}))
			.expect("serialise"),
		)
		.expect("write status");
	});

	let mut sink: Vec<u8> = Vec::new();
	let start = Instant::now();
	let result = crate::cli::account_reload::wait_for_reload_or_warn(&path, &mut sink);
	poster.join().expect("poster join");
	assert_eq!(
		result,
		Ok(ExitCode::SUCCESS),
		"the wait helper must return Ok on a status match"
	);
	// The wait observed the status 200 ms in, the call returns at
	// once after the post. Allow generous slack for a busy test
	// runner; the "no extra sleep" check is the structural one.
	assert!(start.elapsed() < Duration::from_secs(3));
	assert!(
		sink.is_empty(),
		"a matched status must not print anything: {sink:?}"
	);
	// Drop unused-import noise.
	let _ = exit::REFUSED;
}

#[test]
fn wait_helper_actually_blocks_until_status_matches() {
	// A stale status file (one that does not match the just-written
	// fingerprint) must cause the wait helper to block, not return
	// at once. We use a 200 ms timeout to keep the test inside the
	// unit-test budget; the helper must return
	// Ok(ExitCode::FAILURE) and the warning line must land on the
	// sink.
	let dir = fixture();
	let path = dir.path().join("accounts.toml");
	let stale = Fingerprint {
		mtime_secs: 1,
		len: 1,
		ino: 1,
	};
	std::fs::write(
		dir.path().join("reload.status"),
		serde_json::to_string_pretty(&serde_json::json!({
			"accounts.toml": stale,
		}))
		.expect("serialise"),
	)
	.expect("write status");

	let mut sink: Vec<u8> = Vec::new();
	let start = Instant::now();
	let result = crate::cli::account_reload::wait_for_reload_or_warn_within(
		&path,
		&mut sink,
		Duration::from_millis(200),
	);
	assert_eq!(
		result,
		Ok(ExitCode::FAILURE),
		"a stale status must surface as a timeout (the wait must have run)"
	);
	assert!(
		start.elapsed() >= Duration::from_millis(150),
		"the wait must have actually blocked for the timeout"
	);
	let sink_text = String::from_utf8(sink).expect("utf8");
	assert!(
		sink_text.contains("the server has not picked the change up yet"),
		"the timeout warning must reach the operator: {sink_text}"
	);
}
