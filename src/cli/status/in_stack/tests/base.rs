use super::super::super::report::Level;

/// The verdict printed by `epistle check <area> --json` inside the container
/// is the area's verdict on the host.
#[test]
fn the_container_verdict_is_read_from_check_json() {
	let ok = br#"{"db":{"status":"ok","detail":"SELECT 1 answered","items":[]}}"#;
	let report = super::parse(ok, "db", "database");
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "SELECT 1 answered");
	let failed = br#"{"db":{"status":"fail","detail":"cannot reach PostgreSQL","items":[]}}"#;
	assert_eq!(super::parse(failed, "db", "database").status, Level::Fail);
	assert_eq!(
		super::parse(b"podup: no such service", "db", "database").status,
		Level::Fail
	);
}

/// A command that never finishes is killed at the limit instead of hanging
/// `epistle status`.
#[test]
fn a_hung_command_is_killed_at_the_limit() {
	let mut command = std::process::Command::new("sleep");
	command.arg("30");
	let started = std::time::Instant::now();
	let result = super::run_bounded(
		command,
		std::time::Instant::now() + std::time::Duration::from_millis(300),
		"database",
	);
	assert!(result.is_err(), "a hung command must be reported");
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// The antivirus verdict is read from its own key, not the database's.
#[test]
fn the_antivirus_verdict_is_read_from_its_own_key() {
	let ok = br#"{"antivirus":{"status":"ok","detail":"clamd answers","items":[]}}"#;
	assert_eq!(super::parse(ok, "antivirus", "antivirus").status, Level::Ok);
	let wrong_key = br#"{"db":{"status":"ok","detail":"SELECT 1 answered","items":[]}}"#;
	let report = super::parse(wrong_key, "antivirus", "antivirus");
	assert_eq!(report.status, Level::Fail);
	assert_eq!(
		report.detail,
		"the antivirus check in the mail container gave no answer"
	);
}

/// A stack that does not answer, three runs at once and two places: no more than
/// two runs are alive at any time, and each is over by the time of the check,
/// with the program it started killed.
#[tokio::test]
async fn a_hung_podup_neither_outlives_the_deadline_nor_frees_a_place_early() {
	use std::os::unix::fs::PermissionsExt;
	use std::sync::Arc;
	use std::time::{Duration, Instant};

	let dir = tempfile::tempdir().expect("dir");
	let marker = dir.path().join("survived");
	let podup = dir.path().join("podup");
	std::fs::write(
		&podup,
		format!("#!/bin/sh\necho $$ >> {}\nsleep 60\n", marker.display()),
	)
	.expect("script");
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let gate = Arc::new(tokio::sync::Semaphore::new(2));
	let alive = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let started = Instant::now();
	let mut runs = Vec::new();
	let mut refused = 0;
	for _ in 0..3 {
		let Ok(permit) = Arc::clone(&gate).try_acquire_owned() else {
			refused += 1;
			continue;
		};
		let mut ctx = crate::cli::status::test_support::ctx(dir.path(), "");
		ctx.podup = podup.display().to_string();
		ctx.hold = Some(Arc::new(crate::cli::status::RunHold::new(permit)));
		ctx.deadline = Instant::now() + Duration::from_secs(3);
		let (alive, peak) = (Arc::clone(&alive), Arc::clone(&peak));
		runs.push(tokio::spawn(async move {
			let now = alive.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
			peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
			let config = ctx.config.clone().expect("config");
			let report = super::run(
				&ctx,
				&config,
				std::process::Command::new("true"),
				"db",
				"database",
			)
			.await;
			alive.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
			report
		}));
	}
	assert_eq!(refused, 1, "the third run found no place");
	for run in runs {
		let report = run.await.expect("run");
		assert_eq!(report.status, Level::Fail);
	}
	assert!(peak.load(std::sync::atomic::Ordering::SeqCst) <= 2);
	assert!(
		started.elapsed() < Duration::from_secs(30),
		"{:?}",
		started.elapsed()
	);
	// The places come back once the threads of the runs have returned.
	for _ in 0..100 {
		if gate.available_permits() == 2 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert_eq!(gate.available_permits(), 2);
	// Every podup that was started is gone with what it started.
	let pids = std::fs::read_to_string(&marker).expect("both started");
	assert_eq!(pids.lines().count(), 2);
	for pid in pids.lines() {
		assert!(
			!std::path::Path::new(&format!("/proc/{pid}")).exists(),
			"podup {pid} was left running"
		);
	}
}
