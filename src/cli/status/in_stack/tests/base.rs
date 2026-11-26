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
/// two runs are alive at any time, and each is over once its time is, with the
/// program it started killed.
///
/// The time of the runs is long, and the test ends it when both programs have
/// started: the order is `started twice, time over, killed`, and no time is
/// waited for.
#[tokio::test]
async fn a_hung_podup_neither_outlives_the_deadline_nor_frees_a_place_early() {
	use std::os::unix::fs::PermissionsExt;
	use std::sync::Arc;
	use std::time::{Duration, Instant};

	let dir = tempfile::tempdir().expect("dir");
	let podup = dir.path().join("podup");
	std::fs::write(&podup, "#!/bin/sh\nsleep 600\n").expect("script");
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let watch = crate::cli::status::bounded::probe::watch(&podup);
	let gate = Arc::new(tokio::sync::Semaphore::new(2));
	let alive = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
		ctx.deadline = Instant::now() + Duration::from_secs(3600);
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
	watch.started_count(2).await;
	// Both programs are running and hung: the places are still taken.
	assert_eq!(gate.available_permits(), 0);
	watch.expire();
	for run in runs {
		let report = run.await.expect("run");
		assert_eq!(report.status, Level::Fail);
	}
	assert!(peak.load(std::sync::atomic::Ordering::SeqCst) <= 2);
	// The places come back once the threads of the runs have returned.
	let back = tokio::time::timeout(Duration::from_secs(120), gate.acquire_many(2)).await;
	assert!(back.is_ok(), "the places never came back");
	// Every podup that was started is gone with what it started.
	let pids = watch.pids();
	assert_eq!(pids.len(), 2);
	for pid in pids {
		assert!(
			!std::path::Path::new(&format!("/proc/{pid}")).exists(),
			"podup {pid} was left running"
		);
	}
}
