//! Tests for the antivirus check against a fake clamd on a Unix socket.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use super::{evaluate, with_scan_health};
use crate::antispam::clamd::health::HealthFile;
use crate::cli::status::report::{AreaReport, Level};

/// 2026-10-09T08:00:00Z.
const BUILT: i64 = 1_791_532_800;
const LIMIT: Duration = Duration::from_secs(2);

/// A clamd that answers `nPING` with `ping_reply` and `nVERSION` with
/// `version_reply`; `None` leaves that command unanswered (connection held).
fn fake_clamd(
	dir: &Path,
	ping_reply: Option<&'static str>,
	version_reply: Option<&'static str>,
) -> PathBuf {
	let path = dir.join("clamd.sock");
	let listener = UnixListener::bind(&path).expect("bind");
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut line = Vec::new();
				let mut byte = [0u8; 1];
				while stream.read(&mut byte).await.is_ok_and(|n| n == 1) {
					line.push(byte[0]);
					if byte[0] == b'\n' {
						break;
					}
				}
				let reply = match line.as_slice() {
					b"nPING\n" => ping_reply,
					b"nVERSION\n" => version_reply,
					_ => Some("UNKNOWN COMMAND\n"),
				};
				match reply {
					Some(text) => {
						let _ = stream.write_all(text.as_bytes()).await;
					}
					None => std::future::pending::<()>().await,
				}
			});
		}
	});
	path
}

#[tokio::test]
async fn a_healthy_clamd_reports_the_database_age() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = fake_clamd(
		dir.path(),
		Some("PONG\n"),
		Some("ClamAV 1.0.1/27000/Mon Oct  5 08:00:00 2026\n"),
	);
	let report = evaluate(&socket, BUILT, LIMIT).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(
		report.detail,
		"clamd answers; ClamAV 1.0.1, signature database 4 days old"
	);
}

#[tokio::test]
async fn a_version_without_a_date_is_still_ok_and_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = fake_clamd(dir.path(), Some("PONG\n"), Some("ClamAV 1.0.1\n"));
	let report = evaluate(&socket, BUILT, LIMIT).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(
		report.items[1].detail,
		"ClamAV 1.0.1, signature database age not reported"
	);
}

#[tokio::test]
async fn anything_but_pong_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = fake_clamd(dir.path(), Some("ERROR\n"), Some("ClamAV 1.0.1\n"));
	let report = evaluate(&socket, BUILT, LIMIT).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(report.detail, "unexpected reply: ERROR");
}

#[tokio::test]
async fn a_missing_socket_fails_naming_the_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = dir.path().join("absent.sock");
	let report = evaluate(&socket, BUILT, LIMIT).await;
	assert_eq!(report.status, Level::Fail);
	assert!(
		report
			.detail
			.starts_with(&format!("cannot connect to {}", socket.display())),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn a_clamd_that_never_replies_is_cut_off_at_the_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = fake_clamd(dir.path(), None, None);
	let began = Instant::now();
	let report = evaluate(&socket, BUILT, Duration::from_millis(300)).await;
	assert_eq!(report.status, Level::Fail);
	assert_eq!(report.detail, "no PING reply within 300ms");
	assert!(began.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_failing_version_command_only_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let socket = fake_clamd(dir.path(), Some("PONG\n"), None);
	let report = evaluate(&socket, BUILT, Duration::from_millis(300)).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items[0].status, Level::Ok);
	assert_eq!(report.items[1].detail, "no VERSION reply within 300ms");
}

#[tokio::test]
async fn without_clamd_configured_there_is_nothing_to_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = crate::cli::status::test_support::ctx(dir.path(), "");
	let report = super::check(&ctx).await;
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "no [antispam] clamd_socket is configured");
}

#[test]
fn scans_that_keep_failing_open_turn_a_healthy_clamd_into_a_warning() {
	let dir = tempfile::tempdir().expect("tempdir");
	let healthy = || AreaReport::ok("clamd answers; ClamAV 1.0.1");
	assert_eq!(
		with_scan_health(healthy(), dir.path(), BUILT),
		healthy(),
		"nothing recorded, nothing added"
	);
	let file = HealthFile::new(dir.path());
	file.failed();
	file.failed();
	let report = with_scan_health(healthy(), dir.path(), BUILT);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert!(
		report.detail.contains("2 scans failed open since"),
		"{report:?}"
	);
	assert!(report.detail.contains("accepted unscanned"), "{report:?}");
	let broken = with_scan_health(AreaReport::fail("cannot connect"), dir.path(), BUILT);
	assert_eq!(broken.status, Level::Fail, "a failure stays a failure");
	file.succeeded();
	let report = with_scan_health(healthy(), dir.path(), BUILT);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(
		report.items[0].detail.starts_with("scanning again since"),
		"{report:?}"
	);
}
