//! Tests for the disk check: thresholds on injected numbers, plus the real
//! `statvfs` reading on a temp directory.

use super::{Level, check, evaluate};
use crate::cli::status::test_support::ctx;
use crate::smtp::session::MAX_MESSAGE_SIZE;

const TOTAL: u64 = 100 * 1024 * 1024 * 1024;

fn free_percent(percent: u64) -> Option<(u64, u64)> {
	Some((TOTAL / 100 * percent, TOTAL))
}

#[test]
fn the_free_space_thresholds_are_below_10_percent_for_warn_and_below_5_for_fail() {
	for (percent, expected) in [
		(50, Level::Ok),
		(10, Level::Ok),
		(9, Level::Warn),
		(5, Level::Warn),
		(4, Level::Fail),
		(0, Level::Fail),
	] {
		let report = evaluate(free_percent(percent));
		assert_eq!(report.status, expected, "{percent}% free: {report:?}");
	}
}

#[test]
fn the_detail_says_how_much_is_free() {
	let report = evaluate(free_percent(42));
	assert_eq!(report.detail, "42% free (42.0 GiB of 100.0 GiB)");
}

#[test]
fn less_room_than_one_message_fails_because_smtp_refuses_mail_there() {
	// A small disk that is still 24% free by percentage, but under the 25 MiB
	// the SMTP guard requires before accepting MAIL FROM.
	let total = 100 * 1024 * 1024u64;
	let available = MAX_MESSAGE_SIZE as u64 - 1;
	let report = evaluate(Some((available, total)));
	assert_eq!(report.status, Level::Fail, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "smtp")
		.expect("smtp item");
	assert_eq!(item.status, Level::Fail);
	assert_eq!(
		item.detail,
		"under 25.0 MiB free: SMTP answers 452 and refuses new mail"
	);
	let enough = evaluate(Some((MAX_MESSAGE_SIZE as u64, total)));
	assert_eq!(enough.status, Level::Ok, "{enough:?}");
}

#[test]
fn an_unreadable_filesystem_warns_instead_of_guessing() {
	let report = evaluate(None);
	assert_eq!(report.status, Level::Warn);
	assert_eq!(report.detail, "cannot read the filesystem's free space");
	let empty = evaluate(Some((0, 0)));
	assert_eq!(empty.status, Level::Warn, "{empty:?}");
}

#[tokio::test]
async fn the_real_filesystem_is_measured_through_the_data_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	let report = check(&ctx).await;
	assert!(
		report.detail.contains("% free ("),
		"expected a measured percentage: {report:?}"
	);
	assert!(matches!(
		report.status,
		Level::Ok | Level::Warn | Level::Fail
	));
}

#[tokio::test]
async fn a_data_directory_that_does_not_exist_yet_is_measured_at_its_nearest_parent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = ctx(dir.path(), "");
	let missing = dir.path().join("not/yet/created");
	ctx.config.as_mut().expect("config").data_dir = missing;
	let report = check(&ctx).await;
	assert!(report.detail.contains("% free ("), "{report:?}");
}
