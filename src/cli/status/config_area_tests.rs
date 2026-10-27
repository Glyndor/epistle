//! Tests for the config check, including "restart pending". `sh -f <compose>`
//! stands in for `podup -f <compose> ps ...` (see `src/cli/stack/started_tests.rs`).

use std::time::{Duration, UNIX_EPOCH};

use super::check;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

/// 2026-10-09T08:00:00Z, the container start in these tests.
const STARTED: u64 = 1_791_532_800;

fn set_mtime(path: &std::path::Path, epoch: u64) {
	std::fs::File::options()
		.write(true)
		.open(path)
		.expect("open")
		.set_modified(UNIX_EPOCH + Duration::from_secs(epoch))
		.expect("set mtime");
}

fn compose(ctx: &super::Ctx, script: &str) {
	let dir = ctx
		.config
		.as_ref()
		.expect("config")
		.data_dir
		.join("compose");
	std::fs::create_dir_all(&dir).expect("compose dir");
	std::fs::write(dir.join("compose.yaml"), script).expect("compose file");
}

const MAIL_STARTED: &str =
	r#"printf '%s' '[{"Service":"mail","StartedAt":"2026-10-09T08:00:00Z"}]'"#;

#[tokio::test]
async fn a_config_edited_after_the_container_started_is_restart_pending() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	compose(&ctx, MAIL_STARTED);
	set_mtime(&ctx.path, STARTED + 3600);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "restart")
		.expect("restart item");
	assert_eq!(item.status, Level::Warn);
	assert!(item.detail.contains("restart pending"), "{}", item.detail);
}

#[tokio::test]
async fn a_config_older_than_the_container_start_is_current() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	compose(&ctx, MAIL_STARTED);
	set_mtime(&ctx.path, STARTED - 3600);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "restart")
		.expect("restart item");
	assert!(
		item.detail.contains("no restart pending"),
		"{}",
		item.detail
	);
}

#[tokio::test]
async fn without_a_compose_stack_the_restart_check_is_skipped_with_a_note() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "restart")
		.expect("restart item");
	assert!(item.detail.starts_with("skipped:"), "{}", item.detail);
	assert!(item.detail.contains("no compose stack"), "{}", item.detail);
}

#[tokio::test]
async fn an_unreadable_container_state_is_a_note_not_a_failure() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "");
	compose(&ctx, "exit 1");
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "restart")
		.expect("restart item");
	assert!(item.detail.starts_with("skipped:"), "{}", item.detail);
}

#[tokio::test]
async fn a_config_that_does_not_load_fails_and_skips_the_restart_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = ctx(dir.path(), "");
	ctx.config = Err("bad config".to_string());
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Fail);
	assert_eq!(report.detail, "bad config");
	assert!(report.items.is_empty());
}

#[tokio::test]
async fn the_verified_email_line_is_information_and_leaves_the_area_green() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(
		dir.path(),
		"[oauth]\nissuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n",
	);
	compose(&ctx, MAIL_STARTED);
	set_mtime(&ctx.path, STARTED - 3600);
	let report = check(&ctx).await;
	let item = report
		.items
		.iter()
		.find(|i| i.name == "bearer sign-in")
		.expect("the line about email_verified");
	assert_eq!(item.status, Level::Ok, "{item:?}");
	assert_eq!(report.status, Level::Ok, "{report:?}");
}
