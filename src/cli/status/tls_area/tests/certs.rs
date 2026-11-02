//! The certificates container in `status`: its state, and the days the
//! certificate in service has left when nothing renews it.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::super::certs::{item, state_in};
use super::evaluate;
use crate::cli::status::Ctx;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const NOW: u64 = 1_791_504_000;
const DAY: i64 = 86_400;

#[test]
fn the_state_is_read_from_the_certs_row() {
	let rows = r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"exited"}]"#;
	assert_eq!(state_in(rows), Ok(Some("exited".to_string())));
	assert_eq!(
		state_in(r#"[{"Service":"mail","State":"running"}]"#),
		Ok(None)
	);
	assert!(state_in("not json").is_err());
}

#[test]
fn a_running_container_renews() {
	let running = item(&Ok(Some("running".to_string())), 40 * DAY);
	assert_eq!(running.status, Level::Ok);
	assert!(
		running.detail.contains("40 days left"),
		"{}",
		running.detail
	);
}

#[test]
fn a_stopped_container_warns_with_the_days_left_and_fails_close_to_expiry() {
	let stopped = item(&Ok(Some("exited".to_string())), 40 * DAY);
	assert_eq!(stopped.status, Level::Warn);
	assert!(stopped.detail.contains("is exited"), "{}", stopped.detail);
	assert!(
		stopped.detail.contains("40 days left"),
		"{}",
		stopped.detail
	);
	let late = item(&Ok(Some("exited".to_string())), 3 * DAY);
	assert_eq!(late.status, Level::Fail);
	let missing = item(&Ok(None), 40 * DAY);
	assert!(
		missing.detail.contains("is not running"),
		"{}",
		missing.detail
	);
	let unread = item(&Err("cannot run podup".to_string()), 40 * DAY);
	assert_eq!(unread.status, Level::Warn);
	assert!(
		unread.detail.contains("could not be read"),
		"{}",
		unread.detail
	);
}

/// A `[tls]` pair expiring 40 days after the clock, and `extra` config.
fn tls_ctx(dir: &Path, extra: &str) -> Ctx {
	let mut params =
		rcgen::CertificateParams::new(vec!["mail.example.org".to_string()]).expect("params");
	let secs = i64::try_from(NOW).expect("now") + 40 * DAY;
	let (year, month, day) = crate::webdav::rrule::civil_from_secs(secs);
	params.not_before = rcgen::date_time_ymd(2020, 1, 1);
	params.not_after = rcgen::date_time_ymd(year as i32, month as u8, day as u8);
	let key = rcgen::KeyPair::generate().expect("key");
	let cert = params.self_signed(&key).expect("certificate");
	let (cert_path, key_path) = (dir.join("tls.pem"), dir.join("tls.key"));
	std::fs::write(&cert_path, cert.pem()).expect("write cert");
	std::fs::write(&key_path, key.serialize_pem()).expect("write key");
	let mut ctx = ctx(
		dir,
		&format!(
			"{extra}[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
			cert_path.display().to_string(),
			key_path.display().to_string()
		),
	);
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	ctx
}

/// A compose file with the given services, and a `podup` that answers `ps`
/// with `rows` whatever it is asked.
fn stack(ctx: &mut Ctx, dir: &Path, services: &str, rows: &str) {
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let compose = crate::cli::init::compose_file_path(&data_dir);
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("compose dir");
	std::fs::write(&compose, format!(r#"{{"services": {services}}}"#)).expect("compose");
	let podup = dir.join("podup");
	std::fs::write(&podup, format!("#!/bin/sh\nprintf '%s' '{rows}'\n")).expect("podup");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("mode");
	ctx.podup = podup.display().to_string();
}

#[tokio::test]
async fn a_split_stack_reports_the_container_and_the_waiting_dkim_rotation() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(
		dir.path(),
		"[dkim]\nselector = \"s1\"\nkey_file = \"/nonexistent/dkim.pem\"\n",
	);
	stack(
		&mut ctx,
		dir.path(),
		r#"{"mail": {}, "certs": {}}"#,
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"exited"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let certs = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(certs.status, Level::Warn, "{report:?}");
	assert!(certs.detail.contains("40 days left"), "{}", certs.detail);
	assert!(
		report.items.iter().any(|item| item.name == "dkim rotation"),
		"{report:?}"
	);
}

/// The control: the same `podup` answer on a stack without the container
/// says nothing about it.
#[tokio::test]
async fn a_stack_without_the_container_has_no_certs_item() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), "");
	stack(
		&mut ctx,
		dir.path(),
		r#"{"mail": {}}"#,
		r#"[{"Service":"certs","State":"exited"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert!(
		!report
			.items
			.iter()
			.any(|item| item.name == "certs" || item.name == "dkim rotation"),
		"{report:?}"
	);
}
