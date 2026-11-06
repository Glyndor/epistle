//! The certificates container in `status`: its state, and the days the
//! certificate in service has left when nothing renews it.

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::super::certs::{Renewal, item};
use super::evaluate;
use crate::cli::stack::certs::Upness;
use crate::cli::status::Ctx;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const NOW: u64 = 1_791_504_000;
const DAY: i64 = 86_400;

/// A `certs` container that keeps running, with the same start in both looks.
const RUNNING: &str = r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"running","StartedAt":"2026-11-02T06:30:01Z"}]"#;

#[test]
fn a_running_container_renews() {
	let running = item(&Upness::Up, None, 40 * DAY);
	assert_eq!(running.status, Level::Ok);
	assert!(
		running.detail.contains("40 days left"),
		"{}",
		running.detail
	);
}

#[test]
fn a_stopped_container_warns_with_the_days_left_and_fails_close_to_expiry() {
	let stopped = item(&Upness::Down("is exited".to_string()), None, 40 * DAY);
	assert_eq!(stopped.status, Level::Warn);
	assert!(stopped.detail.contains("is exited"), "{}", stopped.detail);
	assert!(
		stopped.detail.contains("40 days left"),
		"{}",
		stopped.detail
	);
	let late = item(&Upness::Down("is exited".to_string()), None, 3 * DAY);
	assert_eq!(late.status, Level::Fail);
	let missing = item(&Upness::Down("is not running".to_string()), None, 40 * DAY);
	assert!(
		missing.detail.contains("is not running"),
		"{}",
		missing.detail
	);
	let unread = item(
		&Upness::Unreadable("cannot run podup".to_string()),
		None,
		40 * DAY,
	);
	assert_eq!(unread.status, Level::Warn);
	assert!(
		unread.detail.contains("could not be read"),
		"{}",
		unread.detail
	);
}

/// A container that keeps restarting is not up: the renewal it is supposed
/// to do is not proven, so the item is not `ok`.
#[test]
fn an_unsteady_container_is_not_ok() {
	let unsteady = item(
		&Upness::Unsteady(
			"did not stay up (it was running since \"a\", then running since \
		                    \"b\")"
				.to_string(),
		),
		None,
		40 * DAY,
	);
	assert_ne!(unsteady.status, Level::Ok, "{unsteady:?}");
	assert!(
		unsteady.detail.contains("did not stay up"),
		"{}",
		unsteady.detail
	);
}

/// A renewal that failed leaves its reason behind; the item says so instead
/// of reporting that the certificate is renewed.
#[test]
fn a_failed_renewal_is_not_ok() {
	let failed = item(
		&Upness::Up,
		Some(&Renewal::Failed(
			"the DNS provider refused the challenge".to_string(),
		)),
		40 * DAY,
	);
	assert_eq!(failed.status, Level::Warn, "{failed:?}");
	assert!(
		failed
			.detail
			.contains("the DNS provider refused the challenge"),
		"{}",
		failed.detail
	);
	let late = item(
		&Upness::Up,
		Some(&Renewal::Failed("the CA refused".to_string())),
		3 * DAY,
	);
	assert_eq!(late.status, Level::Fail);
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

/// The compose file of the stack, with the given services.
fn compose_file(ctx: &Ctx, services: &str) -> PathBuf {
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let compose = crate::cli::init::compose_file_path(&data_dir);
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("compose dir");
	std::fs::write(&compose, format!(r#"{{"services": {services}}}"#)).expect("compose");
	compose
}

/// A `podup` that answers `ps` with `rows` whatever it is asked.
fn podup(dir: &Path, rows: &str) -> String {
	write_podup(dir, &format!("#!/bin/sh\nprintf '%s' '{rows}'\n"))
}

/// A `podup` that answers `ps` with `first` the first time and `second` from
/// the second time on: a container that restarts between the two looks looks
/// the same in both, except for the moment it started.
fn podup_that_changes(dir: &Path, first: &str, second: &str) -> String {
	let counter = dir.join("podup.calls").display().to_string();
	write_podup(
		dir,
		&format!(
			"#!/bin/sh\nn=0\nif [ -f \"{counter}\" ]; then n=$(cat \"{counter}\"); fi\nn=$((n + 1))\n\
			 printf '%s' \"$n\" > \"{counter}\"\nif [ \"$n\" -eq 1 ]; then printf '%s' '{first}'; \
			 else printf '%s' '{second}'; fi\n"
		),
	)
}

fn write_podup(dir: &Path, script: &str) -> String {
	let podup = dir.join("podup");
	std::fs::write(&podup, script).expect("podup");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("mode");
	podup.display().to_string()
}

/// The pair of files the ACME renewal writes, and the moment it wrote them.
fn write_pair(dir: &Path, days: i64, written: u64) -> (PathBuf, PathBuf) {
	let mut params =
		rcgen::CertificateParams::new(vec!["mail.example.org".to_string()]).expect("params");
	let secs = i64::try_from(NOW).expect("now") + days * DAY;
	let (year, month, day) = crate::webdav::rrule::civil_from_secs(secs);
	params.not_before = rcgen::date_time_ymd(2020, 1, 1);
	params.not_after = rcgen::date_time_ymd(year as i32, month as u8, day as u8);
	let key = rcgen::KeyPair::generate().expect("key");
	let cert = params.self_signed(&key).expect("certificate");
	let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
	std::fs::write(&cert_path, cert.pem()).expect("write cert");
	std::fs::write(&key_path, key.serialize_pem()).expect("write key");
	let times = std::fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(written));
	std::fs::File::options()
		.write(true)
		.open(&cert_path)
		.expect("open")
		.set_times(times)
		.expect("mtime");
	(cert_path, key_path)
}

/// An `[acme]` section that renews 30 days before the expiry.
fn acme_section() -> String {
	"[acme]\ndirectory_url = \"https://acme.invalid/dir\"\ndomains = [\"mail.example.org\"]\n\
	 renew_before_days = 30\n"
		.to_string()
}

#[tokio::test]
async fn a_split_stack_reports_the_container() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(
		dir.path(),
		"[dkim]\nselector = \"s1\"\nkey_file = \"/nonexistent/dkim.pem\"\n",
	);
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(
		dir.path(),
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"exited"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let container = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(container.status, Level::Warn);
	assert!(container.detail.contains("40 days left"));
	assert!(
		!report.items.iter().any(|item| item.name == "dkim rotation"),
		"the rotation keeps running through the certificates container: {report:?}"
	);
}

/// Measured on the Debian 13 machine: a `certs` that exits at start is
/// "running" again a second later, so one look is not enough. The item is
/// not `ok` when the two looks do not agree.
#[tokio::test]
async fn a_container_that_restarts_between_the_two_looks_is_not_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), "");
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup_that_changes(
		dir.path(),
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"running","StartedAt":"2026-11-02T06:30:01Z"}]"#,
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"running","StartedAt":"2026-11-02T06:30:13Z"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let container = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_ne!(container.status, Level::Ok, "{container:?}");
	assert!(
		container.detail.contains("did not stay up"),
		"{}",
		container.detail
	);
}

/// A renewal that failed leaves its reason under `<data_dir>/acme`, and the
/// item says so instead of reporting that the certificate is renewed.
#[tokio::test]
async fn a_failed_renewal_downgrades_the_item() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let acme = data_dir.join("acme");
	std::fs::create_dir_all(&acme).expect("acme dir");
	std::fs::write(
		acme.join("renew.error"),
		"1791504000 the DNS provider refused the challenge\n",
	)
	.expect("error");
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(dir.path(), RUNNING);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let container = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(container.status, Level::Warn, "{container:?}");
	assert!(
		container
			.detail
			.contains("the DNS provider refused the challenge"),
		"{}",
		container.detail
	);
}

/// A scheduled renewal that fails leaves no file behind, so the pair on
/// disk is what says it: a pair older than the window in which it had to be
/// renewed is a renewal that did not happen.
#[tokio::test]
async fn a_pair_older_than_the_renewal_window_downgrades_the_item() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let acme = data_dir.join("acme");
	std::fs::create_dir_all(&acme).expect("acme dir");
	// It expires in twenty days, so the renewal was due ten days ago, and
	// the pair in place was written forty days ago.
	write_pair(&acme, 20, NOW - 40 * DAY as u64);
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(dir.path(), RUNNING);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let container = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(container.status, Level::Warn, "{container:?}");
	assert!(
		container.detail.contains("was not renewed"),
		"{}",
		container.detail
	);
}

/// The control: a pair written inside the renewal window says nothing.
#[tokio::test]
async fn a_pair_written_inside_the_renewal_window_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let acme = data_dir.join("acme");
	std::fs::create_dir_all(&acme).expect("acme dir");
	// It expires in sixty days, so the renewal is not due until thirty
	// days from now, and the pair was written yesterday.
	write_pair(&acme, 60, NOW - DAY as u64);
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(dir.path(), RUNNING);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let container = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(container.status, Level::Ok, "{container:?}");
}

/// The control: the same `podup` answer on a stack without the container
/// says nothing about it.
#[tokio::test]
async fn a_stack_without_the_container_has_no_certs_item() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), "");
	compose_file(&ctx, r#"{"mail": {}}"#);
	ctx.podup = podup(dir.path(), r#"[{"Service":"certs","State":"exited"}]"#);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert!(
		!report
			.items
			.iter()
			.any(|item| item.name == "certs" || item.name == "dkim rotation"),
		"{report:?}"
	);
}

/// A split stack with the container down: the renewal happens in the
/// container, so the `renewal` item must not say the certificate is renewed
/// while it is down, and it names the container that renews it.
#[tokio::test]
async fn a_split_stack_with_the_container_down_does_not_renew() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(
		dir.path(),
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"exited"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let renewal = report
		.items
		.iter()
		.find(|item| item.name == "renewal")
		.expect("renewal item");
	assert_ne!(renewal.status, Level::Ok, "{renewal:?}");
	assert!(
		renewal.detail.contains("certificates container"),
		"{}",
		renewal.detail
	);
}

/// The control: a split stack with the container up says the certificate is
/// renewed, and says who renews it.
#[tokio::test]
async fn a_split_stack_with_the_container_up_renews() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	compose_file(&ctx, r#"{"mail": {}, "certs": {}}"#);
	ctx.podup = podup(dir.path(), RUNNING);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let renewal = report
		.items
		.iter()
		.find(|item| item.name == "renewal")
		.expect("renewal item");
	assert_eq!(renewal.status, Level::Ok, "{renewal:?}");
	assert!(
		renewal.detail.contains("certificates container"),
		"{}",
		renewal.detail
	);
}

/// A container the compose file does not name, but that runs, may still hold
/// the DNS credential and the account key: it is reported, not ignored.
#[tokio::test]
async fn an_orphan_container_the_compose_file_does_not_name_is_reported() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &acme_section());
	compose_file(&ctx, r#"{"mail": {}}"#);
	ctx.podup = podup(
		dir.path(),
		r#"[{"Service":"mail","State":"running"},{"Service":"certs","State":"running","StartedAt":"2026-11-02T06:30:01Z"}]"#,
	);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let orphan = report
		.items
		.iter()
		.find(|item| item.name == "certs")
		.expect("certs item");
	assert_eq!(orphan.status, Level::Warn, "{orphan:?}");
	assert!(orphan.detail.contains("does not name"), "{}", orphan.detail);
}
