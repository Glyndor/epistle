//! Tests for the certificate check, with generated certificates whose
//! `notAfter` and names are chosen. The clock is fixed at 2026-10-09 00:00 UTC.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::evaluate;
use crate::cli::status::Ctx;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const NOW: u64 = 1_791_504_000;

/// Write a certificate and key for `names` that expires `days` days after
/// the fixed clock (negative: already expired) and return their paths.
fn write_cert(dir: &Path, name: &str, names: &[&str], days: i64) -> (String, String) {
	let mut params =
		rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<String>>())
			.expect("params");
	let secs = i64::try_from(NOW).expect("now") + days * 86_400;
	let (year, month, day) = crate::webdav::rrule::civil_from_secs(secs);
	params.not_before = rcgen::date_time_ymd(2020, 1, 1);
	params.not_after = rcgen::date_time_ymd(year as i32, month as u8, day as u8);
	let key = rcgen::KeyPair::generate().expect("key");
	let cert = params.self_signed(&key).expect("certificate");
	let cert_path = dir.join(format!("{name}.pem"));
	let key_path = dir.join(format!("{name}.key"));
	std::fs::write(&cert_path, cert.pem()).expect("write cert");
	std::fs::write(&key_path, key.serialize_pem()).expect("write key");
	(
		cert_path.display().to_string(),
		key_path.display().to_string(),
	)
}

fn tls_ctx(dir: &Path, names: &[&str], days: i64) -> Ctx {
	let (cert, key) = write_cert(dir, "tls", names, days);
	let mut ctx = ctx(
		dir,
		&format!("[tls]\ncert_file = {cert:?}\nkey_file = {key:?}\n"),
	);
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	ctx
}

#[tokio::test]
async fn a_certificate_far_from_expiry_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path(), &["mail.example.org"], 45);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "mail.example.org expires in 45 days");
}

#[tokio::test]
async fn the_expiry_thresholds_are_21_days_for_warn_and_7_for_fail() {
	for (days, expected) in [
		(22, Level::Ok),
		(21, Level::Ok),
		(20, Level::Warn),
		(8, Level::Warn),
		(7, Level::Warn),
		(6, Level::Fail),
		(1, Level::Fail),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let ctx = tls_ctx(dir.path(), &["mail.example.org"], days);
		let report = evaluate(&ctx, &FakeDns::default()).await;
		assert_eq!(report.status, expected, "{days} days left: {report:?}");
	}
}

#[tokio::test]
async fn an_expired_certificate_fails_and_says_for_how_long() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path(), &["mail.example.org"], -8);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(report.items[0].detail, "expired 8 days ago");
}

#[tokio::test]
async fn a_hostname_missing_from_the_names_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path(), &["other.example.net", "example.net"], 60);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|i| i.name == "names")
		.expect("names item");
	assert_eq!(
		item.detail,
		"mail.example.org is not covered by: other.example.net, example.net"
	);
}

#[tokio::test]
async fn a_wildcard_name_covers_one_label_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ok = tls_ctx(dir.path(), &["*.example.org"], 60);
	assert_eq!(evaluate(&ok, &FakeDns::default()).await.status, Level::Ok);
	let dir = tempfile::tempdir().expect("tempdir");
	let deep = tls_ctx(dir.path(), &["*.org"], 60);
	assert_eq!(
		evaluate(&deep, &FakeDns::default()).await.status,
		Level::Fail
	);
}

#[tokio::test]
async fn an_unreadable_certificate_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = tls_ctx(dir.path(), &["mail.example.org"], 60);
	let missing = dir.path().join("gone.pem");
	ctx.config
		.as_mut()
		.expect("config")
		.tls
		.as_mut()
		.expect("tls")
		.cert_file = missing;
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Fail);
	assert!(
		report.detail.starts_with("cannot read the certificate"),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn without_a_tls_section_the_area_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut ctx = ctx(dir.path(), "");
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Warn);
	assert_eq!(report.detail, "no [tls] certificate is configured");
}

#[tokio::test]
async fn a_renewed_acme_certificate_wins_over_the_bootstrap_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The bootstrap file in [tls] is about to expire; ACME already renewed.
	let mut ctx = tls_ctx(dir.path(), &["mail.example.org"], 3);
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let acme = data_dir.join("acme");
	std::fs::create_dir_all(&acme).expect("acme dir");
	let (renewed, key) = write_cert(dir.path(), "renewed", &["mail.example.org"], 80);
	std::fs::copy(renewed, acme.join("cert.pem")).expect("copy");
	std::fs::copy(key, acme.join("key.pem")).expect("copy key");
	ctx.config.as_mut().expect("config").acme = Some(crate::config::Acme {
		directory_url: "https://acme.invalid/dir".into(),
		contacts: Vec::new(),
		domains: vec!["mail.example.org".into()],
		renew_before_days: 30,
		challenge: crate::config::AcmeChallenge::Http01,
	});
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "mail.example.org expires in 80 days");
}
