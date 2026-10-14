//! A certificate nothing renews, and a DANE TLSA record that no longer
//! matches the certificate in use.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::evaluate;
use crate::cli::status::Ctx;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::{Item, Level};
use crate::cli::status::test_support::ctx;
use crate::dane::rrset::TlsaRrset;
use crate::dane::tlsa::TlsaRecord;

const NOW: u64 = 1_791_504_000;
const TLSA_NAME: &str = "_25._tcp.mail.example.org";

/// A `[tls]` pair for mail.example.org expiring `days` after the clock,
/// and the certificate's PEM.
fn tls_ctx(dir: &Path, days: i64) -> (Ctx, String) {
	let mut params =
		rcgen::CertificateParams::new(vec!["mail.example.org".to_string()]).expect("params");
	let secs = i64::try_from(NOW).expect("now") + days * 86_400;
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
			"[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
			cert_path.display().to_string(),
			key_path.display().to_string()
		),
	);
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	(ctx, cert.pem())
}

fn with_acme(ctx: &mut Ctx) {
	ctx.config.as_mut().expect("config").acme = Some(crate::config::Acme {
		directory_url: "https://acme.invalid/dir".into(),
		contacts: Vec::new(),
		domains: vec!["mail.example.org".into()],
		renew_before_days: 30,
		challenge: crate::config::AcmeChallenge::Http01,
	});
}

fn item<'a>(items: &'a [Item], name: &str) -> Option<&'a Item> {
	items.iter().find(|item| item.name == name)
}

#[tokio::test]
async fn a_static_certificate_close_to_expiry_says_nothing_renews_it() {
	for (days, expected) in [
		(15, Level::Ok),
		(14, Level::Ok),
		(13, Level::Warn),
		(2, Level::Warn),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let (ctx, _) = tls_ctx(dir.path(), days);
		let report = evaluate(&ctx, &FakeDns::default()).await;
		let renewal = item(&report.items, "renewal").expect("renewal item");
		assert_eq!(renewal.status, expected, "{days} days left");
		if expected == Level::Warn {
			assert!(
				renewal.detail.contains("nothing renews it"),
				"the warning says why it matters"
			);
		}
	}
}

#[tokio::test]
async fn a_certificate_acme_renews_does_not_warn_about_renewal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (mut ctx, _) = tls_ctx(dir.path(), 10);
	with_acme(&mut ctx);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	let renewal = item(&report.items, "renewal").expect("renewal item");
	assert_eq!(renewal.status, Level::Ok);
	assert!(renewal.detail.contains("ACME"), "ACME renews it");
}

fn tlsa(value: &str) -> TlsaRrset {
	TlsaRrset::Usable(vec![
		TlsaRecord::parse_presentation(value).expect("TLSA record"),
	])
}

#[tokio::test]
async fn a_tlsa_record_of_another_certificate_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (ctx, pem) = tls_ctx(dir.path(), 60);
	let other =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	let stale = crate::dns::records::tlsa_full_cert(&other.cert.pem()).expect("association");
	let mut dns = FakeDns::default();
	dns.tlsa.insert(TLSA_NAME.into(), tlsa(&stale));
	let report = evaluate(&ctx, &dns).await;
	let found = item(&report.items, "tlsa").expect("tlsa item");
	assert_eq!(found.status, Level::Fail, "a stale TLSA stops DANE senders");
	let wanted = crate::dns::records::tlsa_full_cert(&pem).expect("association");
	assert!(
		found.detail.contains(&wanted),
		"the detail names the association to publish"
	);
	assert_eq!(report.status, Level::Fail);
}

#[tokio::test]
async fn a_tlsa_record_of_the_certificate_in_use_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (ctx, pem) = tls_ctx(dir.path(), 60);
	let current = crate::dns::records::tlsa_full_cert(&pem).expect("association");
	let mut dns = FakeDns::default();
	dns.tlsa.insert(TLSA_NAME.into(), tlsa(&current));
	let report = evaluate(&ctx, &dns).await;
	assert_eq!(
		item(&report.items, "tlsa").expect("tlsa item").status,
		Level::Ok
	);
	assert_eq!(report.status, Level::Ok);
}

#[tokio::test]
async fn without_a_secure_tlsa_record_there_is_nothing_to_compare() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (ctx, _) = tls_ctx(dir.path(), 60);
	let report = evaluate(&ctx, &FakeDns::default()).await;
	assert!(item(&report.items, "tlsa").is_none(), "DANE is not in use");
}

#[tokio::test]
async fn the_status_resolver_wrapper_passes_tlsa_lookups_through() {
	use crate::spf::DnsLookup;
	let other =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	let value = crate::dns::records::tlsa_full_cert(&other.cert.pem()).expect("association");
	let mut dns = FakeDns::default();
	dns.tlsa.insert(TLSA_NAME.into(), tlsa(&value));
	let wrapped = crate::cli::status::dns_area::TimeoutDns(dns);
	assert!(
		wrapped.tlsa(TLSA_NAME).await == Ok(tlsa(&value)),
		"the check sees the same RRset the resolver returns"
	);
}
