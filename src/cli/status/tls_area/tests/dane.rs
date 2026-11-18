//! `status` shows the DANE record only when the configuration publishes it.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::evaluate;
use crate::cli::status::dns_fake::FakeDns;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;

const NOW: u64 = 1_791_504_000;

/// A resolver that answers a TLSA record of some other certificate.
fn stale_dns() -> FakeDns {
	let other =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".into()]).expect("certificate");
	let value = crate::dns::records::tlsa_full_cert(&other.cert.pem()).expect("association");
	let mut dns = FakeDns::default();
	dns.tlsa.insert(
		"_25._tcp.mail.example.org".into(),
		crate::dane::rrset::TlsaRrset::Usable(vec![
			crate::dane::tlsa::TlsaRecord::parse_presentation(&value).expect("TLSA record"),
		]),
	);
	dns
}

fn tls_ctx(dir: &Path, dns_publish: &str) -> crate::cli::status::Ctx {
	let key = rcgen::KeyPair::generate().expect("key");
	let params =
		rcgen::CertificateParams::new(vec!["mail.example.org".to_string()]).expect("params");
	let cert = params.self_signed(&key).expect("certificate");
	let (cert_path, key_path) = (dir.join("tls.pem"), dir.join("tls.key"));
	std::fs::write(&cert_path, cert.pem()).expect("write cert");
	std::fs::write(&key_path, key.serialize_pem()).expect("write key");
	let mut ctx = ctx(
		dir,
		&format!(
			"[tls]\ncert_file = {:?}\nkey_file = {:?}\n{dns_publish}",
			cert_path.display().to_string(),
			key_path.display().to_string()
		),
	);
	ctx.now = UNIX_EPOCH + Duration::from_secs(NOW);
	ctx
}

#[tokio::test]
async fn by_default_status_reports_the_tlsa_group_as_skipped_and_owes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path(), "");
	let data_dir = ctx.config.as_ref().expect("config").data_dir.clone();
	let mut state = crate::dns::tlsa::State::load(&data_dir, "mail.example.org");
	state.fail("3 0 1 abcd", "provider down".to_string(), NOW - 7_300);
	state.save(&data_dir).expect("state");

	let report = evaluate(&ctx, &stale_dns()).await;

	let found = report
		.items
		.iter()
		.find(|item| item.name == "tlsa")
		.expect("tlsa item");
	assert_eq!(found.status, Level::Ok);
	assert!(found.detail.contains("skipped by configuration"));
	assert!(report.items.iter().all(|item| item.name != "tlsa-pending"));
}

#[tokio::test]
async fn with_dane_on_status_checks_the_record_and_fails_on_a_stale_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = tls_ctx(dir.path(), "[dns_publish]\ndane = true\n");
	let report = evaluate(&ctx, &stale_dns()).await;
	let found = report
		.items
		.iter()
		.find(|item| item.name == "tlsa")
		.expect("tlsa item");
	assert_eq!(found.status, Level::Fail, "{}", found.detail);
}
